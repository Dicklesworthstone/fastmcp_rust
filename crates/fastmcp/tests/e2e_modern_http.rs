//! Public modern HTTP round trip: shipped client against shipped server.
//!
//! Both ends of these tests are real shipped surfaces — the turnkey
//! `Server::bind_http`/`serve` lifecycle on one side and facade client
//! connection lifecycles on the other — joined over one real localhost socket.
//! The fixture uses the lower server builder only to select the explicit
//! Auto, ModernOnly, or LegacyOnly server policy under test; no scripted peer,
//! fixture transcript, or mock stands in for either endpoint.
//!
//! What this proves (and only this): the shipped dual-era HTTP server and
//! facade clients can complete Auto classification plus typed ModernOnly and
//! LegacyOnly tool, resource, and prompt round trips against each other. The
//! cross-era refusal cases additionally prove that a rejected connection does
//! not change later matched-era handler observables. It is not an aggregate
//! MCP 2026-07-28 conformance claim.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fastmcp_rust::server::{BoxFuture, FinalMethodOutcome};
use fastmcp_rust::{
    AccessToken, AuthContext, AuthRequest, CacheScope, CacheTtl, CanonicalHttpUrl,
    ClientCapabilities, ClientHttpConnectionError, ClientHttpResponse, ClientProtocolPlan,
    CompleteResult, CompletionHandler, Content, ContentBlock, CoreResult, Cx, DuplicateBehavior,
    EmbeddedResourceContents, FinalCallToolResult, FinalCoreResult, FinalElicitationContextExt,
    FinalEmbeddedRootsListParams, FinalGetPromptResult, FinalPromptMessage,
    FinalReadResourceResult, FinalResourceTemplate, FinalRootsContextExt, FinalSamplingContextExt,
    FinalToolOutcome, HttpNonquiescentShutdown, HttpServerShutdown, HttpShutdownSettlement,
    JsonRpcMessage, JsonRpcRequest, McpContext, McpError, McpErrorCode, McpOutcome,
    McpRequestCancellation, McpResult, Middleware, MiddlewareDecision, ModernHttpResponseKind,
    ModernHttpResponseStream, Outcome, Prompt, PromptArgument, PromptHandler, PromptMessage,
    ProtocolEra, ProtocolPolicy, RawIcon, Resource, ResourceContent, ResourceHandler,
    ResourceTemplate, ResultMeta, Role, SseLimits, StaticTokenVerifier, TokenAuthProvider,
    TokenVerifier, Tool, ToolAnnotations, ToolErrorKind, ToolHandler, auto, caching, core,
    legacy_2024, modern, prompt, providers, rate_limiting, resource, tool, transform,
};
#[cfg(feature = "tasks")]
use fastmcp_rust::{
    ApplicationTaskSupervisor, FinalTask, FinalTaskId, FinalTaskInputRequests,
    FinalTaskInputResponses, FinalTaskRuntime, FinalTaskRuntimeConfig, FinalTaskSupervisorFuture,
    FinalTaskSupervisorHandoff, FinalTaskWorkDescriptor, FinalToolCallOutcome, RequestId,
};
#[cfg(feature = "websocket-experimental")]
use fastmcp_rust::{
    AsyncWsClientTransport, WebSocketNonquiescentShutdown, WebSocketServerShutdown,
};
#[cfg(feature = "proxy")]
use fastmcp_rust::{
    ClientInfo, ProxyClient, ProxyPromptCatalog, ProxyResourceCatalog, ProxyToolCatalog,
    StdioSubscriptionEvent,
};
use fastmcp_server::ServerBuilder;
use serde_json::json;

const PUBLIC_HTTP_TOOL_NAME: &str = "public-http-e2e-tool";
const PUBLIC_HTTP_TASK_TOOL_NAME: &str = "public-http-e2e-task";
const PUBLIC_HTTP_LOG_TOOL_NAME: &str = "public-http-e2e-log";
const PUBLIC_HTTP_HANDLER_LOG_TEXT: &str = "public-http-handler-info";
const PUBLIC_HTTP_CURSOR_SECONDARY_TOOL_NAME: &str = "public-http-e2e-cursor-secondary";
const PUBLIC_HTTP_RESOURCE_URI: &str = "test://public-http-e2e/resource";
const PUBLIC_HTTP_PROMPT_NAME: &str = "public-http-e2e-prompt";
const PUBLIC_HTTP_TOOL_ARGUMENT: &str = "cross-era";
const PUBLIC_HTTP_TOOL_TEXT: &str = "tool:cross-era";
const PUBLIC_HTTP_RESOURCE_TEXT: &str = "resource:deterministic";
const PUBLIC_HTTP_PROMPT_TEXT: &str = "prompt:cross-era";
const PUBLIC_HTTP_COMPLETION_VALUE: &str = "cross-era-completion";
const PUBLIC_HTTP_AUTH_TOOL_NAME: &str = "public-http-e2e-auth";
const PUBLIC_HTTP_AUTH_SUBJECT: &str = "e2e-native-http-principal";
const PUBLIC_HTTP_ICON_TOOL_NAME: &str = "public-http-e2e-icon";
const PUBLIC_HTTP_PLAIN_TOOL_NAME: &str = "public-http-e2e-plain";
const PUBLIC_HTTP_ICON_SRC: &str = "https://example.test/e2e-icon.png";
const PUBLIC_HTTP_OUTPUT_TOOL_NAME: &str = "public-http-e2e-output";
const PUBLIC_HTTP_COMPOSE_TOOL_NAME: &str = "public-http-e2e-compose";
const PUBLIC_HTTP_COMPOSE_PROMPT_NAME: &str = "public-http-e2e-compose-prompt";
const PUBLIC_HTTP_MACRO_COMPOSE_PROMPT_NAME: &str = "public-http-e2e-macro-compose";
const PUBLIC_HTTP_MACRO_COMPOSE_TOOL_NAME: &str = "public-http-e2e-macro-compose-tool";
const PUBLIC_HTTP_MACRO_COMPOSE_RESOURCE_URI: &str = "test://public-http-e2e/macro-compose";
const PUBLIC_HTTP_MACRO_COMPOSE_MISSING_TOOL_RESOURCE_URI: &str =
    "test://public-http-e2e/macro-compose-missing-tool";
const PUBLIC_HTTP_COMPOSE_RESOURCE_URI: &str = "test://public-http-e2e/compose";
const PUBLIC_HTTP_COMPOSE_MISSING_TOOL_RESOURCE_URI: &str =
    "test://public-http-e2e/compose-missing-tool";
const PUBLIC_HTTP_COMPOSE_MISSING_RESOURCE_URI: &str =
    "test://public-http-e2e/compose-missing-resource";
const PUBLIC_HTTP_STATE_TOOL_NAME: &str = "public-http-e2e-state";
const PUBLIC_HTTP_STATE_KEY: &str = "e2e-request-local-state";
const PUBLIC_HTTP_CAPS_TOOL_NAME: &str = "public-http-e2e-caps";
const PUBLIC_HTTP_INSTRUCTIONS: &str = "use the public-http-e2e-tool";
const PUBLIC_HTTP_DEFAULT_TOOL_NAME: &str = "public-http-e2e-default";
const PUBLIC_HTTP_DEFAULT_SUFFIX: &str = "!";
const PUBLIC_HTTP_RICH_TOOL_NAME: &str = "public-http-e2e-rich";
const PUBLIC_HTTP_IMAGE_MIME: &str = "image/png";
const PUBLIC_HTTP_AUDIO_MIME: &str = "audio/wav";
const PUBLIC_HTTP_IMAGE_DATA: &str = "e2eimage";
const PUBLIC_HTTP_AUDIO_DATA: &str = "e2eaudio";
const PUBLIC_HTTP_CUSTOM_AUTH_SUBJECT: &str = "e2e-custom-verifier-principal";
const PUBLIC_HTTP_CUSTOM_AUTH_TOKEN: &str = "gamma";

/// The deterministic user handler exercised through both public HTTP facades.
#[tool(name = "public-http-e2e-tool", tags = ["cursor"])]
fn public_http_value(_ctx: &McpContext, value: String) -> String {
    format!("tool:{value}")
}

/// Additional catalog entries make the public cursor test cross a real page
/// boundary while keeping the ordinary tool handler deterministic.
#[tool(name = "public-http-e2e-cursor-secondary", tags = ["cursor"])]
fn public_http_cursor_secondary(_ctx: &McpContext) -> String {
    "cursor-secondary".to_owned()
}

/// Deliberately outside the cursor query used by the positive continuation.
#[tool(name = "public-http-e2e-cursor-other", tags = ["other"])]
fn public_http_cursor_other(_ctx: &McpContext) -> String {
    "cursor-other".to_owned()
}

/// The deterministic resource exercised through both public HTTP facades.
#[resource(uri = "test://public-http-e2e/resource")]
fn public_http_snapshot(_ctx: &McpContext) -> String {
    PUBLIC_HTTP_RESOURCE_TEXT.to_owned()
}

#[resource(uri = "test://public-http-e2e/cursor-a", tags = ["cursor"])]
fn public_http_cursor_resource_a(_ctx: &McpContext) -> String {
    "cursor-resource-a".to_owned()
}

#[resource(uri = "test://public-http-e2e/cursor-b", tags = ["cursor"])]
fn public_http_cursor_resource_b(_ctx: &McpContext) -> String {
    "cursor-resource-b".to_owned()
}

#[prompt(name = "public-http-e2e-cursor-prompt-a", tags = ["cursor"])]
fn public_http_cursor_prompt_a(_ctx: &McpContext) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::text("cursor-prompt-a"),
    }]
}

#[prompt(name = "public-http-e2e-cursor-prompt-b", tags = ["cursor"])]
fn public_http_cursor_prompt_b(_ctx: &McpContext) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::text("cursor-prompt-b"),
    }]
}

/// The deterministic prompt exercised through both public HTTP facades.
#[prompt(name = "public-http-e2e-prompt")]
fn public_http_instruction(_ctx: &McpContext, subject: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("prompt:{subject}"),
        },
    }]
}

/// Generated async `#[prompt]` that composes nested tool and resource reads.
#[prompt(name = "public-http-e2e-macro-compose")]
async fn public_http_macro_compose(
    ctx: &McpContext,
    value: String,
    tool: String,
    resource: String,
) -> McpResult<Vec<PromptMessage>> {
    if !ctx.can_call_tools() || !ctx.can_read_resources() {
        return Err(McpError::invalid_request(format!(
            "compose-no-router: can_call_tools={} can_read_resources={}",
            ctx.can_call_tools(),
            ctx.can_read_resources()
        )));
    }
    let tool_text = ctx
        .call_tool_text(&tool, json!({ "value": value }))
        .await
        .map_err(|error| {
            McpError::invalid_request(format!(
                "compose-nested-tool:{tool}:{:?}:{}",
                error.code, error.message
            ))
        })?;
    let resource_text = ctx.read_resource_text(&resource).await.map_err(|error| {
        McpError::invalid_request(format!(
            "compose-nested-resource:{resource}:{:?}:{}",
            error.code, error.message
        ))
    })?;
    Ok(vec![PromptMessage {
        role: Role::User,
        content: Content::text(format!("compose:{tool_text}|{resource_text}")),
    }])
}

async fn public_http_compose_nested(
    ctx: &McpContext,
    value: &str,
    tool: &str,
    resource: &str,
) -> McpResult<String> {
    if !ctx.can_call_tools() || !ctx.can_read_resources() {
        return Err(McpError::invalid_request(format!(
            "compose-no-router: can_call_tools={} can_read_resources={}",
            ctx.can_call_tools(),
            ctx.can_read_resources()
        )));
    }
    let tool_text = ctx
        .call_tool_text(tool, json!({ "value": value }))
        .await
        .map_err(|error| {
            McpError::invalid_request(format!(
                "compose-nested-tool:{tool}:{:?}:{}",
                error.code, error.message
            ))
        })?;
    let resource_text = ctx.read_resource_text(resource).await.map_err(|error| {
        McpError::invalid_request(format!(
            "compose-nested-resource:{resource}:{:?}:{}",
            error.code, error.message
        ))
    })?;
    Ok(format!("compose:{tool_text}|{resource_text}"))
}

/// Generated async `#[tool]` that composes nested tool and resource reads.
#[tool(name = "public-http-e2e-macro-compose-tool")]
async fn public_http_macro_compose_tool(
    ctx: &McpContext,
    value: String,
    tool: String,
    resource: String,
) -> McpResult<String> {
    public_http_compose_nested(ctx, &value, &tool, &resource).await
}

/// Generated async `#[resource]` that composes nested tool and resource reads.
#[resource(uri = "test://public-http-e2e/macro-compose")]
async fn public_http_macro_compose_view(ctx: &McpContext) -> McpResult<String> {
    public_http_compose_nested(
        ctx,
        "alpha",
        PUBLIC_HTTP_TOOL_NAME,
        PUBLIC_HTTP_RESOURCE_URI,
    )
    .await
}

/// Near-identical generated resource whose only change is the nested tool name.
#[resource(uri = "test://public-http-e2e/macro-compose-missing-tool")]
async fn public_http_macro_compose_missing(ctx: &McpContext) -> McpResult<String> {
    public_http_compose_nested(
        ctx,
        "alpha",
        "public-http-e2e-missing",
        PUBLIC_HTTP_RESOURCE_URI,
    )
    .await
}

/// Live modern HTTP tool whose omitted `suffix` is injected from `#[tool]` defaults.
#[tool(name = "public-http-e2e-default", defaults(suffix = "!"))]
fn public_http_default(_ctx: &McpContext, name: String, suffix: String) -> String {
    format!("greet:{name}{suffix}")
}

/// Live modern HTTP tool whose official Tasks create is visible through a prefixed gateway.
#[cfg(all(feature = "proxy", feature = "tasks"))]
struct PublicHttpTaskTool;

#[cfg(all(feature = "proxy", feature = "tasks"))]
impl ToolHandler for PublicHttpTaskTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_TASK_TOOL_NAME.to_owned(),
            description: Some("Creates one official final Tasks operation".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text("exact-2024 Tasks are unavailable")])
    }

    fn declares_final_tasks(&self) -> bool {
        true
    }

    fn call_final_outcome(
        &self,
        _ctx: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<FinalToolOutcome> {
        Ok(FinalToolOutcome::CreateTask {
            work_descriptor: FinalTaskWorkDescriptor::new(json!({
                "operation": "public-http-e2e-task",
            }))?,
            status_message: Some("working through the public HTTP as_proxy Tasks relay".to_owned()),
        })
    }
}

/// Keeps one created official Task live until `tasks/cancel` is honored.
#[cfg(all(feature = "proxy", feature = "tasks"))]
struct PublicHttpHoldingTaskSupervisor;

#[cfg(all(feature = "proxy", feature = "tasks"))]
impl ApplicationTaskSupervisor for PublicHttpHoldingTaskSupervisor {
    fn resume<'a>(
        &'a self,
        cx: &'a Cx,
        handoff: FinalTaskSupervisorHandoff,
    ) -> FinalTaskSupervisorFuture<'a> {
        Box::pin(async move {
            match handoff {
                FinalTaskSupervisorHandoff::Initial(initial) => {
                    let requests: FinalTaskInputRequests = serde_json::from_value(json!({
                        "roots": {"method": "roots/list"}
                    }))
                    .map_err(|error| {
                        McpError::internal_error(format!(
                            "public HTTP as_proxy Tasks input descriptor is invalid: {error}"
                        ))
                    })?;
                    initial.require_input(
                        requests,
                        Some(
                            "awaiting roots through the public HTTP as_proxy Tasks relay"
                                .to_owned(),
                        ),
                    )?;
                }
                FinalTaskSupervisorHandoff::Resumed(accepted) => loop {
                    if accepted.is_cancellation_requested()? {
                        accepted.honor_cancellation(Some(
                            "cancelled through the public HTTP as_proxy Tasks relay".to_owned(),
                        ))?;
                        break;
                    }
                    cx.checkpoint()
                        .map_err(|error| McpError::internal_error(error.to_string()))?;
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                },
            }
            Ok(())
        })
    }
}

#[derive(Default)]
struct PublicHttpHandlerCallCounters {
    tool: AtomicUsize,
    resource: AtomicUsize,
    prompt: AtomicUsize,
    completion: AtomicUsize,
}

#[derive(Debug, Eq, PartialEq)]
struct PublicHttpHandlerCallSnapshot {
    tool: usize,
    resource: usize,
    prompt: usize,
    completion: usize,
}

impl PublicHttpHandlerCallCounters {
    fn snapshot(&self) -> PublicHttpHandlerCallSnapshot {
        PublicHttpHandlerCallSnapshot {
            tool: self.tool.load(Ordering::SeqCst),
            resource: self.resource.load(Ordering::SeqCst),
            prompt: self.prompt.load(Ordering::SeqCst),
            completion: self.completion.load(Ordering::SeqCst),
        }
    }
}

struct CountingPublicHttpValue {
    counters: Arc<PublicHttpHandlerCallCounters>,
}

impl ToolHandler for CountingPublicHttpValue {
    fn definition(&self) -> fastmcp_rust::Tool {
        PublicHttpValue.definition()
    }

    fn call(&self, context: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        self.counters.tool.fetch_add(1, Ordering::SeqCst);
        PublicHttpValue.call(context, arguments)
    }
}

/// Second registration of the same catalog name, used to prove on_duplicate.
struct ReplacedPublicHttpValue;

impl ToolHandler for ReplacedPublicHttpValue {
    fn definition(&self) -> Tool {
        PublicHttpValue.definition()
    }

    fn call(&self, _context: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let value = arguments
            .get("value")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("missing");
        Ok(vec![Content::text(format!("replaced:{value}"))])
    }
}

/// Returns the committed native-HTTP `AuthContext` subject.
struct PublicHttpAuthSubject {
    counters: Arc<PublicHttpHandlerCallCounters>,
}

impl ToolHandler for PublicHttpAuthSubject {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_AUTH_TOOL_NAME.to_owned(),
            description: Some("Returns the committed native HTTP auth subject".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, context: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        self.counters.tool.fetch_add(1, Ordering::SeqCst);
        let subject = context
            .auth()
            .and_then(|auth| auth.subject)
            .unwrap_or_else(|| "anonymous".to_owned());
        Ok(vec![Content::text(format!("subject:{subject}"))])
    }
}

/// Custom `TokenVerifier` that is not a `StaticTokenVerifier`.
struct PublicHttpCustomVerifier;

impl TokenVerifier for PublicHttpCustomVerifier {
    fn verify(
        &self,
        _ctx: &McpContext,
        _request: AuthRequest<'_>,
        token: &AccessToken,
    ) -> McpResult<AuthContext> {
        if token.scheme.eq_ignore_ascii_case("Bearer")
            && token.token == PUBLIC_HTTP_CUSTOM_AUTH_TOKEN
        {
            return Ok(AuthContext::with_subject(PUBLIC_HTTP_CUSTOM_AUTH_SUBJECT));
        }
        Err(McpError::invalid_request("unknown custom token"))
    }
}

/// Returns image and audio content blocks on a live modern tools/call.
struct PublicHttpRichTool;

impl ToolHandler for PublicHttpRichTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_RICH_TOOL_NAME.to_owned(),
            description: Some("Returns image and audio content blocks".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(
        &self,
        _context: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<Vec<Content>> {
        // Exact 2024-11-05 has image but not audio. Keep the representable
        // block here; the final hook below authors both.
        Ok(vec![Content::image_base64(
            PUBLIC_HTTP_IMAGE_DATA,
            PUBLIC_HTTP_IMAGE_MIME,
        )])
    }

    fn call_final(
        &self,
        _context: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<CompleteResult<FinalCallToolResult>> {
        Ok(CompleteResult::new(
            FinalCallToolResult {
                content: vec![
                    ContentBlock::Image {
                        data: PUBLIC_HTTP_IMAGE_DATA.to_owned(),
                        mime_type: PUBLIC_HTTP_IMAGE_MIME.to_owned(),
                        annotations: None,
                        meta: None,
                        additional: BTreeMap::new(),
                    },
                    ContentBlock::Audio {
                        data: PUBLIC_HTTP_AUDIO_DATA.to_owned(),
                        mime_type: PUBLIC_HTTP_AUDIO_MIME.to_owned(),
                        annotations: None,
                        meta: None,
                        additional: BTreeMap::new(),
                    },
                ],
                is_error: false,
                structured_content: None,
            },
            ResultMeta::empty(),
        ))
    }
}

/// Advertises exact-final catalog icons, title, and annotations.
struct PublicHttpIconTool {
    icons: Vec<RawIcon>,
}

impl ToolHandler for PublicHttpIconTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_ICON_TOOL_NAME.to_owned(),
            description: Some("Catalog metadata tool with final icons".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: Some("1.2.3".to_owned()),
            tags: vec!["catalog".to_owned()],
            annotations: Some(ToolAnnotations::new().read_only(true).idempotent(true)),
        }
    }

    fn final_title(&self) -> Option<&str> {
        Some("Icon Tool")
    }

    fn final_icons(&self) -> Option<&[RawIcon]> {
        Some(&self.icons)
    }

    fn call(
        &self,
        _context: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text("icon")])
    }
}

/// Near-identical peer that advertises no final icons, title, or annotations.
struct PublicHttpPlainTool;

impl ToolHandler for PublicHttpPlainTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_PLAIN_TOOL_NAME.to_owned(),
            description: Some("Catalog metadata peer without final icons".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(
        &self,
        _context: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text("plain")])
    }
}

/// Advertises an output schema and authors matching structured content.
struct PublicHttpOutputTool;

impl ToolHandler for PublicHttpOutputTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_OUTPUT_TOOL_NAME.to_owned(),
            description: Some(
                "Returns structured output matching the advertised schema".to_owned(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"]
            }),
            output_schema: Some(json!({
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"]
            })),
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn final_tool_error_structured_content(
        &self,
        kind: ToolErrorKind,
    ) -> Option<serde_json::Value> {
        Some(json!({
            "value": match kind {
                ToolErrorKind::InputValidation => "input-error",
                ToolErrorKind::Handler => "handler-error",
            }
        }))
    }

    fn call(&self, _context: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let value = arguments
            .get("value")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("missing");
        Ok(vec![Content::text(format!("tool:{value}"))])
    }

    fn call_final(
        &self,
        _context: &McpContext,
        arguments: serde_json::Value,
    ) -> McpResult<CompleteResult<FinalCallToolResult>> {
        let value = arguments
            .get("value")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("missing")
            .to_owned();
        Ok(CompleteResult::new(
            FinalCallToolResult {
                content: vec![ContentBlock::text(format!("tool:{value}"))],
                is_error: false,
                structured_content: Some(json!({"value": value})),
            },
            ResultMeta::empty(),
        ))
    }
}

/// Nested `ctx.call_tool` + `ctx.read_resource` through the request-owned router.
struct PublicHttpComposeTool;

impl ToolHandler for PublicHttpComposeTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_COMPOSE_TOOL_NAME.to_owned(),
            description: Some(
                "Composes a nested tools/call and resources/read on the same request".to_owned(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "value": {"type": "string"},
                    "tool": {"type": "string"},
                    "resource": {"type": "string"}
                },
                "required": ["value"]
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(
        &self,
        _context: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<Vec<Content>> {
        // InvalidRequest survives sanitize_handler_error; InternalError is
        // always rewritten to the opaque "Internal server error" terminal.
        Err(McpError::invalid_request(
            "compose-sync-hook: compose must run through the request-owned final async hook",
        ))
    }

    fn call_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
        Box::pin(async move {
            match self.compose_text(ctx, request_cx, arguments).await {
                Outcome::Ok(text) => Outcome::Ok(vec![Content::text(text)]),
                Outcome::Err(error) => Outcome::Err(error),
                Outcome::Cancelled(cancelled) => Outcome::Cancelled(cancelled),
                Outcome::Panicked(panic) => Outcome::Panicked(panic),
            }
        })
    }

    fn call_final_outcome_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
        self.compose_from_request(ctx, request_cx, arguments)
    }

    fn call_final_outcome_async_resuming_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: serde_json::Value,
        _resume_inputs: Option<&'a fastmcp_rust::MrtrCompletedInputs>,
    ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
        self.compose_from_request(ctx, request_cx, arguments)
    }
}

impl PublicHttpComposeTool {
    fn compose_text<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<String>> {
        Box::pin(async move {
            if !ctx.can_call_tools() || !ctx.can_read_resources() {
                return Outcome::Err(McpError::invalid_request(format!(
                    "compose-no-router: can_call_tools={} can_read_resources={}",
                    ctx.can_call_tools(),
                    ctx.can_read_resources()
                )));
            }
            let value = arguments
                .get("value")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("missing");
            let tool_name = arguments
                .get("tool")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(PUBLIC_HTTP_TOOL_NAME);
            let resource_uri = arguments
                .get("resource")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(PUBLIC_HTTP_RESOURCE_URI);
            let tool_text = match ctx
                .call_tool_text(tool_name, json!({ "value": value }))
                .await
            {
                Ok(text) => text,
                Err(error) => {
                    return Outcome::Err(McpError::invalid_request(format!(
                        "compose-nested-tool:{tool_name}:{:?}:{}",
                        error.code, error.message
                    )));
                }
            };
            let resource_text = match ctx.read_resource_text(resource_uri).await {
                Ok(text) => text,
                Err(error) => {
                    return Outcome::Err(McpError::invalid_request(format!(
                        "compose-nested-resource:{resource_uri}:{:?}:{}",
                        error.code, error.message
                    )));
                }
            };
            Outcome::Ok(format!("compose:{tool_text}|{resource_text}"))
        })
    }

    fn compose_from_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
        Box::pin(async move {
            match self.compose_text(ctx, request_cx, arguments).await {
                Outcome::Ok(text) => Outcome::Ok(FinalToolOutcome::Complete(CompleteResult::new(
                    FinalCallToolResult {
                        content: vec![ContentBlock::text(text)],
                        is_error: false,
                        structured_content: None,
                    },
                    ResultMeta::empty(),
                ))),
                Outcome::Err(error) => Outcome::Err(error),
                Outcome::Cancelled(cancelled) => Outcome::Cancelled(cancelled),
                Outcome::Panicked(panic) => Outcome::Panicked(panic),
            }
        })
    }
}

/// Nested `ctx.call_tool` + `ctx.read_resource` from a prompt handler.
struct PublicHttpComposePrompt;

impl PromptHandler for PublicHttpComposePrompt {
    fn definition(&self) -> Prompt {
        Prompt {
            name: PUBLIC_HTTP_COMPOSE_PROMPT_NAME.to_owned(),
            description: Some(
                "Composes a nested tools/call and resources/read from prompts/get".to_owned(),
            ),
            arguments: vec![
                PromptArgument {
                    name: "value".to_owned(),
                    description: Some("Value forwarded to the nested tool".to_owned()),
                    required: true,
                },
                PromptArgument {
                    name: "tool".to_owned(),
                    description: Some("Nested tool name".to_owned()),
                    required: false,
                },
                PromptArgument {
                    name: "resource".to_owned(),
                    description: Some("Nested resource URI".to_owned()),
                    required: false,
                },
            ],
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn get(
        &self,
        _ctx: &McpContext,
        _arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        Err(McpError::invalid_request(
            "compose-sync-hook: prompt compose must run through the request-owned async hook",
        ))
    }

    fn get_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<Vec<PromptMessage>>> {
        Box::pin(async move {
            match self.compose_text(ctx, request_cx, arguments).await {
                Outcome::Ok(text) => Outcome::Ok(vec![PromptMessage {
                    role: Role::User,
                    content: Content::text(text),
                }]),
                Outcome::Err(error) => Outcome::Err(error),
                Outcome::Cancelled(cancelled) => Outcome::Cancelled(cancelled),
                Outcome::Panicked(panic) => Outcome::Panicked(panic),
            }
        })
    }

    fn get_final_outcome_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalGetPromptResult>>> {
        self.compose_from_request(ctx, request_cx, arguments)
    }

    fn get_final_outcome_async_resuming_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: HashMap<String, String>,
        _resume_inputs: Option<&'a fastmcp_rust::MrtrCompletedInputs>,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalGetPromptResult>>> {
        self.compose_from_request(ctx, request_cx, arguments)
    }
}

impl PublicHttpComposePrompt {
    fn compose_text<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        arguments: HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<String>> {
        Box::pin(async move {
            if !ctx.can_call_tools() || !ctx.can_read_resources() {
                return Outcome::Err(McpError::invalid_request(format!(
                    "compose-no-router: can_call_tools={} can_read_resources={}",
                    ctx.can_call_tools(),
                    ctx.can_read_resources()
                )));
            }
            let value = arguments
                .get("value")
                .map(String::as_str)
                .unwrap_or("missing");
            let tool_name = arguments
                .get("tool")
                .map(String::as_str)
                .unwrap_or(PUBLIC_HTTP_TOOL_NAME);
            let resource_uri = arguments
                .get("resource")
                .map(String::as_str)
                .unwrap_or(PUBLIC_HTTP_RESOURCE_URI);
            let tool_text = match ctx
                .call_tool_text(tool_name, json!({ "value": value }))
                .await
            {
                Ok(text) => text,
                Err(error) => {
                    return Outcome::Err(McpError::invalid_request(format!(
                        "compose-nested-tool:{tool_name}:{:?}:{}",
                        error.code, error.message
                    )));
                }
            };
            let resource_text = match ctx.read_resource_text(resource_uri).await {
                Ok(text) => text,
                Err(error) => {
                    return Outcome::Err(McpError::invalid_request(format!(
                        "compose-nested-resource:{resource_uri}:{:?}:{}",
                        error.code, error.message
                    )));
                }
            };
            Outcome::Ok(format!("compose:{tool_text}|{resource_text}"))
        })
    }

    fn compose_from_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalGetPromptResult>>> {
        Box::pin(async move {
            match self.compose_text(ctx, request_cx, arguments).await {
                Outcome::Ok(text) => {
                    Outcome::Ok(FinalMethodOutcome::Complete(CompleteResult::new(
                        FinalGetPromptResult {
                            description: None,
                            messages: vec![FinalPromptMessage {
                                role: Role::User,
                                content: ContentBlock::text(text),
                            }],
                        },
                        ResultMeta::empty(),
                    )))
                }
                Outcome::Err(error) => Outcome::Err(error),
                Outcome::Cancelled(cancelled) => Outcome::Cancelled(cancelled),
                Outcome::Panicked(panic) => Outcome::Panicked(panic),
            }
        })
    }
}

/// Nested `ctx.call_tool` + `ctx.read_resource` from a resource handler.
struct PublicHttpComposeResource {
    uri: &'static str,
    tool: &'static str,
    resource: &'static str,
}

impl ResourceHandler for PublicHttpComposeResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: self.uri.to_owned(),
            name: self.uri.to_owned(),
            description: Some(
                "Composes a nested tools/call and resources/read from resources/read".to_owned(),
            ),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Err(McpError::invalid_request(
            "compose-sync-hook: resource compose must run through the request-owned async hook",
        ))
    }

    fn read_async_with_uri_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        uri: &'a str,
        _params: &'a HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
        Box::pin(async move {
            match self.compose_text(ctx, request_cx).await {
                Outcome::Ok(text) => Outcome::Ok(vec![ResourceContent {
                    uri: uri.to_owned(),
                    mime_type: Some("text/plain".to_owned()),
                    text: Some(text),
                    blob: None,
                }]),
                Outcome::Err(error) => Outcome::Err(error),
                Outcome::Cancelled(cancelled) => Outcome::Cancelled(cancelled),
                Outcome::Panicked(panic) => Outcome::Panicked(panic),
            }
        })
    }

    fn read_final_outcome_async_with_uri_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        uri: &'a str,
        _params: &'a HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalReadResourceResult>>> {
        self.compose_from_request(ctx, request_cx, uri)
    }

    fn read_final_outcome_async_with_uri_resuming_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        uri: &'a str,
        _params: &'a HashMap<String, String>,
        _resume_inputs: Option<&'a fastmcp_rust::MrtrCompletedInputs>,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalReadResourceResult>>> {
        self.compose_from_request(ctx, request_cx, uri)
    }
}

impl PublicHttpComposeResource {
    fn compose_text<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
    ) -> BoxFuture<'a, McpOutcome<String>> {
        Box::pin(async move {
            if !ctx.can_call_tools() || !ctx.can_read_resources() {
                return Outcome::Err(McpError::invalid_request(format!(
                    "compose-no-router: can_call_tools={} can_read_resources={}",
                    ctx.can_call_tools(),
                    ctx.can_read_resources()
                )));
            }
            let tool_text = match ctx
                .call_tool_text(self.tool, json!({ "value": "alpha" }))
                .await
            {
                Ok(text) => text,
                Err(error) => {
                    return Outcome::Err(McpError::invalid_request(format!(
                        "compose-nested-tool:{}:{:?}:{}",
                        self.tool, error.code, error.message
                    )));
                }
            };
            let resource_text = match ctx.read_resource_text(self.resource).await {
                Ok(text) => text,
                Err(error) => {
                    return Outcome::Err(McpError::invalid_request(format!(
                        "compose-nested-resource:{}:{:?}:{}",
                        self.resource, error.code, error.message
                    )));
                }
            };
            Outcome::Ok(format!("compose:{tool_text}|{resource_text}"))
        })
    }

    fn compose_from_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        uri: &'a str,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalReadResourceResult>>> {
        Box::pin(async move {
            match self.compose_text(ctx, request_cx).await {
                Outcome::Ok(text) => {
                    let parsed = match modern::AbsoluteUri::parse(uri) {
                        Ok(parsed) => parsed,
                        Err(error) => {
                            return Outcome::Err(McpError::invalid_request(format!(
                                "compose-resource-uri:{error}"
                            )));
                        }
                    };
                    Outcome::Ok(FinalMethodOutcome::Complete(CompleteResult::new(
                        FinalReadResourceResult {
                            contents: vec![EmbeddedResourceContents::Text {
                                uri: parsed,
                                text,
                                mime_type: Some("text/plain".to_owned()),
                                meta: None,
                                additional: std::collections::BTreeMap::new(),
                            }],
                            ttl_ms: CacheTtl::milliseconds(3_600_000),
                            cache_scope: CacheScope::Private,
                        },
                        ResultMeta::empty(),
                    )))
                }
                Outcome::Err(error) => Outcome::Err(error),
                Outcome::Cancelled(cancelled) => Outcome::Cancelled(cancelled),
                Outcome::Panicked(panic) => Outcome::Panicked(panic),
            }
        })
    }
}

/// Session-state write/read/remove on the request-local modern HTTP bag.
struct PublicHttpStateTool;

impl ToolHandler for PublicHttpStateTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_STATE_TOOL_NAME.to_owned(),
            description: Some("Reads and writes request-local session state".to_owned()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {"type": "string"},
                    "value": {"type": "string"}
                },
                "required": ["action"]
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, context: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        if !context.has_session_state() {
            return Err(McpError::internal_error(
                "modern HTTP request context must carry session state",
            ));
        }
        let action = arguments
            .get("action")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("read");
        let rendered = match action {
            "write" => {
                let value = arguments
                    .get("value")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("missing");
                if !context.set_state(PUBLIC_HTTP_STATE_KEY, value) {
                    return Err(McpError::internal_error(
                        "set_state must succeed on the request-local bag",
                    ));
                }
                let got = context
                    .get_state::<String>(PUBLIC_HTTP_STATE_KEY)
                    .unwrap_or_else(|| "missing".to_owned());
                format!("state:{got}")
            }
            "remove" => {
                let _ = context.remove_state(PUBLIC_HTTP_STATE_KEY);
                let got = context
                    .get_state::<String>(PUBLIC_HTTP_STATE_KEY)
                    .unwrap_or_else(|| "missing".to_owned());
                format!("state:{got}")
            }
            _ => {
                let got = context
                    .get_state::<String>(PUBLIC_HTTP_STATE_KEY)
                    .unwrap_or_else(|| "missing".to_owned());
                format!("state:{got}")
            }
        };
        Ok(vec![Content::text(rendered)])
    }
}

/// Reports handler-visible client and server capability flags.
struct PublicHttpCapsTool;

impl ToolHandler for PublicHttpCapsTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_CAPS_TOOL_NAME.to_owned(),
            description: Some("Returns handler-visible client and server capabilities".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, context: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let client = context.client_capabilities();
        let server = context.server_capabilities();
        Ok(vec![Content::text(format!(
            "caps:sampling={};roots={};tools={};resources={}",
            client.is_some_and(|caps| caps.sampling),
            client.is_some_and(|caps| caps.roots),
            server.is_some_and(|caps| caps.tools),
            server.is_some_and(|caps| caps.resources),
        ))])
    }
}

struct CountingPublicHttpSnapshot {
    counters: Arc<PublicHttpHandlerCallCounters>,
}

impl ResourceHandler for CountingPublicHttpSnapshot {
    fn definition(&self) -> fastmcp_rust::Resource {
        PublicHttpSnapshotResource.definition()
    }

    fn read(&self, context: &McpContext) -> McpResult<Vec<fastmcp_rust::ResourceContent>> {
        self.counters.resource.fetch_add(1, Ordering::SeqCst);
        PublicHttpSnapshotResource.read(context)
    }
}

struct CountingPublicHttpInstruction {
    counters: Arc<PublicHttpHandlerCallCounters>,
}

impl PromptHandler for CountingPublicHttpInstruction {
    fn definition(&self) -> fastmcp_rust::Prompt {
        PublicHttpInstructionPrompt.definition()
    }

    fn get(
        &self,
        context: &McpContext,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        self.counters.prompt.fetch_add(1, Ordering::SeqCst);
        PublicHttpInstructionPrompt.get(context, arguments)
    }
}

struct CountingPublicHttpCompletion {
    counters: Arc<PublicHttpHandlerCallCounters>,
}

impl CompletionHandler for CountingPublicHttpCompletion {
    fn complete_legacy(
        &self,
        _context: &McpContext,
        _params: legacy_2024::LegacyCompletionParams,
    ) -> McpResult<legacy_2024::CompletionValues> {
        Ok(legacy_2024::CompletionValues {
            values: vec![PUBLIC_HTTP_COMPLETION_VALUE.to_owned()],
            total: Some(1),
            has_more: Some(false),
        })
    }

    fn complete_final(
        &self,
        context: &McpContext,
        params: modern::FinalCompletionParams,
    ) -> McpResult<modern::FinalCompletionValues> {
        context.report_progress(0.5, Some("completion-halfway"));
        self.counters.completion.fetch_add(1, Ordering::SeqCst);
        if !matches!(
            &params.reference,
            modern::FinalCompletionReference::PromptWithTitle { name, title }
                if name == PUBLIC_HTTP_PROMPT_NAME && title == "Public HTTP E2E Prompt"
        ) || params.argument.name != "subject"
            || params.argument.value != "cross-era"
            || params
                .context
                .as_ref()
                .and_then(|context| context.arguments.as_ref())
                .and_then(|arguments| arguments.get("region"))
                .map(String::as_str)
                != Some("us-east-1")
        {
            return Err(McpError::invalid_params(
                "the completion fixture requires the exact modern request shape",
            ));
        }
        Ok(modern::FinalCompletionValues {
            values: vec![PUBLIC_HTTP_COMPLETION_VALUE.to_owned()],
            total: Some(modern::JsonInteger::from(1_i64)),
            has_more: Some(false),
        })
    }
}

fn runtime_block_on<F: std::future::Future>(future: F) -> F::Output {
    core::block_on(future)
}

/// Runs one public HTTP operation on the facade-owned runtime. The operation
/// itself is bounded against the supplied caller-owned context clock, so a
/// stalled peer cannot hold this test thread indefinitely.
fn runtime_block_on_bounded<F: std::future::Future>(cx: &Cx, future: F) -> F::Output {
    runtime_block_on_bounded_named(cx, "public HTTP operation", future)
}

fn runtime_block_on_bounded_named<F: std::future::Future>(
    cx: &Cx,
    operation: &str,
    future: F,
) -> F::Output {
    runtime_block_on(async {
        asupersync::time::timeout(cx.now(), HTTP_OPERATION_BOUND, future)
            .await
            .unwrap_or_else(|_| panic!("{operation} stays within its caller-owned deadline"))
    })
}

const HTTP_SERVER_STARTUP_BOUND: Duration = Duration::from_secs(2);
const HTTP_SERVER_TEARDOWN_BOUND: Duration = Duration::from_secs(2);
const HTTP_OPERATION_BOUND: Duration = Duration::from_secs(2);

/// Owns one real public HTTP server composition and proves its teardown.
///
/// The fixture composes one policy-selected server with deterministic public
/// tool, resource, and prompt handlers. Its clients use only shipped facade
/// HTTP clients and real localhost routes; no transcript or mock peer is
/// involved.
struct HttpServerFixture {
    address: SocketAddr,
    server_cx: Cx,
    finished: mpsc::Receiver<Result<HttpServerShutdown, String>>,
    shutdown_completion: Option<Result<HttpServerShutdown, String>>,
    join: Option<JoinHandle<()>>,
    nonquiescent: Option<HttpNonquiescentShutdown>,
    handler_calls: Arc<PublicHttpHandlerCallCounters>,
}

/// Retains a just-spawned fixture until the ready handshake succeeds and it
/// can be transferred into `HttpServerFixture`.
struct HttpServerStartupGuard {
    server_cx: Option<Cx>,
    server_cx_rx: Option<mpsc::Receiver<Cx>>,
    finished: Option<mpsc::Receiver<Result<HttpServerShutdown, String>>>,
    join: Option<JoinHandle<()>>,
}

impl HttpServerStartupGuard {
    fn capture_server_cx(&mut self) {
        if self.server_cx.is_some() {
            return;
        }
        let Some(server_cx_rx) = self.server_cx_rx.as_ref() else {
            return;
        };
        if let Ok(server_cx) = server_cx_rx.try_recv() {
            self.server_cx = Some(server_cx);
            self.server_cx_rx = None;
        }
    }

    fn into_parts(
        mut self,
    ) -> (
        Cx,
        mpsc::Receiver<Result<HttpServerShutdown, String>>,
        Option<JoinHandle<()>>,
    ) {
        (
            self.server_cx
                .take()
                .expect("startup guard retains the runtime-installed server context"),
            self.finished
                .take()
                .expect("startup guard retains completion"),
            self.join.take(),
        )
    }

    fn resume_thread_panic_if_finished(&mut self) {
        let Some(handle) = self.join.as_ref() else {
            return;
        };
        if !handle.is_finished() {
            return;
        }
        let handle = self
            .join
            .take()
            .expect("finished startup thread retains its join handle");
        if let Err(payload) = handle.join() {
            std::panic::resume_unwind(payload);
        }
    }
}

impl Drop for HttpServerStartupGuard {
    fn drop(&mut self) {
        if self.join.is_none() {
            return;
        }
        self.capture_server_cx();
        // If the context has not arrived yet, dropping this receiver makes
        // the server task fail closed before it binds a listener.
        self.server_cx_rx = None;
        if let Some(server_cx) = self.server_cx.as_ref() {
            server_cx.set_cancel_requested(true);
        }
        let Some(finished) = self.finished.as_ref() else {
            return;
        };
        let mut shutdown_completion = None;
        let settlement =
            await_http_server_shutdown(finished, &mut shutdown_completion, &mut self.join);
        if settlement.is_err() && self.join.is_some() {
            eprintln!(
                "public HTTP server startup left a live unjoinable thread after bounded settlement"
            );
            std::process::abort();
        }
    }
}

impl HttpServerFixture {
    fn spawn() -> Self {
        Self::spawn_with_policy(ProtocolPolicy::Auto)
    }

    fn spawn_with_policy(protocol_policy: ProtocolPolicy) -> Self {
        Self::spawn_with_policy_and_middleware(protocol_policy, None)
    }

    fn spawn_modern_with_page_size(page_size: usize) -> Self {
        spawn_modern_facade_http_server(false, Some(page_size), false)
    }

    fn spawn_with_middleware(middleware: Option<Arc<dyn Middleware>>) -> Self {
        Self::spawn_with_policy_and_middleware(ProtocolPolicy::Auto, middleware)
    }

    fn spawn_with_policy_and_middleware(
        protocol_policy: ProtocolPolicy,
        middleware: Option<Arc<dyn Middleware>>,
    ) -> Self {
        Self::spawn_with_configuration(protocol_policy, middleware, None)
    }

    fn spawn_with_configuration(
        protocol_policy: ProtocolPolicy,
        middleware: Option<Arc<dyn Middleware>>,
        page_size: Option<usize>,
    ) -> Self {
        let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
        let tool_calls = Arc::clone(&handler_calls);
        let resource_calls = Arc::clone(&handler_calls);
        let prompt_calls = Arc::clone(&handler_calls);
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
        let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
        let (finished_tx, finished_rx) =
            mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
        let join = Some(thread::spawn(move || {
            let ready_for_spawn_failure = ready_tx.clone();
            let finished_for_spawn_failure = finished_tx.clone();
            let outcome = runtime_block_on(async move {
                let cx = Cx::current().expect("facade runtime installs an ambient server context");
                if server_cx_tx.send(cx.clone()).is_err() {
                    cx.set_cancel_requested(true);
                    return Err("HTTP E2E server control receiver went away".to_owned());
                }
                let builder = ServerBuilder::new("facade-http-example", "1.0.0")
                    .protocol_policy(protocol_policy)
                    .expect("the fixture selects an available protocol policy");
                let builder = match page_size {
                    Some(page_size) => builder.list_page_size(page_size),
                    None => builder,
                };
                let builder = builder
                    .tool(CountingPublicHttpValue {
                        counters: tool_calls,
                    })
                    .tool(PublicHttpCursorSecondary)
                    .tool(PublicHttpCursorOther)
                    .resource(CountingPublicHttpSnapshot {
                        counters: resource_calls,
                    })
                    .prompt(CountingPublicHttpInstruction {
                        counters: prompt_calls,
                    });
                let server = match middleware {
                    Some(middleware) => builder.middleware(middleware).build(),
                    None => builder.build(),
                };
                let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                    Ok(bound) => bound,
                    Err(error) => {
                        let message = format!("facade HTTP server bind failed: {error}");
                        let _ = ready_tx.send(Err(message.clone()));
                        return Err(message);
                    }
                };
                let address = match bound.local_addr() {
                    Ok(address) => address,
                    Err(error) => {
                        let message = format!("facade HTTP server address failed: {error}");
                        let _ = ready_tx.send(Err(message.clone()));
                        return Err(message);
                    }
                };
                if ready_tx.send(Ok(address)).is_err() {
                    cx.set_cancel_requested(true);
                    return Err("HTTP E2E startup receiver went away".to_owned());
                }
                bound
                    .serve(&cx)
                    .await
                    .map_err(|error| format!("facade HTTP server stopped unexpectedly: {error}"))
            });
            if let Err(message) = &outcome {
                let _ = ready_for_spawn_failure.send(Err(message.clone()));
            }
            let _ = finished_for_spawn_failure.send(outcome);
        }));

        let mut startup = HttpServerStartupGuard {
            server_cx: None,
            server_cx_rx: Some(server_cx_rx),
            finished: Some(finished_rx),
            join,
        };
        let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
        let address = loop {
            startup.capture_server_cx();
            let remaining = startup_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                panic!("public HTTP server startup exceeded its bound");
            }
            match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
                Ok(Ok(address)) => break address,
                Ok(Err(error)) => panic!("public HTTP server failed to start: {error}"),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    startup.resume_thread_panic_if_finished();
                    panic!("public HTTP server startup readiness channel disconnected")
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        };
        startup.capture_server_cx();
        let (server_cx, finished, join) = startup.into_parts();

        Self {
            address,
            server_cx,
            finished,
            shutdown_completion: None,
            join,
            nonquiescent: None,
            handler_calls,
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn handler_call_snapshot(&self) -> PublicHttpHandlerCallSnapshot {
        self.handler_calls.snapshot()
    }

    fn settle(&mut self) -> Result<(), String> {
        if let Some(shutdown) = self.nonquiescent.as_mut() {
            return match runtime_block_on(shutdown.settle_for(HTTP_SERVER_TEARDOWN_BOUND)) {
                HttpShutdownSettlement::Settled => {
                    self.nonquiescent = None;
                    Err("facade HTTP server stopped nonquiescently but settled during fixture cleanup"
                        .to_owned())
                }
                HttpShutdownSettlement::Failed { failures } => Err(format!(
                    "facade HTTP server child settlement observed {failures} terminal failure(s)"
                )),
                HttpShutdownSettlement::Pending { remaining } => Err(format!(
                    "facade HTTP server remains nonquiescent after bounded fixture cleanup ({remaining} retained children)"
                )),
            };
        }
        self.server_cx.set_cancel_requested(true);
        match await_http_server_shutdown(
            &self.finished,
            &mut self.shutdown_completion,
            &mut self.join,
        )? {
            HttpServerShutdown::Quiescent => Ok(()),
            HttpServerShutdown::Nonquiescent(shutdown) => {
                self.nonquiescent = Some(shutdown);
                self.settle()
            }
        }
    }

    fn shutdown(mut self) {
        self.settle()
            .unwrap_or_else(|error| panic!("public HTTP server teardown failed: {error}"));
    }
}

/// Starts the public ModernOnly facade with optional native bearer admission.
///
/// This fixture intentionally uses the facade builder instead of the lower
/// server crate so the test covers the public modern API's HTTP delegation.
fn spawn_modern_facade_http_server(
    with_native_bearer_auth: bool,
    page_size: Option<usize>,
    with_resource: bool,
) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let tool_calls = Arc::clone(&handler_calls);
    let resource_calls = Arc::clone(&handler_calls);
    let prompt_calls = Arc::clone(&handler_calls);
    let completion_calls = Arc::clone(&handler_calls);
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("authenticated HTTP server control receiver went away".to_owned());
            }
            let builder = modern::ServerBuilder::new("facade-native-http-auth", "1.0.0");
            let builder = if with_native_bearer_auth {
                let verifier = StaticTokenVerifier::new([(
                    "alpha",
                    AuthContext::with_subject("e2e-native-http-principal"),
                )])
                .expect("the deterministic native bearer verifier is valid")
                .with_allowed_schemes(["Bearer"])
                .expect("the bearer scheme allowlist is valid");
                builder.auth_provider(TokenAuthProvider::new(verifier))
            } else {
                builder
            };
            let builder = builder.tool(CountingPublicHttpValue {
                counters: tool_calls,
            });
            let builder = match page_size {
                Some(page_size) => builder
                    .list_page_size(page_size)
                    .tool(PublicHttpCursorSecondary)
                    .tool(PublicHttpCursorOther),
                None => builder,
            };
            let builder = if with_resource {
                builder.resource(CountingPublicHttpSnapshot {
                    counters: resource_calls,
                })
            } else {
                let _ = resource_calls;
                builder
            };
            let server = builder
                .prompt(CountingPublicHttpInstruction {
                    counters: prompt_calls,
                })
                .prompt_completion_handler(
                    PUBLIC_HTTP_PROMPT_NAME,
                    CountingPublicHttpCompletion {
                        counters: completion_calls,
                    },
                )
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("authenticated facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("authenticated facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("authenticated HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("authenticated facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("authenticated facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("authenticated facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("authenticated facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

/// Starts a public ModernOnly facade whose catalog is composed with `mount()`.
///
/// Tools and prompts come from a prefixed child (`child/...`). The resource
/// stays unprefixed so its exact final URI remains absolute.
fn spawn_modern_mounted_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("mounted HTTP server control receiver went away".to_owned());
            }
            let child = modern::ServerBuilder::new("facade-mounted-child", "1.0.0")
                .tool(PublicHttpValue)
                .prompt(PublicHttpInstructionPrompt)
                .resource(PublicHttpSnapshotResource)
                .build();
            let server = modern::ServerBuilder::new("facade-mounted-parent", "1.0.0")
                .mount(child, Some("child"))
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("mounted facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("mounted facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("mounted HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("mounted facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("mounted facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("mounted facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("mounted facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

impl Drop for HttpServerFixture {
    fn drop(&mut self) {
        if self.join.is_none() && self.nonquiescent.is_none() {
            return;
        }
        if let Err(error) = self.settle() {
            eprintln!("public HTTP server fixture drop failed: {error}");
            // A `JoinHandle` dropped after a failed bounded settlement detaches
            // a live server. Aborting is fail-closed in both normal and panic
            // unwinding paths, after shutdown has already been requested.
            std::process::abort();
        }
    }
}

/// Signals shutdown without blocking, waits for the owned thread's bounded
/// completion report, then joins only after the thread is known to have exited.
/// A timed-out owner remains retained for a controlled retry rather than being
/// detached.
fn await_http_server_shutdown(
    finished: &mpsc::Receiver<Result<HttpServerShutdown, String>>,
    completion: &mut Option<Result<HttpServerShutdown, String>>,
    join: &mut Option<JoinHandle<()>>,
) -> Result<HttpServerShutdown, String> {
    let completion_result = if completion.is_some() {
        Ok(())
    } else {
        finished
            .recv_timeout(HTTP_SERVER_TEARDOWN_BOUND)
            .map(|shutdown| *completion = Some(shutdown))
            .map_err(|error| format!("public HTTP server teardown exceeded its bound: {error}"))
    };
    let join_result = join_finished_thread(join, HTTP_SERVER_TEARDOWN_BOUND, "HTTP server");
    match (completion_result, join_result) {
        (Ok(()), Ok(())) => match completion
            .take()
            .expect("a completed server shutdown retains its completion report")
        {
            Ok(shutdown) => Ok(shutdown),
            Err(completion) => Err(format!("public HTTP server teardown failed: {completion}")),
        },
        (Ok(()), Err(join)) => Err(join),
        (Err(completion), Ok(())) => Err(completion),
        (Err(completion), Err(join)) => Err(format!(
            "{completion}; owned thread settlement failed: {join}"
        )),
    }
}

/// This helper is separately bounded so planted timeout tests can prove that
/// both an unread completion and a received-but-unjoined completion retain
/// their owner for a later controlled retry.
fn settle_http_server_with_bound(
    shutdown: &mpsc::SyncSender<()>,
    finished: &mpsc::Receiver<Result<(), String>>,
    completion: &mut Option<Result<(), String>>,
    join: &mut Option<JoinHandle<()>>,
    completion_bound: Duration,
) -> Result<(), String> {
    match shutdown.try_send(()) {
        Ok(()) | Err(mpsc::TrySendError::Full(()) | mpsc::TrySendError::Disconnected(())) => {}
    }
    let completion_result = if completion.is_some() {
        Ok(())
    } else {
        finished
            .recv_timeout(completion_bound)
            .map(|reported_completion| *completion = Some(reported_completion))
            .map_err(|error| format!("public HTTP server teardown exceeded its bound: {error}"))
    };
    let join_result = join_finished_thread(join, completion_bound, "HTTP server");
    match (completion_result, join_result) {
        (Ok(()), Ok(())) => match completion
            .take()
            .expect("a completed server shutdown retains its completion report")
        {
            Ok(()) => Ok(()),
            Err(completion) => Err(format!("public HTTP server teardown failed: {completion}")),
        },
        (Ok(()), Err(join)) => Err(join),
        (Err(completion), Ok(())) => Err(completion),
        (Err(completion), Err(join)) => Err(format!(
            "{completion}; owned thread settlement failed: {join}"
        )),
    }
}

fn join_finished_thread(
    join: &mut Option<JoinHandle<()>>,
    completion_bound: Duration,
    owner: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + completion_bound;
    loop {
        let Some(handle) = join.as_ref() else {
            return Ok(());
        };
        if handle.is_finished() {
            return join
                .take()
                .expect("completed thread retains its join handle")
                .join()
                .map_err(|_| format!("{owner} thread panicked during settlement"));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{owner} reported completion but did not exit within its bounded settlement window"
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn e2e_http_fixture_planted_teardown_timeout_retains_owner_for_controlled_retry() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (shutdown_tx, shutdown_rx) = mpsc::sync_channel::<()>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let joined = Arc::new(AtomicBool::new(false));
    let joined_by_server = Arc::clone(&joined);
    let mut completion = None;
    let mut server = Some(thread::spawn(move || {
        shutdown_rx
            .recv()
            .expect("the bounded settlement path sends one shutdown signal");
        release_rx
            .recv()
            .expect("the test releases the planted server after the deadline");
        joined_by_server.store(true, Ordering::SeqCst);
        let _ = finished_tx.send(Ok(()));
    }));

    let settlement = settle_http_server_with_bound(
        &shutdown_tx,
        &finished_rx,
        &mut completion,
        &mut server,
        Duration::ZERO,
    );

    assert!(
        !joined.load(Ordering::SeqCst),
        "a timeout must not make an unbounded join attempt"
    );
    assert!(matches!(settlement, Err(error) if error.contains("exceeded its bound")));
    assert!(
        server.is_some(),
        "the timed-out owner stays retained for an explicit controlled retry"
    );
    release_tx
        .send(())
        .expect("the retained server remains controllable after its deadline");
    settle_http_server_with_bound(
        &shutdown_tx,
        &finished_rx,
        &mut completion,
        &mut server,
        HTTP_SERVER_TEARDOWN_BOUND,
    )
    .expect("the released server settles without detaching its owner");
    assert!(joined.load(Ordering::SeqCst));
    assert!(server.is_none(), "settlement joins the retained owner");
}

#[test]
fn e2e_http_fixture_post_completion_join_timeout_retains_completion_for_retry() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (shutdown_tx, shutdown_rx) = mpsc::sync_channel::<()>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let (completion_reported_tx, completion_reported_rx) = mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let joined = Arc::new(AtomicBool::new(false));
    let joined_by_server = Arc::clone(&joined);
    let mut completion = None;
    let mut server = Some(thread::spawn(move || {
        shutdown_rx
            .recv()
            .expect("the controlled test sends one shutdown signal");
        finished_tx
            .send(Ok(()))
            .expect("the completion receiver remains available before the join timeout");
        completion_reported_tx
            .send(())
            .expect("the test observes the queued completion before settlement");
        release_rx
            .recv()
            .expect("the test releases the server after its bounded join timeout");
        joined_by_server.store(true, Ordering::SeqCst);
    }));

    shutdown_tx
        .send(())
        .expect("the test initiates shutdown before waiting for the completion report");
    completion_reported_rx
        .recv_timeout(HTTP_SERVER_TEARDOWN_BOUND)
        .expect("the planted server reports completion within the bound");

    let settlement = settle_http_server_with_bound(
        &shutdown_tx,
        &finished_rx,
        &mut completion,
        &mut server,
        Duration::ZERO,
    );

    assert!(matches!(settlement, Err(error) if error.contains("reported completion")));
    assert!(
        matches!(completion.as_ref(), Some(Ok(()))),
        "a failed bounded join retains the already-received completion for retry"
    );
    assert!(
        server.is_some(),
        "a post-completion join timeout retains the owned thread for controlled retry"
    );
    assert!(
        !joined.load(Ordering::SeqCst),
        "a received completion must not permit an unbounded join"
    );

    release_tx
        .send(())
        .expect("the retained server remains controllable after the join timeout");
    settle_http_server_with_bound(
        &shutdown_tx,
        &finished_rx,
        &mut completion,
        &mut server,
        HTTP_SERVER_TEARDOWN_BOUND,
    )
    .expect("retry consumes the retained completion only after joining the released owner");
    assert!(joined.load(Ordering::SeqCst));
    assert!(
        completion.is_none(),
        "successful settlement consumes the retained completion"
    );
    assert!(server.is_none(), "retry joins the retained owner");
}

#[test]
fn e2e_http_fixture_reported_teardown_failure_still_joins_owner() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (shutdown_tx, shutdown_rx) = mpsc::sync_channel::<()>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let joined = Arc::new(AtomicBool::new(false));
    let joined_by_server = Arc::clone(&joined);
    let mut completion = None;
    let mut server = Some(thread::spawn(move || {
        shutdown_rx
            .recv()
            .expect("the bounded settlement path sends one shutdown signal");
        joined_by_server.store(true, Ordering::SeqCst);
        let _ = finished_tx.send(Err("planted server failure".to_owned()));
    }));

    let settlement = settle_http_server_with_bound(
        &shutdown_tx,
        &finished_rx,
        &mut completion,
        &mut server,
        HTTP_SERVER_TEARDOWN_BOUND,
    );

    assert!(matches!(settlement, Err(error) if error.contains("planted server failure")));
    assert!(joined.load(Ordering::SeqCst));
    assert!(
        server.is_none(),
        "a reported server failure still joins its owner instead of detaching it"
    );
}

#[test]
fn e2e_http_startup_guard_preserves_planted_startup_error() {
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let startup = HttpServerStartupGuard {
        server_cx: Some(Cx::for_request()),
        server_cx_rx: None,
        finished: Some(finished_rx),
        join: Some(thread::spawn(move || {
            let _ = finished_tx.send(Err("planted startup failure".to_owned()));
        })),
    };

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _startup = startup;
        panic!("original startup diagnostic");
    }))
    .expect_err("the enclosing startup failure must propagate");
    assert_eq!(
        *panic
            .downcast::<&str>()
            .expect("the original startup diagnostic is retained"),
        "original startup diagnostic"
    );
}

#[test]
fn e2e_http_startup_guard_resumes_planted_pre_readiness_panic() {
    let (_finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: None,
        finished: Some(finished_rx),
        join: Some(thread::spawn(|| panic!("planted pre-readiness panic"))),
    };
    let deadline = Instant::now() + HTTP_SERVER_TEARDOWN_BOUND;
    while !startup
        .join
        .as_ref()
        .expect("startup guard retains the spawned thread")
        .is_finished()
    {
        assert!(
            Instant::now() < deadline,
            "the planted pre-readiness panic finishes within the bound"
        );
        thread::sleep(Duration::from_millis(1));
    }

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        startup.resume_thread_panic_if_finished();
    }))
    .expect_err("the original pre-readiness panic must be resumed");
    assert_eq!(
        *panic
            .downcast::<&str>()
            .expect("the original pre-readiness panic is retained"),
        "planted pre-readiness panic"
    );
    assert!(startup.join.is_none());
}

fn plan(addr: SocketAddr, policy: ProtocolPolicy) -> ClientProtocolPlan {
    plan_with_modern_post_path(addr, policy, "/mcp")
}

/// Builds one immutable public endpoint plan while allowing an Auto probe to
/// target a live server route that is intentionally not mounted as modern.
/// This supports real 404 fallback coverage without substituting a scripted
/// HTTP peer.
fn plan_with_modern_post_path(
    addr: SocketAddr,
    policy: ProtocolPolicy,
    modern_post_path: &str,
) -> ClientProtocolPlan {
    let modern_target = CanonicalHttpUrl::parse(&format!("http://{addr}{modern_post_path}"))
        .expect("local modern target must be canonical");
    let legacy_sse = CanonicalHttpUrl::parse(&format!("http://{addr}/sse"))
        .expect("legacy SSE target must be canonical");
    let legacy_message = CanonicalHttpUrl::parse(&format!("http://{addr}/messages"))
        .expect("legacy message target must be canonical");
    ClientProtocolPlan::http(
        policy,
        (!matches!(policy, ProtocolPolicy::LegacyOnly)).then_some(modern_target),
        (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_sse),
        (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_message),
        "credential-partition-e2e-http".to_owned(),
        "security-partition-e2e-http".to_owned(),
        "native-h1-e2e-http".to_owned(),
        1,
        1,
        0,
    )
    .expect("the complete HTTP plan must be accepted")
}

/// Consumes whichever response lane the real server selected and returns the
/// final correlated JSON-RPC response document.
fn final_response_document(cx: &Cx, response: ModernHttpResponseStream) -> serde_json::Value {
    match response.metadata().kind() {
        ModernHttpResponseKind::Json => {
            let bytes = runtime_block_on_bounded(cx, response.read_to_end(cx, 1 << 20))
                .expect("immediate JSON body reads to end");
            serde_json::from_slice(&bytes).expect("immediate JSON response parses")
        }
        ModernHttpResponseKind::Sse => {
            let mut stream = response
                .into_sse_stream(SseLimits::new(65_536, 1 << 20, 64).expect("nonzero SSE limits"))
                .expect("SSE response admits the shipped parser");
            let mut terminal = None;
            while let Some(event) = runtime_block_on_bounded(cx, stream.next_event(cx))
                .expect("SSE stream stays readable")
            {
                let value: serde_json::Value =
                    serde_json::from_str(&event).expect("SSE payload is one JSON document");
                if value.get("id").is_some() {
                    terminal = Some(value);
                }
            }
            terminal.expect("SSE stream carried a final correlated response")
        }
        ModernHttpResponseKind::EmptyAcknowledgement => {
            panic!("a correlated request cannot complete with an empty acknowledgement")
        }
        ModernHttpResponseKind::HttpFailure => panic!(
            "unexpected HTTP failure status {} from the shipped server",
            response.metadata().status()
        ),
    }
}

#[derive(Debug, PartialEq)]
struct PublicHttpHandlerObservables {
    tool: serde_json::Value,
    resource: serde_json::Value,
    prompt: serde_json::Value,
}

fn public_http_target(address: SocketAddr, path: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(&format!("http://{address}{path}"))
        .expect("a fixture route must form a canonical HTTP target")
}

fn assert_public_handler_observables(observables: &PublicHttpHandlerObservables) {
    assert_eq!(
        observables.tool["content"][0]["type"],
        json!("text"),
        "the public tool result must retain text content"
    );
    assert_eq!(
        observables.tool["content"][0]["text"],
        json!(PUBLIC_HTTP_TOOL_TEXT),
        "the public tool result must retain the deterministic handler value"
    );
    assert_eq!(
        observables.resource["contents"][0]["uri"],
        json!(PUBLIC_HTTP_RESOURCE_URI),
        "the public resource result must retain the registered URI"
    );
    assert_eq!(
        observables.resource["contents"][0]["text"],
        json!(PUBLIC_HTTP_RESOURCE_TEXT),
        "the public resource result must retain the deterministic handler value"
    );
    assert_eq!(
        observables.prompt["messages"][0]["role"],
        json!("user"),
        "the public prompt result must retain its message role"
    );
    assert_eq!(
        observables.prompt["messages"][0]["content"]["type"],
        json!("text"),
        "the public prompt result must retain text content"
    );
    assert_eq!(
        observables.prompt["messages"][0]["content"]["text"],
        json!(PUBLIC_HTTP_PROMPT_TEXT),
        "the public prompt result must retain the deterministic handler value"
    );
}

fn invoke_modern_public_handlers(cx: &Cx, address: SocketAddr) -> PublicHttpHandlerObservables {
    let mut client = runtime_block_on_bounded(
        cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-modern-handler-client", "1.0.0")
            .connect_http_with_cx(public_http_target(address, "/mcp"), cx),
    )
    .expect("the ModernOnly public facade connects to the live modern route");

    let tool = runtime_block_on_bounded(
        cx,
        client.call_tool_with_mrtr_retry(
            cx,
            Instant::now() + HTTP_SERVER_TEARDOWN_BOUND,
            PUBLIC_HTTP_TOOL_NAME,
            json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
            SseLimits::new(65_536, 1 << 20, 64).expect("nonzero SSE limits"),
            1 << 20,
            |_| {
                Err(McpError::invalid_request(
                    "the deterministic public tool must not request MRTR input",
                ))
            },
        ),
    )
    .expect("the ModernOnly public facade invokes the live deterministic tool");
    let modern::FinalCoreResult::ToolsCall { result: tool, .. } = tool else {
        panic!("the deterministic public tool must complete without MRTR input");
    };
    let tool = serde_json::to_value(tool.payload)
        .expect("the typed modern tool result serializes for its observable assertion");

    let resource = runtime_block_on_bounded(cx, client.read_resource(cx, PUBLIC_HTTP_RESOURCE_URI))
        .expect("the ModernOnly public facade reads the live deterministic resource");
    let resource = serde_json::to_value(resource)
        .expect("the typed modern resource result serializes for its observable assertion");

    let prompt = runtime_block_on_bounded(
        cx,
        client.get_prompt(
            cx,
            PUBLIC_HTTP_PROMPT_NAME,
            HashMap::from([("subject".to_owned(), PUBLIC_HTTP_TOOL_ARGUMENT.to_owned())]),
        ),
    )
    .expect("the ModernOnly public facade gets the live deterministic prompt");
    let prompt = serde_json::to_value(prompt)
        .expect("the typed modern prompt result serializes for its observable assertion");

    let observables = PublicHttpHandlerObservables {
        tool,
        resource,
        prompt,
    };
    assert_public_handler_observables(&observables);
    observables
}

fn invoke_legacy_public_handlers(cx: &Cx, address: SocketAddr) -> PublicHttpHandlerObservables {
    let mut client = runtime_block_on_bounded(
        cx,
        legacy_2024::http_client_builder(
            public_http_target(address, "/sse"),
            public_http_target(address, "/messages"),
        )
        .expect("the exact legacy HTTP endpoints form one public facade plan")
        .client_info("e2e-public-legacy-handler-client", "1.0.0")
        .connect_http_client_with_cx(cx),
    )
    .expect("the LegacyOnly public facade connects to the live exact-legacy routes");
    assert_eq!(
        client.protocol_policy(),
        legacy_2024::ProtocolPolicy::LegacyOnly
    );

    let tool = runtime_block_on_bounded(
        cx,
        client.call_tool(
            cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_TOOL_NAME.to_owned(),
                arguments: Some(json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT })),
                meta: None,
            },
        ),
    )
    .expect("the LegacyOnly public facade invokes the live deterministic tool");
    let tool = serde_json::to_value(tool)
        .expect("the typed legacy tool result serializes for its observable assertion");

    let resource = runtime_block_on_bounded(
        cx,
        client.read_resource(
            cx,
            legacy_2024::ReadResourceParams {
                uri: PUBLIC_HTTP_RESOURCE_URI.to_owned(),
                meta: None,
            },
        ),
    )
    .expect("the LegacyOnly public facade reads the live deterministic resource");
    let resource = serde_json::to_value(resource)
        .expect("the typed legacy resource result serializes for its observable assertion");

    let prompt = runtime_block_on_bounded(
        cx,
        client.get_prompt(
            cx,
            legacy_2024::GetPromptParams {
                name: PUBLIC_HTTP_PROMPT_NAME.to_owned(),
                arguments: Some(HashMap::from([(
                    "subject".to_owned(),
                    PUBLIC_HTTP_TOOL_ARGUMENT.to_owned(),
                )])),
                meta: None,
            },
        ),
    )
    .expect("the LegacyOnly public facade gets the live deterministic prompt");
    let prompt = serde_json::to_value(prompt)
        .expect("the typed legacy prompt result serializes for its observable assertion");

    let observables = PublicHttpHandlerObservables {
        tool,
        resource,
        prompt,
    };
    assert_public_handler_observables(&observables);
    observables
}

#[derive(Default)]
struct OverlapFinalMethodGate {
    state: Mutex<OverlapFinalMethodGateState>,
    entered: Condvar,
    released: Condvar,
}

#[derive(Default)]
struct OverlapFinalMethodGateState {
    modern_tools_list_entered: bool,
    legacy_ping_entered: bool,
    modern_request_id: Option<serde_json::Value>,
    legacy_request_id: Option<serde_json::Value>,
    released: bool,
}

impl OverlapFinalMethodGate {
    fn wait_for_cross_era_requests(&self) -> Result<(), String> {
        let deadline = Instant::now() + HTTP_SERVER_TEARDOWN_BOUND;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !(state.modern_tools_list_entered && state.legacy_ping_entered) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(
                    "the modern tools/list and legacy ping requests did not both reach the overlap gate"
                        .to_owned(),
                );
            }
            let (next, timeout) = self
                .entered
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
            if timeout.timed_out()
                && !(state.modern_tools_list_entered && state.legacy_ping_entered)
            {
                return Err(
                    "the modern tools/list and legacy ping requests did not both reach the overlap gate"
                        .to_owned(),
                );
            }
        }
        if state.modern_request_id != state.legacy_request_id {
            return Err(format!(
                "the overlapping modern and legacy requests used different IDs: modern={:?}, legacy={:?}",
                state.modern_request_id, state.legacy_request_id
            ));
        }
        Ok(())
    }

    fn release(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.released = true;
        self.released.notify_all();
    }
}

impl Middleware for OverlapFinalMethodGate {
    fn on_request(
        &self,
        _ctx: &McpContext,
        request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let request_id = serde_json::to_value(&request.id).map_err(|error| {
            McpError::internal_error(format!("overlap request ID serializes: {error}"))
        })?;
        match request.method.as_str() {
            "tools/list" => {
                state.modern_tools_list_entered = true;
                state.modern_request_id = Some(request_id);
            }
            "ping" => {
                state.legacy_ping_entered = true;
                state.legacy_request_id = Some(request_id);
            }
            _ => return Ok(MiddlewareDecision::Continue),
        }
        self.entered.notify_all();
        while !state.released {
            state = self
                .released
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        Ok(MiddlewareDecision::Continue)
    }
}

enum OverlapWorkerCompletion {
    Modern(Result<serde_json::Value, String>),
    Legacy(Result<serde_json::Value, String>),
}

/// Owns the planted stalled worker through both the deadline observation and
/// panic unwinding. Dropping it releases the worker before a bounded join.
struct StalledOverlapWorker {
    release: mpsc::SyncSender<()>,
    join: Option<JoinHandle<()>>,
}

impl StalledOverlapWorker {
    fn release(&self) {
        match self.release.try_send(()) {
            Ok(()) | Err(mpsc::TrySendError::Full(()) | mpsc::TrySendError::Disconnected(())) => {}
        }
    }

    fn settle(&mut self) -> Result<(), String> {
        self.release();
        join_finished_thread(
            &mut self.join,
            HTTP_SERVER_TEARDOWN_BOUND,
            "stalled overlap worker",
        )
    }
}

impl Drop for StalledOverlapWorker {
    fn drop(&mut self) {
        if self.join.is_none() {
            return;
        }
        if let Err(error) = self.settle() {
            eprintln!("stalled overlap worker settlement failed: {error}");
            std::process::abort();
        }
    }
}

/// Collects the two request outcomes within a deadline. Every caller must
/// then drive the workers to completion and join their retained owners.
fn collect_overlap_worker_results(
    completed: &mpsc::Receiver<OverlapWorkerCompletion>,
    completion_bound: Duration,
) -> (
    Result<serde_json::Value, String>,
    Result<serde_json::Value, String>,
) {
    let deadline = Instant::now() + completion_bound;
    let mut modern = None;
    let mut legacy = None;

    while modern.is_none() || legacy.is_none() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match completed.recv_timeout(remaining) {
            Ok(OverlapWorkerCompletion::Modern(result)) if modern.is_none() => {
                modern = Some(result);
            }
            Ok(OverlapWorkerCompletion::Legacy(result)) if legacy.is_none() => {
                legacy = Some(result);
            }
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    (
        modern.unwrap_or_else(|| {
            Err("the modern overlap worker did not complete before the bounded deadline".to_owned())
        }),
        legacy.unwrap_or_else(|| {
            Err("the legacy overlap worker did not complete before the bounded deadline".to_owned())
        }),
    )
}

#[test]
fn e2e_overlap_worker_timeout_releases_fixture_teardown() {
    let mut server = HttpServerFixture::spawn();
    let (completed_tx, completed_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let stalled_completed_tx = completed_tx.clone();
    let mut stalled_worker = StalledOverlapWorker {
        release: release_tx,
        join: Some(thread::spawn(move || {
            release_rx
                .recv()
                .expect("the test releases the single stalled worker after its deadline");
            let _ = stalled_completed_tx.send(OverlapWorkerCompletion::Modern(Ok(json!({}))));
        })),
    };

    completed_tx
        .send(OverlapWorkerCompletion::Legacy(Ok(json!({}))))
        .expect("the non-stalled worker completion reaches the collector");
    drop(completed_tx);

    let (modern, legacy) = collect_overlap_worker_results(&completed_rx, Duration::from_millis(20));
    assert!(
        matches!(modern, Err(error) if error.contains("modern overlap worker")),
        "only the deliberately stalled modern worker may exceed the completion deadline"
    );
    assert!(
        legacy.is_ok(),
        "the unchanged legacy worker completion is retained"
    );

    stalled_worker.release();
    let completion = completed_rx
        .recv_timeout(HTTP_SERVER_TEARDOWN_BOUND)
        .expect("the released worker reports completion within its bounded cleanup window");
    assert!(matches!(completion, OverlapWorkerCompletion::Modern(Ok(_))));
    stalled_worker
        .settle()
        .expect("the released worker joins without detaching");
    assert!(stalled_worker.join.is_none());
    let teardown = server.settle();
    teardown.expect("the bounded fixture teardown runs after a worker completion timeout");
}

#[test]
fn e2e_public_http_typed_facades_invoke_real_handlers_in_each_exact_era() {
    let cx = Cx::for_request();

    let modern_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::ModernOnly);
    let modern = invoke_modern_public_handlers(&cx, modern_server.address());
    assert_public_handler_observables(&modern);
    modern_server.shutdown();

    let legacy_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::LegacyOnly);
    let legacy = invoke_legacy_public_handlers(&cx, legacy_server.address());
    assert_public_handler_observables(&legacy);
    legacy_server.shutdown();
}

#[test]
fn e2e_public_sse_constructor_invokes_live_legacy_handlers() {
    let cx = Cx::for_request();
    let server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::LegacyOnly);
    let mut client = runtime_block_on_bounded(
        &cx,
        fastmcp_rust::Client::sse_with_cx(
            public_http_target(server.address(), "/sse"),
            public_http_target(server.address(), "/messages"),
            &cx,
        ),
    )
    .expect("Client::sse_with_cx connects exact-2024 SSE without probing modern HTTP");

    let result = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PUBLIC_HTTP_TOOL_NAME,
            json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
        ),
    )
    .expect("the standalone SSE constructor must invoke the live legacy tool");
    let CoreResult::Legacy(legacy_2024::LegacyCoreResult::ToolsCall(result)) = result else {
        panic!("Client::sse must stay on the exact-2024 tool result: {result:?}");
    };
    let tool = serde_json::to_value(result)
        .expect("the exact-2024 SSE tool result serializes for its observable assertion");
    assert_eq!(
        tool["content"][0]["text"],
        json!(PUBLIC_HTTP_TOOL_TEXT),
        "Client::sse must retain the live handler value"
    );
    drop(client);
    server.shutdown();
}

fn spawn_legacy_compose_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let tool_calls = Arc::clone(&handler_calls);
    let resource_calls = Arc::clone(&handler_calls);
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy compose HTTP server control receiver went away".to_owned());
            }
            let server = ServerBuilder::new("facade-http-legacy-compose", "1.0.0")
                .protocol_policy(ProtocolPolicy::LegacyOnly)
                .expect("LegacyOnly is available")
                .tool(CountingPublicHttpValue {
                    counters: Arc::clone(&tool_calls),
                })
                .tool(PublicHttpComposeTool)
                .resource(CountingPublicHttpSnapshot {
                    counters: resource_calls,
                })
                .resource(PublicHttpComposeResource {
                    uri: PUBLIC_HTTP_COMPOSE_RESOURCE_URI,
                    tool: PUBLIC_HTTP_TOOL_NAME,
                    resource: PUBLIC_HTTP_RESOURCE_URI,
                })
                .resource(PublicHttpComposeResource {
                    uri: PUBLIC_HTTP_COMPOSE_MISSING_TOOL_RESOURCE_URI,
                    tool: "public-http-e2e-missing",
                    resource: PUBLIC_HTTP_RESOURCE_URI,
                })
                .resource(PublicHttpComposeResource {
                    uri: PUBLIC_HTTP_COMPOSE_MISSING_RESOURCE_URI,
                    tool: PUBLIC_HTTP_TOOL_NAME,
                    resource: "test://public-http-e2e/missing",
                })
                .prompt(PublicHttpComposePrompt)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("legacy compose HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("legacy compose HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy compose HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("legacy compose HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("legacy compose HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("legacy compose HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("legacy compose HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_sse_compose_nested_tool_and_resource() {
    let cx = Cx::for_request();
    let server = spawn_legacy_compose_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        fastmcp_rust::Client::sse_with_cx(
            public_http_target(server.address(), "/sse"),
            public_http_target(server.address(), "/messages"),
            &cx,
        ),
    )
    .expect("Client::sse_with_cx connects exact-2024 SSE to the compose server");

    let result = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PUBLIC_HTTP_COMPOSE_TOOL_NAME,
            json!({"value": "alpha"}),
        ),
    )
    .expect("exact-2024 SSE must compose a nested tool call and resource read");
    let CoreResult::Legacy(legacy_2024::LegacyCoreResult::ToolsCall(result)) = result else {
        panic!("Client::sse compose must stay on the exact-2024 tool result: {result:?}");
    };
    let tool = serde_json::to_value(result).expect("the exact-2024 SSE compose result serializes");
    assert_eq!(
        tool["content"][0]["text"],
        json!("compose:tool:alpha|resource:deterministic"),
        "exact-2024 session dispatch must attach request-scoped callers: {tool}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the nested tools/call must invoke the peer tool exactly once"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "the nested resources/read must invoke the peer resource exactly once"
    );

    let missing = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PUBLIC_HTTP_COMPOSE_TOOL_NAME,
            json!({"value": "alpha", "tool": "public-http-e2e-missing"}),
        ),
    );
    let missing = match missing {
        Ok(result) => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        missing.contains("public-http-e2e-missing")
            || missing.contains("compose-nested-tool")
            || missing.contains("Unknown tool")
            || missing.contains("not found"),
        "the nested unknown tool must stay a handler-visible refusal: {missing}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "an unknown nested tool name must not invoke the peer tool"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_sse_prompt_composes_nested_tool_and_resource() {
    let cx = Cx::for_request();
    let server = spawn_legacy_compose_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        fastmcp_rust::Client::sse_with_cx(
            public_http_target(server.address(), "/sse"),
            public_http_target(server.address(), "/messages"),
            &cx,
        ),
    )
    .expect("Client::sse_with_cx connects exact-2024 SSE to the prompt compose server");

    let result = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            PUBLIC_HTTP_COMPOSE_PROMPT_NAME,
            HashMap::from([("value".to_owned(), "alpha".to_owned())]),
        ),
    )
    .expect("exact-2024 SSE must compose a nested tool call and resource read from prompts/get");
    let CoreResult::Legacy(legacy_2024::LegacyCoreResult::PromptsGet(result)) = result else {
        panic!("Client::sse prompt compose must stay on the exact-2024 prompt result: {result:?}");
    };
    let prompt = serde_json::to_value(result).expect("the exact-2024 SSE prompt result serializes");
    assert_eq!(
        prompt["messages"][0]["content"]["text"],
        json!("compose:tool:alpha|resource:deterministic"),
        "exact-2024 session prompt dispatch must attach request-scoped callers: {prompt}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the nested tools/call must invoke the peer tool exactly once"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "the nested resources/read must invoke the peer resource exactly once"
    );

    let missing = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            PUBLIC_HTTP_COMPOSE_PROMPT_NAME,
            HashMap::from([
                ("value".to_owned(), "alpha".to_owned()),
                ("tool".to_owned(), "public-http-e2e-missing".to_owned()),
            ]),
        ),
    );
    let missing = match missing {
        Ok(result) => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        missing.contains("public-http-e2e-missing")
            || missing.contains("compose-nested-tool")
            || missing.contains("Unknown tool")
            || missing.contains("not found"),
        "the nested unknown tool must stay a handler-visible refusal: {missing}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "an unknown nested tool name must not invoke the peer tool"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_sse_resource_composes_nested_tool_and_resource() {
    let cx = Cx::for_request();
    let server = spawn_legacy_compose_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        fastmcp_rust::Client::sse_with_cx(
            public_http_target(server.address(), "/sse"),
            public_http_target(server.address(), "/messages"),
            &cx,
        ),
    )
    .expect("Client::sse_with_cx connects exact-2024 SSE to the resource compose server");

    let result = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_COMPOSE_RESOURCE_URI),
    )
    .expect("exact-2024 SSE must compose a nested tool call and resource read from resources/read");
    let CoreResult::Legacy(legacy_2024::LegacyCoreResult::ResourcesRead(result)) = result else {
        panic!(
            "Client::sse resource compose must stay on the exact-2024 resource result: {result:?}"
        );
    };
    let resource =
        serde_json::to_value(result).expect("the exact-2024 SSE resource result serializes");
    assert_eq!(
        resource["contents"][0]["text"],
        json!("compose:tool:alpha|resource:deterministic"),
        "exact-2024 session resource dispatch must attach request-scoped callers: {resource}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the nested tools/call must invoke the peer tool exactly once"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "the nested resources/read must invoke the peer resource exactly once"
    );

    let missing = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_COMPOSE_MISSING_TOOL_RESOURCE_URI),
    );
    let missing = match missing {
        Ok(result) => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        missing.contains("public-http-e2e-missing")
            || missing.contains("compose-nested-tool")
            || missing.contains("Unknown tool")
            || missing.contains("not found"),
        "the nested unknown tool must stay a handler-visible refusal: {missing}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "an unknown nested tool name must not invoke the peer tool"
    );

    drop(client);
    server.shutdown();
}

fn spawn_legacy_caps_http_server(with_resource: bool) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy caps HTTP server control receiver went away".to_owned());
            }
            let builder = ServerBuilder::new("facade-http-legacy-caps", "1.0.0")
                .protocol_policy(ProtocolPolicy::LegacyOnly)
                .expect("LegacyOnly is available")
                .tool(PublicHttpCapsTool);
            let builder = if with_resource {
                builder.resource(PublicHttpSnapshotResource)
            } else {
                builder
            };
            let server = builder.build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("legacy caps HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("legacy caps HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy caps HTTP server startup receiver went away".to_owned());
            }
            bound
                .serve(&cx)
                .await
                .map_err(|error| format!("legacy caps HTTP server stopped unexpectedly: {error}"))
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("legacy caps HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("legacy caps HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("legacy caps HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

fn legacy_caps_text(result: &legacy_2024::CallToolResult) -> String {
    serde_json::to_value(result)
        .ok()
        .and_then(|value| value["content"][0]["text"].as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("missing text: {result:?}"))
}

#[test]
fn e2e_public_sse_handler_sees_initialized_client_capabilities() {
    let cx = Cx::for_request();
    let with_resources = spawn_legacy_caps_http_server(true);
    let without_resources = spawn_legacy_caps_http_server(false);

    let mut default_client = runtime_block_on_bounded(
        &cx,
        legacy_2024::http_client_builder(
            public_http_target(with_resources.address(), "/sse"),
            public_http_target(with_resources.address(), "/messages"),
        )
        .expect("default exact-2024 SSE endpoints form one plan")
        .client_info("e2e-legacy-caps-default", "1.0.0")
        .connect_http_client_with_cx(&cx),
    )
    .expect("the default exact-2024 client connects");
    let default = runtime_block_on_bounded(
        &cx,
        default_client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_CAPS_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("default exact-2024 tools/call must reach the capability handler");
    assert_eq!(
        legacy_caps_text(&default),
        "caps:sampling=false;roots=false;tools=true;resources=true",
        "a default initialize must not invent sampling/roots, and a resource-bearing server must advertise both"
    );

    let mut sampling_client = runtime_block_on_bounded(
        &cx,
        legacy_2024::http_client_builder(
            public_http_target(with_resources.address(), "/sse"),
            public_http_target(with_resources.address(), "/messages"),
        )
        .expect("sampling exact-2024 SSE endpoints form one plan")
        .client_info("e2e-legacy-caps-sampling", "1.0.0")
        .capabilities(ClientCapabilities {
            sampling: Some(Default::default()),
            elicitation: None,
            roots: Some(Default::default()),
        })
        .reverse_request_handlers(
            legacy_2024::LegacyReverseRequestHandlers::new()
                .with_sampling_create_message(|_cx, _cancel, _params| {
                    Box::pin(async {
                        Ok(legacy_2024::LegacyCreateMessageResult::text(
                            "e2e-unused-sample",
                            "e2e-unused-model",
                        ))
                    })
                })
                .with_roots_list(|_cx, _cancel, _params| {
                    Box::pin(async { Ok(legacy_2024::LegacyListRootsResult::empty()) })
                }),
        )
        .connect_http_client_with_cx(&cx),
    )
    .expect("the sampling/roots exact-2024 client connects");
    let sampling = runtime_block_on_bounded(
        &cx,
        sampling_client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_CAPS_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("sampling exact-2024 tools/call must reach the capability handler");
    assert_eq!(
        legacy_caps_text(&sampling),
        "caps:sampling=true;roots=true;tools=true;resources=true",
        "initialize sampling+roots must reach ctx.client_capabilities on the exact-2024 session path"
    );

    let mut bare_client = runtime_block_on_bounded(
        &cx,
        legacy_2024::http_client_builder(
            public_http_target(without_resources.address(), "/sse"),
            public_http_target(without_resources.address(), "/messages"),
        )
        .expect("bare exact-2024 SSE endpoints form one plan")
        .client_info("e2e-legacy-caps-bare", "1.0.0")
        .connect_http_client_with_cx(&cx),
    )
    .expect("the default client connects to the tool-only exact-2024 server");
    let bare = runtime_block_on_bounded(
        &cx,
        bare_client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_CAPS_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("tool-only exact-2024 tools/call must reach the capability handler");
    assert_eq!(
        legacy_caps_text(&bare),
        "caps:sampling=false;roots=false;tools=true;resources=false",
        "omitting the resource registration must clear only the handler-visible resources flag"
    );

    drop(default_client);
    drop(sampling_client);
    drop(bare_client);
    with_resources.shutdown();
    without_resources.shutdown();
}

#[cfg(feature = "proxy")]
fn spawn_modern_http_proxy_gateway(upstream: SocketAddr) -> HttpServerFixture {
    spawn_modern_http_proxy_gateway_with_prefix(upstream, None)
}

#[cfg(feature = "proxy")]
fn spawn_modern_http_proxy_gateway_with_prefix(
    upstream: SocketAddr,
    prefix: Option<&'static str>,
) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(
                asupersync::runtime::reactor::create_reactor()
                    .expect("proxy gateway HTTP server reactor initializes"),
            )
            .build()
            .expect("proxy gateway HTTP server installs an owned runtime");
        let outcome = runtime.block_on(async move {
            let cx =
                Cx::current().expect("owned gateway runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("proxy gateway HTTP server control receiver went away".to_owned());
            }
            let plan = ClientProtocolPlan::http(
                ProtocolPolicy::ModernOnly,
                Some(public_http_target(upstream, "/mcp")),
                None,
                None,
                "e2e-http-proxy-gateway".to_owned(),
                "e2e-http-proxy-gateway".to_owned(),
                "modern-http".to_owned(),
                0,
                0,
                0,
            )
            .map_err(|error| format!("proxy gateway HTTP plan failed: {error}"))?;
            let mut registry = ProxyClient::upstream_binding_registry();
            let proxy = registry
                .connect_http_with_protocol_plan(
                    "e2e-live-upstream",
                    "native-h1:e2e-live-upstream",
                    1,
                    plan,
                    ClientInfo {
                        name: "e2e-http-proxy".to_owned(),
                        version: "1.0.0".to_owned(),
                    },
                    ClientCapabilities::default(),
                    cx.clone(),
                )
                .map_err(|error| format!("live HTTP proxy upstream connect failed: {error}"))?;
            let catalog = proxy
                .catalog_typed()
                .map_err(|error| format!("live HTTP proxy catalog failed: {error}"))?;
            let tool_names = catalog
                .final_tools()
                .map(|tools| {
                    tools
                        .iter()
                        .map(|tool| tool.name.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !tool_names.contains(&PUBLIC_HTTP_TOOL_NAME) {
                return Err(format!(
                    "live HTTP proxy catalog omitted {PUBLIC_HTTP_TOOL_NAME}: {tool_names:?}"
                ));
            }
            let prompt_names = catalog
                .final_prompts()
                .map(|prompts| {
                    prompts
                        .iter()
                        .map(|prompt| prompt.name.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !prompt_names.contains(&PUBLIC_HTTP_PROMPT_NAME) {
                return Err(format!(
                    "live HTTP proxy catalog omitted {PUBLIC_HTTP_PROMPT_NAME}: {prompt_names:?}"
                ));
            }
            let resource_uris = catalog
                .final_resources()
                .map(|resources| {
                    resources
                        .iter()
                        .map(|resource| resource.uri.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !resource_uris.contains(&PUBLIC_HTTP_RESOURCE_URI) {
                return Err(format!(
                    "live HTTP proxy catalog omitted {PUBLIC_HTTP_RESOURCE_URI}: {resource_uris:?}"
                ));
            }
            let server = match prefix {
                Some(prefix) => {
                    let server = modern::ServerBuilder::new("e2e-http-gateway", "1.0.0")
                        .as_proxy_typed(prefix, proxy, catalog)
                        .map_err(|error| format!("as_proxy_typed install failed: {error}"))?
                        .build();
                    if server.final_task_runtime().is_some() {
                        return Err(
                            "as_proxy_typed must install the route-bound Tasks relay instead of the default in-memory store"
                                .to_owned(),
                        );
                    }
                    server
                }
                None => modern::ServerBuilder::new("e2e-http-gateway", "1.0.0")
                    .proxy_typed(proxy, catalog)
                    .map_err(|error| format!("proxy_typed install failed: {error}"))?
                    .build(),
            };
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("proxy gateway HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("proxy gateway HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("proxy gateway HTTP server startup receiver went away".to_owned());
            }
            bound
                .serve(&cx)
                .await
                .map_err(|error| format!("proxy gateway HTTP server stopped unexpectedly: {error}"))
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("proxy gateway HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("proxy gateway HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("proxy gateway HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[cfg(feature = "proxy")]
#[test]
fn e2e_public_http_proxy_gateway_forwards_live_bind_http_tool() {
    let cx = Cx::for_request();
    let upstream = spawn_modern_facade_http_server(false, None, true);
    let gateway = spawn_modern_http_proxy_gateway(upstream.address());
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-proxy-client", "1.0.0")
            .connect_http_with_cx(public_http_target(gateway.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live HTTP proxy gateway");

    let listed = runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("the live HTTP gateway must advertise the upstream tools/list catalog");
    assert!(
        listed
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_TOOL_NAME),
        "proxy_typed must retain the live upstream tool name: {listed:?}"
    );

    let result = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PUBLIC_HTTP_TOOL_NAME,
            json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
        ),
    )
    .expect("the live HTTP gateway must forward tools/call to the upstream bind_http server");
    assert!(
        result.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == PUBLIC_HTTP_TOOL_TEXT,
            _ => false,
        }),
        "the proxied live tool must retain the upstream handler value: {result:?}"
    );

    let listed_prompts = runtime_block_on_bounded(&cx, client.list_prompts(&cx, None))
        .expect("the live HTTP gateway must advertise the upstream prompts/list catalog");
    assert!(
        listed_prompts
            .prompts
            .iter()
            .any(|prompt| prompt.name == PUBLIC_HTTP_PROMPT_NAME),
        "proxy_typed must retain the live upstream prompt name: {listed_prompts:?}"
    );
    let prompt = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            PUBLIC_HTTP_PROMPT_NAME,
            HashMap::from([("subject".to_owned(), PUBLIC_HTTP_TOOL_ARGUMENT.to_owned())]),
        ),
    )
    .expect("the live HTTP gateway must forward prompts/get to the upstream bind_http server");
    let prompt = serde_json::to_value(prompt)
        .expect("the proxied prompt result serializes for its observable assertion");
    assert_eq!(
        prompt["messages"][0]["content"]["text"],
        json!(PUBLIC_HTTP_PROMPT_TEXT),
        "the proxied live prompt must retain the upstream handler value: {prompt:?}"
    );

    let listed_resources = runtime_block_on_bounded(&cx, client.list_resources(&cx, None))
        .expect("the live HTTP gateway must advertise the upstream resources/list catalog");
    assert!(
        listed_resources
            .resources
            .iter()
            .any(|resource| resource.uri.as_str() == PUBLIC_HTTP_RESOURCE_URI),
        "proxy_typed must retain the live upstream resource URI: {listed_resources:?}"
    );
    let resource =
        runtime_block_on_bounded(&cx, client.read_resource(&cx, PUBLIC_HTTP_RESOURCE_URI)).expect(
            "the live HTTP gateway must forward resources/read to the upstream bind_http server",
        );
    assert!(
        matches!(
            resource.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == PUBLIC_HTTP_RESOURCE_TEXT
        ),
        "the proxied live resource must retain the upstream handler value: {:?}",
        resource.contents
    );

    let completion = runtime_block_on_bounded(
        &cx,
        client.complete(
            &cx,
            modern::CompletionParams {
                reference: modern::CompletionReference::PromptWithTitle {
                    name: PUBLIC_HTTP_PROMPT_NAME.to_owned(),
                    title: "Public HTTP E2E Prompt".to_owned(),
                },
                argument: modern::FinalCompletionArgument {
                    name: "subject".to_owned(),
                    value: "cross-era".to_owned(),
                },
                context: Some(modern::FinalCompletionContext {
                    arguments: Some(std::collections::BTreeMap::from([(
                        "region".to_owned(),
                        "us-east-1".to_owned(),
                    )])),
                }),
            },
        ),
    )
    .expect(
        "the live HTTP gateway must forward completion/complete to the upstream bind_http server",
    );
    assert_eq!(
        completion.completion.values,
        vec![PUBLIC_HTTP_COMPLETION_VALUE.to_owned()],
        "the proxied live completion must retain the upstream provider values: {completion:?}"
    );

    drop(client);
    gateway.shutdown();
    upstream.shutdown();
}

#[cfg(feature = "proxy")]
#[test]
fn e2e_public_http_prefixed_as_proxy_forwards_prefixed_tool_and_unprefixed_resource() {
    const PREFIXED_TOOL_NAME: &str = "ext/public-http-e2e-tool";
    const PREFIXED_PROMPT_NAME: &str = "ext/public-http-e2e-prompt";

    let cx = Cx::for_request();
    let upstream = spawn_modern_facade_http_server(false, None, true);
    let gateway = spawn_modern_http_proxy_gateway_with_prefix(upstream.address(), Some("ext"));
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-as-proxy-client", "1.0.0")
            .connect_http_with_cx(public_http_target(gateway.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live prefixed as_proxy HTTP gateway");

    let listed = runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("the live prefixed gateway must advertise the upstream tools/list catalog");
    assert!(
        listed
            .tools
            .iter()
            .any(|tool| tool.name == PREFIXED_TOOL_NAME),
        "as_proxy_typed must prefix the live upstream tool name: {listed:?}"
    );
    assert!(
        !listed
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_TOOL_NAME),
        "a nonempty as_proxy prefix must not keep the unprefixed upstream tool: {listed:?}"
    );

    let result = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PREFIXED_TOOL_NAME,
            json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
        ),
    )
    .expect("the live prefixed gateway must forward tools/call to the upstream bind_http server");
    assert!(
        result.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == PUBLIC_HTTP_TOOL_TEXT,
            _ => false,
        }),
        "the prefixed live tool must retain the upstream handler value: {result:?}"
    );

    let listed_prompts = runtime_block_on_bounded(&cx, client.list_prompts(&cx, None))
        .expect("the live prefixed gateway must advertise the upstream prompts/list catalog");
    assert!(
        listed_prompts
            .prompts
            .iter()
            .any(|prompt| prompt.name == PREFIXED_PROMPT_NAME),
        "as_proxy_typed must prefix the live upstream prompt name: {listed_prompts:?}"
    );
    let prompt = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            PREFIXED_PROMPT_NAME,
            HashMap::from([("subject".to_owned(), PUBLIC_HTTP_TOOL_ARGUMENT.to_owned())]),
        ),
    )
    .expect("the live prefixed gateway must forward prompts/get to the upstream bind_http server");
    let prompt = serde_json::to_value(prompt)
        .expect("the prefixed prompt result serializes for its observable assertion");
    assert_eq!(
        prompt["messages"][0]["content"]["text"],
        json!(PUBLIC_HTTP_PROMPT_TEXT),
        "the prefixed live prompt must retain the upstream handler value: {prompt:?}"
    );

    let listed_resources = runtime_block_on_bounded(&cx, client.list_resources(&cx, None)).expect(
        "the live prefixed gateway must advertise the exact upstream resources/list catalog",
    );
    assert!(
        listed_resources
            .resources
            .iter()
            .any(|resource| resource.uri.as_str() == PUBLIC_HTTP_RESOURCE_URI),
        "as_proxy_typed must keep the exact final resource URI: {listed_resources:?}"
    );
    assert!(
        listed_resources
            .resources
            .iter()
            .all(|resource| { !resource.uri.as_str().starts_with("ext/") }),
        "a nonempty as_proxy prefix must not invent a non-absolute modern resource URI: {listed_resources:?}"
    );
    let resource = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_RESOURCE_URI),
    )
    .expect(
        "the live prefixed gateway must forward resources/read to the upstream bind_http server",
    );
    assert!(
        matches!(
            resource.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == PUBLIC_HTTP_RESOURCE_TEXT
        ),
        "the prefixed live resource must retain the upstream handler value: {:?}",
        resource.contents
    );

    let completion = runtime_block_on_bounded(
        &cx,
        client.complete(
            &cx,
            modern::CompletionParams {
                reference: modern::CompletionReference::PromptWithTitle {
                    name: PREFIXED_PROMPT_NAME.to_owned(),
                    title: "Public HTTP E2E Prompt".to_owned(),
                },
                argument: modern::FinalCompletionArgument {
                    name: "subject".to_owned(),
                    value: "cross-era".to_owned(),
                },
                context: Some(modern::FinalCompletionContext {
                    arguments: Some(std::collections::BTreeMap::from([(
                        "region".to_owned(),
                        "us-east-1".to_owned(),
                    )])),
                }),
            },
        ),
    )
    .expect(
        "the live prefixed gateway must forward completion/complete to the upstream bind_http server",
    );
    assert_eq!(
        completion.completion.values,
        vec![PUBLIC_HTTP_COMPLETION_VALUE.to_owned()],
        "the prefixed live completion must retain the upstream provider values: {completion:?}"
    );

    drop(client);
    gateway.shutdown();
    upstream.shutdown();
}

#[cfg(all(feature = "proxy", feature = "tasks"))]
fn spawn_modern_task_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("task HTTP server control receiver went away".to_owned());
            }
            let task_runtime = FinalTaskRuntime::in_memory(
                FinalTaskRuntimeConfig::new(60_000, Some(5_000))
                    .expect("task HTTP server timing policy is valid"),
                Arc::new(|_| {}),
            );
            let task_runner = task_runtime
                .install_task_service(1, Arc::new(PublicHttpHoldingTaskSupervisor))
                .map_err(|error| format!("task HTTP server service install failed: {error}"))?;
            let server = modern::ServerBuilder::new("facade-http-task", "1.0.0")
                .tool(PublicHttpTaskTool)
                .final_tasks(task_runtime)
                .map_err(|error| format!("task HTTP server final_tasks install failed: {error}"))?
                .build();
            let mut service = std::pin::pin!(task_runner.run(&cx));
            std::future::poll_fn(|task_context| match service.as_mut().poll(task_context) {
                std::task::Poll::Pending => std::task::Poll::Ready(Ok(())),
                std::task::Poll::Ready(Ok(())) => {
                    std::task::Poll::Ready(Err("task HTTP service stopped before bind".to_owned()))
                }
                std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(format!(
                    "task HTTP service failed before bind: {error}"
                ))),
            })
            .await?;
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("task facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("task facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("task HTTP server startup receiver went away".to_owned());
            }
            let mut serving = std::pin::pin!(bound.serve(&cx));
            let mut service_stopped = false;
            std::future::poll_fn(|task_context| {
                if !service_stopped {
                    match service.as_mut().poll(task_context) {
                        std::task::Poll::Ready(Ok(())) if cx.checkpoint().is_ok() => {
                            return std::task::Poll::Ready(Err(
                                "task HTTP service stopped while the server remained live"
                                    .to_owned(),
                            ));
                        }
                        std::task::Poll::Ready(Err(error)) if cx.checkpoint().is_ok() => {
                            return std::task::Poll::Ready(Err(format!(
                                "task HTTP service failed while the server remained live: {error}"
                            )));
                        }
                        std::task::Poll::Ready(_) => service_stopped = true,
                        std::task::Poll::Pending => {}
                    }
                }
                match serving.as_mut().poll(task_context) {
                    std::task::Poll::Ready(Ok(shutdown)) => std::task::Poll::Ready(Ok(shutdown)),
                    std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(format!(
                        "task facade HTTP server stopped unexpectedly: {error}"
                    ))),
                    std::task::Poll::Pending => std::task::Poll::Pending,
                }
            })
            .await
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("task facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("task facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("task facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[cfg(all(feature = "proxy", feature = "tasks"))]
fn spawn_modern_http_task_proxy_gateway(upstream: SocketAddr) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(
                asupersync::runtime::reactor::create_reactor()
                    .expect("task proxy gateway HTTP server reactor initializes"),
            )
            .build()
            .expect("task proxy gateway HTTP server installs an owned runtime");
        let outcome = runtime.block_on(async move {
            let cx =
                Cx::current().expect("owned gateway runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("task proxy gateway HTTP server control receiver went away".to_owned());
            }
            let plan = ClientProtocolPlan::http(
                ProtocolPolicy::ModernOnly,
                Some(public_http_target(upstream, "/mcp")),
                None,
                None,
                "e2e-http-task-proxy-gateway".to_owned(),
                "e2e-http-task-proxy-gateway".to_owned(),
                "modern-http".to_owned(),
                0,
                0,
                0,
            )
            .map_err(|error| format!("task proxy gateway HTTP plan failed: {error}"))?;
            let mut registry = ProxyClient::upstream_binding_registry();
            let proxy = registry
                .connect_http_with_protocol_plan(
                    "e2e-live-task-upstream",
                    "native-h1:e2e-live-task-upstream",
                    1,
                    plan,
                    ClientInfo {
                        name: "e2e-http-task-proxy".to_owned(),
                        version: "1.0.0".to_owned(),
                    },
                    ClientCapabilities::default(),
                    cx.clone(),
                )
                .map_err(|error| format!("live HTTP task proxy upstream connect failed: {error}"))?;
            let catalog = proxy
                .catalog_typed()
                .map_err(|error| format!("live HTTP task proxy catalog failed: {error}"))?;
            let tool_names = catalog
                .final_tools()
                .map(|tools| {
                    tools
                        .iter()
                        .map(|tool| tool.name.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !tool_names.contains(&PUBLIC_HTTP_TASK_TOOL_NAME) {
                return Err(format!(
                    "live HTTP task proxy catalog omitted {PUBLIC_HTTP_TASK_TOOL_NAME}: {tool_names:?}"
                ));
            }
            let server = modern::ServerBuilder::new("e2e-http-task-gateway", "1.0.0")
                .as_proxy_typed("ext", proxy, catalog)
                .map_err(|error| format!("as_proxy_typed task install failed: {error}"))?
                .build();
            if server.final_task_runtime().is_some() {
                return Err(
                    "as_proxy_typed must install the route-bound Tasks relay instead of the default in-memory store"
                        .to_owned(),
                );
            }
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("task proxy gateway HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("task proxy gateway HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("task proxy gateway HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("task proxy gateway HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("task proxy gateway HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("task proxy gateway HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("task proxy gateway HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[cfg(all(feature = "proxy", feature = "tasks"))]
#[test]
fn e2e_public_http_prefixed_as_proxy_gets_upstream_created_task() {
    let cx = Cx::for_request();
    let upstream = spawn_modern_task_http_server();
    let gateway = spawn_modern_http_task_proxy_gateway(upstream.address());

    let mut upstream_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-task-upstream-client", "1.0.0")
            .connect_http_with_cx(public_http_target(upstream.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live task upstream HTTP server");
    let created = runtime_block_on_bounded(
        &cx,
        upstream_client.call_tool_outcome(
            &cx,
            RequestId::Number(2),
            PUBLIC_HTTP_TASK_TOOL_NAME,
            json!({}),
            1 << 20,
        ),
    )
    .expect("the live upstream must create one official Task");
    let FinalToolCallOutcome::Task(created) = created else {
        panic!(
            "the task-capable live tool must return the official Task result branch: {created:?}"
        );
    };
    let task_id = created.task.base().task_id.clone();
    drop(upstream_client);

    let mut gateway_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-task-gateway-client", "1.0.0")
            .connect_http_with_cx(public_http_target(gateway.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live prefixed as_proxy Tasks gateway");

    let input_deadline = Instant::now() + HTTP_OPERATION_BOUND;
    let mut next_get_id = 4_i64;
    let observed = loop {
        let observed = runtime_block_on_bounded(
            &cx,
            gateway_client.get_task(
                &cx,
                RequestId::Number(next_get_id),
                task_id.clone(),
                1 << 20,
            ),
        )
        .expect("the live prefixed gateway must forward tasks/get to the upstream store");
        next_get_id = next_get_id
            .checked_add(1)
            .expect("the official Tasks request id space does not overflow");
        if matches!(observed.task, FinalTask::InputRequired { .. }) {
            break observed;
        }
        if Instant::now() >= input_deadline {
            panic!(
                "as_proxy_typed must observe the upstream input_required Task rather than a disconnected local store: {observed:?}"
            );
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(
        observed.task.base().task_id,
        task_id,
        "as_proxy_typed must return the upstream-created Task rather than a disconnected local store: {observed:?}"
    );

    let missing = FinalTaskId::parse("missing-upstream-task")
        .expect("the planted-missing task id is a valid official TaskId");
    let missing_get = runtime_block_on_bounded(
        &cx,
        gateway_client.get_task(
            &cx,
            RequestId::Number(next_get_id),
            missing.clone(),
            1 << 20,
        ),
    )
    .expect_err("changing only the task id must not invent a Task on the gateway");
    let _ = missing_get;
    next_get_id += 1;

    let wrong_update: FinalTaskInputResponses =
        serde_json::from_value(json!({"roots": {"action": "accept"}}))
            .expect("the planted-wrong Tasks update payload is typed");
    let rejected_update = runtime_block_on_bounded(
        &cx,
        gateway_client.update_task(
            &cx,
            RequestId::Number(next_get_id),
            &observed.task,
            wrong_update,
            1 << 20,
        ),
    )
    .expect_err("changing only the input response kind must not resume the upstream Task");
    let _ = rejected_update;
    next_get_id += 1;

    let still_waiting = runtime_block_on_bounded(
        &cx,
        gateway_client.get_task(
            &cx,
            RequestId::Number(next_get_id),
            task_id.clone(),
            1 << 20,
        ),
    )
    .expect("a rejected tasks/update must leave the upstream Task in place");
    next_get_id += 1;
    assert!(
        matches!(still_waiting.task, FinalTask::InputRequired { .. }),
        "a rejected tasks/update must not leave the input_required Task: {still_waiting:?}"
    );

    let responses: FinalTaskInputResponses =
        serde_json::from_value(json!({"roots": {"roots": []}}))
            .expect("the public final roots response is typed");
    runtime_block_on_bounded(
        &cx,
        gateway_client.update_task(
            &cx,
            RequestId::Number(next_get_id),
            &observed.task,
            responses,
            1 << 20,
        ),
    )
    .expect("the live prefixed gateway must forward tasks/update to the upstream store");
    next_get_id += 1;

    let working_deadline = Instant::now() + HTTP_OPERATION_BOUND;
    let working = loop {
        let observed = runtime_block_on_bounded(
            &cx,
            gateway_client.get_task(
                &cx,
                RequestId::Number(next_get_id),
                task_id.clone(),
                1 << 20,
            ),
        )
        .expect("the live prefixed gateway must keep forwarding tasks/get after update");
        next_get_id = next_get_id
            .checked_add(1)
            .expect("the official Tasks request id space does not overflow");
        if matches!(observed.task, FinalTask::Working(_)) {
            break observed;
        }
        if Instant::now() >= working_deadline {
            panic!(
                "as_proxy_typed must observe the upstream working Task after a matching update: {observed:?}"
            );
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(
        working.task.base().task_id,
        task_id,
        "as_proxy_typed must resume the same upstream-created Task: {working:?}"
    );

    let missing_cancel = runtime_block_on_bounded(
        &cx,
        gateway_client.cancel_task(&cx, RequestId::Number(next_get_id), missing, 1 << 20),
    )
    .expect_err("changing only the task id must not invent a cancellation on the gateway");
    let _ = missing_cancel;
    next_get_id += 1;

    runtime_block_on_bounded(
        &cx,
        gateway_client.cancel_task(
            &cx,
            RequestId::Number(next_get_id),
            task_id.clone(),
            1 << 20,
        ),
    )
    .expect("the live prefixed gateway must forward tasks/cancel to the upstream store");
    next_get_id += 1;

    let cancel_deadline = Instant::now() + HTTP_OPERATION_BOUND;
    let cancelled = loop {
        let observed = runtime_block_on_bounded(
            &cx,
            gateway_client.get_task(
                &cx,
                RequestId::Number(next_get_id),
                task_id.clone(),
                1 << 20,
            ),
        )
        .expect("the live prefixed gateway must keep forwarding tasks/get after cancel");
        next_get_id = next_get_id
            .checked_add(1)
            .expect("the official Tasks request id space does not overflow");
        if matches!(observed.task, FinalTask::Cancelled(_)) {
            break observed;
        }
        if Instant::now() >= cancel_deadline {
            panic!(
                "as_proxy_typed must observe the upstream cancelled Task rather than a disconnected local store: {observed:?}"
            );
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(
        cancelled.task.base().task_id,
        task_id,
        "as_proxy_typed must cancel the same upstream-created Task: {cancelled:?}"
    );

    drop(gateway_client);
    gateway.shutdown();
    upstream.shutdown();
}

#[cfg(all(unix, feature = "proxy", feature = "tasks"))]
fn spawn_modern_http_stdio_as_proxy_gateway() -> (HttpServerFixture, FinalTaskId) {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(SocketAddr, FinalTaskId), String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(
                asupersync::runtime::reactor::create_reactor()
                    .expect("stdio as_proxy gateway HTTP server reactor initializes"),
            )
            .build()
            .expect("stdio as_proxy gateway HTTP server installs an owned runtime");
        let outcome = runtime.block_on(async move {
            let cx =
                Cx::current().expect("owned gateway runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("stdio as_proxy gateway HTTP server control receiver went away".to_owned());
            }
            let mut last_connect_error = None;
            let mut stdio = None;
            for attempt in 1_u32..=4 {
                match modern::ClientBuilder::new()
                    .client_info("e2e-http-stdio-as-proxy-upstream", "1.0.0")
                    .env("FASTMCP_PROTOCOL_POLICY", "modern-only")
                    .max_retries(2)
                    .retry_delay_ms(150)
                    .connect_stdio_with_cx(env!("CARGO_BIN_EXE_echo_server"), &[], &cx)
                {
                    Ok(client) => {
                        stdio = Some(client);
                        break;
                    }
                    Err(error) => {
                        last_connect_error = Some(error);
                        if attempt < 4 {
                            thread::sleep(Duration::from_millis(50 * u64::from(attempt)));
                        }
                    }
                }
            }
            let mut stdio = stdio.ok_or_else(|| {
                format!(
                    "live stdio as_proxy upstream connect failed: {}",
                    last_connect_error
                        .expect("a failed stdio connect records its last transport error")
                )
            })?;
            let created = stdio
                .call_tool_outcome("durable_task", json!({}))
                .map_err(|error| {
                    format!("live stdio as_proxy upstream must create one official Task: {error}")
                })?;
            let FinalToolCallOutcome::Task(created) = created else {
                return Err(format!(
                    "the shipped durable_task tool must return the official Task result branch: {created:?}"
                ));
            };
            let task_id = created.task.base().task_id.clone();
            let server = modern::ServerBuilder::new("e2e-http-stdio-as-proxy", "1.0.0")
                .as_proxy("ext", stdio)
                .map_err(|error| format!("as_proxy stdio install failed: {error}"))?
                .build();
            if server.final_task_runtime().is_some() {
                return Err(
                    "as_proxy must install the route-bound Tasks relay instead of the default in-memory store"
                        .to_owned(),
                );
            }
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("stdio as_proxy gateway HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("stdio as_proxy gateway HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok((address, task_id))).is_err() {
                cx.set_cancel_requested(true);
                return Err("stdio as_proxy gateway HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("stdio as_proxy gateway HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let (address, task_id) = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("stdio as_proxy gateway HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(ready)) => break ready,
            Ok(Err(error)) => panic!("stdio as_proxy gateway HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("stdio as_proxy gateway HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    (
        HttpServerFixture {
            address,
            server_cx,
            finished,
            shutdown_completion: None,
            join,
            nonquiescent: None,
            handler_calls,
        },
        task_id,
    )
}

#[cfg(all(unix, feature = "proxy", feature = "tasks"))]
#[test]
fn e2e_public_http_as_proxy_stdio_forwards_prefixed_echo() {
    let cx = Cx::for_request();
    let (gateway, task_id) = spawn_modern_http_stdio_as_proxy_gateway();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-stdio-as-proxy-client", "1.0.0")
            .connect_http_with_cx(public_http_target(gateway.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live stdio as_proxy HTTP gateway");

    let listed = runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("the live stdio as_proxy gateway must advertise the prefixed echo catalog");
    assert!(
        listed.tools.iter().any(|tool| tool.name == "ext/echo"),
        "as_proxy must prefix the live stdio echo tool: {listed:?}"
    );
    assert!(
        !listed.tools.iter().any(|tool| tool.name == "echo"),
        "a nonempty as_proxy prefix must not keep the unprefixed stdio echo tool: {listed:?}"
    );

    let missing = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, "echo", json!({"message": "nope"})),
    )
    .expect_err("changing only the tool name must not reach the unprefixed stdio handler");
    let _ = missing;

    let result = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, "ext/echo", json!({ "message": "stdio-as-proxy" })),
    )
    .expect("the live stdio as_proxy gateway must forward tools/call to the shipped echo server");
    assert!(
        result.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "stdio-as-proxy",
            _ => false,
        }),
        "the prefixed live stdio tool must retain the echo handler value: {result:?}"
    );

    let hidden = runtime_block_on_bounded(&cx, client.call_tool(&cx, "ext/hide_echo", json!({})))
        .expect(
            "the live stdio as_proxy gateway must forward hide_echo to the shipped echo session",
        );
    assert!(
        hidden.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "hidden",
            _ => false,
        }),
        "as_proxy must retain the echo disable_tool mutation: {hidden:?}"
    );
    let still_listed = runtime_block_on_bounded(&cx, client.list_tools(&cx, None)).expect(
        "the live stdio as_proxy gateway must keep its install-time catalog after hide_echo",
    );
    assert!(
        still_listed
            .tools
            .iter()
            .any(|tool| tool.name == "ext/echo"),
        "as_proxy must not drop the prefixed echo tool from the gateway snapshot: {still_listed:?}"
    );
    let disabled = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, "ext/echo", json!({ "message": "after-hide" })),
    )
    .expect("hide_echo on the live stdio session must keep the public tools/call result");
    assert!(
        disabled.is_error,
        "hide_echo on the live stdio session must mark a later ext/echo call as a tool error: {disabled:?}"
    );
    assert!(
        disabled.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text.contains("Method not found"),
            _ => false,
        }),
        "the refused ext/echo call must keep the session-disabled MethodNotFound tool error: {disabled:?}"
    );
    let added = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, "ext/add", json!({ "a": 2, "b": 3 })),
    )
    .expect("changing only the tool name must still reach an undisabled stdio handler");
    assert!(
        added.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "5",
            _ => false,
        }),
        "as_proxy must keep undisabled stdio tools callable after hide_echo: {added:?}"
    );
    let shown = runtime_block_on_bounded(&cx, client.call_tool(&cx, "ext/show_echo", json!({})))
        .expect(
            "the live stdio as_proxy gateway must forward show_echo to the shipped echo session",
        );
    assert!(
        shown.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "shown",
            _ => false,
        }),
        "as_proxy must retain the echo enable_tool mutation: {shown:?}"
    );
    let restored = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, "ext/echo", json!({ "message": "after-show" })),
    )
    .expect("show_echo on the live stdio session must restore the prefixed echo tool");
    assert!(
        restored.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "after-show",
            _ => false,
        }),
        "as_proxy must keep the restored stdio echo tool callable: {restored:?}"
    );

    let listed_resources = runtime_block_on_bounded(&cx, client.list_resources(&cx, None))
        .expect("the live stdio as_proxy gateway must advertise the exact upstream resource URIs");
    assert!(
        listed_resources
            .resources
            .iter()
            .any(|resource| resource.uri.as_str() == "info://server"),
        "as_proxy must keep the live stdio resource URI unprefixed: {listed_resources:?}"
    );
    assert!(
        !listed_resources
            .resources
            .iter()
            .any(|resource| resource.uri.as_str().contains("ext/")),
        "as_proxy must not prefix exact-final resource URIs: {listed_resources:?}"
    );
    let resource = runtime_block_on_bounded(&cx, client.read_resource(&cx, "info://server"))
        .expect("the live stdio as_proxy gateway must forward the unprefixed resource URI");
    assert!(
        resource.contents.iter().any(|content| match content {
            EmbeddedResourceContents::Text { text, .. } => text.contains("echo-server"),
            _ => false,
        }),
        "the unprefixed live stdio resource must retain the echo handler value: {resource:?}"
    );

    let listed_prompts = runtime_block_on_bounded(&cx, client.list_prompts(&cx, None))
        .expect("the live stdio as_proxy gateway must advertise the prefixed prompt catalog");
    assert!(
        listed_prompts
            .prompts
            .iter()
            .any(|prompt| prompt.name == "ext/greeting"),
        "as_proxy must prefix the live stdio greeting prompt: {listed_prompts:?}"
    );
    let missing_prompt = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            "greeting",
            HashMap::from([("name".to_owned(), "Ada".to_owned())]),
        ),
    )
    .expect_err("changing only the prompt name must not reach the unprefixed stdio handler");
    let _ = missing_prompt;
    let prompt = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            "ext/greeting",
            HashMap::from([("name".to_owned(), "Ada".to_owned())]),
        ),
    )
    .expect("the live stdio as_proxy gateway must forward prompts/get to the shipped echo server");
    let prompt = serde_json::to_value(prompt)
        .expect("the prefixed stdio prompt result serializes for its observable assertion");
    assert_eq!(
        prompt["messages"][0]["content"]["text"],
        json!("Please greet Ada in a friendly way."),
        "the prefixed live stdio prompt must retain the echo handler value: {prompt:?}"
    );

    let completion_params = modern::CompletionParams {
        reference: modern::CompletionReference::PromptWithTitle {
            name: "ext/greeting".to_owned(),
            title: "Greeting".to_owned(),
        },
        argument: modern::FinalCompletionArgument {
            name: "name".to_owned(),
            value: "co".to_owned(),
        },
        context: Some(modern::FinalCompletionContext {
            arguments: Some(std::collections::BTreeMap::from([(
                "locale".to_owned(),
                "en-US".to_owned(),
            )])),
        }),
    };
    let mut unprefixed_completion = completion_params.clone();
    unprefixed_completion.reference = modern::CompletionReference::PromptWithTitle {
        name: "greeting".to_owned(),
        title: "Greeting".to_owned(),
    };
    let missing_completion =
        runtime_block_on_bounded(&cx, client.complete(&cx, unprefixed_completion)).expect_err(
            "changing only the completion prompt name must not reach the stdio provider",
        );
    let _ = missing_completion;

    let completion = runtime_block_on_bounded(&cx, client.complete(&cx, completion_params)).expect(
        "the live stdio as_proxy gateway must rewrite ext/greeting and forward completion/complete",
    );
    assert_eq!(
        completion.completion.values,
        vec!["stdio-completion-1".to_owned()],
        "the prefixed live stdio completion must retain the echo provider value: {completion:?}"
    );

    let hidden_catalog =
        runtime_block_on_bounded(&cx, client.call_tool(&cx, "ext/hide_catalog", json!({}))).expect(
            "the live stdio as_proxy gateway must forward hide_catalog to the shipped echo session",
        );
    assert!(
        hidden_catalog.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "hidden",
            _ => false,
        }),
        "as_proxy must retain the echo disable_resource and disable_prompt mutations: {hidden_catalog:?}"
    );
    let still_listed_resources =
        runtime_block_on_bounded(&cx, client.list_resources(&cx, None)).expect(
            "the live stdio as_proxy gateway must keep its install-time resource catalog after hide_catalog",
        );
    assert!(
        still_listed_resources
            .resources
            .iter()
            .any(|resource| resource.uri.as_str() == "info://server"),
        "as_proxy must not drop the unprefixed resource URI from the gateway snapshot: {still_listed_resources:?}"
    );
    let still_listed_prompts = runtime_block_on_bounded(&cx, client.list_prompts(&cx, None)).expect(
        "the live stdio as_proxy gateway must keep its install-time prompt catalog after hide_catalog",
    );
    assert!(
        still_listed_prompts
            .prompts
            .iter()
            .any(|prompt| prompt.name == "ext/greeting"),
        "as_proxy must not drop the prefixed greeting prompt from the gateway snapshot: {still_listed_prompts:?}"
    );
    let cached_resource = runtime_block_on_bounded(&cx, client.read_resource(&cx, "info://server"))
        .expect(
            "the warmed HTTP client must keep its cached info://server read after hide_catalog",
        );
    assert!(
        cached_resource
            .contents
            .iter()
            .any(|content| match content {
                EmbeddedResourceContents::Text { text, .. } => text.contains("echo-server"),
                _ => false,
            }),
        "as_proxy must not invent a resources/list_changed that would drop the client cache: {cached_resource:?}"
    );
    let mut fresh_after_hide = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-stdio-as-proxy-hide-catalog", "1.0.0")
            .connect_http_with_cx(public_http_target(gateway.address(), "/mcp"), &cx),
    )
    .expect("a second HTTP client connects after hide_catalog");
    let disabled_resource = runtime_block_on_bounded(
        &cx,
        fresh_after_hide.read_resource(&cx, "info://server"),
    )
    .expect_err(
        "hide_catalog on the live stdio session must refuse a later uncached info://server read",
    );
    let disabled_resource = format!("{disabled_resource:?}");
    assert!(
        disabled_resource.contains("disabled") && disabled_resource.contains("info://server"),
        "the refused resource read must be the session-disabled upstream URI: {disabled_resource}"
    );
    drop(fresh_after_hide);
    let disabled_prompt = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            "ext/greeting",
            HashMap::from([("name".to_owned(), "Bea".to_owned())]),
        ),
    )
    .expect_err("hide_catalog on the live stdio session must refuse a later ext/greeting get");
    let disabled_prompt = format!("{disabled_prompt:?}");
    assert!(
        disabled_prompt.contains("disabled") && disabled_prompt.contains("greeting"),
        "the refused prompt get must be the session-disabled upstream prompt: {disabled_prompt}"
    );
    let shown_catalog =
        runtime_block_on_bounded(&cx, client.call_tool(&cx, "ext/show_catalog", json!({}))).expect(
            "the live stdio as_proxy gateway must forward show_catalog to the shipped echo session",
        );
    assert!(
        shown_catalog.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "shown",
            _ => false,
        }),
        "as_proxy must retain the echo enable_resource and enable_prompt mutations: {shown_catalog:?}"
    );
    let mut fresh_after_show = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-stdio-as-proxy-show-catalog", "1.0.0")
            .connect_http_with_cx(public_http_target(gateway.address(), "/mcp"), &cx),
    )
    .expect("a third HTTP client connects after show_catalog");
    let restored_resource =
        runtime_block_on_bounded(&cx, fresh_after_show.read_resource(&cx, "info://server")).expect(
            "show_catalog on the live stdio session must restore an uncached info://server read",
        );
    assert!(
        restored_resource
            .contents
            .iter()
            .any(|content| match content {
                EmbeddedResourceContents::Text { text, .. } => text.contains("echo-server"),
                _ => false,
            }),
        "as_proxy must keep the restored stdio resource readable: {restored_resource:?}"
    );
    drop(fresh_after_show);
    let restored_prompt = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            "ext/greeting",
            HashMap::from([("name".to_owned(), "Cyd".to_owned())]),
        ),
    )
    .expect("show_catalog on the live stdio session must restore the prefixed greeting prompt");
    let restored_prompt = serde_json::to_value(restored_prompt)
        .expect("the restored stdio prompt result serializes for its observable assertion");
    assert_eq!(
        restored_prompt["messages"][0]["content"]["text"],
        json!("Please greet Cyd in a friendly way."),
        "as_proxy must keep the restored stdio prompt callable: {restored_prompt:?}"
    );

    let input_deadline = Instant::now() + HTTP_OPERATION_BOUND;
    let mut next_input_id = 40_i64;
    let observed = loop {
        let observed = runtime_block_on_bounded(
            &cx,
            client.get_task(
                &cx,
                RequestId::Number(next_input_id),
                task_id.clone(),
                1 << 20,
            ),
        )
        .expect("the live stdio as_proxy gateway must forward tasks/get to the echo store");
        next_input_id = next_input_id
            .checked_add(1)
            .expect("the official Tasks request id space does not overflow");
        if matches!(observed.task, FinalTask::InputRequired { .. }) {
            break observed;
        }
        if Instant::now() >= input_deadline {
            panic!(
                "as_proxy must observe the stdio-created input_required Task rather than a disconnected local store: {observed:?}"
            );
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(
        observed.task.base().task_id,
        task_id,
        "as_proxy must return the stdio-created Task rather than a disconnected local store: {observed:?}"
    );
    let missing_id = FinalTaskId::parse("missing-stdio-upstream-task")
        .expect("the planted-missing task id is a valid official TaskId");
    let missing_get = runtime_block_on_bounded(
        &cx,
        client.get_task(&cx, RequestId::Number(41), missing_id.clone(), 1 << 20),
    )
    .expect_err("changing only the task id must not invent a Task on the stdio as_proxy gateway");
    let _ = missing_get;

    let responses: FinalTaskInputResponses =
        serde_json::from_value(json!({"roots": {"roots": []}}))
            .expect("the public final roots response is typed");
    runtime_block_on_bounded(
        &cx,
        client.update_task(
            &cx,
            RequestId::Number(42),
            &observed.task,
            responses,
            1 << 20,
        ),
    )
    .expect("the live stdio as_proxy gateway must forward tasks/update to the echo store");

    let working_deadline = Instant::now() + HTTP_OPERATION_BOUND;
    let mut next_get_id = 43_i64;
    let working = loop {
        let observed = runtime_block_on_bounded(
            &cx,
            client.get_task(
                &cx,
                RequestId::Number(next_get_id),
                task_id.clone(),
                1 << 20,
            ),
        )
        .expect("the live stdio as_proxy gateway must keep forwarding tasks/get after update");
        next_get_id = next_get_id
            .checked_add(1)
            .expect("the official Tasks request id space does not overflow");
        if matches!(observed.task, FinalTask::Working(_)) {
            break observed;
        }
        if Instant::now() >= working_deadline {
            panic!(
                "as_proxy must observe the stdio-created working Task after a matching update: {observed:?}"
            );
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(
        working.task.base().task_id,
        task_id,
        "as_proxy must resume the same stdio-created Task: {working:?}"
    );

    let missing_cancel = runtime_block_on_bounded(
        &cx,
        client.cancel_task(&cx, RequestId::Number(next_get_id), missing_id, 1 << 20),
    )
    .expect_err(
        "changing only the task id must not invent a cancellation on the stdio as_proxy gateway",
    );
    let _ = missing_cancel;
    next_get_id += 1;

    runtime_block_on_bounded(
        &cx,
        client.cancel_task(
            &cx,
            RequestId::Number(next_get_id),
            task_id.clone(),
            1 << 20,
        ),
    )
    .expect("the live stdio as_proxy gateway must forward tasks/cancel to the echo store");
    next_get_id += 1;
    let cancel_deadline = Instant::now() + HTTP_OPERATION_BOUND;
    let cancelled = loop {
        let observed = runtime_block_on_bounded(
            &cx,
            client.get_task(
                &cx,
                RequestId::Number(next_get_id),
                task_id.clone(),
                1 << 20,
            ),
        )
        .expect("the live stdio as_proxy gateway must keep forwarding tasks/get after cancel");
        next_get_id = next_get_id
            .checked_add(1)
            .expect("the official Tasks request id space does not overflow");
        if matches!(observed.task, FinalTask::Cancelled(_)) {
            break observed;
        }
        if Instant::now() >= cancel_deadline {
            panic!(
                "as_proxy must observe the stdio-created cancelled Task rather than a disconnected local store: {observed:?}"
            );
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(
        cancelled.task.base().task_id,
        task_id,
        "as_proxy must cancel the same stdio-created Task: {cancelled:?}"
    );

    drop(client);
    gateway.shutdown();
}

#[cfg(all(unix, feature = "tasks"))]
#[test]
fn e2e_public_stdio_hide_catalog_refuses_later_read_and_prompt() {
    let cx = Cx::for_request();
    let mut client = modern::ClientBuilder::new()
        .client_info("e2e-stdio-hide-catalog", "1.0.0")
        .env("FASTMCP_PROTOCOL_POLICY", "modern-only")
        .max_retries(2)
        .retry_delay_ms(150)
        .connect_stdio_with_cx(env!("CARGO_BIN_EXE_echo_server"), &[], &cx)
        .expect("a ModernOnly facade client connects to the shipped echo server");

    let before = client
        .read_resource("info://server")
        .expect("the shipped echo resource must be readable before hide_catalog");
    assert!(
        before.contents.iter().any(|content| match content {
            EmbeddedResourceContents::Text { text, .. } => text.contains("echo-server"),
            _ => false,
        }),
        "the live stdio resource must retain the echo handler value: {before:?}"
    );

    let hidden = client
        .call_tool("hide_catalog", json!({}))
        .expect("disabling a shipped resource and prompt must complete");
    assert!(
        hidden.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "hidden",
            _ => false,
        }),
        "stdio session state must retain disable_resource and disable_prompt: {hidden:?}"
    );

    let disabled_resource = client.read_resource("info://server").expect_err(
        "hide_catalog must refuse a later info://server read on the same stdio session",
    );
    let disabled_resource = format!("{disabled_resource:?}");
    assert!(
        disabled_resource.contains("disabled") && disabled_resource.contains("info://server"),
        "the refused resource read must be the session-disabled URI: {disabled_resource}"
    );
    let disabled_prompt = client
        .get_prompt(
            "greeting",
            HashMap::from([("name".to_owned(), "Bea".to_owned())]),
        )
        .expect_err("hide_catalog must refuse a later greeting get on the same stdio session");
    let disabled_prompt = format!("{disabled_prompt:?}");
    assert!(
        disabled_prompt.contains("disabled") && disabled_prompt.contains("greeting"),
        "the refused prompt get must be the session-disabled prompt: {disabled_prompt}"
    );

    let shown = client
        .call_tool("show_catalog", json!({}))
        .expect("re-enabling a shipped resource and prompt must complete");
    assert!(
        shown.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "shown",
            _ => false,
        }),
        "stdio session state must retain enable_resource and enable_prompt: {shown:?}"
    );
    let restored = client
        .read_resource("info://server")
        .expect("show_catalog must restore a later info://server read on the same stdio session");
    assert!(
        restored.contents.iter().any(|content| match content {
            EmbeddedResourceContents::Text { text, .. } => text.contains("echo-server"),
            _ => false,
        }),
        "the restored stdio resource must retain the echo handler value: {restored:?}"
    );
    let restored_prompt = client
        .get_prompt(
            "greeting",
            HashMap::from([("name".to_owned(), "Cyd".to_owned())]),
        )
        .expect("show_catalog must restore a later greeting get on the same stdio session");
    let restored_prompt = serde_json::to_value(restored_prompt)
        .expect("the restored stdio prompt result serializes for its observable assertion");
    assert_eq!(
        restored_prompt["messages"][0]["content"]["text"],
        json!("Please greet Cyd in a friendly way."),
        "the restored stdio prompt must retain the echo handler value: {restored_prompt:?}"
    );

    client
        .close()
        .expect("modern-only stdio hide_catalog client cleanup");
}

#[cfg(feature = "proxy")]
fn spawn_modern_http_template_proxy_gateway(
    upstream: SocketAddr,
    expected_template: &'static str,
) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(
                asupersync::runtime::reactor::create_reactor()
                    .expect("template proxy gateway HTTP server reactor initializes"),
            )
            .build()
            .expect("template proxy gateway HTTP server installs an owned runtime");
        let outcome = runtime.block_on(async move {
            let cx =
                Cx::current().expect("owned gateway runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err(
                    "template proxy gateway HTTP server control receiver went away".to_owned(),
                );
            }
            let plan = ClientProtocolPlan::http(
                ProtocolPolicy::ModernOnly,
                Some(public_http_target(upstream, "/mcp")),
                None,
                None,
                "e2e-http-template-proxy-gateway".to_owned(),
                "e2e-http-template-proxy-gateway".to_owned(),
                "modern-http".to_owned(),
                0,
                0,
                0,
            )
            .map_err(|error| format!("template proxy gateway HTTP plan failed: {error}"))?;
            let mut registry = ProxyClient::upstream_binding_registry();
            let proxy = registry
                .connect_http_with_protocol_plan(
                    "e2e-live-template-upstream",
                    "native-h1:e2e-live-template-upstream",
                    1,
                    plan,
                    ClientInfo {
                        name: "e2e-http-template-proxy".to_owned(),
                        version: "1.0.0".to_owned(),
                    },
                    ClientCapabilities::default(),
                    cx.clone(),
                )
                .map_err(|error| {
                    format!("live HTTP template proxy upstream connect failed: {error}")
                })?;
            let catalog = proxy
                .catalog_typed()
                .map_err(|error| format!("live HTTP template proxy catalog failed: {error}"))?;
            let templates = catalog
                .final_resource_templates()
                .map(|templates| {
                    templates
                        .iter()
                        .map(|template| template.uri_template.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !templates.contains(&expected_template) {
                return Err(format!(
                    "live HTTP template proxy catalog omitted {expected_template}: {templates:?}"
                ));
            }
            let server = modern::ServerBuilder::new("e2e-http-template-gateway", "1.0.0")
                .as_proxy_typed("ext", proxy, catalog)
                .map_err(|error| format!("as_proxy_typed template install failed: {error}"))?
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message =
                        format!("template proxy gateway HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("template proxy gateway HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err(
                    "template proxy gateway HTTP server startup receiver went away".to_owned(),
                );
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("template proxy gateway HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("template proxy gateway HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("template proxy gateway HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("template proxy gateway HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[cfg(feature = "proxy")]
#[test]
fn e2e_public_http_prefixed_as_proxy_forwards_unprefixed_resource_template() {
    let cx = Cx::for_request();
    let (upstream, reads) = spawn_modern_template_http_server();
    let gateway =
        spawn_modern_http_template_proxy_gateway(upstream.address(), PUBLIC_HTTP_TEMPLATE);
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-as-proxy-template-client", "1.0.0")
            .connect_http_with_cx(public_http_target(gateway.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live template as_proxy HTTP gateway");

    let listed = runtime_block_on_bounded(&cx, client.list_resource_templates(&cx, None))
        .expect("the live prefixed gateway must advertise the exact upstream resource template");
    assert!(
        listed
            .resource_templates
            .iter()
            .any(|template| template.uri_template == PUBLIC_HTTP_TEMPLATE
                && template.name == PUBLIC_HTTP_TEMPLATE_NAME),
        "as_proxy_typed must keep the exact final resource template: {:?}",
        listed.resource_templates
    );
    assert!(
        listed
            .resource_templates
            .iter()
            .all(|template| !template.uri_template.starts_with("ext/")),
        "a nonempty as_proxy prefix must not invent a non-absolute template URI: {:?}",
        listed.resource_templates
    );

    let matched = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_TEMPLATE_MATCHED_URI),
    )
    .expect("the live prefixed gateway must expand a URI that matches the upstream template");
    assert!(
        matches!(
            matched.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == "item:alpha"
        ),
        "the proxied matched template read must retain the extracted id: {:?}",
        matched.contents
    );
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "a matching proxied resources/read must invoke the upstream templated handler once"
    );

    let unmatched = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_TEMPLATE_UNMATCHED_URI),
    )
    .expect_err(
        "changing only the path that the template cannot bind must refuse before upstream dispatch",
    );
    assert!(
        matches!(
            unmatched,
            modern::HttpClientError::CoreResult(ref error)
                if error.code == McpErrorCode::InvalidParams
        ),
        "an unmatched proxied template URI must stay InvalidParams: {unmatched:?}"
    );
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "the unmatched URI must leave the upstream templated handler uninvoked"
    );

    drop(client);
    gateway.shutdown();
    upstream.shutdown();
}

#[test]
fn e2e_public_http_mount_forwards_prefixed_tool_and_unprefixed_resource() {
    const MOUNTED_TOOL_NAME: &str = "child/public-http-e2e-tool";
    const MOUNTED_PROMPT_NAME: &str = "child/public-http-e2e-prompt";

    let cx = Cx::for_request();
    let server = spawn_modern_mounted_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-mount-client", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live mounted HTTP server");

    let listed = runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("the mounted parent must advertise the prefixed child tools/list catalog");
    assert!(
        listed
            .tools
            .iter()
            .any(|tool| tool.name == MOUNTED_TOOL_NAME),
        "mount() must rewrite the child tool name: {listed:?}"
    );
    assert!(
        !listed
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_TOOL_NAME),
        "a nonempty mount prefix must not keep the unprefixed child tool: {listed:?}"
    );

    let result = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            MOUNTED_TOOL_NAME,
            json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
        ),
    )
    .expect("the mounted parent must dispatch tools/call through the prefixed child handler");
    assert!(
        result.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == PUBLIC_HTTP_TOOL_TEXT,
            _ => false,
        }),
        "the mounted live tool must retain the child handler value: {result:?}"
    );

    let listed_prompts = runtime_block_on_bounded(&cx, client.list_prompts(&cx, None))
        .expect("the mounted parent must advertise the prefixed child prompts/list catalog");
    assert!(
        listed_prompts
            .prompts
            .iter()
            .any(|prompt| prompt.name == MOUNTED_PROMPT_NAME),
        "mount() must rewrite the child prompt name: {listed_prompts:?}"
    );
    let prompt = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            MOUNTED_PROMPT_NAME,
            HashMap::from([("subject".to_owned(), PUBLIC_HTTP_TOOL_ARGUMENT.to_owned())]),
        ),
    )
    .expect("the mounted parent must dispatch prompts/get through the prefixed child handler");
    let prompt = serde_json::to_value(prompt)
        .expect("the mounted prompt result serializes for its observable assertion");
    assert_eq!(
        prompt["messages"][0]["content"]["text"],
        json!(PUBLIC_HTTP_PROMPT_TEXT),
        "the mounted live prompt must retain the child handler value: {prompt:?}"
    );

    let listed_resources = runtime_block_on_bounded(&cx, client.list_resources(&cx, None))
        .expect("the unprefixed mount must advertise the exact child resources/list catalog");
    assert!(
        listed_resources
            .resources
            .iter()
            .any(|resource| resource.uri.as_str() == PUBLIC_HTTP_RESOURCE_URI),
        "an unprefixed mount must keep the exact final resource URI: {listed_resources:?}"
    );
    assert!(
        listed_resources
            .resources
            .iter()
            .all(|resource| { !resource.uri.as_str().starts_with("child/") }),
        "a nonempty prefix must not invent a non-absolute modern resource URI: {listed_resources:?}"
    );
    let resource =
        runtime_block_on_bounded(&cx, client.read_resource(&cx, PUBLIC_HTTP_RESOURCE_URI))
            .expect("the unprefixed mount must dispatch resources/read through the child handler");
    assert!(
        matches!(
            resource.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == PUBLIC_HTTP_RESOURCE_TEXT
        ),
        "the mounted live resource must retain the child handler value: {:?}",
        resource.contents
    );

    drop(client);
    server.shutdown();
}

const PUBLIC_HTTP_FS_PREFIX: &str = "e2e";
const PUBLIC_HTTP_FS_TEMPLATE: &str = "file:///e2e/{+path}";
const PUBLIC_HTTP_FS_FILE_NAME: &str = "note.txt";
const PUBLIC_HTTP_FS_FILE_URI: &str = "file:///e2e/note.txt";
const PUBLIC_HTTP_FS_FILE_TEXT: &str = "filesystem:deterministic";

/// Starts a public ModernOnly facade whose catalog is one live FilesystemProvider.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn spawn_modern_filesystem_http_server() -> HttpServerFixture {
    spawn_modern_filesystem_http_server_named("direct")
}

fn spawn_modern_filesystem_http_server_named(label: &'static str) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let root = std::env::temp_dir().join(format!(
        "fastmcp-public-http-fs-e2e-{}-{label}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("the filesystem e2e root is created");
    std::fs::write(
        root.join(PUBLIC_HTTP_FS_FILE_NAME),
        PUBLIC_HTTP_FS_FILE_TEXT,
    )
    .expect("the filesystem e2e file is written");
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("filesystem HTTP server control receiver went away".to_owned());
            }
            let handler = providers::FilesystemProvider::new(&root)
                .with_prefix(PUBLIC_HTTP_FS_PREFIX)
                .with_exclude(&[])
                .build()
                .map_err(|error| format!("FilesystemProvider::build failed: {error}"))?;
            let server = if label == "mounted" {
                let child = modern::ServerBuilder::new("facade-filesystem-child", "1.0.0")
                    .resource(handler)
                    .build();
                modern::ServerBuilder::new("facade-filesystem-parent", "1.0.0")
                    .mount(child, Some("child"))
                    .build()
            } else {
                modern::ServerBuilder::new("facade-filesystem-http", "1.0.0")
                    .resource(handler)
                    .build()
            };
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("filesystem facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("filesystem facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("filesystem HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("filesystem facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("filesystem facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("filesystem facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("filesystem facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn e2e_public_http_filesystem_provider_lists_and_reads_live_file() {
    let cx = Cx::for_request();
    let server = spawn_modern_filesystem_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-fs-client", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live filesystem HTTP server");

    let listed = runtime_block_on_bounded(&cx, client.list_resource_templates(&cx, None))
        .expect("live bind_http must list the FilesystemProvider template");
    assert!(
        listed
            .resource_templates
            .iter()
            .any(|template| template.uri_template == PUBLIC_HTTP_FS_TEMPLATE
                && template.name == PUBLIC_HTTP_FS_PREFIX),
        "FilesystemProvider must advertise its reversible file template: {:?}",
        listed.resource_templates
    );

    let unmatched =
        runtime_block_on_bounded(&cx, client.read_resource(&cx, "file:///other/note.txt"))
            .expect_err(
                "changing only the prefix the template cannot bind must refuse before dispatch",
            );
    assert!(
        matches!(
            unmatched,
            modern::HttpClientError::CoreResult(ref error)
                if error.code == McpErrorCode::InvalidParams
        ),
        "an unmatched filesystem URI must stay InvalidParams: {unmatched:?}"
    );

    let file = runtime_block_on_bounded(&cx, client.read_resource(&cx, PUBLIC_HTTP_FS_FILE_URI))
        .expect("resources/read must expand the live file URI through the filesystem handler");
    assert!(
        matches!(
            file.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == PUBLIC_HTTP_FS_FILE_TEXT
        ),
        "the live filesystem read must retain the file bytes: {:?}",
        file.contents
    );

    drop(client);
    server.shutdown();
}

#[cfg(all(feature = "proxy", any(target_os = "linux", target_os = "macos")))]
#[test]
fn e2e_public_http_prefixed_as_proxy_forwards_filesystem_template() {
    let cx = Cx::for_request();
    let upstream = spawn_modern_filesystem_http_server_named("as-proxy");
    let gateway =
        spawn_modern_http_template_proxy_gateway(upstream.address(), PUBLIC_HTTP_FS_TEMPLATE);
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-as-proxy-fs-client", "1.0.0")
            .connect_http_with_cx(public_http_target(gateway.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live filesystem as_proxy HTTP gateway");

    let listed = runtime_block_on_bounded(&cx, client.list_resource_templates(&cx, None))
        .expect("the live prefixed gateway must advertise the exact filesystem template");
    assert!(
        listed
            .resource_templates
            .iter()
            .any(|template| template.uri_template == PUBLIC_HTTP_FS_TEMPLATE
                && template.name == PUBLIC_HTTP_FS_PREFIX),
        "as_proxy_typed must keep the exact filesystem template: {:?}",
        listed.resource_templates
    );
    assert!(
        listed
            .resource_templates
            .iter()
            .all(|template| !template.uri_template.starts_with("ext/")),
        "a nonempty as_proxy prefix must not invent a non-absolute filesystem template URI: {:?}",
        listed.resource_templates
    );

    let unmatched = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, "file:///other/note.txt"),
    )
    .expect_err(
        "changing only the prefix the template cannot bind must refuse before upstream dispatch",
    );
    assert!(
        matches!(
            unmatched,
            modern::HttpClientError::CoreResult(ref error)
                if error.code == McpErrorCode::InvalidParams
        ),
        "an unmatched proxied filesystem URI must stay InvalidParams: {unmatched:?}"
    );

    let file = runtime_block_on_bounded(&cx, client.read_resource(&cx, PUBLIC_HTTP_FS_FILE_URI))
        .expect("the live prefixed gateway must expand the live file URI through the upstream filesystem handler");
    assert!(
        matches!(
            file.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == PUBLIC_HTTP_FS_FILE_TEXT
        ),
        "the proxied live filesystem read must retain the file bytes: {:?}",
        file.contents
    );

    drop(client);
    gateway.shutdown();
    upstream.shutdown();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn e2e_public_http_mount_forwards_unprefixed_filesystem_template() {
    let cx = Cx::for_request();
    let server = spawn_modern_filesystem_http_server_named("mounted");
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-mount-fs-client", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the public facade connects to the live mounted filesystem HTTP server");

    let listed = runtime_block_on_bounded(&cx, client.list_resource_templates(&cx, None))
        .expect("the mounted parent must advertise the exact filesystem template");
    assert!(
        listed
            .resource_templates
            .iter()
            .any(|template| template.uri_template == PUBLIC_HTTP_FS_TEMPLATE
                && template.name == PUBLIC_HTTP_FS_PREFIX),
        "mount() must keep the exact filesystem template: {:?}",
        listed.resource_templates
    );
    assert!(
        listed
            .resource_templates
            .iter()
            .all(|template| !template.uri_template.starts_with("child/")),
        "a nonempty mount prefix must not invent a non-absolute filesystem template URI: {:?}",
        listed.resource_templates
    );

    let unmatched = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, "file:///other/note.txt"),
    )
    .expect_err(
        "changing only the prefix the template cannot bind must refuse before the child handler",
    );
    assert!(
        matches!(
            unmatched,
            modern::HttpClientError::CoreResult(ref error)
                if error.code == McpErrorCode::InvalidParams
        ),
        "an unmatched mounted filesystem URI must stay InvalidParams: {unmatched:?}"
    );

    let file = runtime_block_on_bounded(&cx, client.read_resource(&cx, PUBLIC_HTTP_FS_FILE_URI))
        .expect(
            "the mounted parent must expand the live file URI through the child filesystem handler",
        );
    assert!(
        matches!(
            file.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == PUBLIC_HTTP_FS_FILE_TEXT
        ),
        "the mounted live filesystem read must retain the file bytes: {:?}",
        file.contents
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_modern_facade_native_http_negotiates_then_dispatches_authenticated_tool() {
    const MAX_NATIVE_HTTP_RESPONSE_BYTES: usize = 1 << 20;

    fn exchange(
        address: SocketAddr,
        protocol_version: &str,
        method: &str,
        tool_name: Option<&str>,
        body: &[u8],
    ) -> Vec<u8> {
        let mut stream = std::net::TcpStream::connect_timeout(&address, HTTP_OPERATION_BOUND)
            .expect("native HTTP client connects to the public facade listener");
        stream
            .set_read_timeout(Some(HTTP_OPERATION_BOUND))
            .expect("native HTTP client read deadline is configured");
        stream
            .set_write_timeout(Some(HTTP_OPERATION_BOUND))
            .expect("native HTTP client write deadline is configured");
        let tool_name_header =
            tool_name.map_or_else(String::new, |name| format!("Mcp-Name: {name}\r\n"));
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer alpha\r\nAccept: application/json\r\nContent-Type: application/json\r\nMCP-Protocol-Version: {protocol_version}\r\nMcp-Method: {method}\r\n{tool_name_header}Content-Length: {}\r\n\r\n",
            body.len(),
        );
        stream
            .write_all(request.as_bytes())
            .and_then(|()| stream.write_all(body))
            .expect("native HTTP request commits to the public facade listener");
        let mut response = Vec::new();
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let read = stream
                .read(&mut buffer)
                .expect("native HTTP response reads within its configured deadline");
            if read == 0 {
                break;
            }
            assert!(
                response
                    .len()
                    .checked_add(read)
                    .is_some_and(|size| size <= MAX_NATIVE_HTTP_RESPONSE_BYTES),
                "native HTTP response exceeds the test's bounded response budget"
            );
            response.extend_from_slice(&buffer[..read]);
        }
        response
    }

    fn chunked_response_body(body: &[u8]) -> Vec<u8> {
        let mut cursor = 0;
        let mut decoded = Vec::new();
        loop {
            let size_end = body[cursor..]
                .windows(2)
                .position(|window| window == b"\r\n")
                .map(|offset| cursor + offset)
                .expect("chunked response contains a complete chunk-size line");
            let size_line = std::str::from_utf8(&body[cursor..size_end])
                .expect("chunked response chunk size is ASCII");
            let size = usize::from_str_radix(size_line.split(';').next().unwrap_or_default(), 16)
                .expect("chunked response chunk size is hexadecimal");
            cursor = size_end + 2;
            if size == 0 {
                loop {
                    let trailer_end = body[cursor..]
                        .windows(2)
                        .position(|window| window == b"\r\n")
                        .map(|offset| cursor + offset)
                        .expect("chunked response contains a complete trailer line");
                    let trailer = &body[cursor..trailer_end];
                    cursor = trailer_end + 2;
                    if trailer.is_empty() {
                        assert_eq!(
                            cursor,
                            body.len(),
                            "chunked response has no bytes after its terminal trailer"
                        );
                        return decoded;
                    }
                    assert!(
                        trailer.contains(&b':'),
                        "chunked response trailer has an HTTP field delimiter"
                    );
                }
            }
            let chunk_end = cursor
                .checked_add(size)
                .expect("chunked response chunk length does not overflow");
            assert!(
                chunk_end.checked_add(2).is_some_and(|terminator_end| {
                    terminator_end <= body.len() && &body[chunk_end..terminator_end] == b"\r\n"
                }),
                "chunked response contains a complete chunk body and terminator"
            );
            decoded.extend_from_slice(&body[cursor..chunk_end]);
            cursor = chunk_end + 2;
        }
    }

    fn response_body(response: &[u8]) -> Vec<u8> {
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("native HTTP response contains a complete header terminator");
        let headers = std::str::from_utf8(&response[..header_end])
            .expect("native HTTP response headers are ASCII");
        let mut content_length = None;
        let mut chunked = false;
        for header in headers.lines().skip(1) {
            let (name, value) = header
                .split_once(':')
                .expect("native HTTP response header has a field delimiter");
            if name.eq_ignore_ascii_case("content-length") {
                assert!(
                    content_length.is_none(),
                    "native HTTP response has one Content-Length field"
                );
                content_length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .expect("native HTTP Content-Length is a valid byte count"),
                );
            }
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"))
            {
                chunked = true;
            }
        }
        let body = &response[header_end + 4..];
        if chunked {
            assert!(
                content_length.is_none(),
                "chunked native HTTP response does not also carry Content-Length"
            );
            return chunked_response_body(body);
        }
        let content_length =
            content_length.expect("native HTTP response uses Content-Length or chunked framing");
        assert_eq!(
            body.len(),
            content_length,
            "native HTTP response body is complete according to Content-Length"
        );
        body.to_vec()
    }

    let server = spawn_modern_facade_http_server(true, None, false);
    let discovery = JsonRpcRequest::new(
        "server/discover",
        Some(json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": modern::PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        })),
        1_i64,
    );
    let discovery_body =
        serde_json::to_vec(&discovery).expect("exact-modern discovery request serializes");
    let discovery_response = exchange(
        server.address(),
        modern::PROTOCOL_VERSION,
        "server/discover",
        None,
        &discovery_body,
    );
    assert!(
        discovery_response.starts_with(b"HTTP/1.1 200"),
        "authenticated exact-modern discovery must succeed: {}",
        String::from_utf8_lossy(&discovery_response)
    );
    let discovery_body = response_body(&discovery_response);
    let discovery: serde_json::Value = serde_json::from_slice(&discovery_body)
        .expect("authenticated discovery response is JSON-RPC");
    assert_eq!(discovery["id"], json!(1));
    assert!(
        discovery.get("error").is_none(),
        "authenticated discovery must negotiate the modern era: {discovery}"
    );
    assert_eq!(discovery["result"]["resultType"], json!("complete"));
    assert_eq!(
        discovery["result"]["supportedVersions"],
        json!([modern::PROTOCOL_VERSION]),
        "the public server advertises only its exact final wire version"
    );
    assert_eq!(
        discovery["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        json!("facade-native-http-auth"),
        "final server identity belongs in result metadata, never a legacy initialize field"
    );
    assert_eq!(
        discovery["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["version"],
        json!("1.0.0")
    );
    assert_eq!(discovery["result"]["capabilities"]["tools"], json!({}));
    assert_eq!(discovery["result"]["capabilities"]["prompts"], json!({}));
    assert_eq!(
        discovery["result"]["capabilities"]["completions"],
        json!({})
    );
    assert_eq!(discovery["result"]["cacheScope"], json!("private"));
    assert!(
        discovery["result"]["ttlMs"].is_u64(),
        "final discovery exposes a nonnegative cache lifetime"
    );

    let tool = JsonRpcRequest::new(
        "tools/call",
        Some(json!({
            "name": PUBLIC_HTTP_TOOL_NAME,
            "arguments": {"value": PUBLIC_HTTP_TOOL_ARGUMENT},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": modern::PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        })),
        2_i64,
    );
    let tool_body = serde_json::to_vec(&tool).expect("exact-modern tool request serializes");
    let tool_response = exchange(
        server.address(),
        modern::PROTOCOL_VERSION,
        "tools/call",
        Some(PUBLIC_HTTP_TOOL_NAME),
        &tool_body,
    );
    assert!(
        tool_response.starts_with(b"HTTP/1.1 200"),
        "authenticated exact-modern tool call must succeed: {}",
        String::from_utf8_lossy(&tool_response)
    );
    let tool_response_body = response_body(&tool_response);
    let tool: serde_json::Value = serde_json::from_slice(&tool_response_body)
        .expect("authenticated tool response is JSON-RPC");
    assert_eq!(tool["id"], json!(2));
    assert!(
        tool.get("error").is_none(),
        "authenticated exact-modern tool call must reach the handler: {tool}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the authenticated exact-modern tool call invokes the facade handler once"
    );

    // RH-5 near-negative: retain the valid bearer and exact JSON-RPC body,
    // changing only the native MCP-Protocol-Version header to an unsupported
    // date. Strict admission must reject before the handler can run again.
    let rejection = exchange(
        server.address(),
        "2025-11-25",
        "tools/call",
        Some(PUBLIC_HTTP_TOOL_NAME),
        &tool_body,
    );
    assert!(
        rejection.starts_with(b"HTTP/1.1 400"),
        "the one-variable unsupported-era request must fail before dispatch: {}",
        String::from_utf8_lossy(&rejection)
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "changing only MCP-Protocol-Version must not invoke the authenticated handler"
    );
    server.shutdown();
}

#[test]
fn e2e_public_http_final_cursor_query_kind_and_cache_identity_are_live_and_fail_closed() {
    fn tools_page(result: CoreResult) -> fastmcp_rust::FinalListToolsResult {
        let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = result else {
            panic!("tools/list must retain its exact final result vocabulary");
        };
        result.payload
    }

    fn typed_page_identity(page: &fastmcp_rust::FinalListToolsResult) -> serde_json::Value {
        serde_json::to_value(page).expect("a typed final tools page retains an exact JSON identity")
    }

    let cx = Cx::for_request();
    let server = HttpServerFixture::spawn_modern_with_page_size(1);

    let admitted_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-final-cursor-cache-admission-client", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the public typed HTTP client admits the live final discovery response");
    let discovery = admitted_client.server_discovery();
    assert_eq!(discovery.result_type(), "complete");
    assert_eq!(discovery.supported_versions().len(), 1);
    assert_eq!(
        discovery.supported_versions().first().map(String::as_str),
        Some(modern::PROTOCOL_VERSION),
        "typed HTTP admission retains the exact live final discovery version"
    );
    assert_eq!(
        discovery
            .server_info()
            .expect("typed HTTP admission retains the discovered server identity")
            .name,
        "facade-native-http-auth"
    );
    drop(admitted_client);

    let mut client = runtime_block_on_bounded(
        &cx,
        auto::client_builder()
            .client_info("e2e-final-cursor-cache-client", "1.0.0")
            .protocol_plan(plan(server.address(), ProtocolPolicy::ModernOnly))
            .connect_http_client_with_cx(&cx),
    )
    .expect("the public HTTP client completes live modern discovery");

    let first = tools_page(
        runtime_block_on_bounded(
            &cx,
            client.request_final_core(&cx, "tools/list", json!({ "includeTags": ["cursor"] })),
        )
        .expect("the filtered first public tools page is admitted"),
    );
    assert_eq!(
        first.tools.len(),
        1,
        "page size creates a real continuation"
    );
    assert_eq!(
        first.ttl_ms,
        CacheTtl::milliseconds(5 * 60 * 1_000),
        "the typed first page retains its exact final ttlMs"
    );
    assert_eq!(
        first.cache_scope,
        CacheScope::Private,
        "the typed first page retains its exact final cacheScope"
    );
    let first_identity = typed_page_identity(&first);
    let cursor = first
        .next_cursor
        .clone()
        .expect("the first filtered page carries an opaque cursor");
    assert_eq!(client.final_result_cache_stats().fills, 1);
    assert_eq!(client.final_result_cache_stats().hits, 0);

    let replay = tools_page(
        runtime_block_on_bounded(
            &cx,
            client.request_final_core(&cx, "tools/list", json!({ "includeTags": ["cursor"] })),
        )
        .expect("the identical public list request uses its local final cache"),
    );
    assert_eq!(
        typed_page_identity(&replay),
        first_identity,
        "the cache replay retains the complete typed first-page identity"
    );
    assert_eq!(client.final_result_cache_stats().fills, 1);
    assert_eq!(
        client.final_result_cache_stats().hits,
        1,
        "an identical final request is a public cache hit"
    );

    let second = tools_page(
        runtime_block_on_bounded(
            &cx,
            client.request_final_core(
                &cx,
                "tools/list",
                json!({ "cursor": cursor.clone(), "includeTags": ["cursor"] }),
            ),
        )
        .expect("the exact cursor/query continuation reaches the second live page"),
    );
    assert_eq!(second.tools.len(), 1);
    assert_eq!(
        second.tools[0].name, PUBLIC_HTTP_CURSOR_SECONDARY_TOOL_NAME,
        "the sole valid continuation retains the exact cursor-secondary tool identity"
    );
    assert!(second.next_cursor.is_none());
    assert_eq!(
        second.ttl_ms,
        CacheTtl::milliseconds(5 * 60 * 1_000),
        "the typed continuation page retains its exact final ttlMs"
    );
    assert_eq!(
        second.cache_scope,
        CacheScope::Private,
        "the typed continuation page retains its exact final cacheScope"
    );
    assert_ne!(
        typed_page_identity(&second),
        first_identity,
        "the continuation must retain a complete typed page identity distinct from page one"
    );

    // RH-5: only the query changes. The retained cursor must not cross into a
    // different filtered catalog, and the prior cached first page stays live.
    let query_rejection = runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "tools/list",
            json!({ "cursor": cursor.clone(), "includeTags": ["other"] }),
        ),
    )
    .expect_err("changing only includeTags rejects the cursor before page projection");
    assert!(matches!(
        query_rejection,
        fastmcp_rust::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::InvalidParams
    ));

    // RH-5: only the catalog method changes. A tools cursor cannot select a
    // resources page, and this rejection must not flush the cached tools page.
    let kind_rejection = runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "resources/list",
            json!({ "cursor": cursor.clone(), "includeTags": ["cursor"] }),
        ),
    )
    .expect_err("changing only the catalog kind rejects the tools cursor");
    assert!(matches!(
        kind_rejection,
        fastmcp_rust::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::InvalidParams
    ));

    // RH-5: only wire presence changes from an absent cursor to the explicitly
    // present empty cursor. The cache must not replay the absent-cursor page.
    let empty_cursor_rejection = runtime_block_on_bounded(
        &cx,
        client.request_final_core(
            &cx,
            "tools/list",
            json!({ "cursor": "", "includeTags": ["cursor"] }),
        ),
    )
    .expect_err("an explicit empty cursor is not the absent-cursor cache identity");
    assert!(matches!(
        empty_cursor_rejection,
        fastmcp_rust::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::InvalidParams
    ));

    let before_unchanged_retry = client.final_result_cache_stats();
    let unchanged_retry = tools_page(
        runtime_block_on_bounded(
            &cx,
            client.request_final_core(&cx, "tools/list", json!({ "includeTags": ["cursor"] })),
        )
        .expect("cursor rejections leave the already-cached first page unchanged"),
    );
    assert_eq!(
        typed_page_identity(&unchanged_retry),
        first_identity,
        "cursor rejections leave the complete cached typed first-page identity unchanged"
    );
    assert_eq!(
        client.final_result_cache_stats().fills,
        before_unchanged_retry.fills,
        "rejected cursor variations cannot overwrite the admitted cached page"
    );
    assert_eq!(
        client.final_result_cache_stats().hits,
        before_unchanged_retry.hits + 1,
        "the unchanged original request still resolves from its prior cache entry"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_modern_facade_native_http_completion_returns_typed_result_and_rejects_undeclared_argument() {
    let cx = Cx::for_request();
    let server = spawn_modern_facade_http_server(false, None, false);
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-modern-completion-client", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the live completion provider");
    let params = modern::CompletionParams {
        reference: modern::CompletionReference::PromptWithTitle {
            name: PUBLIC_HTTP_PROMPT_NAME.to_owned(),
            title: "Public HTTP E2E Prompt".to_owned(),
        },
        argument: modern::FinalCompletionArgument {
            name: "subject".to_owned(),
            value: "cross-era".to_owned(),
        },
        context: Some(modern::FinalCompletionContext {
            arguments: Some(std::collections::BTreeMap::from([(
                "region".to_owned(),
                "us-east-1".to_owned(),
            )])),
        }),
    };

    runtime_block_on_bounded(&cx, client.complete(&cx, params.clone()))
        .expect("a completion/complete without a progress token still completes");
    assert!(
        client.take_progress_notifications().is_empty(),
        "without a progressToken the completion handler must not emit request-scoped progress"
    );

    let marker = modern::ProgressMarker::from("http-completion-progress");
    let result = runtime_block_on_bounded(
        &cx,
        client.complete_with_progress_marker(&cx, params.clone(), marker.clone()),
    )
    .expect("the typed modern HTTP completion reaches the live facade provider");
    assert_eq!(
        result.completion.values,
        vec![PUBLIC_HTTP_COMPLETION_VALUE.to_owned()],
        "the exact FinalCompletionResult retains the provider values"
    );
    assert_eq!(
        result.completion.total,
        Some(modern::JsonInteger::from(1_i64)),
        "the exact FinalCompletionResult retains its JSON-integer total"
    );
    assert_eq!(
        result.completion.has_more,
        Some(false),
        "the exact FinalCompletionResult retains the terminal pagination flag"
    );
    let progress = client.take_progress_notifications();
    assert!(
        progress.iter().any(|notification| {
            notification.progress_token == marker
                && notification.message.as_deref() == Some("completion-halfway")
        }),
        "live bind_http must retain completion notifications/progress after a progressToken: {progress:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().completion,
        2,
        "the accepted typed completion invokes the registered provider once per successful request"
    );

    // RH-5 near-negative: retain the target, title, completion context, and
    // prefix, changing only the completion argument name. Router validation
    // must reject before the registered provider can run again.
    let mut undeclared_argument = params;
    undeclared_argument.argument.name = "undeclared".to_owned();
    let error = runtime_block_on_bounded(&cx, client.complete(&cx, undeclared_argument))
        .expect_err("only an undeclared completion argument is rejected");
    assert!(matches!(
        error,
        modern::HttpClientError::CoreResult(error) if error.code == McpErrorCode::InvalidParams
    ));
    assert_eq!(
        server.handler_call_snapshot().completion,
        2,
        "changing only the argument name leaves provider state unchanged"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_cross_era_refusals_leave_handler_observables_unchanged() {
    let cx = Cx::for_request();

    let modern_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::ModernOnly);
    let modern_before = invoke_modern_public_handlers(&cx, modern_server.address());
    let modern_calls_before_refusal = modern_server.handler_call_snapshot();
    // Keep the legacy facade configuration identical to its matched-era
    // control; the endpoint's live server policy is the only intentional
    // protocol-selection variable.
    let legacy_refusal = match runtime_block_on_bounded(
        &cx,
        legacy_2024::http_client_builder(
            public_http_target(modern_server.address(), "/sse"),
            public_http_target(modern_server.address(), "/messages"),
        )
        .expect("the exact legacy HTTP endpoints form one public facade plan")
        .client_info("e2e-public-legacy-handler-client", "1.0.0")
        .connect_http_client_with_cx(&cx),
    ) {
        Err(error) => error,
        Ok(_) => {
            panic!(
                "a LegacyOnly public facade must reject the ModernOnly server's live SSE refusal"
            )
        }
    };
    assert!(matches!(
        legacy_refusal,
        legacy_2024::HttpClientError::Connection(ClientHttpConnectionError::Modern(
            fastmcp_rust::ModernHttpClientError::LegacySse(
                fastmcp_rust::LegacySseHttpClientError::SseGetRejected { status: 400 }
            )
        ))
    ));
    assert_eq!(
        modern_server.handler_call_snapshot(),
        modern_calls_before_refusal,
        "the refused exact-legacy connection must not invoke a ModernOnly handler"
    );
    let modern_after = invoke_modern_public_handlers(&cx, modern_server.address());
    assert_eq!(
        modern_after, modern_before,
        "the refused exact-legacy connection must not alter later ModernOnly handler observables"
    );
    modern_server.shutdown();

    let legacy_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::LegacyOnly);
    let legacy_before = invoke_legacy_public_handlers(&cx, legacy_server.address());
    let legacy_calls_before_refusal = legacy_server.handler_call_snapshot();
    // Keep the modern facade configuration identical to its matched-era
    // control; the endpoint's live server policy is the only intentional
    // protocol-selection variable.
    let modern_refusal = match runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-modern-handler-client", "1.0.0")
            .connect_http_with_cx(public_http_target(legacy_server.address(), "/mcp"), &cx),
    ) {
        Err(error) => error,
        Ok(_) => {
            panic!(
                "a ModernOnly public facade must reject the LegacyOnly server's live probe refusal"
            )
        }
    };
    assert!(matches!(
        modern_refusal,
        modern::HttpClientConnectError::Connect(
            modern::HttpClientError::Connection(ClientHttpConnectionError::Modern(
                fastmcp_rust::ModernHttpClientError::Negotiation(
                    fastmcp_rust::ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback {
                        status: 400,
                        ..
                    }
                )
            ))
        )
    ));
    assert_eq!(
        legacy_server.handler_call_snapshot(),
        legacy_calls_before_refusal,
        "the refused modern connection must not invoke a LegacyOnly handler"
    );
    let legacy_after = invoke_legacy_public_handlers(&cx, legacy_server.address());
    assert_eq!(
        legacy_after, legacy_before,
        "the refused modern connection must not alter later LegacyOnly handler observables"
    );
    legacy_server.shutdown();
}

#[test]
fn e2e_public_http_auto_selects_modern_on_the_shipped_facade_server() {
    let server = HttpServerFixture::spawn();
    let cx = Cx::for_request();
    let builder = auto::client_builder()
        .client_info("e2e-modern-http-client", "1.0.0")
        .protocol_plan(plan(server.address(), ProtocolPolicy::Auto));
    assert_eq!(
        builder.selected_protocol_plan().policy(),
        ProtocolPolicy::Auto
    );

    let mut client = runtime_block_on_bounded(&cx, builder.connect_http_client_with_cx(&cx))
        .expect("the public Auto facade client completes live modern discovery");
    assert_eq!(
        client.selected_protocol_era(),
        ProtocolEra::Modern2026,
        "a live modern discovery response must never downgrade Auto"
    );
    assert_eq!(client.protocol_plan().policy(), ProtocolPolicy::Auto);
    assert!(
        client.server_discovery().is_some(),
        "modern selection exposes the public discovery result"
    );
    assert_eq!(
        client.connection().protocol_version(),
        Some(fastmcp_rust::modern::PROTOCOL_VERSION),
        "the public HTTP connection reports the exact modern negotiated version"
    );

    let response = runtime_block_on_bounded(
        &cx,
        client.request(&cx, "tools/list", json!({ "cursor": null })),
    )
    .expect("the Auto-selected modern connection serves requests");
    let ClientHttpResponse::Modern(response) = response else {
        panic!("the selected modern HTTP client must retain the modern response lane");
    };
    let document = final_response_document(&cx, response);
    assert_eq!(document["id"], json!(2));
    assert!(
        document.get("error").is_none(),
        "tools/list over the Auto-selected connection must not fail: {document}"
    );
    assert!(
        document["result"]["tools"].is_array(),
        "the modern tools/list response must carry its tools result: {document}"
    );
    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_modern_only_selects_modern_and_refuses_legacy_only() {
    let modern_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::ModernOnly);
    let cx = Cx::for_request();
    let builder = auto::client_builder()
        .client_info("e2e-modern-only-http-client", "1.0.0")
        .protocol_plan(plan(modern_server.address(), ProtocolPolicy::ModernOnly));

    let mut client = runtime_block_on_bounded(&cx, builder.connect_http_client_with_cx(&cx))
        .expect("a ModernOnly facade plan selects the real ModernOnly endpoint");
    assert_eq!(client.selected_protocol_era(), ProtocolEra::Modern2026);
    assert_eq!(
        client.connection().protocol_version(),
        Some(fastmcp_rust::modern::PROTOCOL_VERSION),
        "the positive ModernOnly connection reports the exact modern version"
    );
    assert!(
        client.server_discovery().is_some(),
        "the positive ModernOnly connection retains modern discovery"
    );
    let response = runtime_block_on_bounded(
        &cx,
        client.request(&cx, "tools/list", json!({ "cursor": null })),
    )
    .expect("the selected ModernOnly connection serves tools/list");
    let ClientHttpResponse::Modern(response) = response else {
        panic!("the ModernOnly connection must retain the modern response lane");
    };
    let document = final_response_document(&cx, response);
    assert_eq!(document["id"], json!(2));
    assert!(
        document.get("error").is_none(),
        "the positive ModernOnly tools/list response must not fail: {document}"
    );
    assert!(
        document["result"]["tools"].is_array(),
        "the positive ModernOnly tools/list response carries its result: {document}"
    );
    drop(client);
    modern_server.shutdown();

    // This differs from the positive case only in the live server policy.
    // A ModernOnly plan has no configured legacy fallback and must not create
    // a client after the LegacyOnly endpoint refuses its modern request.
    let legacy_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::LegacyOnly);
    let refusal = match runtime_block_on_bounded(
        &cx,
        auto::client_builder()
            .client_info("e2e-modern-only-http-client", "1.0.0")
            .protocol_plan(plan(legacy_server.address(), ProtocolPolicy::ModernOnly))
            .connect_http_client_with_cx(&cx),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a ModernOnly facade plan must reject the LegacyOnly endpoint's live 400"),
    };
    assert!(matches!(
        refusal,
        auto::HttpClientError::Connection(auto::ClientHttpConnectionError::Modern(
            fastmcp_rust::ModernHttpClientError::Negotiation(
                auto::ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback {
                    status: 400,
                    ..
                }
            )
        ))
    ));
    legacy_server.shutdown();
}

#[test]
fn e2e_public_http_legacy_only_selects_legacy_and_refuses_modern_only() {
    let legacy_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::LegacyOnly);
    let cx = Cx::for_request();
    let builder = auto::client_builder()
        .client_info("e2e-legacy-only-http-client", "1.0.0")
        .protocol_plan(plan(legacy_server.address(), ProtocolPolicy::LegacyOnly));

    let mut client = runtime_block_on_bounded(&cx, builder.connect_http_client_with_cx(&cx))
        .expect("a LegacyOnly facade plan selects the real exact-legacy endpoint");
    assert_eq!(client.selected_protocol_era(), ProtocolEra::Legacy2024);
    assert_eq!(
        client.connection().protocol_version(),
        Some(fastmcp_rust::legacy_2024::PROTOCOL_VERSION),
        "the positive LegacyOnly connection reports the exact 2024-11-05 version"
    );
    assert!(
        client.server_discovery().is_none(),
        "the positive LegacyOnly connection cannot retain modern discovery"
    );
    let response = runtime_block_on_bounded(&cx, client.request(&cx, "ping", json!({})))
        .expect("the selected LegacyOnly connection serves ping");
    let ClientHttpResponse::Legacy(JsonRpcMessage::Response(ping)) = response else {
        panic!("the LegacyOnly connection must retain the exact-legacy response lane");
    };
    assert!(
        ping.error.is_none(),
        "the positive exact-legacy ping must not fail"
    );
    assert_eq!(ping.result, Some(json!({})));
    drop(client);
    legacy_server.shutdown();

    // This differs from the positive case only in the live server policy.
    // A LegacyOnly plan has no configured modern route and must not manufacture
    // an exact-legacy session after the ModernOnly endpoint refuses its SSE GET.
    let modern_server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::ModernOnly);
    let refusal = match runtime_block_on_bounded(
        &cx,
        auto::client_builder()
            .client_info("e2e-legacy-only-http-client", "1.0.0")
            .protocol_plan(plan(modern_server.address(), ProtocolPolicy::LegacyOnly))
            .connect_http_client_with_cx(&cx),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a LegacyOnly facade plan must reject the ModernOnly endpoint's live 400"),
    };
    assert!(matches!(
        refusal,
        auto::HttpClientError::Connection(auto::ClientHttpConnectionError::Modern(
            fastmcp_rust::ModernHttpClientError::LegacySse(
                fastmcp_rust::LegacySseHttpClientError::SseGetRejected { status: 400 }
            )
        ))
    ));
    modern_server.shutdown();
}

#[test]
fn e2e_public_http_auto_falls_back_to_exact_legacy_on_live_eligible_refusal() {
    let server = HttpServerFixture::spawn_with_policy(ProtocolPolicy::LegacyOnly);
    let cx = Cx::for_request();

    // This differs from the matched Auto-modern positive only in the live
    // server policy. The LegacyOnly endpoint returns its real modern-route
    // refusal, after which Auto may open the configured exact-legacy routes.
    let builder = auto::client_builder()
        .client_info("e2e-modern-http-client", "1.0.0")
        .protocol_plan(plan(server.address(), ProtocolPolicy::Auto));
    assert_eq!(
        builder.selected_protocol_plan().policy(),
        ProtocolPolicy::Auto
    );
    let mut client = runtime_block_on_bounded(&cx, builder.connect_http_client_with_cx(&cx))
        .expect("an eligible live modern-route refusal completes the exact legacy lifecycle");
    assert_eq!(
        client.selected_protocol_era(),
        ProtocolEra::Legacy2024,
        "Auto must expose exact legacy selection only after its eligible live refusal"
    );
    assert_eq!(client.protocol_plan().policy(), ProtocolPolicy::Auto);
    assert!(
        client.server_discovery().is_none(),
        "exact legacy fallback cannot expose modern discovery state"
    );
    assert_eq!(
        client.connection().protocol_version(),
        Some(fastmcp_rust::legacy_2024::PROTOCOL_VERSION),
        "the public HTTP connection retains the exact validated legacy initialize wire version"
    );
    assert_eq!(
        client.server_info().name,
        "facade-http-example",
        "the legacy initialization result comes from the shipped facade server composition"
    );
    let ping = runtime_block_on_bounded(&cx, client.request(&cx, "ping", json!({})))
        .expect("the initialized exact-legacy fallback remains usable");
    let ClientHttpResponse::Legacy(JsonRpcMessage::Response(ping)) = ping else {
        panic!("the exact-legacy fallback must answer ping through its legacy response lane");
    };
    assert!(ping.error.is_none(), "legacy ping must not fail: {ping:?}");
    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_auto_isolates_live_modern_and_legacy_clients() {
    let gate = Arc::new(OverlapFinalMethodGate::default());
    let mut server =
        HttpServerFixture::spawn_with_middleware(Some(Arc::clone(&gate) as Arc<dyn Middleware>));
    let address = server.address();

    let (completed_tx, completed_rx) = mpsc::channel();
    let modern_completed_tx = completed_tx.clone();
    let mut modern_worker = Some(thread::spawn(move || {
        let result = (|| -> Result<serde_json::Value, String> {
            let cx = Cx::for_request();
            let builder = auto::client_builder()
                .client_info("e2e-isolated-modern-client", "1.0.0")
                .protocol_plan(plan(address, ProtocolPolicy::Auto));
            let mut client =
                runtime_block_on_bounded(&cx, builder.connect_http_client_with_cx(&cx)).map_err(
                    |error| format!("the first Auto client did not select modern: {error}"),
                )?;
            if client.selected_protocol_era() != ProtocolEra::Modern2026 {
                return Err("the first client did not retain an independent modern era".to_owned());
            }
            let response = runtime_block_on_bounded(
                &cx,
                client.request(&cx, "tools/list", json!({ "cursor": null })),
            )
            .map_err(|error| format!("the modern tools/list request failed: {error}"))?;
            let ClientHttpResponse::Modern(response) = response else {
                return Err("the first client did not retain its modern response lane".to_owned());
            };
            Ok(final_response_document(&cx, response))
        })();
        let _ = modern_completed_tx.send(OverlapWorkerCompletion::Modern(result));
    }));
    let legacy_completed_tx = completed_tx.clone();
    let mut legacy_worker = Some(thread::spawn(move || {
        let result = (|| -> Result<serde_json::Value, String> {
            let cx = Cx::for_request();
            let builder = auto::client_builder()
                .client_info("e2e-isolated-legacy-client", "1.0.0")
                .protocol_plan(plan_with_modern_post_path(
                    address,
                    ProtocolPolicy::Auto,
                    "/modern-unavailable",
                ));
            let mut client =
                runtime_block_on_bounded(&cx, builder.connect_http_client_with_cx(&cx)).map_err(
                    |error| format!("the second Auto client did not select legacy: {error}"),
                )?;
            if client.selected_protocol_era() != ProtocolEra::Legacy2024 {
                return Err("the second client inherited a foreign protocol era".to_owned());
            }
            let response = runtime_block_on_bounded(&cx, client.request(&cx, "ping", json!({})))
                .map_err(|error| format!("the legacy ping request failed: {error}"))?;
            let ClientHttpResponse::Legacy(JsonRpcMessage::Response(response)) = response else {
                return Err("the second client did not retain its legacy response lane".to_owned());
            };
            serde_json::to_value(response)
                .map_err(|error| format!("the legacy response did not serialize: {error}"))
        })();
        let _ = legacy_completed_tx.send(OverlapWorkerCompletion::Legacy(result));
    }));
    drop(completed_tx);

    let admission = gate.wait_for_cross_era_requests();
    gate.release();
    let (modern_document, legacy_document) =
        collect_overlap_worker_results(&completed_rx, HTTP_SERVER_TEARDOWN_BOUND);
    let modern_join = join_finished_thread(
        &mut modern_worker,
        HTTP_SERVER_TEARDOWN_BOUND,
        "modern overlap worker",
    );
    let legacy_join = join_finished_thread(
        &mut legacy_worker,
        HTTP_SERVER_TEARDOWN_BOUND,
        "legacy overlap worker",
    );
    let teardown = server.settle();

    admission.expect(
        "the modern tools/list and legacy ping requests must reach the server before either response runs",
    );
    teardown.expect("the bounded server teardown runs after overlap completion collection");
    modern_join.expect("the modern overlap worker joins without detaching");
    legacy_join.expect("the legacy overlap worker joins without detaching");
    let modern_document = modern_document.expect("the overlapping modern request completes");
    assert_eq!(modern_document["id"], json!(2));
    assert!(
        modern_document.get("error").is_none(),
        "the isolated modern tools/list request must not fail: {modern_document}"
    );
    assert!(
        modern_document["result"]["tools"].is_array(),
        "the isolated modern tools/list response must carry its tools result: {modern_document}"
    );

    let legacy_document = legacy_document.expect("the overlapping legacy request completes");
    assert_eq!(
        legacy_document["id"],
        json!(2),
        "both clients reuse their local final-request id without cross-client correlation"
    );
    assert!(
        legacy_document.get("error").is_none(),
        "the isolated legacy ping must not fail: {legacy_document}"
    );
    assert_eq!(
        legacy_document["result"],
        json!({}),
        "the isolated legacy response must remain the ping acknowledgement: {legacy_document}"
    );
}

const PUBLIC_HTTP_SAMPLING_TOOL_NAME: &str = "public-http-e2e-sampling";
const PUBLIC_HTTP_ROOTS_TOOL_NAME: &str = "public-http-e2e-roots";
const PUBLIC_HTTP_URL_ELICITATION_TOOL_NAME: &str = "public-http-e2e-url-elicitation";
const PUBLIC_HTTP_ELICITATION_RESOURCE_URI: &str = "test://public-http-e2e/elicitation";
const PUBLIC_HTTP_ELICITATION_PROMPT_NAME: &str = "public-http-e2e-elicitation-prompt";

/// Live modern HTTP tool that returns framework-issued MRTR sampling input.
struct PublicHttpSamplingTool;

impl ToolHandler for PublicHttpSamplingTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_SAMPLING_TOOL_NAME.to_owned(),
            description: Some("Proves live facade HTTP final sampling input_required".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text("exact legacy result")])
    }

    fn declares_final_mrtr(&self) -> bool {
        true
    }

    fn call_final_outcome(
        &self,
        ctx: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<FinalToolOutcome> {
        let sampling = ctx.final_sampling(
            "sample",
            serde_json::from_value(json!({
                "messages": [{
                    "role": "assistant",
                    "content": {
                        "type": "tool_use",
                        "id": "weather-request",
                        "name": "weather",
                        "input": {"city": "Boston"},
                    },
                }],
                "maxTokens": 16,
                "tools": [{
                    "name": "weather",
                    "inputSchema": {"type": "object"},
                }],
                "toolChoice": {"mode": "required"},
            }))
            .map_err(|error| McpError::internal_error(error.to_string()))?,
        )?;
        Ok(FinalToolOutcome::InputRequired(
            sampling.into_input_required()?,
        ))
    }
}

/// Live modern HTTP tool that returns framework-issued MRTR roots input.
struct PublicHttpRootsTool;

impl ToolHandler for PublicHttpRootsTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_ROOTS_TOOL_NAME.to_owned(),
            description: Some("Proves live facade HTTP final roots input_required".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text("exact legacy result")])
    }

    fn declares_final_mrtr(&self) -> bool {
        true
    }

    fn call_final_outcome(
        &self,
        ctx: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<FinalToolOutcome> {
        let roots = ctx.final_roots("roots", FinalEmbeddedRootsListParams::default())?;
        Ok(FinalToolOutcome::InputRequired(
            roots.into_input_required()?,
        ))
    }
}

/// Live modern HTTP tool that returns framework-issued MRTR URL elicitation.
struct PublicHttpUrlElicitationTool;

impl ToolHandler for PublicHttpUrlElicitationTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_URL_ELICITATION_TOOL_NAME.to_owned(),
            description: Some(
                "Proves live facade HTTP final URL elicitation input_required".to_owned(),
            ),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text("exact legacy result")])
    }

    fn declares_final_mrtr(&self) -> bool {
        true
    }

    fn call_final_outcome(
        &self,
        ctx: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<FinalToolOutcome> {
        let elicitation = ctx.final_elicitation_url(
            "approval",
            "Approve this operation",
            "https://example.com/approve",
        )?;
        Ok(FinalToolOutcome::InputRequired(
            elicitation.into_input_required()?,
        ))
    }
}

fn public_http_form_elicitation(ctx: &McpContext) -> McpResult<fastmcp_rust::InputRequiredResult> {
    ctx.final_elicitation_form(
        "approval",
        "Approve this operation",
        json!({
            "type": "object",
            "properties": {"approved": {"type": "boolean"}},
            "required": ["approved"],
        }),
    )?
    .into_input_required()
}

/// Live modern HTTP resource that returns framework-issued MRTR elicitation.
struct PublicHttpElicitationResource;

impl ResourceHandler for PublicHttpElicitationResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: PUBLIC_HTTP_ELICITATION_RESOURCE_URI.to_owned(),
            name: "public-http-e2e-elicitation".to_owned(),
            description: Some("Proves live facade HTTP resource input_required".to_owned()),
            mime_type: None,
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Ok(vec![ResourceContent {
            uri: PUBLIC_HTTP_ELICITATION_RESOURCE_URI.to_owned(),
            mime_type: None,
            text: Some("exact legacy resource".to_owned()),
            blob: None,
        }])
    }

    fn declares_final_mrtr(&self) -> bool {
        true
    }

    fn read_final_outcome(
        &self,
        ctx: &McpContext,
    ) -> McpResult<FinalMethodOutcome<fastmcp_rust::FinalReadResourceResult>> {
        public_http_form_elicitation(ctx).map(FinalMethodOutcome::InputRequired)
    }
}

/// Live modern HTTP prompt that returns framework-issued MRTR elicitation.
struct PublicHttpElicitationPrompt;

impl PromptHandler for PublicHttpElicitationPrompt {
    fn definition(&self) -> Prompt {
        Prompt {
            name: PUBLIC_HTTP_ELICITATION_PROMPT_NAME.to_owned(),
            description: Some("Proves live facade HTTP prompt input_required".to_owned()),
            arguments: Vec::new(),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn get(
        &self,
        _ctx: &McpContext,
        _arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        Ok(vec![PromptMessage {
            role: Role::User,
            content: Content::text("exact legacy prompt"),
        }])
    }

    fn declares_final_mrtr(&self) -> bool {
        true
    }

    fn get_final_outcome(
        &self,
        ctx: &McpContext,
        _arguments: HashMap<String, String>,
    ) -> McpResult<FinalMethodOutcome<fastmcp_rust::FinalGetPromptResult>> {
        public_http_form_elicitation(ctx).map(FinalMethodOutcome::InputRequired)
    }
}

/// Starts one ModernOnly facade whose only tool is live final sampling.
fn spawn_modern_sampling_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("sampling HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-sampling", "1.0.0")
                .tool(PublicHttpSamplingTool)
                .tool(PublicHttpRootsTool)
                .tool(PublicHttpUrlElicitationTool)
                .resource(PublicHttpElicitationResource)
                .prompt(PublicHttpElicitationPrompt)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("sampling facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("sampling facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("sampling HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("sampling facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("sampling facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("sampling facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("sampling facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

fn assert_live_input_required(result: &fastmcp_rust::InputRequiredResult, key: &str, kind: &str) {
    assert!(
        result.request_state().is_some(),
        "{kind} must return framework-issued requestState"
    );
    assert!(
        result
            .input_requests()
            .is_some_and(|requests| requests.get(key).is_some()),
        "{kind} must retain its {key} input request"
    );
}

#[test]
fn e2e_public_http_result_verbs_return_live_input_required() {
    let cx = Cx::for_request();
    let server = spawn_modern_sampling_http_server();
    let mut capabilities = ClientCapabilities::default();
    capabilities.sampling = Some(Default::default());
    capabilities.roots = serde_json::from_value(json!({})).expect("roots capability is valid");
    capabilities.elicitation = serde_json::from_value(json!({"form": {}, "url": {}}))
        .expect("form and url elicitation capabilities are valid");
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-mrtr-client", "1.0.0")
            .capabilities(capabilities)
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the live MRTR route");

    let tool = runtime_block_on_bounded(
        &cx,
        client.call_tool_result(&cx, PUBLIC_HTTP_SAMPLING_TOOL_NAME, json!({})),
    )
    .expect("live bind_http final sampling must return a typed tools/call result");
    let FinalCoreResult::ToolsCallInputRequired { result, .. } = tool else {
        panic!("live bind_http final sampling must keep input_required: {tool:?}");
    };
    assert_live_input_required(&result, "sample", "tools/call");

    let roots = runtime_block_on_bounded(
        &cx,
        client.call_tool_result(&cx, PUBLIC_HTTP_ROOTS_TOOL_NAME, json!({})),
    )
    .expect("live bind_http final roots must return a typed tools/call result");
    let FinalCoreResult::ToolsCallInputRequired { result, .. } = roots else {
        panic!("live bind_http final roots must keep input_required: {roots:?}");
    };
    assert_live_input_required(&result, "roots", "tools/call");

    let mut no_roots_capabilities = ClientCapabilities::default();
    no_roots_capabilities.sampling = Some(Default::default());
    no_roots_capabilities.elicitation =
        serde_json::from_value(json!({"form": {}})).expect("form elicitation capability is valid");
    let mut no_roots_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-mrtr-no-roots", "1.0.0")
            .capabilities(no_roots_capabilities)
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects without advertising roots");
    let missing_roots = runtime_block_on_bounded(
        &cx,
        no_roots_client.call_tool_result(&cx, PUBLIC_HTTP_ROOTS_TOOL_NAME, json!({})),
    )
    .expect("live bind_http ctx.final_roots must return a typed tools/call result");
    let FinalCoreResult::ToolsCall { result, .. } = missing_roots else {
        panic!("missing roots capability must fail closed as a tool error: {missing_roots:?}");
    };
    assert!(
        result.payload.is_error,
        "missing roots capability must fail closed: {result:?}"
    );
    assert!(
        result.payload.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text.contains("not advertised by the client"),
            _ => false,
        }),
        "missing roots capability must name the capability gate: {result:?}"
    );

    let url_elicitation = runtime_block_on_bounded(
        &cx,
        client.call_tool_result(&cx, PUBLIC_HTTP_URL_ELICITATION_TOOL_NAME, json!({})),
    )
    .expect("live bind_http final URL elicitation must return a typed tools/call result");
    let FinalCoreResult::ToolsCallInputRequired { result, .. } = url_elicitation else {
        panic!(
            "live bind_http final URL elicitation must keep input_required: {url_elicitation:?}"
        );
    };
    assert_live_input_required(&result, "approval", "tools/call");

    let mut no_url_capabilities = ClientCapabilities::default();
    no_url_capabilities.sampling = Some(Default::default());
    no_url_capabilities.roots =
        serde_json::from_value(json!({})).expect("roots capability is valid");
    no_url_capabilities.elicitation =
        serde_json::from_value(json!({"form": {}})).expect("form elicitation capability is valid");
    let mut no_url_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-mrtr-no-url", "1.0.0")
            .capabilities(no_url_capabilities)
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects without advertising URL elicitation");
    let missing_url = runtime_block_on_bounded(
        &cx,
        no_url_client.call_tool_result(&cx, PUBLIC_HTTP_URL_ELICITATION_TOOL_NAME, json!({})),
    )
    .expect("live bind_http ctx.final_elicitation_url must return a typed tools/call result");
    let FinalCoreResult::ToolsCall { result, .. } = missing_url else {
        panic!(
            "missing URL elicitation capability must fail closed as a tool error: {missing_url:?}"
        );
    };
    assert!(
        result.payload.is_error,
        "missing URL elicitation capability must fail closed: {result:?}"
    );
    assert!(
        result.payload.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text.contains("not advertised by the client"),
            _ => false,
        }),
        "missing URL elicitation capability must name the capability gate: {result:?}"
    );

    let resource = runtime_block_on_bounded(
        &cx,
        client.read_resource_result(&cx, PUBLIC_HTTP_ELICITATION_RESOURCE_URI),
    )
    .expect("live bind_http final resource elicitation must return a typed resources/read result");
    let FinalCoreResult::ResourcesReadInputRequired { result, .. } = resource else {
        panic!("live bind_http resource elicitation must keep input_required: {resource:?}");
    };
    assert_live_input_required(&result, "approval", "resources/read");

    let prompt = runtime_block_on_bounded(
        &cx,
        client.get_prompt_result(&cx, PUBLIC_HTTP_ELICITATION_PROMPT_NAME, HashMap::new()),
    )
    .expect("live bind_http final prompt elicitation must return a typed prompts/get result");
    let FinalCoreResult::PromptsGetInputRequired { result, .. } = prompt else {
        panic!("live bind_http prompt elicitation must keep input_required: {prompt:?}");
    };
    assert_live_input_required(&result, "approval", "prompts/get");
    server.shutdown();
}

#[test]
fn e2e_public_http_typed_verbs_honor_pre_send_cancellation() {
    let cx = Cx::for_request();
    let server = spawn_modern_facade_http_server(false, None, false);
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-pre-send-cancel", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before pre-send cancellation");
    runtime_block_on_bounded(&cx, client.ping(&cx))
        .expect("live bind_http modern ping completes before local cancellation");
    let cancellation = McpRequestCancellation::new();
    cancellation.cancel();
    let ping = runtime_block_on_bounded(&cx, client.ping_with_cancellation(&cx, &cancellation))
        .expect_err("pre-send HTTP ping cancellation must reject locally");
    assert!(matches!(
        ping,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));

    let list = runtime_block_on_bounded(
        &cx,
        client.list_tools_with_cancellation(&cx, &cancellation, None),
    )
    .expect_err("pre-send HTTP list_tools cancellation must reject locally");
    assert!(matches!(
        list,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));
    let resources = runtime_block_on_bounded(
        &cx,
        client.list_resources_with_cancellation(&cx, &cancellation, None),
    )
    .expect_err("pre-send HTTP list_resources cancellation must reject locally");
    assert!(matches!(
        resources,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));
    let templates = runtime_block_on_bounded(
        &cx,
        client.list_resource_templates_with_cancellation(&cx, &cancellation, None),
    )
    .expect_err("pre-send HTTP list_resource_templates cancellation must reject locally");
    assert!(matches!(
        templates,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));
    let prompts = runtime_block_on_bounded(
        &cx,
        client.list_prompts_with_cancellation(&cx, &cancellation, None),
    )
    .expect_err("pre-send HTTP list_prompts cancellation must reject locally");
    assert!(matches!(
        prompts,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));

    let call = runtime_block_on_bounded(
        &cx,
        client.call_tool_with_cancellation(
            &cx,
            &cancellation,
            PUBLIC_HTTP_TOOL_NAME,
            json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
        ),
    )
    .expect_err("pre-send HTTP call_tool cancellation must reject locally");
    assert!(matches!(
        call,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));

    let resource = runtime_block_on_bounded(
        &cx,
        client.read_resource_with_cancellation(&cx, &cancellation, PUBLIC_HTTP_RESOURCE_URI),
    )
    .expect_err("pre-send HTTP read_resource cancellation must reject locally");
    assert!(matches!(
        resource,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));

    let prompt = runtime_block_on_bounded(
        &cx,
        client.get_prompt_with_cancellation(
            &cx,
            &cancellation,
            PUBLIC_HTTP_PROMPT_NAME,
            HashMap::from([("subject".to_owned(), PUBLIC_HTTP_TOOL_ARGUMENT.to_owned())]),
        ),
    )
    .expect_err("pre-send HTTP get_prompt cancellation must reject locally");
    assert!(matches!(
        prompt,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));
    let completion = runtime_block_on_bounded(
        &cx,
        client.complete_with_cancellation(
            &cx,
            &cancellation,
            modern::CompletionParams {
                reference: modern::CompletionReference::PromptWithTitle {
                    name: PUBLIC_HTTP_PROMPT_NAME.to_owned(),
                    title: "Public HTTP E2E Prompt".to_owned(),
                },
                argument: modern::FinalCompletionArgument {
                    name: "subject".to_owned(),
                    value: "cross-era".to_owned(),
                },
                context: None,
            },
        ),
    )
    .expect_err("pre-send HTTP complete cancellation must reject locally");
    assert!(matches!(
        completion,
        modern::HttpClientError::CoreResult(error)
            if error.code == McpErrorCode::RequestCancelled
    ));

    runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("the same HTTP session remains usable after local cancellation");
    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_set_log_level_stamps_request_metadata() {
    let cx = Cx::for_request();
    let server = spawn_modern_facade_http_server(false, None, false);
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-log-level", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before logLevel configuration");
    runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("JSON tools/list succeeds before request logLevel is configured");
    assert_eq!(client.log_level(), None);

    client
        .set_log_level(modern::LoggingLevel::Info)
        .expect("modern HTTP set_log_level stores request metadata locally");
    assert_eq!(client.log_level(), Some(modern::LoggingLevel::Info));
    runtime_block_on_bounded(&cx, client.list_tools(&cx, None)).expect(
        "info logLevel is request metadata; the public JSON+SSE Accept still completes tools/list",
    );

    client
        .set_log_level(modern::LoggingLevel::Emergency)
        .expect("emergency logLevel still stores request metadata locally");
    runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("changing only the logLevel rank cannot break the same public tools/list verb");
    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_set_log_level_retains_request_scoped_message_notifications() {
    let cx = Cx::for_request();
    let server = spawn_modern_facade_http_server(false, None, false);
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-log-notify", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before log notification retention");

    assert!(
        client.take_server_notifications().is_empty(),
        "no request has produced a request-scoped log yet"
    );

    client
        .set_log_level(modern::LoggingLevel::Info)
        .expect("info logLevel is stored as request metadata");
    runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("info logLevel forces the request-owned SSE body that can carry logs");
    let info_notifications = client.take_server_notifications();
    assert!(
        info_notifications.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.level == modern::LoggingLevel::Info
        )),
        "live bind_http must retain notifications/message after set_log_level(Info): {info_notifications:?}"
    );
    assert!(
        client.take_server_notifications().is_empty(),
        "take_server_notifications must drain the retained queue"
    );

    client
        .set_log_level(modern::LoggingLevel::Emergency)
        .expect("emergency logLevel still stores request metadata locally");
    runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("raising the floor cannot break the same public tools/list verb");
    let emergency_notifications = client.take_server_notifications();
    assert!(
        !emergency_notifications.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.level == modern::LoggingLevel::Info
        )),
        "raising only the logLevel floor must suppress the info notification: {emergency_notifications:?}"
    );
    drop(client);
    server.shutdown();
}

/// Live modern HTTP tool that emits `ctx.info` so request-scoped logs are observable.
struct PublicHttpLogTool;

impl ToolHandler for PublicHttpLogTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_LOG_TOOL_NAME.to_owned(),
            description: Some("Proves live facade HTTP handler log notifications".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        ctx.info(PUBLIC_HTTP_HANDLER_LOG_TEXT);
        Ok(vec![Content::text("logged")])
    }
}

const PUBLIC_HTTP_LOG_RESOURCE_URI: &str = "test://public-http-e2e/log";
const PUBLIC_HTTP_RESOURCE_LOG_TEXT: &str = "public-http-resource-info";

/// Live modern HTTP resource that emits `ctx.info` on read.
struct PublicHttpLogResource;

impl ResourceHandler for PublicHttpLogResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: PUBLIC_HTTP_LOG_RESOURCE_URI.to_owned(),
            name: "public-http-e2e-log".to_owned(),
            description: Some("Proves live facade HTTP resource log notifications".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        ctx.info(PUBLIC_HTTP_RESOURCE_LOG_TEXT);
        Ok(vec![ResourceContent {
            uri: PUBLIC_HTTP_LOG_RESOURCE_URI.to_owned(),
            mime_type: None,
            text: Some("logged".to_owned()),
            blob: None,
        }])
    }
}

const PUBLIC_HTTP_LOG_PROMPT_NAME: &str = "public-http-e2e-log-prompt";
const PUBLIC_HTTP_PROMPT_LOG_TEXT: &str = "public-http-prompt-info";

/// Live modern HTTP prompt that emits `ctx.info` on get.
struct PublicHttpLogPrompt;

impl PromptHandler for PublicHttpLogPrompt {
    fn definition(&self) -> Prompt {
        Prompt {
            name: PUBLIC_HTTP_LOG_PROMPT_NAME.to_owned(),
            description: Some("Proves live facade HTTP prompt log notifications".to_owned()),
            arguments: Vec::new(),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn get(
        &self,
        ctx: &McpContext,
        _arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        ctx.info(PUBLIC_HTTP_PROMPT_LOG_TEXT);
        Ok(vec![PromptMessage {
            role: Role::User,
            content: Content::text("logged"),
        }])
    }
}

fn spawn_modern_log_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("log HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-log", "1.0.0")
                .tool(PublicHttpLogTool)
                .resource(PublicHttpLogResource)
                .prompt(PublicHttpLogPrompt)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("log facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("log facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("log HTTP server startup receiver went away".to_owned());
            }
            bound
                .serve(&cx)
                .await
                .map_err(|error| format!("log facade HTTP server stopped unexpectedly: {error}"))
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("log facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("log facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("log facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_ctx_info_is_retained_after_set_log_level() {
    let cx = Cx::for_request();
    let server = spawn_modern_log_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-ctx-info", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before handler log emission");

    client
        .set_log_level(modern::LoggingLevel::Info)
        .expect("info logLevel is stored as request metadata");
    runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_LOG_TOOL_NAME, json!({})),
    )
    .expect("ctx.info must not prevent the same tools/call from completing");
    let info_notifications = client.take_server_notifications();
    assert!(
        info_notifications.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.level == modern::LoggingLevel::Info
                    && message.data == json!(PUBLIC_HTTP_HANDLER_LOG_TEXT)
        )),
        "live bind_http must retain ctx.info after set_log_level(Info): {info_notifications:?}"
    );

    runtime_block_on_bounded(&cx, client.read_resource(&cx, PUBLIC_HTTP_LOG_RESOURCE_URI))
        .expect("ctx.info must not prevent the same resources/read from completing");
    let resource_notifications = client.take_server_notifications();
    assert!(
        resource_notifications.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.level == modern::LoggingLevel::Info
                    && message.data == json!(PUBLIC_HTTP_RESOURCE_LOG_TEXT)
        )),
        "live bind_http must retain resource ctx.info after set_log_level(Info): {resource_notifications:?}"
    );

    runtime_block_on_bounded(
        &cx,
        client.get_prompt(&cx, PUBLIC_HTTP_LOG_PROMPT_NAME, HashMap::new()),
    )
    .expect("ctx.info must not prevent the same prompts/get from completing");
    let prompt_notifications = client.take_server_notifications();
    assert!(
        prompt_notifications.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.level == modern::LoggingLevel::Info
                    && message.data == json!(PUBLIC_HTTP_PROMPT_LOG_TEXT)
        )),
        "live bind_http must retain prompt ctx.info after set_log_level(Info): {prompt_notifications:?}"
    );

    client
        .set_log_level(modern::LoggingLevel::Emergency)
        .expect("emergency logLevel still stores request metadata locally");
    runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_LOG_TOOL_NAME, json!({})),
    )
    .expect("raising only the logLevel floor cannot break the same public tools/call");
    let emergency_notifications = client.take_server_notifications();
    assert!(
        !emergency_notifications.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.data == json!(PUBLIC_HTTP_HANDLER_LOG_TEXT)
        )),
        "raising only the logLevel floor must suppress ctx.info: {emergency_notifications:?}"
    );
    runtime_block_on_bounded(&cx, client.read_resource(&cx, PUBLIC_HTTP_LOG_RESOURCE_URI))
        .expect("raising only the logLevel floor cannot break resources/read");
    runtime_block_on_bounded(
        &cx,
        client.get_prompt(&cx, PUBLIC_HTTP_LOG_PROMPT_NAME, HashMap::new()),
    )
    .expect("raising only the logLevel floor cannot break prompts/get");
    let emergency_follow = client.take_server_notifications();
    assert!(
        !emergency_follow.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.data == json!(PUBLIC_HTTP_RESOURCE_LOG_TEXT)
                    || message.data == json!(PUBLIC_HTTP_PROMPT_LOG_TEXT)
        )),
        "raising only the logLevel floor must suppress resource and prompt ctx.info: {emergency_follow:?}"
    );
    drop(client);
    server.shutdown();
}

const PUBLIC_HTTP_PROGRESS_TOOL_NAME: &str = "public-http-e2e-progress";

/// Live modern HTTP tool that reports progress when the request carries a token.
struct PublicHttpProgressTool;

impl ToolHandler for PublicHttpProgressTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_PROGRESS_TOOL_NAME.to_owned(),
            description: Some("Proves live facade HTTP progress notifications".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        ctx.report_progress(0.5, Some("halfway"));
        Ok(vec![Content::text("progressed")])
    }
}

const PUBLIC_HTTP_PROGRESS_RESOURCE_URI: &str = "test://public-http-e2e/progress";
const PUBLIC_HTTP_PROGRESS_PROMPT_NAME: &str = "public-http-e2e-progress-prompt";

/// Live modern HTTP resource that reports progress when the request carries a token.
struct PublicHttpProgressResource;

impl ResourceHandler for PublicHttpProgressResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: PUBLIC_HTTP_PROGRESS_RESOURCE_URI.to_owned(),
            name: "public-http-e2e-progress".to_owned(),
            description: Some("Proves live facade HTTP resource progress notifications".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        ctx.report_progress(0.5, Some("resource-halfway"));
        Ok(vec![ResourceContent {
            uri: PUBLIC_HTTP_PROGRESS_RESOURCE_URI.to_owned(),
            mime_type: None,
            text: Some("progressed".to_owned()),
            blob: None,
        }])
    }
}

/// Live modern HTTP prompt that reports progress when the request carries a token.
struct PublicHttpProgressPrompt;

impl PromptHandler for PublicHttpProgressPrompt {
    fn definition(&self) -> Prompt {
        Prompt {
            name: PUBLIC_HTTP_PROGRESS_PROMPT_NAME.to_owned(),
            description: Some("Proves live facade HTTP prompt progress notifications".to_owned()),
            arguments: Vec::new(),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn get(
        &self,
        ctx: &McpContext,
        _arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        ctx.report_progress(0.5, Some("prompt-halfway"));
        Ok(vec![PromptMessage {
            role: Role::User,
            content: Content::text("progressed"),
        }])
    }
}

fn spawn_modern_progress_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("progress HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-progress", "1.0.0")
                .tool(PublicHttpProgressTool)
                .resource(PublicHttpProgressResource)
                .prompt(PublicHttpProgressPrompt)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("progress facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("progress facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("progress HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("progress facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("progress facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("progress facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("progress facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_progress_marker_is_retained_from_request_sse() {
    let cx = Cx::for_request();
    let server = spawn_modern_progress_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-progress", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before progress emission");

    runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_PROGRESS_TOOL_NAME, json!({})),
    )
    .expect("a tools/call without a progress token still completes");
    assert!(
        client.take_progress_notifications().is_empty(),
        "without a progressToken the handler must not emit request-scoped progress"
    );

    let marker = modern::ProgressMarker::from("http-progress");
    runtime_block_on_bounded(
        &cx,
        client.call_tool_with_progress_marker(
            &cx,
            PUBLIC_HTTP_PROGRESS_TOOL_NAME,
            json!({}),
            marker.clone(),
        ),
    )
    .expect("a progressToken must not prevent the same tools/call from completing");
    let progress = client.take_progress_notifications();
    assert!(
        progress.iter().any(|notification| {
            notification.progress_token == marker
                && notification.message.as_deref() == Some("halfway")
        }),
        "live bind_http must retain notifications/progress after a progressToken: {progress:?}"
    );
    assert!(
        client.take_progress_notifications().is_empty(),
        "take_progress_notifications must drain the retained queue"
    );

    runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_PROGRESS_RESOURCE_URI),
    )
    .expect("a resources/read without a progress token still completes");
    assert!(
        client.take_progress_notifications().is_empty(),
        "without a progressToken the resource handler must not emit request-scoped progress"
    );

    let resource_marker = modern::ProgressMarker::from("http-resource-progress");
    runtime_block_on_bounded(
        &cx,
        client.read_resource_with_progress_marker(
            &cx,
            PUBLIC_HTTP_PROGRESS_RESOURCE_URI,
            resource_marker.clone(),
        ),
    )
    .expect("a progressToken must not prevent the same resources/read from completing");
    let resource_progress = client.take_progress_notifications();
    assert!(
        resource_progress.iter().any(|notification| {
            notification.progress_token == resource_marker
                && notification.message.as_deref() == Some("resource-halfway")
        }),
        "live bind_http must retain resource notifications/progress after a progressToken: {resource_progress:?}"
    );

    runtime_block_on_bounded(
        &cx,
        client.get_prompt(&cx, PUBLIC_HTTP_PROGRESS_PROMPT_NAME, HashMap::new()),
    )
    .expect("a prompts/get without a progress token still completes");
    assert!(
        client.take_progress_notifications().is_empty(),
        "without a progressToken the prompt handler must not emit request-scoped progress"
    );

    let prompt_marker = modern::ProgressMarker::from("http-prompt-progress");
    runtime_block_on_bounded(
        &cx,
        client.get_prompt_with_progress_marker(
            &cx,
            PUBLIC_HTTP_PROGRESS_PROMPT_NAME,
            HashMap::new(),
            prompt_marker.clone(),
        ),
    )
    .expect("a progressToken must not prevent the same prompts/get from completing");
    let prompt_progress = client.take_progress_notifications();
    assert!(
        prompt_progress.iter().any(|notification| {
            notification.progress_token == prompt_marker
                && notification.message.as_deref() == Some("prompt-halfway")
        }),
        "live bind_http must retain prompt notifications/progress after a progressToken: {prompt_progress:?}"
    );
    assert!(
        client.take_progress_notifications().is_empty(),
        "take_progress_notifications must drain the retained resource and prompt queues"
    );
    drop(client);
    server.shutdown();
}

const PUBLIC_HTTP_TEMPLATE: &str = "test://public-http-e2e/item/{id}";
const PUBLIC_HTTP_TEMPLATE_NAME: &str = "public-http-e2e-item";
const PUBLIC_HTTP_TEMPLATE_MATCHED_URI: &str = "test://public-http-e2e/item/alpha";
const PUBLIC_HTTP_TEMPLATE_UNMATCHED_URI: &str = "test://public-http-e2e/other/alpha";

/// Live modern HTTP resource whose RFC 6570 template expands on `resources/read`.
struct PublicHttpTemplatedResource {
    reads: Arc<AtomicUsize>,
}

impl ResourceHandler for PublicHttpTemplatedResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: PUBLIC_HTTP_TEMPLATE.to_owned(),
            name: PUBLIC_HTTP_TEMPLATE_NAME.to_owned(),
            description: Some("Proves live facade HTTP RFC 6570 resource templates".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn template(&self) -> Option<ResourceTemplate> {
        Some(ResourceTemplate {
            uri_template: PUBLIC_HTTP_TEMPLATE.to_owned(),
            name: PUBLIC_HTTP_TEMPLATE_NAME.to_owned(),
            description: Some("Proves live facade HTTP RFC 6570 resource templates".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        })
    }

    fn final_template_definition(&self) -> Option<FinalResourceTemplate> {
        Some(FinalResourceTemplate {
            uri_template: PUBLIC_HTTP_TEMPLATE.to_owned(),
            name: PUBLIC_HTTP_TEMPLATE_NAME.to_owned(),
            title: Some("Public HTTP E2E Item".to_owned()),
            description: Some("Proves live facade HTTP RFC 6570 resource templates".to_owned()),
            icons: None,
            mime_type: Some("text/plain".to_owned()),
            annotations: None,
            meta: None,
        })
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Err(McpError::invalid_request(
            "templated resource requires a matched URI",
        ))
    }

    fn read_with_uri(
        &self,
        _ctx: &McpContext,
        uri: &str,
        params: &HashMap<String, String>,
    ) -> McpResult<Vec<ResourceContent>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let id = params
            .get("id")
            .ok_or_else(|| McpError::invalid_params("templated resource is missing id"))?;
        Ok(vec![ResourceContent {
            uri: uri.to_owned(),
            mime_type: Some("text/plain".to_owned()),
            text: Some(format!("item:{id}")),
            blob: None,
        }])
    }
}

struct PublicHttpLossyTemplatedResource;

impl ResourceHandler for PublicHttpLossyTemplatedResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: "test://public-http-e2e/item/{id:3}".to_owned(),
            name: "lossy-prefix".to_owned(),
            description: Some("Must fail closed instead of guessing a reverse match".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn template(&self) -> Option<ResourceTemplate> {
        Some(ResourceTemplate {
            uri_template: "test://public-http-e2e/item/{id:3}".to_owned(),
            name: "lossy-prefix".to_owned(),
            description: Some("Must fail closed instead of guessing a reverse match".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        })
    }

    fn final_template_definition(&self) -> Option<FinalResourceTemplate> {
        Some(FinalResourceTemplate {
            uri_template: "test://public-http-e2e/item/{id:3}".to_owned(),
            name: "lossy-prefix".to_owned(),
            title: None,
            description: Some("Must fail closed instead of guessing a reverse match".to_owned()),
            icons: None,
            mime_type: Some("text/plain".to_owned()),
            annotations: None,
            meta: None,
        })
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Err(McpError::internal_error(
            "a lossy prefix template must not become a readable handler",
        ))
    }
}

fn spawn_modern_template_http_server() -> (HttpServerFixture, Arc<AtomicUsize>) {
    let reads = Arc::new(AtomicUsize::new(0));
    let handler_reads = Arc::clone(&reads);
    (
        spawn_modern_resource_http_server(
            "facade-http-template",
            PublicHttpTemplatedResource {
                reads: handler_reads,
            },
        ),
        reads,
    )
}

fn spawn_modern_lossy_template_http_server() -> HttpServerFixture {
    spawn_modern_resource_http_server("lossy-template", PublicHttpLossyTemplatedResource)
}

fn spawn_modern_resource_http_server<H: ResourceHandler + 'static>(
    name: &'static str,
    handler: H,
) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("template HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new(name, "1.0.0")
                .resource(handler)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("template facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("template facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("template HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("template facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("template facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("template facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("template facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_resource_template_lists_and_reads_matched_uri() {
    let cx = Cx::for_request();
    let lossy_server = spawn_modern_lossy_template_http_server();
    let mut lossy_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-lossy-template", "1.0.0")
            .connect_http_with_cx(public_http_target(lossy_server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade still connects when a lossy template is refused");
    let lossy_listed =
        runtime_block_on_bounded(&cx, lossy_client.list_resource_templates(&cx, None))
            .expect("refusing a lossy template must still serve resources/templates/list");
    assert!(
        lossy_listed.resource_templates.is_empty(),
        "a lossy prefix modifier must not be advertised as a reverse-matchable template: {:?}",
        lossy_listed.resource_templates
    );
    let lossy_read = runtime_block_on_bounded(
        &cx,
        lossy_client.read_resource(&cx, "test://public-http-e2e/item/alp"),
    )
    .expect_err("a dropped lossy template must not guess a three-character prefix match");
    assert!(
        matches!(
            lossy_read,
            modern::HttpClientError::CoreResult(ref error)
                if error.code == McpErrorCode::InvalidParams
        ),
        "the unregistered lossy template must stay InvalidParams: {lossy_read:?}"
    );
    drop(lossy_client);
    lossy_server.shutdown();

    let (server, reads) = spawn_modern_template_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-template", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before template expansion");

    let listed = runtime_block_on_bounded(&cx, client.list_resource_templates(&cx, None))
        .expect("live bind_http must list the registered RFC 6570 template");
    assert!(
        listed
            .resource_templates
            .iter()
            .any(|template| template.uri_template == PUBLIC_HTTP_TEMPLATE
                && template.name == PUBLIC_HTTP_TEMPLATE_NAME),
        "resources/templates/list must retain the reversible template: {:?}",
        listed.resource_templates
    );

    let matched = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_TEMPLATE_MATCHED_URI),
    )
    .expect("resources/read must expand a URI that matches the registered template");
    assert!(
        matches!(
            matched.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == "item:alpha"
        ),
        "the matched template read must retain the extracted id: {:?}",
        matched.contents
    );
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "a matching resources/read must invoke the templated handler once"
    );

    let unmatched = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_TEMPLATE_UNMATCHED_URI),
    )
    .expect_err("changing only the path that the template cannot bind must refuse before dispatch");
    assert!(
        matches!(
            unmatched,
            modern::HttpClientError::CoreResult(ref error)
                if error.code == McpErrorCode::InvalidParams
        ),
        "an unmatched template URI must stay InvalidParams: {unmatched:?}"
    );
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "the unmatched URI must leave the templated handler uninvoked"
    );

    drop(client);
    server.shutdown();
}

const PUBLIC_HTTP_WATCH_RESOURCE_URI: &str = "test://public-http-e2e/watched";
const PUBLIC_HTTP_TOUCH_TOOL_NAME: &str = "public-http-e2e-touch";

/// Live modern HTTP resource whose update events are published to listeners.
struct PublicHttpWatchResource;

impl ResourceHandler for PublicHttpWatchResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: PUBLIC_HTTP_WATCH_RESOURCE_URI.to_owned(),
            name: "public-http-e2e-watched".to_owned(),
            description: Some("Proves live facade HTTP resources/updated listen".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Ok(vec![ResourceContent {
            uri: PUBLIC_HTTP_WATCH_RESOURCE_URI.to_owned(),
            mime_type: None,
            text: Some("watched".to_owned()),
            blob: None,
        }])
    }
}

/// Live modern HTTP tool that publishes `notifications/resources/updated`.
struct PublicHttpTouchTool;

impl ToolHandler for PublicHttpTouchTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_TOUCH_TOOL_NAME.to_owned(),
            description: Some("Proves live facade HTTP resource-update publication".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let delivered = ctx.notify_resource_updated(PUBLIC_HTTP_WATCH_RESOURCE_URI);
        Ok(vec![Content::text(if delivered {
            "notified"
        } else {
            "silent"
        })])
    }
}

const PUBLIC_HTTP_HIDE_TOOL_NAME: &str = "public-http-e2e-hide";

/// Live modern HTTP tool that disables a peer tool and publishes `tools/list_changed`.
struct PublicHttpHideTool;

impl ToolHandler for PublicHttpHideTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_HIDE_TOOL_NAME.to_owned(),
            description: Some("Proves live facade HTTP tools/list_changed publication".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let delivered = ctx.disable_tool(PUBLIC_HTTP_TOUCH_TOOL_NAME);
        Ok(vec![Content::text(if delivered {
            "hidden"
        } else {
            "silent"
        })])
    }
}

const PUBLIC_HTTP_TOGGLE_TOOL_NAME: &str = "public-http-e2e-toggle";
const PUBLIC_HTTP_CATALOG_PROMPT_NAME: &str = "public-http-e2e-catalog-prompt";
const PUBLIC_HTTP_HIDE_CATALOG_TOOL_NAME: &str = "public-http-e2e-hide-catalog";

/// Live modern HTTP tool that disables then re-enables a peer in one request.
struct PublicHttpToggleTool;

impl ToolHandler for PublicHttpToggleTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_TOGGLE_TOOL_NAME.to_owned(),
            description: Some(
                "Proves live facade HTTP enable_tool list_changed publication".to_owned(),
            ),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let hidden = ctx.disable_tool(PUBLIC_HTTP_TOUCH_TOOL_NAME);
        let shown = ctx.enable_tool(PUBLIC_HTTP_TOUCH_TOOL_NAME);
        Ok(vec![Content::text(if hidden && shown {
            "toggled"
        } else {
            "stuck"
        })])
    }
}

/// Live modern HTTP prompt used as a catalog-mutation subject.
struct PublicHttpCatalogPrompt;

impl PromptHandler for PublicHttpCatalogPrompt {
    fn definition(&self) -> Prompt {
        Prompt {
            name: PUBLIC_HTTP_CATALOG_PROMPT_NAME.to_owned(),
            description: Some(
                "Proves live facade HTTP prompts/list_changed publication".to_owned(),
            ),
            arguments: Vec::new(),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn get(
        &self,
        _ctx: &McpContext,
        _arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        Ok(vec![PromptMessage {
            role: Role::User,
            content: Content::text("catalog"),
        }])
    }
}

/// Live modern HTTP tool that disables a resource and a prompt.
struct PublicHttpHideCatalogTool;

impl ToolHandler for PublicHttpHideCatalogTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_HIDE_CATALOG_TOOL_NAME.to_owned(),
            description: Some(
                "Proves live facade HTTP resource and prompt list_changed publication".to_owned(),
            ),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let resource = ctx.disable_resource(PUBLIC_HTTP_WATCH_RESOURCE_URI);
        let prompt = ctx.disable_prompt(PUBLIC_HTTP_CATALOG_PROMPT_NAME);
        Ok(vec![Content::text(if resource && prompt {
            "hidden"
        } else {
            "silent"
        })])
    }
}

fn spawn_modern_subscription_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("subscription HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-subscription", "1.0.0")
                .resource(PublicHttpWatchResource)
                .prompt(PublicHttpCatalogPrompt)
                .tool(PublicHttpTouchTool)
                .tool(PublicHttpHideTool)
                .tool(PublicHttpToggleTool)
                .tool(PublicHttpHideCatalogTool)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("subscription facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("subscription facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("subscription HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("subscription facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("subscription facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("subscription facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("subscription facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_resource_updated_is_retained_on_incremental_listen() {
    let cx = Cx::for_request();
    let server = spawn_modern_subscription_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-listen", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before subscriptions/listen");

    let limits = modern::SseLimits::new(64 * 1024, 2 * 1024 * 1024, 256)
        .expect("subscription SSE limits must be nonzero");
    let filter = modern::SubscriptionFilter {
        resource_subscriptions: Some(vec![PUBLIC_HTTP_WATCH_RESOURCE_URI.to_owned()]),
        ..modern::SubscriptionFilter::default()
    };
    runtime_block_on_bounded(
        &cx,
        client.start_subscriptions_listener(&cx, filter, limits),
    )
    .expect("live bind_http must admit an incremental subscriptions/listen");

    let acknowledgement = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("subscriptions/listen must emit its acknowledgement");
    assert!(
        matches!(
            acknowledgement,
            Some(modern::ModernHttpSubscriptionListenEvent::Acknowledged { .. })
        ),
        "the first incremental listen record must be the accepted filter: {acknowledgement:?}"
    );

    let touched = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_TOUCH_TOOL_NAME, json!({})),
    )
    .expect("touching the watched resource must complete");
    assert!(
        touched.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "notified",
            _ => false,
        }),
        "a matching incremental listener must count as notify_resource_updated delivery: {touched:?}"
    );

    let updated = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("subscriptions/listen must retain resources/updated after the handler publish");
    assert!(
        matches!(
            updated,
            Some(modern::ModernHttpSubscriptionListenEvent::Notification(
                modern::ServerNotification::ResourceUpdated(ref params)
            )) if params.uri.as_str() == PUBLIC_HTTP_WATCH_RESOURCE_URI
        ),
        "live bind_http must retain notifications/resources/updated on the incremental listener: {updated:?}"
    );
    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_tools_list_changed_is_retained_on_incremental_listen() {
    let cx = Cx::for_request();
    let server = spawn_modern_subscription_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-list-changed", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before subscriptions/listen");

    let limits = modern::SseLimits::new(64 * 1024, 2 * 1024 * 1024, 256)
        .expect("subscription SSE limits must be nonzero");
    let filter = modern::SubscriptionFilter {
        tools_list_changed: Some(true),
        ..modern::SubscriptionFilter::default()
    };
    runtime_block_on_bounded(
        &cx,
        client.start_subscriptions_listener(&cx, filter, limits),
    )
    .expect("live bind_http must admit an incremental subscriptions/listen");

    let acknowledgement = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("subscriptions/listen must emit its acknowledgement");
    assert!(
        matches!(
            acknowledgement,
            Some(modern::ModernHttpSubscriptionListenEvent::Acknowledged { .. })
        ),
        "the first incremental listen record must be the accepted filter: {acknowledgement:?}"
    );

    let hidden = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_HIDE_TOOL_NAME, json!({})),
    )
    .expect("disabling a peer tool must complete");
    assert!(
        hidden.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "hidden",
            _ => false,
        }),
        "request-local SessionState must let disable_tool publish list_changed: {hidden:?}"
    );

    let changed = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("subscriptions/listen must retain tools/list_changed after the handler mutation");
    assert!(
        matches!(
            changed,
            Some(modern::ModernHttpSubscriptionListenEvent::Notification(
                modern::ServerNotification::ToolsListChanged(_)
            ))
        ),
        "live bind_http must retain notifications/tools/list_changed on the incremental listener: {changed:?}"
    );

    let toggled = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_TOGGLE_TOOL_NAME, json!({})),
    )
    .expect("disable then enable in one request must complete");
    assert!(
        toggled.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "toggled",
            _ => false,
        }),
        "request-local SessionState must let enable_tool reverse the same-request disable: {toggled:?}"
    );
    let first_toggle = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("disable inside the toggle must publish tools/list_changed");
    let second_toggle = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("enable_tool must publish a second tools/list_changed");
    assert!(
        matches!(
            first_toggle,
            Some(modern::ModernHttpSubscriptionListenEvent::Notification(
                modern::ServerNotification::ToolsListChanged(_)
            ))
        ),
        "the toggle disable must publish tools/list_changed: {first_toggle:?}"
    );
    assert!(
        matches!(
            second_toggle,
            Some(modern::ModernHttpSubscriptionListenEvent::Notification(
                modern::ServerNotification::ToolsListChanged(_)
            ))
        ),
        "live bind_http must retain enable_tool notifications/tools/list_changed: {second_toggle:?}"
    );

    runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("a later POST on the same HTTP client must still list tools");
    drop(client);

    let mut other_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-list-changed-other", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("a second ModernOnly facade client connects after the first disable");
    let other_tools = runtime_block_on_bounded(&cx, other_client.list_tools(&cx, None))
        .expect("a later POST from another HTTP client must still list tools");
    assert!(
        other_tools
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_TOUCH_TOOL_NAME),
        "disable_tool must not invent a process-wide HTTP session: {other_tools:?}"
    );
    drop(other_client);
    server.shutdown();
}

#[cfg(feature = "proxy")]
#[test]
fn e2e_public_http_proxy_client_catalog_listen_retains_list_changed() {
    let server = spawn_modern_subscription_http_server();
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(
            asupersync::runtime::reactor::create_reactor()
                .expect("proxy catalog listen client reactor initializes"),
        )
        .build()
        .expect("proxy catalog listen client installs an owned runtime");
    let outcome = runtime.block_on(async {
        let cx = Cx::current().expect("owned proxy client runtime installs an ambient context");
        let plan = ClientProtocolPlan::http(
            ProtocolPolicy::ModernOnly,
            Some(public_http_target(server.address(), "/mcp")),
            None,
            None,
            "e2e-http-proxy-listen".to_owned(),
            "e2e-http-proxy-listen".to_owned(),
            "modern-http".to_owned(),
            0,
            0,
            0,
        )
        .map_err(|error| format!("proxy catalog listen HTTP plan failed: {error}"))?;
        let mut registry = ProxyClient::upstream_binding_registry();
        let proxy = registry
            .connect_http_with_protocol_plan(
                "e2e-listen-upstream",
                "native-h1:e2e-listen-upstream",
                1,
                plan,
                ClientInfo {
                    name: "e2e-http-proxy-listen".to_owned(),
                    version: "1.0.0".to_owned(),
                },
                ClientCapabilities::default(),
                cx.clone(),
            )
            .map_err(|error| format!("live HTTP ProxyClient connect failed: {error}"))?;
        let started = proxy
            .start_catalog_listener(modern::SubscriptionFilter {
                tools_list_changed: Some(true),
                ..modern::SubscriptionFilter::default()
            })
            .map_err(|error| format!("ProxyClient catalog listen start failed: {error}"))?;
        if !started {
            return Err(
                "a live ModernHttp ProxyClient must own the incremental catalog listener"
                    .to_owned(),
            );
        }
        let acknowledgement = proxy
            .next_catalog_listener_event(&cx, &McpRequestCancellation::new())
            .map_err(|error| format!("ProxyClient catalog listen ack failed: {error}"))?;
        if !matches!(
            acknowledgement,
            StdioSubscriptionEvent::Acknowledged(ref filter)
                if filter.tools_list_changed == Some(true)
        ) {
            return Err(format!(
                "the first ProxyClient listen record must be the accepted filter: {acknowledgement:?}"
            ));
        }

        let touched = proxy
            .call_tool_typed(
                &McpContext::new(cx.clone(), 1),
                PUBLIC_HTTP_TOUCH_TOOL_NAME,
                json!({}),
            )
            .map_err(|error| format!("ProxyClient touch tool failed: {error}"))?;
        let CoreResult::Final(FinalCoreResult::ToolsCall { result: touched, .. }) = touched else {
            return Err(format!(
                "the live HTTP ProxyClient must keep a final tools/call result: {touched:?}"
            ));
        };
        if !touched.payload.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "notified" || text == "silent",
            _ => false,
        }) {
            return Err(format!(
                "the live HTTP ProxyClient must forward the non-mutating touch tool: {touched:?}"
            ));
        }

        let hidden = proxy
            .call_tool_typed(
                &McpContext::new(cx.clone(), 2),
                PUBLIC_HTTP_HIDE_TOOL_NAME,
                json!({}),
            )
            .map_err(|error| format!("ProxyClient hide tool failed: {error}"))?;
        let CoreResult::Final(FinalCoreResult::ToolsCall { result: hidden, .. }) = hidden else {
            return Err(format!(
                "the live HTTP ProxyClient must keep a final hide tools/call result: {hidden:?}"
            ));
        };
        if !hidden.payload.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "hidden",
            _ => false,
        }) {
            return Err(format!(
                "the live HTTP ProxyClient must forward disable_tool: {hidden:?}"
            ));
        }

        let changed = proxy
            .next_catalog_listener_event(&cx, &McpRequestCancellation::new())
            .map_err(|error| {
                format!("ProxyClient catalog listen must retain tools/list_changed: {error}")
            })?;
        if !matches!(
            changed,
            StdioSubscriptionEvent::Notification(modern::ServerNotification::ToolsListChanged(_))
        ) {
            return Err(format!(
                "live ProxyClient must retain notifications/tools/list_changed: {changed:?}"
            ));
        }
        Ok(())
    });
    server.shutdown();
    outcome.expect("the live HTTP ProxyClient catalog listener must retain tools/list_changed");
}

const PUBLIC_HTTP_LEAK_RESOURCE_URI: &str = "test://public-http-e2e/leak";
const PUBLIC_HTTP_LEAK_SECRET: &str = "secret-db-dsn";

/// Live modern HTTP resource whose execution error carries an internal secret.
struct PublicHttpLeakResource;

impl ResourceHandler for PublicHttpLeakResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: PUBLIC_HTTP_LEAK_RESOURCE_URI.to_owned(),
            name: "public-http-e2e-leak".to_owned(),
            description: Some("Proves live facade HTTP mask_error_details".to_owned()),
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Err(McpError::tool_error(PUBLIC_HTTP_LEAK_SECRET))
    }
}

fn spawn_modern_mask_http_server(mask_error_details: bool) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("mask HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-mask", "1.0.0")
                .mask_error_details(mask_error_details)
                .resource(PublicHttpLeakResource)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("mask facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("mask facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("mask HTTP server startup receiver went away".to_owned());
            }
            bound
                .serve(&cx)
                .await
                .map_err(|error| format!("mask facade HTTP server stopped unexpectedly: {error}"))
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("mask facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("mask facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("mask facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_mask_error_details_hides_resource_execution_secret() {
    let cx = Cx::for_request();
    let masked_server = spawn_modern_mask_http_server(true);
    let mut masked_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-mask", "1.0.0")
            .connect_http_with_cx(public_http_target(masked_server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the masked HTTP server");
    let masked = runtime_block_on_bounded(
        &cx,
        masked_client.read_resource(&cx, PUBLIC_HTTP_LEAK_RESOURCE_URI),
    )
    .expect_err("a leaking resource must stay a resources/read error");
    let masked = format!("{masked:?}");
    assert!(
        masked.contains("Internal server error"),
        "mask_error_details must replace the execution secret: {masked}"
    );
    assert!(
        !masked.contains(PUBLIC_HTTP_LEAK_SECRET),
        "mask_error_details must not leak the execution secret: {masked}"
    );
    drop(masked_client);
    masked_server.shutdown();

    let unmasked_server = spawn_modern_mask_http_server(false);
    let mut unmasked_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-unmask", "1.0.0")
            .connect_http_with_cx(public_http_target(unmasked_server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the unmasked HTTP server");
    let unmasked = runtime_block_on_bounded(
        &cx,
        unmasked_client.read_resource(&cx, PUBLIC_HTTP_LEAK_RESOURCE_URI),
    )
    .expect_err("changing only mask_error_details must still refuse the leaking resource");
    let unmasked = format!("{unmasked:?}");
    assert!(
        unmasked.contains(PUBLIC_HTTP_LEAK_SECRET),
        "disabling mask_error_details must keep the execution secret: {unmasked}"
    );
    drop(unmasked_client);
    unmasked_server.shutdown();
}

fn spawn_modern_rate_limit_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("rate-limit HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-rate-limit", "1.0.0")
                .middleware(rate_limiting::RateLimitingMiddleware::new(1.0e-300).burst_capacity(1))
                .tool(PublicHttpTouchTool)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("rate-limit facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("rate-limit facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("rate-limit HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("rate-limit facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("rate-limit facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("rate-limit facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("rate-limit facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_rate_limit_refuses_second_same_method_and_admits_another() {
    let cx = Cx::for_request();
    let server = spawn_modern_rate_limit_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-rate-limit", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the rate-limited HTTP server");

    let first = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_TOUCH_TOOL_NAME, json!({})),
    )
    .expect("the first tools/call must be admitted by the live rate limiter");
    assert!(
        first.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "notified" || text == "silent",
            _ => false,
        }),
        "the first live tools/call must reach the touch handler: {first:?}"
    );

    let limited = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_TOUCH_TOOL_NAME, json!({})),
    )
    .expect_err("a second tools/call must be refused by the live rate limiter");
    let limited = format!("{limited:?}");
    assert!(
        limited.contains("Rate limit exceeded"),
        "the refused second tools/call must keep the rate-limit error: {limited}"
    );

    let listed = runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("changing only the method must still be admitted by the live rate limiter");
    assert!(
        listed
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_TOUCH_TOOL_NAME),
        "tools/list must stay callable after tools/call is rate-limited: {listed:?}"
    );

    drop(client);
    server.shutdown();
}

fn spawn_modern_sliding_window_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("sliding-window HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-sliding-window", "1.0.0")
                .middleware(rate_limiting::SlidingWindowRateLimitingMiddleware::new(
                    1, 60,
                ))
                .tool(PublicHttpTouchTool)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("sliding-window facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("sliding-window facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("sliding-window HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("sliding-window facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("sliding-window facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("sliding-window facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("sliding-window facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_sliding_window_refuses_second_same_method_and_admits_another() {
    let cx = Cx::for_request();
    let server = spawn_modern_sliding_window_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-sliding-window", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the sliding-window HTTP server");

    runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_TOUCH_TOOL_NAME, json!({})),
    )
    .expect("the first tools/call must be admitted by the live sliding window");

    let limited = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_TOUCH_TOOL_NAME, json!({})),
    )
    .expect_err("a second tools/call must be refused by the live sliding window");
    let limited = format!("{limited:?}");
    assert!(
        limited.contains("Rate limit exceeded"),
        "the refused second tools/call must keep the sliding-window error: {limited}"
    );

    let listed = runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("changing only the method must still be admitted by the live sliding window");
    assert!(
        listed
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_TOUCH_TOOL_NAME),
        "tools/list must stay callable after tools/call is sliding-window limited: {listed:?}"
    );

    drop(client);
    server.shutdown();
}

const PUBLIC_HTTP_TRANSFORMED_TOOL_NAME: &str = "public-http-e2e-lookup";

fn spawn_modern_transform_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("transform HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-transform", "1.0.0")
                .tool(
                    transform::TransformedTool::from_tool(PublicHttpValue)
                        .name(PUBLIC_HTTP_TRANSFORMED_TOOL_NAME)
                        .rename_arg("value", "query")
                        .build(),
                )
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("transform facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("transform facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("transform HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("transform facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("transform facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("transform facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("transform facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_transformed_tool_renames_catalog_and_argument() {
    let cx = Cx::for_request();
    let server = spawn_modern_transform_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-transform", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the transformed-tool HTTP server");

    let listed = runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("live bind_http must list the transformed tool");
    let transformed = listed
        .tools
        .iter()
        .find(|tool| tool.name == PUBLIC_HTTP_TRANSFORMED_TOOL_NAME)
        .unwrap_or_else(|| {
            panic!("the transformed catalog must advertise the new name: {listed:?}")
        });
    assert!(
        listed
            .tools
            .iter()
            .all(|tool| tool.name != PUBLIC_HTTP_TOOL_NAME),
        "the parent tool name must leave the transformed catalog: {listed:?}"
    );
    let schema = serde_json::to_string(&transformed.input_schema)
        .expect("the transformed input schema serializes");
    assert!(
        schema.contains("query"),
        "the transformed schema must advertise the renamed argument: {schema}"
    );
    assert!(
        !schema.contains("\"value\""),
        "the transformed schema must drop the original argument name: {schema}"
    );

    let looked_up = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PUBLIC_HTTP_TRANSFORMED_TOOL_NAME,
            json!({"query": "alpha"}),
        ),
    )
    .expect("the transformed tools/call must rewrite query back to value");
    assert!(
        looked_up.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "tool:alpha",
            _ => false,
        }),
        "the rewritten argument must reach the parent handler: {looked_up:?}"
    );

    let original = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_TOOL_NAME, json!({"value": "alpha"})),
    )
    .expect_err("the parent tool name must stay unadvertised");
    let original = format!("{original:?}");
    assert!(
        original.contains("Unknown tool")
            || original.contains("Method not found")
            || original.contains("MethodNotFound"),
        "calling the pre-transform name must stay unknown: {original}"
    );

    drop(client);
    server.shutdown();
}

const PUBLIC_HTTP_HIDDEN_TOOL_NAME: &str = "public-http-e2e-hidden";

fn spawn_modern_hide_arg_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("hide-arg HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-hide-arg", "1.0.0")
                .tool(
                    transform::TransformedTool::from_tool(PublicHttpValue)
                        .name(PUBLIC_HTTP_HIDDEN_TOOL_NAME)
                        .hide_arg("value", "hidden-default")
                        .build(),
                )
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("hide-arg facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("hide-arg facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("hide-arg HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("hide-arg facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("hide-arg facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("hide-arg facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("hide-arg facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_transformed_tool_hides_argument_and_injects_default() {
    let cx = Cx::for_request();
    let server = spawn_modern_hide_arg_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-hide-arg", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the hide-arg HTTP server");

    let listed = runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("live bind_http must list the hide-arg tool");
    let hidden = listed
        .tools
        .iter()
        .find(|tool| tool.name == PUBLIC_HTTP_HIDDEN_TOOL_NAME)
        .unwrap_or_else(|| panic!("the hide-arg catalog must advertise the new name: {listed:?}"));
    let schema =
        serde_json::to_string(&hidden.input_schema).expect("the hide-arg input schema serializes");
    assert!(
        !schema.contains("\"value\""),
        "the hide-arg schema must drop the hidden argument: {schema}"
    );

    let injected = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_HIDDEN_TOOL_NAME, json!({})),
    )
    .expect("the hide-arg tools/call must inject the configured default");
    assert!(
        injected.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "tool:hidden-default",
            _ => false,
        }),
        "the hidden default must reach the parent handler: {injected:?}"
    );

    let original = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_TOOL_NAME, json!({"value": "alpha"})),
    )
    .expect_err("the parent tool name must stay unadvertised");
    let original = format!("{original:?}");
    assert!(
        original.contains("Unknown tool")
            || original.contains("Method not found")
            || original.contains("MethodNotFound"),
        "calling the pre-transform name must stay unknown: {original}"
    );

    drop(client);
    server.shutdown();
}

fn spawn_modern_strict_validation_http_server(strict: bool) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("strict-validation HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-strict-validation", "1.0.0")
                .strict_input_validation(strict)
                .tool(PublicHttpValue)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message =
                        format!("strict-validation facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("strict-validation facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("strict-validation HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("strict-validation facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("strict-validation facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => {
                panic!("strict-validation facade HTTP server failed to start: {error}")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("strict-validation facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_strict_input_validation_refuses_unknown_property_and_admits_declared_args() {
    let cx = Cx::for_request();
    let strict_server = spawn_modern_strict_validation_http_server(true);
    let mut strict_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-strict-on", "1.0.0")
            .connect_http_with_cx(public_http_target(strict_server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the strict-validation HTTP server");

    let admitted = runtime_block_on_bounded(
        &cx,
        strict_client.call_tool(&cx, PUBLIC_HTTP_TOOL_NAME, json!({"value": "alpha"})),
    )
    .expect("strict validation must still admit declared arguments");
    assert!(
        !admitted.is_error,
        "declared arguments must not become a tool-level error: {admitted:?}"
    );
    assert!(
        admitted.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "tool:alpha",
            _ => false,
        }),
        "declared arguments must reach the handler under strict validation: {admitted:?}"
    );

    let refused = runtime_block_on_bounded(
        &cx,
        strict_client.call_tool(
            &cx,
            PUBLIC_HTTP_TOOL_NAME,
            json!({"value": "alpha", "extra": 1}),
        ),
    )
    .expect("strict validation returns a complete tools/call result, not a transport failure");
    assert!(
        refused.is_error,
        "an unknown property must become a tool-level error when strict validation is on: {refused:?}"
    );
    assert!(
        refused.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => {
                text.contains("do not match the declared input schema")
            }
            _ => false,
        }),
        "the strict refusal must name the input-schema mismatch: {refused:?}"
    );

    drop(strict_client);
    strict_server.shutdown();

    let lenient_server = spawn_modern_strict_validation_http_server(false);
    let mut lenient_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-strict-off", "1.0.0")
            .connect_http_with_cx(public_http_target(lenient_server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the lenient-validation HTTP server");

    let extra = runtime_block_on_bounded(
        &cx,
        lenient_client.call_tool(
            &cx,
            PUBLIC_HTTP_TOOL_NAME,
            json!({"value": "alpha", "extra": 1}),
        ),
    )
    .expect("lenient validation must admit the same extra property");
    assert!(
        !extra.is_error,
        "changing only the strict flag must admit the extra property: {extra:?}"
    );
    assert!(
        extra.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "tool:alpha",
            _ => false,
        }),
        "the extra property must not change the handler result when strict is off: {extra:?}"
    );

    drop(lenient_client);
    lenient_server.shutdown();
}

#[cfg(all(feature = "proxy", feature = "tasks"))]
#[test]
fn e2e_public_http_official_tasks_create_get_and_cancel_on_bind_http() {
    let cx = Cx::for_request();
    let server = spawn_modern_task_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-direct-tasks", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the official Tasks HTTP server");

    let created = runtime_block_on_bounded(
        &cx,
        client.call_tool_outcome(
            &cx,
            RequestId::Number(2),
            PUBLIC_HTTP_TASK_TOOL_NAME,
            json!({}),
            1 << 20,
        ),
    )
    .expect("live bind_http must create one official Task");
    let FinalToolCallOutcome::Task(created) = created else {
        panic!(
            "the task-capable live tool must return the official Task result branch: {created:?}"
        );
    };
    let task_id = created.task.base().task_id.clone();

    let input_deadline = Instant::now() + HTTP_OPERATION_BOUND;
    let mut next_id = 3_i64;
    let observed = loop {
        let observed = runtime_block_on_bounded(
            &cx,
            client.get_task(&cx, RequestId::Number(next_id), task_id.clone(), 1 << 20),
        )
        .expect("live bind_http must serve tasks/get of the created Task");
        next_id = next_id
            .checked_add(1)
            .expect("the official Tasks request id space does not overflow");
        if matches!(observed.task, FinalTask::InputRequired { .. }) {
            break observed;
        }
        if Instant::now() >= input_deadline {
            panic!("live bind_http must observe the created input_required Task: {observed:?}");
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(
        observed.task.base().task_id,
        task_id,
        "tasks/get must return the created Task: {observed:?}"
    );

    let missing = FinalTaskId::parse("missing-direct-task")
        .expect("the planted-missing task id is a valid official TaskId");
    let missing_get = runtime_block_on_bounded(
        &cx,
        client.get_task(&cx, RequestId::Number(next_id), missing.clone(), 1 << 20),
    )
    .expect_err("changing only the task id must not invent a Task");
    let _ = missing_get;
    next_id += 1;

    let missing_cancel = runtime_block_on_bounded(
        &cx,
        client.cancel_task(&cx, RequestId::Number(next_id), missing, 1 << 20),
    )
    .expect_err("changing only the task id must not invent a cancellation");
    let _ = missing_cancel;
    next_id += 1;

    let wrong_update: FinalTaskInputResponses =
        serde_json::from_value(json!({"roots": {"action": "accept"}}))
            .expect("the planted-wrong Tasks update payload is typed");
    let rejected_update = runtime_block_on_bounded(
        &cx,
        client.update_task(
            &cx,
            RequestId::Number(next_id),
            &observed.task,
            wrong_update,
            1 << 20,
        ),
    )
    .expect_err("changing only the input response kind must not resume the created Task");
    let _ = rejected_update;
    next_id += 1;

    let still_waiting = runtime_block_on_bounded(
        &cx,
        client.get_task(&cx, RequestId::Number(next_id), task_id.clone(), 1 << 20),
    )
    .expect("a rejected tasks/update must leave the created Task in place");
    next_id += 1;
    assert!(
        matches!(still_waiting.task, FinalTask::InputRequired { .. }),
        "a rejected tasks/update must not leave the input_required Task: {still_waiting:?}"
    );

    let responses: FinalTaskInputResponses =
        serde_json::from_value(json!({"roots": {"roots": []}}))
            .expect("the public final roots response is typed");
    runtime_block_on_bounded(
        &cx,
        client.update_task(
            &cx,
            RequestId::Number(next_id),
            &observed.task,
            responses,
            1 << 20,
        ),
    )
    .expect("live bind_http must serve tasks/update of the created Task");
    next_id += 1;

    let working_deadline = Instant::now() + HTTP_OPERATION_BOUND;
    loop {
        let observed = runtime_block_on_bounded(
            &cx,
            client.get_task(&cx, RequestId::Number(next_id), task_id.clone(), 1 << 20),
        )
        .expect("live bind_http must keep serving tasks/get after update");
        next_id = next_id
            .checked_add(1)
            .expect("the official Tasks request id space does not overflow");
        if matches!(observed.task, FinalTask::Working(_)) {
            break;
        }
        if Instant::now() >= working_deadline {
            panic!(
                "live bind_http must observe the working Task after a matching update: {observed:?}"
            );
        }
        thread::sleep(Duration::from_millis(5));
    }

    runtime_block_on_bounded(
        &cx,
        client.cancel_task(&cx, RequestId::Number(next_id), task_id.clone(), 1 << 20),
    )
    .expect("live bind_http must serve tasks/cancel of the created Task");
    next_id += 1;

    let cancel_deadline = Instant::now() + HTTP_OPERATION_BOUND;
    loop {
        let observed = runtime_block_on_bounded(
            &cx,
            client.get_task(&cx, RequestId::Number(next_id), task_id.clone(), 1 << 20),
        )
        .expect("live bind_http must keep serving tasks/get after cancel");
        next_id = next_id
            .checked_add(1)
            .expect("the official Tasks request id space does not overflow");
        if matches!(observed.task, FinalTask::Cancelled(_)) {
            break;
        }
        if Instant::now() >= cancel_deadline {
            panic!("live bind_http must observe the cancelled Task: {observed:?}");
        }
        thread::sleep(Duration::from_millis(5));
    }

    drop(client);
    server.shutdown();
}

fn spawn_modern_duplicate_http_server(behavior: DuplicateBehavior) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("duplicate HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-duplicate", "1.0.0")
                .on_duplicate(behavior)
                .tool(PublicHttpValue)
                .tool(ReplacedPublicHttpValue)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("duplicate facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("duplicate facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("duplicate HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("duplicate facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("duplicate facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("duplicate facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("duplicate facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_on_duplicate_error_keeps_first_and_replace_installs_second() {
    let cx = Cx::for_request();

    let keep_server = spawn_modern_duplicate_http_server(DuplicateBehavior::Error);
    let mut keep_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-duplicate-error", "1.0.0")
            .connect_http_with_cx(public_http_target(keep_server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the Error-on-duplicate HTTP server");
    let kept = runtime_block_on_bounded(
        &cx,
        keep_client.call_tool(&cx, PUBLIC_HTTP_TOOL_NAME, json!({"value": "alpha"})),
    )
    .expect("Error must keep the first registration callable");
    assert!(
        kept.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "tool:alpha",
            _ => false,
        }),
        "on_duplicate Error must keep the first handler: {kept:?}"
    );
    drop(keep_client);
    keep_server.shutdown();

    let replace_server = spawn_modern_duplicate_http_server(DuplicateBehavior::Replace);
    let mut replace_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-duplicate-replace", "1.0.0")
            .connect_http_with_cx(public_http_target(replace_server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the Replace-on-duplicate HTTP server");
    let replaced = runtime_block_on_bounded(
        &cx,
        replace_client.call_tool(&cx, PUBLIC_HTTP_TOOL_NAME, json!({"value": "alpha"})),
    )
    .expect("Replace must install the second registration");
    assert!(
        replaced.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "replaced:alpha",
            _ => false,
        }),
        "changing only on_duplicate to Replace must reach the second handler: {replaced:?}"
    );
    drop(replace_client);
    replace_server.shutdown();
}

fn spawn_modern_cache_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let tool_calls = Arc::clone(&handler_calls);
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("cache HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-cache", "1.0.0")
                .middleware(
                    caching::ResponseCachingMiddleware::new()
                        .include_tools(vec![PUBLIC_HTTP_TOOL_NAME.to_owned()]),
                )
                .tool(CountingPublicHttpValue {
                    counters: tool_calls,
                })
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("cache facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("cache facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("cache HTTP server startup receiver went away".to_owned());
            }
            bound
                .serve(&cx)
                .await
                .map_err(|error| format!("cache facade HTTP server stopped unexpectedly: {error}"))
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("cache facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("cache facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("cache facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_response_cache_hits_same_allowlisted_call_and_misses_changed_args() {
    let cx = Cx::for_request();
    let server = spawn_modern_cache_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-cache", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the cached HTTP server");

    let first = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_TOOL_NAME, json!({"value": "alpha"})),
    )
    .expect("the first allowlisted tools/call must miss and reach the handler");
    assert!(
        first.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "tool:alpha",
            _ => false,
        }),
        "the first live tools/call must return the handler result: {first:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the first allowlisted tools/call must invoke the counting handler"
    );

    let cached = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_TOOL_NAME, json!({"value": "alpha"})),
    )
    .expect("the second identical allowlisted tools/call must be a cache hit");
    assert!(
        cached.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "tool:alpha",
            _ => false,
        }),
        "the cache hit must keep the first complete result: {cached:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "a cache hit must not invoke the counting handler again"
    );

    let missed = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_TOOL_NAME, json!({"value": "beta"})),
    )
    .expect("changing only the arguments must miss the cache");
    assert!(
        missed.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "tool:beta",
            _ => false,
        }),
        "the cache miss must reach the handler with the new arguments: {missed:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        2,
        "a different-arguments tools/call must invoke the counting handler"
    );

    drop(client);
    server.shutdown();
}

const PUBLIC_HTTP_SLOW_TOOL_NAME: &str = "public-http-e2e-slow";
const PUBLIC_HTTP_FAST_TOOL_NAME: &str = "public-http-e2e-fast";

/// Live modern HTTP tool whose handler timeout expires before its delay finishes.
struct PublicHttpSlowTool;

impl ToolHandler for PublicHttpSlowTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_SLOW_TOOL_NAME.to_owned(),
            description: Some("Proves live facade HTTP handler timeout".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_millis(10))
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        thread::sleep(Duration::from_millis(80));
        Ok(vec![Content::text("late")])
    }
}

/// Live modern HTTP peer tool that stays inside the request budget.
struct PublicHttpFastTool;

impl ToolHandler for PublicHttpFastTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_FAST_TOOL_NAME.to_owned(),
            description: Some(
                "Proves live facade HTTP handler timeout does not starve peers".to_owned(),
            ),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text("fast")])
    }
}

fn spawn_modern_handler_timeout_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("handler-timeout HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-handler-timeout", "1.0.0")
                .tool(PublicHttpSlowTool)
                .tool(PublicHttpFastTool)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message =
                        format!("handler-timeout facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("handler-timeout facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("handler-timeout HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("handler-timeout facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("handler-timeout facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("handler-timeout facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("handler-timeout facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_handler_timeout_refuses_late_tool_and_admits_fast_peer() {
    let cx = Cx::for_request();
    let server = spawn_modern_handler_timeout_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-handler-timeout", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the handler-timeout HTTP server");

    let timed_out = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_SLOW_TOOL_NAME, json!({})),
    )
    .expect_err("a handler that outlives its timeout must be refused");
    let timed_out = format!("{timed_out:?}");
    assert!(
        timed_out.contains("Request timeout exceeded") || timed_out.contains("RequestCancelled"),
        "the refused late tools/call must keep the handler-timeout error: {timed_out}"
    );

    let fast = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_FAST_TOOL_NAME, json!({})),
    )
    .expect("changing only the tool must still be admitted after a handler timeout");
    assert!(
        fast.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "fast",
            _ => false,
        }),
        "the fast peer tool must still complete: {fast:?}"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_resource_and_prompt_list_changed_are_retained_on_incremental_listen() {
    let cx = Cx::for_request();
    let server = spawn_modern_subscription_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-catalog-changed", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before subscriptions/listen");

    let limits = modern::SseLimits::new(64 * 1024, 2 * 1024 * 1024, 256)
        .expect("subscription SSE limits must be nonzero");
    let filter = modern::SubscriptionFilter {
        resources_list_changed: Some(true),
        prompts_list_changed: Some(true),
        ..modern::SubscriptionFilter::default()
    };
    runtime_block_on_bounded(
        &cx,
        client.start_subscriptions_listener(&cx, filter, limits),
    )
    .expect("live bind_http must admit an incremental subscriptions/listen");

    let acknowledgement = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("subscriptions/listen must emit its acknowledgement");
    assert!(
        matches!(
            acknowledgement,
            Some(modern::ModernHttpSubscriptionListenEvent::Acknowledged { .. })
        ),
        "the first incremental listen record must be the accepted filter: {acknowledgement:?}"
    );

    let hidden = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_HIDE_CATALOG_TOOL_NAME, json!({})),
    )
    .expect("disabling a resource and a prompt must complete");
    assert!(
        hidden.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "hidden",
            _ => false,
        }),
        "request-local SessionState must let disable_resource and disable_prompt publish: {hidden:?}"
    );

    let first = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("subscriptions/listen must retain the first catalog mutation");
    let second = runtime_block_on_bounded(&cx, client.next_http_subscription_event(&cx))
        .expect("subscriptions/listen must retain the second catalog mutation");
    let kinds = [first, second];
    assert!(
        kinds.iter().any(|event| matches!(
            event,
            Some(modern::ModernHttpSubscriptionListenEvent::Notification(
                modern::ServerNotification::ResourcesListChanged(_)
            ))
        )),
        "live bind_http must retain notifications/resources/list_changed: {kinds:?}"
    );
    assert!(
        kinds.iter().any(|event| matches!(
            event,
            Some(modern::ModernHttpSubscriptionListenEvent::Notification(
                modern::ServerNotification::PromptsListChanged(_)
            ))
        )),
        "live bind_http must retain notifications/prompts/list_changed: {kinds:?}"
    );
    drop(client);
    server.shutdown();
}

fn spawn_modern_auth_admission_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let tool_calls = Arc::clone(&handler_calls);
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("auth admission HTTP server control receiver went away".to_owned());
            }
            let verifier = StaticTokenVerifier::new([(
                "alpha",
                AuthContext::with_subject(PUBLIC_HTTP_AUTH_SUBJECT),
            )])
            .expect("the deterministic native bearer verifier is valid")
            .with_allowed_schemes(["Bearer"])
            .expect("the bearer scheme allowlist is valid");
            let server = modern::ServerBuilder::new("facade-http-auth-admission", "1.0.0")
                .auth_provider(TokenAuthProvider::new(verifier))
                .tool(PublicHttpAuthSubject {
                    counters: tool_calls,
                })
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("auth admission facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("auth admission facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("auth admission HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("auth admission facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("auth admission facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("auth admission facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("auth admission facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_static_token_refuses_missing_and_wrong_and_commits_subject() {
    const MAX_NATIVE_HTTP_RESPONSE_BYTES: usize = 1 << 20;

    fn exchange(address: SocketAddr, authorization: Option<&str>, body: &[u8]) -> Vec<u8> {
        let mut stream = std::net::TcpStream::connect_timeout(&address, HTTP_OPERATION_BOUND)
            .expect("native HTTP client connects to the auth admission listener");
        stream
            .set_read_timeout(Some(HTTP_OPERATION_BOUND))
            .expect("native HTTP client read deadline is configured");
        stream
            .set_write_timeout(Some(HTTP_OPERATION_BOUND))
            .expect("native HTTP client write deadline is configured");
        let authorization_header =
            authorization.map_or_else(String::new, |value| format!("Authorization: {value}\r\n"));
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: {address}\r\n{authorization_header}Accept: application/json\r\nContent-Type: application/json\r\nMCP-Protocol-Version: {}\r\nMcp-Method: tools/call\r\nMcp-Name: {PUBLIC_HTTP_AUTH_TOOL_NAME}\r\nContent-Length: {}\r\n\r\n",
            modern::PROTOCOL_VERSION,
            body.len(),
        );
        stream
            .write_all(request.as_bytes())
            .and_then(|()| stream.write_all(body))
            .expect("native HTTP request commits to the auth admission listener");
        let mut response = Vec::new();
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let read = stream
                .read(&mut buffer)
                .expect("native HTTP response reads within its configured deadline");
            if read == 0 {
                break;
            }
            assert!(
                response
                    .len()
                    .checked_add(read)
                    .is_some_and(|size| size <= MAX_NATIVE_HTTP_RESPONSE_BYTES),
                "native HTTP response exceeds the test's bounded response budget"
            );
            response.extend_from_slice(&buffer[..read]);
        }
        response
    }

    fn response_headers(response: &[u8]) -> &str {
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("native HTTP response contains a complete header terminator");
        std::str::from_utf8(&response[..header_end])
            .expect("native HTTP response headers are ASCII")
    }

    fn response_json_body(response: &[u8]) -> serde_json::Value {
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("native HTTP response contains a complete header terminator");
        let headers = std::str::from_utf8(&response[..header_end])
            .expect("native HTTP response headers are ASCII");
        let mut content_length = None;
        let mut chunked = false;
        for header in headers.lines().skip(1) {
            let (name, value) = header
                .split_once(':')
                .expect("native HTTP response header has a field delimiter");
            if name.eq_ignore_ascii_case("content-length") {
                content_length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .expect("native HTTP Content-Length is a valid byte count"),
                );
            }
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"))
            {
                chunked = true;
            }
        }
        let body = &response[header_end + 4..];
        let decoded = if chunked {
            let mut cursor = 0;
            let mut decoded = Vec::new();
            loop {
                let size_end = body[cursor..]
                    .windows(2)
                    .position(|window| window == b"\r\n")
                    .map(|offset| cursor + offset)
                    .expect("chunked response contains a complete chunk-size line");
                let size_line = std::str::from_utf8(&body[cursor..size_end])
                    .expect("chunked response chunk size is ASCII");
                let size =
                    usize::from_str_radix(size_line.split(';').next().unwrap_or_default(), 16)
                        .expect("chunked response chunk size is hexadecimal");
                cursor = size_end + 2;
                if size == 0 {
                    return serde_json::from_slice(&decoded)
                        .expect("authenticated tool response is JSON-RPC");
                }
                let chunk_end = cursor
                    .checked_add(size)
                    .expect("chunked response chunk length does not overflow");
                decoded.extend_from_slice(&body[cursor..chunk_end]);
                cursor = chunk_end + 2;
            }
        } else {
            let content_length = content_length
                .expect("native HTTP response uses Content-Length or chunked framing");
            body[..content_length].to_vec()
        };
        serde_json::from_slice(&decoded).expect("authenticated tool response is JSON-RPC")
    }

    let server = spawn_modern_auth_admission_http_server();
    let tool = JsonRpcRequest::new(
        "tools/call",
        Some(json!({
            "name": PUBLIC_HTTP_AUTH_TOOL_NAME,
            "arguments": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": modern::PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        })),
        2_i64,
    );
    let tool_body = serde_json::to_vec(&tool).expect("exact-modern tool request serializes");

    let missing = exchange(server.address(), None, &tool_body);
    assert!(
        missing.starts_with(b"HTTP/1.1 401"),
        "missing Authorization must be refused before dispatch: {}",
        String::from_utf8_lossy(&missing)
    );
    assert!(
        response_headers(&missing).lines().any(|header| header
            .to_ascii_lowercase()
            .starts_with("www-authenticate:")
            && header.to_ascii_lowercase().contains("bearer")),
        "the missing-token challenge must advertise Bearer: {}",
        String::from_utf8_lossy(&missing)
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        0,
        "missing Authorization must not invoke the authenticated handler"
    );

    let wrong = exchange(server.address(), Some("Bearer beta"), &tool_body);
    assert!(
        wrong.starts_with(b"HTTP/1.1 401"),
        "changing only the bearer token must be refused before dispatch: {}",
        String::from_utf8_lossy(&wrong)
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        0,
        "a wrong bearer token must not invoke the authenticated handler"
    );

    let admitted = exchange(server.address(), Some("Bearer alpha"), &tool_body);
    assert!(
        admitted.starts_with(b"HTTP/1.1 200"),
        "the matching bearer token must admit tools/call: {}",
        String::from_utf8_lossy(&admitted)
    );
    let admitted = response_json_body(&admitted);
    assert!(
        admitted.get("error").is_none(),
        "the matching bearer token must reach the handler: {admitted}"
    );
    let content = admitted["result"]["content"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        content.iter().any(|block| {
            block["text"].as_str() == Some(&format!("subject:{PUBLIC_HTTP_AUTH_SUBJECT}"))
        }),
        "admitted native HTTP must commit the verifier subject into ctx.auth(): {admitted}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "only the matching bearer token may invoke the authenticated handler"
    );
    server.shutdown();
}

fn spawn_modern_catalog_metadata_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("catalog metadata HTTP server control receiver went away".to_owned());
            }
            let icons = vec![
                RawIcon::try_new(PUBLIC_HTTP_ICON_SRC).expect("the catalog icon source is valid"),
            ];
            let server = modern::ServerBuilder::new("facade-http-catalog-metadata", "1.0.0")
                .tool(PublicHttpIconTool { icons })
                .tool(PublicHttpPlainTool)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message =
                        format!("catalog metadata facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("catalog metadata facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("catalog metadata HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("catalog metadata facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("catalog metadata facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => {
                panic!("catalog metadata facade HTTP server failed to start: {error}")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("catalog metadata facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_list_tools_retains_final_icons_title_and_annotations() {
    let cx = Cx::for_request();
    let server = spawn_modern_catalog_metadata_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-catalog-metadata", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the catalog metadata HTTP server");

    let listed = runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("live bind_http must list the catalog metadata tools");
    let icon_tool = listed
        .tools
        .iter()
        .find(|tool| tool.name == PUBLIC_HTTP_ICON_TOOL_NAME)
        .expect("the icon tool must remain on the live catalog");
    let plain_tool = listed
        .tools
        .iter()
        .find(|tool| tool.name == PUBLIC_HTTP_PLAIN_TOOL_NAME)
        .expect("the plain peer tool must remain on the live catalog");

    assert_eq!(icon_tool.title.as_deref(), Some("Icon Tool"));
    let icons = icon_tool
        .icons
        .as_ref()
        .expect("the icon tool must advertise its exact-final icons");
    assert_eq!(icons.len(), 1);
    assert_eq!(icons[0].src.as_str(), PUBLIC_HTTP_ICON_SRC);
    let annotations = icon_tool
        .annotations
        .as_ref()
        .expect("the icon tool must retain its projected annotations");
    assert_eq!(annotations.read_only, Some(true));
    assert_eq!(annotations.idempotent, Some(true));
    assert_eq!(annotations.destructive, None);

    assert_eq!(plain_tool.title, None);
    assert_eq!(plain_tool.icons, None);
    assert_eq!(plain_tool.annotations, None);

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_two_clients_call_the_same_tool_independently() {
    let cx = Cx::for_request();
    let server = spawn_modern_facade_http_server(false, None, false);
    let mut first = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-multi-client-a", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the first ModernOnly public facade connects to the shared HTTP server");
    let mut second = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-multi-client-b", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the second ModernOnly public facade connects to the same HTTP server");

    let first_result = runtime_block_on_bounded(
        &cx,
        first.call_tool(&cx, PUBLIC_HTTP_TOOL_NAME, json!({"value": "alpha"})),
    )
    .expect("the first live client must reach the shared tool");
    let second_result = runtime_block_on_bounded(
        &cx,
        second.call_tool(&cx, PUBLIC_HTTP_TOOL_NAME, json!({"value": "beta"})),
    )
    .expect("the second live client must reach the shared tool independently");
    assert!(
        first_result.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "tool:alpha",
            _ => false,
        }),
        "the first client must keep its own tools/call result: {first_result:?}"
    );
    assert!(
        second_result.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "tool:beta",
            _ => false,
        }),
        "changing only the second client's arguments must not reuse the first result: {second_result:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        2,
        "two independent HTTP clients must each invoke the shared handler"
    );

    drop(first);
    drop(second);
    server.shutdown();
}

#[test]
fn e2e_public_http_ping_then_tools_call_on_bind_http() {
    let cx = Cx::for_request();
    let server = spawn_modern_facade_http_server(false, None, false);
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-ping", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects before ping");

    runtime_block_on_bounded(&cx, client.ping(&cx)).expect("live bind_http must answer ping");
    assert_eq!(
        server.handler_call_snapshot().tool,
        0,
        "ping must not invoke a tools/call handler"
    );

    let called = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_TOOL_NAME, json!({"value": "alpha"})),
    )
    .expect("tools/call must still be admitted after ping");
    assert!(
        called.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "tool:alpha",
            _ => false,
        }),
        "a later tools/call must keep its handler result after ping: {called:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "only the later tools/call may invoke the handler"
    );

    drop(client);
    server.shutdown();
}

fn spawn_modern_output_schema_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("output schema HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-output-schema", "1.0.0")
                .tool(PublicHttpOutputTool)
                .tool(PublicHttpPlainTool)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("output schema facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("output schema facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("output schema HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("output schema facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("output schema facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("output schema facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("output schema facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_output_schema_retains_structured_content_and_peer_stays_bare() {
    let cx = Cx::for_request();
    let server = spawn_modern_output_schema_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-output-schema", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the output-schema HTTP server");

    let listed = runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("live bind_http must list the output-schema tools");
    let output_tool = listed
        .tools
        .iter()
        .find(|tool| tool.name == PUBLIC_HTTP_OUTPUT_TOOL_NAME)
        .expect("the output-schema tool must remain on the live catalog");
    let plain_tool = listed
        .tools
        .iter()
        .find(|tool| tool.name == PUBLIC_HTTP_PLAIN_TOOL_NAME)
        .expect("the bare peer tool must remain on the live catalog");
    assert_eq!(
        output_tool
            .output_schema
            .as_ref()
            .and_then(|schema| schema.get("required")),
        Some(&json!(["value"])),
        "tools/list must retain the advertised output schema: {output_tool:?}"
    );
    assert_eq!(
        plain_tool.output_schema, None,
        "changing only the missing output schema must keep the peer bare: {plain_tool:?}"
    );

    let called = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_OUTPUT_TOOL_NAME, json!({"value": "alpha"})),
    )
    .expect("live bind_http must admit the structured output tool");
    assert!(
        called.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "tool:alpha",
            _ => false,
        }),
        "the structured tool must still author text content: {called:?}"
    );
    assert_eq!(
        called.structured_content,
        Some(json!({"value": "alpha"})),
        "tools/call must retain structuredContent matching the advertised schema: {called:?}"
    );

    let peer = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_PLAIN_TOOL_NAME, json!({})),
    )
    .expect("the bare peer tool must still be callable");
    assert_eq!(
        peer.structured_content, None,
        "changing only the missing output schema must not invent structuredContent: {peer:?}"
    );

    drop(client);
    server.shutdown();
}

fn spawn_modern_compose_and_state_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let tool_calls = Arc::clone(&handler_calls);
    let resource_calls = Arc::clone(&handler_calls);
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("compose HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-compose", "1.0.0")
                .tool(CountingPublicHttpValue {
                    counters: Arc::clone(&tool_calls),
                })
                .tool(PublicHttpComposeTool)
                .tool(PublicHttpMacroComposeTool)
                .tool(PublicHttpStateTool)
                .resource(CountingPublicHttpSnapshot {
                    counters: resource_calls,
                })
                .resource(PublicHttpMacroComposeViewResource)
                .resource(PublicHttpMacroComposeMissingResource)
                .resource(PublicHttpComposeResource {
                    uri: PUBLIC_HTTP_COMPOSE_RESOURCE_URI,
                    tool: PUBLIC_HTTP_TOOL_NAME,
                    resource: PUBLIC_HTTP_RESOURCE_URI,
                })
                .resource(PublicHttpComposeResource {
                    uri: PUBLIC_HTTP_COMPOSE_MISSING_TOOL_RESOURCE_URI,
                    tool: "public-http-e2e-missing",
                    resource: PUBLIC_HTTP_RESOURCE_URI,
                })
                .resource(PublicHttpComposeResource {
                    uri: PUBLIC_HTTP_COMPOSE_MISSING_RESOURCE_URI,
                    tool: PUBLIC_HTTP_TOOL_NAME,
                    resource: "test://public-http-e2e/missing",
                })
                .prompt(PublicHttpComposePrompt)
                .prompt(PublicHttpMacroComposePrompt)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("compose facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("compose facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("compose HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("compose facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("compose facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("compose facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("compose facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_handler_ctx_call_tool_and_read_resource() {
    let cx = Cx::for_request();
    let server = spawn_modern_compose_and_state_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-compose", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the compose HTTP server");

    let composed = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PUBLIC_HTTP_COMPOSE_TOOL_NAME,
            json!({"value": "alpha"}),
        ),
    )
    .expect("live bind_http must compose a nested tool call and resource read");
    assert!(
        composed.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => {
                text == "compose:tool:alpha|resource:deterministic"
            }
            _ => false,
        }),
        "ctx.call_tool and ctx.read_resource must reach the live peer handlers: {composed:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the nested tools/call must invoke the peer tool exactly once"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "the nested resources/read must invoke the peer resource exactly once"
    );

    let missing_tool = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PUBLIC_HTTP_COMPOSE_TOOL_NAME,
            json!({"value": "alpha", "tool": "public-http-e2e-missing"}),
        ),
    );
    let missing_tool = match missing_tool {
        Ok(result) if result.is_error => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
        Ok(result) => panic!(
            "changing only the nested tool name must refuse before the peer handlers run: {result:?}"
        ),
    };
    assert!(
        missing_tool.contains("public-http-e2e-missing")
            || missing_tool.contains("Unknown tool")
            || missing_tool.contains("not found")
            || missing_tool.contains("MethodNotFound")
            || missing_tool.contains("compose-nested-tool"),
        "the nested unknown tool must stay a handler-visible refusal: {missing_tool}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "an unknown nested tool name must not invoke the peer tool"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "an unknown nested tool name must not reach the peer resource"
    );

    let missing_resource = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PUBLIC_HTTP_COMPOSE_TOOL_NAME,
            json!({
                "value": "beta",
                "resource": "test://public-http-e2e/missing"
            }),
        ),
    );
    let missing_resource = match missing_resource {
        Ok(result) if result.is_error => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
        Ok(result) => panic!(
            "changing only the nested resource URI must refuse after the peer tool runs: {result:?}"
        ),
    };
    assert!(
        missing_resource.contains("test://public-http-e2e/missing")
            || missing_resource.contains("not found")
            || missing_resource.contains("ResourceNotFound")
            || missing_resource.contains("compose-nested-resource"),
        "the nested unknown resource must stay a handler-visible refusal: {missing_resource}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        2,
        "the peer tool must still run when only the nested resource URI changes"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "an unknown nested resource URI must not invoke the peer resource"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_prompt_composes_nested_tool_and_resource() {
    let cx = Cx::for_request();
    let server = spawn_modern_compose_and_state_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-prompt-compose", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the prompt compose HTTP server");

    let composed = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            PUBLIC_HTTP_COMPOSE_PROMPT_NAME,
            HashMap::from([("value".to_owned(), "alpha".to_owned())]),
        ),
    )
    .expect("live bind_http prompts/get must compose a nested tool call and resource read");
    assert!(
        composed
            .messages
            .iter()
            .any(|message| match &message.content {
                ContentBlock::Text { text, .. } => {
                    text == "compose:tool:alpha|resource:deterministic"
                }
                _ => false,
            }),
        "prompt ctx.call_tool and ctx.read_resource must reach the live peer handlers: {composed:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the nested tools/call must invoke the peer tool exactly once"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "the nested resources/read must invoke the peer resource exactly once"
    );

    let missing_tool = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            PUBLIC_HTTP_COMPOSE_PROMPT_NAME,
            HashMap::from([
                ("value".to_owned(), "alpha".to_owned()),
                ("tool".to_owned(), "public-http-e2e-missing".to_owned()),
            ]),
        ),
    );
    let missing_tool = match missing_tool {
        Ok(result) => panic!(
            "changing only the nested tool name must refuse before the peer handlers run: {result:?}"
        ),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        missing_tool.contains("public-http-e2e-missing")
            || missing_tool.contains("Unknown tool")
            || missing_tool.contains("not found")
            || missing_tool.contains("MethodNotFound")
            || missing_tool.contains("compose-nested-tool"),
        "the nested unknown tool must stay a handler-visible refusal: {missing_tool}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "an unknown nested tool name must not invoke the peer tool"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "an unknown nested tool name must not reach the peer resource"
    );

    let missing_resource = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            PUBLIC_HTTP_COMPOSE_PROMPT_NAME,
            HashMap::from([
                ("value".to_owned(), "beta".to_owned()),
                (
                    "resource".to_owned(),
                    "test://public-http-e2e/missing".to_owned(),
                ),
            ]),
        ),
    );
    let missing_resource = match missing_resource {
        Ok(result) => panic!(
            "changing only the nested resource URI must refuse after the peer tool runs: {result:?}"
        ),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        missing_resource.contains("test://public-http-e2e/missing")
            || missing_resource.contains("not found")
            || missing_resource.contains("ResourceNotFound")
            || missing_resource.contains("compose-nested-resource"),
        "the nested unknown resource must stay a handler-visible refusal: {missing_resource}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        2,
        "the peer tool must still run when only the nested resource URI changes"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "an unknown nested resource URI must not invoke the peer resource"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_macro_prompt_composes_nested_tool_and_resource() {
    let cx = Cx::for_request();
    let server = spawn_modern_compose_and_state_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-macro-compose", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the macro prompt compose HTTP server");

    let composed = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            PUBLIC_HTTP_MACRO_COMPOSE_PROMPT_NAME,
            HashMap::from([
                ("value".to_owned(), "alpha".to_owned()),
                ("tool".to_owned(), PUBLIC_HTTP_TOOL_NAME.to_owned()),
                ("resource".to_owned(), PUBLIC_HTTP_RESOURCE_URI.to_owned()),
            ]),
        ),
    )
    .expect("live bind_http async #[prompt] must compose a nested tool call and resource read");
    assert!(
        composed
            .messages
            .iter()
            .any(|message| match &message.content {
                ContentBlock::Text { text, .. } => {
                    text == "compose:tool:alpha|resource:deterministic"
                }
                _ => false,
            }),
        "async #[prompt] ctx.call_tool and ctx.read_resource must reach the live peer handlers: {composed:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the nested tools/call must invoke the peer tool exactly once"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "the nested resources/read must invoke the peer resource exactly once"
    );

    let missing_tool = runtime_block_on_bounded(
        &cx,
        client.get_prompt(
            &cx,
            PUBLIC_HTTP_MACRO_COMPOSE_PROMPT_NAME,
            HashMap::from([
                ("value".to_owned(), "alpha".to_owned()),
                ("tool".to_owned(), "public-http-e2e-missing".to_owned()),
                ("resource".to_owned(), PUBLIC_HTTP_RESOURCE_URI.to_owned()),
            ]),
        ),
    );
    let missing_tool = match missing_tool {
        Ok(result) => panic!(
            "changing only the nested tool name must refuse before the peer handlers run: {result:?}"
        ),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        missing_tool.contains("public-http-e2e-missing")
            || missing_tool.contains("Unknown tool")
            || missing_tool.contains("not found")
            || missing_tool.contains("MethodNotFound")
            || missing_tool.contains("compose-nested-tool"),
        "the nested unknown tool must stay a handler-visible refusal: {missing_tool}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "an unknown nested tool name must not invoke the peer tool"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_macro_tool_composes_nested_tool_and_resource() {
    let cx = Cx::for_request();
    let server = spawn_modern_compose_and_state_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-macro-tool-compose", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the macro tool compose HTTP server");

    let composed = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PUBLIC_HTTP_MACRO_COMPOSE_TOOL_NAME,
            json!({
                "value": "alpha",
                "tool": PUBLIC_HTTP_TOOL_NAME,
                "resource": PUBLIC_HTTP_RESOURCE_URI
            }),
        ),
    )
    .expect("live bind_http async #[tool] must compose a nested tool call and resource read");
    assert!(
        composed.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => {
                text == "compose:tool:alpha|resource:deterministic"
            }
            _ => false,
        }),
        "async #[tool] ctx.call_tool and ctx.read_resource must reach the live peer handlers: {composed:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the nested tools/call must invoke the peer tool exactly once"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "the nested resources/read must invoke the peer resource exactly once"
    );

    let missing_tool = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PUBLIC_HTTP_MACRO_COMPOSE_TOOL_NAME,
            json!({
                "value": "alpha",
                "tool": "public-http-e2e-missing",
                "resource": PUBLIC_HTTP_RESOURCE_URI
            }),
        ),
    );
    let missing_tool = match missing_tool {
        Ok(result) if result.is_error => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
        Ok(result) => panic!(
            "changing only the nested tool name must refuse before the peer handlers run: {result:?}"
        ),
    };
    assert!(
        missing_tool.contains("public-http-e2e-missing")
            || missing_tool.contains("Unknown tool")
            || missing_tool.contains("not found")
            || missing_tool.contains("MethodNotFound")
            || missing_tool.contains("compose-nested-tool"),
        "the nested unknown tool must stay a handler-visible refusal: {missing_tool}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "an unknown nested tool name must not invoke the peer tool"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_macro_resource_composes_nested_tool_and_resource() {
    let cx = Cx::for_request();
    let server = spawn_modern_compose_and_state_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-macro-resource-compose", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the macro resource compose HTTP server");

    let composed = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_MACRO_COMPOSE_RESOURCE_URI),
    )
    .expect("live bind_http async #[resource] must compose a nested tool call and resource read");
    assert!(
        matches!(
            composed.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }]
                if text == "compose:tool:alpha|resource:deterministic"
        ),
        "async #[resource] ctx.call_tool and ctx.read_resource must reach the live peer handlers: {composed:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the nested tools/call must invoke the peer tool exactly once"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "the nested resources/read must invoke the peer resource exactly once"
    );

    let missing_tool = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_MACRO_COMPOSE_MISSING_TOOL_RESOURCE_URI),
    );
    let missing_tool = match missing_tool {
        Ok(result) => panic!(
            "changing only the nested tool name must refuse before the peer handlers run: {result:?}"
        ),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        missing_tool.contains("public-http-e2e-missing")
            || missing_tool.contains("Unknown tool")
            || missing_tool.contains("not found")
            || missing_tool.contains("MethodNotFound")
            || missing_tool.contains("compose-nested-tool"),
        "the nested unknown tool must stay a handler-visible refusal: {missing_tool}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "an unknown nested tool name must not invoke the peer tool"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_resource_composes_nested_tool_and_resource() {
    let cx = Cx::for_request();
    let server = spawn_modern_compose_and_state_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-resource-compose", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the resource compose HTTP server");

    let composed = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_COMPOSE_RESOURCE_URI),
    )
    .expect("live bind_http resources/read must compose a nested tool call and resource read");
    assert!(
        matches!(
            composed.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }]
                if text == "compose:tool:alpha|resource:deterministic"
        ),
        "resource ctx.call_tool and ctx.read_resource must reach the live peer handlers: {composed:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the nested tools/call must invoke the peer tool exactly once"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "the nested resources/read must invoke the peer resource exactly once"
    );

    let missing_tool = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_COMPOSE_MISSING_TOOL_RESOURCE_URI),
    );
    let missing_tool = match missing_tool {
        Ok(result) => panic!(
            "changing only the nested tool name must refuse before the peer handlers run: {result:?}"
        ),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        missing_tool.contains("public-http-e2e-missing")
            || missing_tool.contains("Unknown tool")
            || missing_tool.contains("not found")
            || missing_tool.contains("MethodNotFound")
            || missing_tool.contains("compose-nested-tool"),
        "the nested unknown tool must stay a handler-visible refusal: {missing_tool}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "an unknown nested tool name must not invoke the peer tool"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "an unknown nested tool name must not reach the peer resource"
    );

    let missing_resource = runtime_block_on_bounded(
        &cx,
        client.read_resource(&cx, PUBLIC_HTTP_COMPOSE_MISSING_RESOURCE_URI),
    );
    let missing_resource = match missing_resource {
        Ok(result) => panic!(
            "changing only the nested resource URI must refuse after the peer tool runs: {result:?}"
        ),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        missing_resource.contains("test://public-http-e2e/missing")
            || missing_resource.contains("not found")
            || missing_resource.contains("ResourceNotFound")
            || missing_resource.contains("compose-nested-resource"),
        "the nested unknown resource must stay a handler-visible refusal: {missing_resource}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        2,
        "the peer tool must still run when only the nested resource URI changes"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "an unknown nested resource URI must not invoke the peer resource"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_json_only_accept_composes_nested_tool_and_resource() {
    const MAX_NATIVE_HTTP_RESPONSE_BYTES: usize = 1 << 20;

    fn exchange(address: SocketAddr, body: &[u8]) -> Vec<u8> {
        let mut stream = std::net::TcpStream::connect_timeout(&address, HTTP_OPERATION_BOUND)
            .expect("JSON-only client connects to the compose listener");
        stream
            .set_read_timeout(Some(HTTP_OPERATION_BOUND))
            .expect("JSON-only client read deadline is configured");
        stream
            .set_write_timeout(Some(HTTP_OPERATION_BOUND))
            .expect("JSON-only client write deadline is configured");
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: {address}\r\nAccept: application/json\r\nContent-Type: application/json\r\nMCP-Protocol-Version: {}\r\nMcp-Method: tools/call\r\nMcp-Name: {PUBLIC_HTTP_COMPOSE_TOOL_NAME}\r\nContent-Length: {}\r\n\r\n",
            modern::PROTOCOL_VERSION,
            body.len(),
        );
        stream
            .write_all(request.as_bytes())
            .and_then(|()| stream.write_all(body))
            .expect("JSON-only compose request commits");
        let mut response = Vec::new();
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let read = stream
                .read(&mut buffer)
                .expect("JSON-only compose response reads within its deadline");
            if read == 0 {
                break;
            }
            assert!(
                response
                    .len()
                    .checked_add(read)
                    .is_some_and(|size| size <= MAX_NATIVE_HTTP_RESPONSE_BYTES),
                "JSON-only compose response exceeds the bounded budget"
            );
            response.extend_from_slice(&buffer[..read]);
        }
        response
    }

    fn response_json_body(response: &[u8]) -> serde_json::Value {
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("JSON-only response contains a header terminator");
        let headers = std::str::from_utf8(&response[..header_end])
            .expect("JSON-only response headers are ASCII");
        let body = &response[header_end + 4..];
        let content_length = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        });
        let decoded = if headers.lines().any(|line| {
            line.to_ascii_lowercase()
                .contains("transfer-encoding: chunked")
        }) {
            let mut cursor = 0;
            let mut decoded = Vec::new();
            loop {
                let size_end = body[cursor..]
                    .windows(2)
                    .position(|window| window == b"\r\n")
                    .map(|offset| cursor + offset)
                    .expect("chunked JSON response contains a chunk-size line");
                let size_line =
                    std::str::from_utf8(&body[cursor..size_end]).expect("chunk size is ASCII");
                let size =
                    usize::from_str_radix(size_line.split(';').next().unwrap_or_default(), 16)
                        .expect("chunk size is hexadecimal");
                cursor = size_end + 2;
                if size == 0 {
                    break decoded;
                }
                let chunk_end = cursor
                    .checked_add(size)
                    .expect("chunk length does not overflow");
                decoded.extend_from_slice(&body[cursor..chunk_end]);
                cursor = chunk_end + 2;
            }
        } else {
            let content_length =
                content_length.expect("JSON response uses Content-Length or chunked framing");
            body[..content_length].to_vec()
        };
        serde_json::from_slice(&decoded).expect("JSON-only compose response is JSON-RPC")
    }

    let server = spawn_modern_compose_and_state_http_server();
    let tool = JsonRpcRequest::new(
        "tools/call",
        Some(json!({
            "name": PUBLIC_HTTP_COMPOSE_TOOL_NAME,
            "arguments": {"value": "alpha"},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": modern::PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        })),
        7_i64,
    );
    let tool_body = serde_json::to_vec(&tool).expect("JSON-only compose request serializes");
    let admitted = exchange(server.address(), &tool_body);
    assert!(
        admitted.starts_with(b"HTTP/1.1 200"),
        "JSON-only Accept must admit composed tools/call: {}",
        String::from_utf8_lossy(&admitted)
    );
    let admitted = response_json_body(&admitted);
    assert!(
        admitted.get("error").is_none(),
        "JSON-only compose must not be a JSON-RPC error: {admitted}"
    );
    let content = admitted["result"]["content"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        content.iter().any(|block| {
            block["text"].as_str() == Some("compose:tool:alpha|resource:deterministic")
        }),
        "JSON-only Accept must compose through the same request-owned callers: {admitted}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "JSON-only compose must invoke the nested tool once"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "JSON-only compose must invoke the nested resource once"
    );

    let missing = JsonRpcRequest::new(
        "tools/call",
        Some(json!({
            "name": PUBLIC_HTTP_COMPOSE_TOOL_NAME,
            "arguments": {"value": "alpha", "tool": "public-http-e2e-missing"},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": modern::PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        })),
        8_i64,
    );
    let missing_body =
        serde_json::to_vec(&missing).expect("JSON-only missing-tool request serializes");
    let refused = exchange(server.address(), &missing_body);
    let refused = response_json_body(&refused);
    let refused_text = format!("{refused:?}");
    assert!(
        refused_text.contains("public-http-e2e-missing")
            || refused_text.contains("compose-nested-tool"),
        "JSON-only compose must keep the nested unknown tool visible: {refused}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "a nested unknown tool name must not invoke the peer tool"
    );
    server.shutdown();
}

#[test]
fn e2e_public_http_session_state_is_request_local_across_posts() {
    let cx = Cx::for_request();
    let server = spawn_modern_compose_and_state_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-state", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the session-state HTTP server");

    let written = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PUBLIC_HTTP_STATE_TOOL_NAME,
            json!({"action": "write", "value": "alpha"}),
        ),
    )
    .expect("live bind_http must write request-local session state");
    assert!(
        written.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "state:alpha",
            _ => false,
        }),
        "set_state then get_state on the same POST must retain the value: {written:?}"
    );

    let later_read = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_STATE_TOOL_NAME, json!({"action": "read"})),
    )
    .expect("a later POST must still be admitted");
    assert!(
        later_read.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "state:missing",
            _ => false,
        }),
        "changing only the POST must not reuse the previous request-local bag: {later_read:?}"
    );

    let removed = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PUBLIC_HTTP_STATE_TOOL_NAME,
            json!({"action": "write", "value": "beta"}),
        ),
    )
    .expect("a later write must still succeed on a fresh request-local bag");
    assert!(
        removed.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "state:beta",
            _ => false,
        }),
        "a later POST write must see only its own bag: {removed:?}"
    );

    drop(client);
    server.shutdown();
}

fn spawn_modern_caps_http_server(with_resource: bool) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("caps HTTP server control receiver went away".to_owned());
            }
            let builder =
                modern::ServerBuilder::new("facade-http-caps", "1.0.0").tool(PublicHttpCapsTool);
            let builder = if with_resource {
                builder.resource(PublicHttpSnapshotResource)
            } else {
                builder
            };
            let server = builder.build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("caps facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("caps facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("caps HTTP server startup receiver went away".to_owned());
            }
            bound
                .serve(&cx)
                .await
                .map_err(|error| format!("caps facade HTTP server stopped unexpectedly: {error}"))
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("caps facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("caps facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("caps facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

fn advertised_caps_text(result: &FinalCallToolResult) -> String {
    result
        .content
        .iter()
        .find_map(|content| match content {
            ContentBlock::Text { text, .. } => Some(text.clone()),
            _ => None,
        })
        .unwrap_or_else(|| format!("missing text: {result:?}"))
}

#[test]
fn e2e_public_http_handler_sees_client_and_server_capabilities() {
    let cx = Cx::for_request();
    let with_resources = spawn_modern_caps_http_server(true);
    let without_resources = spawn_modern_caps_http_server(false);

    let mut default_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-caps-default", "1.0.0")
            .connect_http_with_cx(public_http_target(with_resources.address(), "/mcp"), &cx),
    )
    .expect("the default ModernOnly client connects to the capability HTTP server");
    let default = runtime_block_on_bounded(
        &cx,
        default_client.call_tool(&cx, PUBLIC_HTTP_CAPS_TOOL_NAME, json!({})),
    )
    .expect("default client tools/call must reach the capability handler");
    assert_eq!(
        advertised_caps_text(&default),
        "caps:sampling=false;roots=false;tools=true;resources=true",
        "a default client must not invent sampling/roots, and a resource-bearing server must advertise both"
    );

    let mut sampling_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-caps-sampling", "1.0.0")
            .capabilities(ClientCapabilities {
                sampling: Some(Default::default()),
                elicitation: None,
                roots: Some(Default::default()),
            })
            .connect_http_with_cx(public_http_target(with_resources.address(), "/mcp"), &cx),
    )
    .expect("the sampling/roots ModernOnly client connects to the capability HTTP server");
    let sampling = runtime_block_on_bounded(
        &cx,
        sampling_client.call_tool(&cx, PUBLIC_HTTP_CAPS_TOOL_NAME, json!({})),
    )
    .expect("sampling client tools/call must reach the capability handler");
    assert_eq!(
        advertised_caps_text(&sampling),
        "caps:sampling=true;roots=true;tools=true;resources=true",
        "advertising only sampling and roots must flip those client flags without changing the server slice"
    );

    let mut bare_server_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-caps-bare", "1.0.0")
            .connect_http_with_cx(public_http_target(without_resources.address(), "/mcp"), &cx),
    )
    .expect("the default client connects to the tool-only capability HTTP server");
    let bare = runtime_block_on_bounded(
        &cx,
        bare_server_client.call_tool(&cx, PUBLIC_HTTP_CAPS_TOOL_NAME, json!({})),
    )
    .expect("tool-only server tools/call must reach the capability handler");
    assert_eq!(
        advertised_caps_text(&bare),
        "caps:sampling=false;roots=false;tools=true;resources=false",
        "omitting the resource registration must clear only the handler-visible resources flag"
    );

    drop(default_client);
    drop(sampling_client);
    drop(bare_server_client);
    with_resources.shutdown();
    without_resources.shutdown();
}

fn spawn_modern_instructions_http_server(with_instructions: bool) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("instructions HTTP server control receiver went away".to_owned());
            }
            let builder = modern::ServerBuilder::new("facade-http-instructions", "1.0.0")
                .tool(PublicHttpValue);
            let builder = if with_instructions {
                builder.instructions(PUBLIC_HTTP_INSTRUCTIONS)
            } else {
                builder
            };
            let server = builder.build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("instructions facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("instructions facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("instructions HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("instructions facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("instructions facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("instructions facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("instructions facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

fn spawn_modern_lifespan_http_server(
    startup: Option<Arc<AtomicBool>>,
    shutdown: Option<Arc<AtomicBool>>,
) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("lifespan HTTP server control receiver went away".to_owned());
            }
            let builder =
                modern::ServerBuilder::new("facade-http-lifespan", "1.0.0").tool(PublicHttpValue);
            let builder = match startup {
                Some(flag) => builder.on_startup(move || -> Result<(), std::io::Error> {
                    flag.store(true, Ordering::SeqCst);
                    Ok(())
                }),
                None => builder,
            };
            let builder = match shutdown {
                Some(flag) => builder.on_shutdown(move || {
                    flag.store(true, Ordering::SeqCst);
                }),
                None => builder,
            };
            let server = builder.build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("lifespan facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("lifespan facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("lifespan HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("lifespan facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup_guard = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup_guard.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("lifespan facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("lifespan facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup_guard.resume_thread_panic_if_finished();
                panic!("lifespan facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup_guard.capture_server_cx();
    let (server_cx, finished, join) = startup_guard.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_discovery_retains_instructions_and_peer_stays_bare() {
    let cx = Cx::for_request();
    let instructed = spawn_modern_instructions_http_server(true);
    let bare = spawn_modern_instructions_http_server(false);
    let instructed_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-instructions", "1.0.0")
            .connect_http_with_cx(public_http_target(instructed.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the instructed HTTP server");
    let bare_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-instructions-bare", "1.0.0")
            .connect_http_with_cx(public_http_target(bare.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the bare HTTP server");

    assert_eq!(
        instructed_client
            .server_discovery()
            .instructions()
            .map(fastmcp_rust::ServerInstructions::as_str),
        Some(PUBLIC_HTTP_INSTRUCTIONS),
        "live bind_http discovery must retain the configured instructions"
    );
    assert_eq!(
        bare_client.server_discovery().instructions(),
        None,
        "changing only the missing instructions must keep the peer bare"
    );

    drop(instructed_client);
    drop(bare_client);
    instructed.shutdown();
    bare.shutdown();
}

fn spawn_legacy_instructions_http_server(with_instructions: bool) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy instructions HTTP server control receiver went away".to_owned());
            }
            let builder = ServerBuilder::new("facade-http-legacy-instructions", "1.0.0")
                .protocol_policy(ProtocolPolicy::LegacyOnly)
                .expect("LegacyOnly is available")
                .tool(PublicHttpValue);
            let builder = if with_instructions {
                builder.instructions(PUBLIC_HTTP_INSTRUCTIONS)
            } else {
                builder
            };
            let server = builder.build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message =
                        format!("legacy instructions facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("legacy instructions facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy instructions HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("legacy instructions facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("legacy instructions facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => {
                panic!("legacy instructions facade HTTP server failed to start: {error}")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("legacy instructions facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_legacy_initialize_retains_instructions_and_peer_stays_bare() {
    let cx = Cx::for_request();
    let instructed = spawn_legacy_instructions_http_server(true);
    let bare = spawn_legacy_instructions_http_server(false);
    let instructed_client = runtime_block_on_bounded(
        &cx,
        legacy_2024::http_client_builder(
            public_http_target(instructed.address(), "/sse"),
            public_http_target(instructed.address(), "/messages"),
        )
        .expect("the exact-2024 instructed HTTP endpoints form one public facade plan")
        .client_info("e2e-public-http-legacy-instructions", "1.0.0")
        .connect_http_client_with_cx(&cx),
    )
    .expect("the LegacyOnly public facade connects to the instructed HTTP server");
    let bare_client = runtime_block_on_bounded(
        &cx,
        legacy_2024::http_client_builder(
            public_http_target(bare.address(), "/sse"),
            public_http_target(bare.address(), "/messages"),
        )
        .expect("the exact-2024 bare HTTP endpoints form one public facade plan")
        .client_info("e2e-public-http-legacy-instructions-bare", "1.0.0")
        .connect_http_client_with_cx(&cx),
    )
    .expect("the LegacyOnly public facade connects to the bare HTTP server");

    assert_eq!(
        instructed_client.instructions(),
        Some(PUBLIC_HTTP_INSTRUCTIONS),
        "live exact-2024 bind_http initialize must retain the configured instructions"
    );
    assert_eq!(
        bare_client.instructions(),
        None,
        "changing only the missing instructions must keep the peer bare"
    );

    drop(instructed_client);
    drop(bare_client);
    instructed.shutdown();
    bare.shutdown();
}

fn spawn_legacy_catalog_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy catalog HTTP server control receiver went away".to_owned());
            }
            let server = ServerBuilder::new("facade-http-legacy-catalog", "1.0.0")
                .protocol_policy(ProtocolPolicy::LegacyOnly)
                .expect("LegacyOnly is available")
                .tool(PublicHttpValue)
                .tool(PublicHttpTouchTool)
                .tool(PublicHttpHideTool)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("legacy catalog facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("legacy catalog facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy catalog HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("legacy catalog facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("legacy catalog facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("legacy catalog facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("legacy catalog facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

fn take_legacy_http_notifications_until(
    client: &mut legacy_2024::HttpClient,
    deadline: Instant,
) -> Vec<legacy_2024::ServerNotification> {
    let mut notifications = Vec::new();
    loop {
        match client.take_server_notification() {
            Ok(Some(notification)) => notifications.push(notification),
            Ok(None) => {
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("exact-2024 HTTP SSE notification must decode: {error}"),
        }
    }
    notifications
}

#[test]
fn e2e_public_http_legacy_tools_list_changed_is_retained_on_sse() {
    let cx = Cx::for_request();
    let server = spawn_legacy_catalog_http_server();
    let mut client = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 catalog HTTP connect",
        legacy_2024::http_client_builder(
            public_http_target(server.address(), "/sse"),
            public_http_target(server.address(), "/messages"),
        )
        .expect("the exact-2024 catalog HTTP endpoints form one public facade plan")
        .client_info("e2e-public-http-legacy-list-changed", "1.0.0")
        .connect_http_client_with_cx(&cx),
    )
    .expect("the LegacyOnly public facade connects to the catalog HTTP server");

    let quiet = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 non-mutating tools/call",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_TOOL_NAME.to_owned(),
                arguments: Some(json!({ "value": "quiet" })),
                meta: None,
            },
        ),
    )
    .expect("a non-mutating exact-2024 tools/call must complete");
    assert!(
        serde_json::to_value(&quiet)
            .ok()
            .and_then(|value| value["content"][0]["text"].as_str().map(str::to_owned))
            .as_deref()
            == Some("tool:quiet"),
        "the non-mutating peer must still return its text: {quiet:?}"
    );
    let silent = take_legacy_http_notifications_until(
        &mut client,
        Instant::now() + Duration::from_millis(150),
    );
    assert!(
        !silent.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::ToolsListChanged
        )),
        "changing only the missing catalog mutation must keep tools/list_changed silent: {silent:?}"
    );

    let hidden = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 hide tools/call",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_HIDE_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("disabling a peer tool must complete");
    assert!(
        serde_json::to_value(&hidden)
            .ok()
            .and_then(|value| value["content"][0]["text"].as_str().map(str::to_owned))
            .as_deref()
            == Some("hidden"),
        "exact-2024 SSE session state must let disable_tool publish list_changed: {hidden:?}"
    );
    let changed =
        take_legacy_http_notifications_until(&mut client, Instant::now() + Duration::from_secs(1));
    assert!(
        changed.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::ToolsListChanged
        )),
        "live exact-2024 HTTP SSE must retain notifications/tools/list_changed: {changed:?}"
    );

    drop(client);
    server.shutdown();
}

fn spawn_legacy_progress_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy progress HTTP server control receiver went away".to_owned());
            }
            let server = ServerBuilder::new("facade-http-legacy-progress", "1.0.0")
                .protocol_policy(ProtocolPolicy::LegacyOnly)
                .expect("LegacyOnly is available")
                .tool(PublicHttpProgressTool)
                .resource(PublicHttpProgressResource)
                .prompt(PublicHttpProgressPrompt)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message =
                        format!("legacy progress facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("legacy progress facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy progress HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("legacy progress facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("legacy progress facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => {
                panic!("legacy progress facade HTTP server failed to start: {error}")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("legacy progress facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

fn legacy_http_progress_meta(
    marker: legacy_2024::ProgressMarker,
) -> Option<legacy_2024::RequestMeta> {
    Some(legacy_2024::RequestMeta {
        progress_marker: Some(marker),
    })
}

#[test]
fn e2e_public_http_legacy_progress_marker_is_retained_on_sse() {
    let cx = Cx::for_request();
    let server = spawn_legacy_progress_http_server();
    let mut client = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 progress HTTP connect",
        legacy_2024::http_client_builder(
            public_http_target(server.address(), "/sse"),
            public_http_target(server.address(), "/messages"),
        )
        .expect("the exact-2024 progress HTTP endpoints form one public facade plan")
        .client_info("e2e-public-http-legacy-progress", "1.0.0")
        .connect_http_client_with_cx(&cx),
    )
    .expect("the LegacyOnly public facade connects to the progress HTTP server");

    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 progress tools/call without token",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_PROGRESS_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("a tools/call without a progress token still completes");
    let silent = take_legacy_http_notifications_until(
        &mut client,
        Instant::now() + Duration::from_millis(150),
    );
    assert!(
        !silent.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Progress(_)
        )),
        "without a progressToken the exact-2024 HTTP tool must stay silent: {silent:?}"
    );

    let marker = legacy_2024::ProgressMarker::from("http-legacy-progress");
    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 progress tools/call with token",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_PROGRESS_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: legacy_http_progress_meta(marker.clone()),
            },
        ),
    )
    .expect("a progressToken must not prevent the exact-2024 HTTP tool from completing");
    let progress =
        take_legacy_http_notifications_until(&mut client, Instant::now() + Duration::from_secs(1));
    assert!(
        progress.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Progress(params)
                if params.progress_marker == marker
                    && params.message.as_deref() == Some("halfway")
        )),
        "live exact-2024 HTTP SSE must retain notifications/progress after a progressToken: {progress:?}"
    );

    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 progress resources/read without token",
        client.read_resource(
            &cx,
            legacy_2024::ReadResourceParams {
                uri: PUBLIC_HTTP_PROGRESS_RESOURCE_URI.to_owned(),
                meta: None,
            },
        ),
    )
    .expect("a resources/read without a progress token still completes");
    let silent_resource = take_legacy_http_notifications_until(
        &mut client,
        Instant::now() + Duration::from_millis(150),
    );
    assert!(
        !silent_resource.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Progress(_)
        )),
        "without a progressToken the exact-2024 HTTP resource must stay silent: {silent_resource:?}"
    );

    let resource_marker = legacy_2024::ProgressMarker::from("http-legacy-resource-progress");
    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 progress resources/read with token",
        client.read_resource(
            &cx,
            legacy_2024::ReadResourceParams {
                uri: PUBLIC_HTTP_PROGRESS_RESOURCE_URI.to_owned(),
                meta: legacy_http_progress_meta(resource_marker.clone()),
            },
        ),
    )
    .expect("a progressToken must not prevent the exact-2024 HTTP resource from completing");
    let resource_progress =
        take_legacy_http_notifications_until(&mut client, Instant::now() + Duration::from_secs(1));
    assert!(
        resource_progress.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Progress(params)
                if params.progress_marker == resource_marker
                    && params.message.as_deref() == Some("resource-halfway")
        )),
        "live exact-2024 HTTP SSE must retain resource notifications/progress after a progressToken: {resource_progress:?}"
    );

    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 progress prompts/get without token",
        client.get_prompt(
            &cx,
            legacy_2024::GetPromptParams {
                name: PUBLIC_HTTP_PROGRESS_PROMPT_NAME.to_owned(),
                arguments: None,
                meta: None,
            },
        ),
    )
    .expect("a prompts/get without a progress token still completes");
    let silent_prompt = take_legacy_http_notifications_until(
        &mut client,
        Instant::now() + Duration::from_millis(150),
    );
    assert!(
        !silent_prompt.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Progress(_)
        )),
        "without a progressToken the exact-2024 HTTP prompt must stay silent: {silent_prompt:?}"
    );

    let prompt_marker = legacy_2024::ProgressMarker::from("http-legacy-prompt-progress");
    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 progress prompts/get with token",
        client.get_prompt(
            &cx,
            legacy_2024::GetPromptParams {
                name: PUBLIC_HTTP_PROGRESS_PROMPT_NAME.to_owned(),
                arguments: None,
                meta: legacy_http_progress_meta(prompt_marker.clone()),
            },
        ),
    )
    .expect("a progressToken must not prevent the exact-2024 HTTP prompt from completing");
    let prompt_progress =
        take_legacy_http_notifications_until(&mut client, Instant::now() + Duration::from_secs(1));
    assert!(
        prompt_progress.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Progress(params)
                if params.progress_marker == prompt_marker
                    && params.message.as_deref() == Some("prompt-halfway")
        )),
        "live exact-2024 HTTP SSE must retain prompt notifications/progress after a progressToken: {prompt_progress:?}"
    );

    drop(client);
    server.shutdown();
}

fn spawn_legacy_log_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy log HTTP server control receiver went away".to_owned());
            }
            let server = ServerBuilder::new("facade-http-legacy-log", "1.0.0")
                .protocol_policy(ProtocolPolicy::LegacyOnly)
                .expect("LegacyOnly is available")
                .tool(PublicHttpLogTool)
                .resource(PublicHttpLogResource)
                .prompt(PublicHttpLogPrompt)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("legacy log facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("legacy log facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy log HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("legacy log facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("legacy log facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("legacy log facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("legacy log facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

fn legacy_http_log_message_is(
    notification: &legacy_2024::ServerNotification,
    expected: &str,
) -> bool {
    matches!(
        notification,
        legacy_2024::ServerNotification::Message(message)
            if message.level == legacy_2024::LogLevel::Info
                && message.data == json!(expected)
    )
}

#[test]
fn e2e_public_http_legacy_ctx_info_is_retained_on_sse() {
    let cx = Cx::for_request();
    let server = spawn_legacy_log_http_server();
    let mut client = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 log HTTP connect",
        legacy_2024::http_client_builder(
            public_http_target(server.address(), "/sse"),
            public_http_target(server.address(), "/messages"),
        )
        .expect("the exact-2024 log HTTP endpoints form one public facade plan")
        .client_info("e2e-public-http-legacy-log", "1.0.0")
        .connect_http_client_with_cx(&cx),
    )
    .expect("the LegacyOnly public facade connects to the log HTTP server");

    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 tools/call before setLevel",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_LOG_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("ctx.info must not prevent the exact-2024 HTTP tool from completing");
    let silent = take_legacy_http_notifications_until(
        &mut client,
        Instant::now() + Duration::from_millis(150),
    );
    assert!(
        !silent.iter().any(|notification| legacy_http_log_message_is(
            notification,
            PUBLIC_HTTP_HANDLER_LOG_TEXT
        )),
        "omitting only logging/setLevel must keep exact-2024 HTTP ctx.info silent: {silent:?}"
    );

    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 logging/setLevel Info",
        client.set_log_level(&cx, legacy_2024::LogLevel::Info),
    )
    .expect("exact-2024 HTTP logging/setLevel must be admitted");
    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 tools/call after setLevel Info",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_LOG_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("ctx.info must not prevent the exact-2024 HTTP tool from completing");
    let info =
        take_legacy_http_notifications_until(&mut client, Instant::now() + Duration::from_secs(1));
    assert!(
        info.iter().any(|notification| legacy_http_log_message_is(
            notification,
            PUBLIC_HTTP_HANDLER_LOG_TEXT
        )),
        "live exact-2024 HTTP SSE must retain ctx.info after set_log_level(Info): {info:?}"
    );

    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 resources/read after setLevel Info",
        client.read_resource(
            &cx,
            legacy_2024::ReadResourceParams {
                uri: PUBLIC_HTTP_LOG_RESOURCE_URI.to_owned(),
                meta: None,
            },
        ),
    )
    .expect("ctx.info must not prevent the exact-2024 HTTP resource from completing");
    let resource_info =
        take_legacy_http_notifications_until(&mut client, Instant::now() + Duration::from_secs(1));
    assert!(
        resource_info
            .iter()
            .any(|notification| legacy_http_log_message_is(
                notification,
                PUBLIC_HTTP_RESOURCE_LOG_TEXT
            )),
        "live exact-2024 HTTP SSE must retain resource ctx.info after set_log_level(Info): {resource_info:?}"
    );

    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 prompts/get after setLevel Info",
        client.get_prompt(
            &cx,
            legacy_2024::GetPromptParams {
                name: PUBLIC_HTTP_LOG_PROMPT_NAME.to_owned(),
                arguments: None,
                meta: None,
            },
        ),
    )
    .expect("ctx.info must not prevent the exact-2024 HTTP prompt from completing");
    let prompt_info =
        take_legacy_http_notifications_until(&mut client, Instant::now() + Duration::from_secs(1));
    assert!(
        prompt_info
            .iter()
            .any(|notification| legacy_http_log_message_is(
                notification,
                PUBLIC_HTTP_PROMPT_LOG_TEXT
            )),
        "live exact-2024 HTTP SSE must retain prompt ctx.info after set_log_level(Info): {prompt_info:?}"
    );

    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 logging/setLevel Emergency",
        client.set_log_level(&cx, legacy_2024::LogLevel::Emergency),
    )
    .expect("raising the exact-2024 HTTP log floor must be admitted");
    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 tools/call after setLevel Emergency",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_LOG_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("raising the log floor must not prevent the exact-2024 HTTP tool from completing");
    let emergency = take_legacy_http_notifications_until(
        &mut client,
        Instant::now() + Duration::from_millis(150),
    );
    assert!(
        !emergency
            .iter()
            .any(|notification| legacy_http_log_message_is(
                notification,
                PUBLIC_HTTP_HANDLER_LOG_TEXT
            )),
        "raising only the logLevel floor must suppress exact-2024 HTTP ctx.info: {emergency:?}"
    );

    drop(client);
    server.shutdown();
}

fn spawn_legacy_subscription_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy subscription HTTP server control receiver went away".to_owned());
            }
            let server = ServerBuilder::new("facade-http-legacy-subscription", "1.0.0")
                .protocol_policy(ProtocolPolicy::LegacyOnly)
                .expect("LegacyOnly is available")
                .resource(PublicHttpWatchResource)
                .prompt(PublicHttpCatalogPrompt)
                .tool(PublicHttpTouchTool)
                .tool(PublicHttpHideCatalogTool)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message =
                        format!("legacy subscription facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("legacy subscription facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy subscription HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("legacy subscription facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("legacy subscription facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => {
                panic!("legacy subscription facade HTTP server failed to start: {error}")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("legacy subscription facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

fn connect_legacy_subscription_http_client(
    cx: &Cx,
    address: SocketAddr,
    name: &str,
) -> legacy_2024::HttpClient {
    runtime_block_on_bounded_named(
        cx,
        "exact-2024 subscription HTTP connect",
        legacy_2024::http_client_builder(
            public_http_target(address, "/sse"),
            public_http_target(address, "/messages"),
        )
        .expect("the exact-2024 subscription HTTP endpoints form one public facade plan")
        .client_info(name, "1.0.0")
        .connect_http_client_with_cx(cx),
    )
    .expect("the LegacyOnly public facade connects to the subscription HTTP server")
}

fn legacy_http_tool_text(result: &legacy_2024::CallToolResult) -> Option<String> {
    serde_json::to_value(result)
        .ok()
        .and_then(|value| value["content"][0]["text"].as_str().map(str::to_owned))
}

#[test]
fn e2e_public_http_legacy_resource_updated_is_retained_on_sse() {
    let cx = Cx::for_request();
    let server = spawn_legacy_subscription_http_server();
    let mut client = connect_legacy_subscription_http_client(
        &cx,
        server.address(),
        "e2e-public-http-legacy-updated",
    );

    let silent_touch = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 resources/updated touch without subscribe",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_TOUCH_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("touching an unsubscribed resource must complete");
    assert_eq!(
        legacy_http_tool_text(&silent_touch).as_deref(),
        Some("silent"),
        "without resources/subscribe the handler must not claim updated delivery: {silent_touch:?}"
    );
    let silent = take_legacy_http_notifications_until(
        &mut client,
        Instant::now() + Duration::from_millis(150),
    );
    assert!(
        !silent.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::ResourceUpdated(_)
        )),
        "omitting only resources/subscribe must keep resources/updated silent: {silent:?}"
    );

    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 resources/subscribe",
        client.subscribe_resource(
            &cx,
            legacy_2024::SubscribeResourceParams {
                uri: PUBLIC_HTTP_WATCH_RESOURCE_URI.to_owned(),
            },
        ),
    )
    .expect("exact-2024 HTTP resources/subscribe must be admitted");
    let touched = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 resources/updated touch after subscribe",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_TOUCH_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("touching a subscribed resource must complete");
    assert_eq!(
        legacy_http_tool_text(&touched).as_deref(),
        Some("notified"),
        "resources/subscribe must count as notify_resource_updated delivery: {touched:?}"
    );
    let updated =
        take_legacy_http_notifications_until(&mut client, Instant::now() + Duration::from_secs(1));
    assert!(
        updated.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::ResourceUpdated(params)
                if params.uri == PUBLIC_HTTP_WATCH_RESOURCE_URI
        )),
        "live exact-2024 HTTP SSE must retain notifications/resources/updated: {updated:?}"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_legacy_resource_unsubscribe_stops_updated_notifications() {
    let cx = Cx::for_request();
    let server = spawn_legacy_subscription_http_server();
    let mut client = connect_legacy_subscription_http_client(
        &cx,
        server.address(),
        "e2e-public-http-legacy-unsubscribe",
    );

    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 resources/subscribe before unsubscribe",
        client.subscribe_resource(
            &cx,
            legacy_2024::SubscribeResourceParams {
                uri: PUBLIC_HTTP_WATCH_RESOURCE_URI.to_owned(),
            },
        ),
    )
    .expect("exact-2024 HTTP resources/subscribe must be admitted");
    let subscribed = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 resources/updated touch after subscribe",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_TOUCH_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("touching a subscribed resource must complete");
    assert_eq!(
        legacy_http_tool_text(&subscribed).as_deref(),
        Some("notified"),
        "resources/subscribe must count as notify_resource_updated delivery: {subscribed:?}"
    );
    let updated =
        take_legacy_http_notifications_until(&mut client, Instant::now() + Duration::from_secs(1));
    assert!(
        updated.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::ResourceUpdated(params)
                if params.uri == PUBLIC_HTTP_WATCH_RESOURCE_URI
        )),
        "the subscribed exact-2024 HTTP SSE session must retain resources/updated: {updated:?}"
    );

    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 resources/unsubscribe",
        client.unsubscribe_resource(
            &cx,
            legacy_2024::UnsubscribeResourceParams {
                uri: PUBLIC_HTTP_WATCH_RESOURCE_URI.to_owned(),
            },
        ),
    )
    .expect("exact-2024 HTTP resources/unsubscribe must be admitted");
    let silent_touch = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 resources/updated touch after unsubscribe",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_TOUCH_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("touching an unsubscribed resource must complete");
    assert_eq!(
        legacy_http_tool_text(&silent_touch).as_deref(),
        Some("silent"),
        "resources/unsubscribe must stop notify_resource_updated delivery: {silent_touch:?}"
    );
    let silent = take_legacy_http_notifications_until(
        &mut client,
        Instant::now() + Duration::from_millis(150),
    );
    assert!(
        !silent.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::ResourceUpdated(_)
        )),
        "changing only resources/unsubscribe must keep later resources/updated silent: {silent:?}"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_legacy_resource_and_prompt_list_changed_are_retained_on_sse() {
    let cx = Cx::for_request();
    let server = spawn_legacy_subscription_http_server();
    let mut client = connect_legacy_subscription_http_client(
        &cx,
        server.address(),
        "e2e-public-http-legacy-catalog",
    );

    let quiet = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 catalog touch without mutation",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_TOUCH_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("a non-mutating exact-2024 tools/call must complete");
    assert_eq!(
        legacy_http_tool_text(&quiet).as_deref(),
        Some("silent"),
        "the unsubscribed touch peer must stay non-mutating: {quiet:?}"
    );
    let silent = take_legacy_http_notifications_until(
        &mut client,
        Instant::now() + Duration::from_millis(150),
    );
    assert!(
        !silent.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::ResourcesListChanged
                | legacy_2024::ServerNotification::PromptsListChanged
        )),
        "changing only the missing catalog mutation must keep resource/prompt list_changed silent: {silent:?}"
    );

    let hidden = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 hide catalog tools/call",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_HIDE_CATALOG_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("disabling a peer resource and prompt must complete");
    assert_eq!(
        legacy_http_tool_text(&hidden).as_deref(),
        Some("hidden"),
        "exact-2024 SSE session state must let disable_resource/disable_prompt publish: {hidden:?}"
    );
    let changed =
        take_legacy_http_notifications_until(&mut client, Instant::now() + Duration::from_secs(1));
    assert!(
        changed.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::ResourcesListChanged
        )),
        "live exact-2024 HTTP SSE must retain notifications/resources/list_changed: {changed:?}"
    );
    assert!(
        changed.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::PromptsListChanged
        )),
        "live exact-2024 HTTP SSE must retain notifications/prompts/list_changed: {changed:?}"
    );

    drop(client);
    server.shutdown();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn spawn_legacy_filesystem_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let root = std::env::temp_dir().join(format!(
        "fastmcp-public-http-legacy-fs-e2e-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("the legacy filesystem e2e root is created");
    std::fs::write(
        root.join(PUBLIC_HTTP_FS_FILE_NAME),
        PUBLIC_HTTP_FS_FILE_TEXT,
    )
    .expect("the legacy filesystem e2e file is written");
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy filesystem HTTP server control receiver went away".to_owned());
            }
            let handler = providers::FilesystemProvider::new(&root)
                .with_prefix(PUBLIC_HTTP_FS_PREFIX)
                .with_exclude(&[])
                .build()
                .map_err(|error| format!("FilesystemProvider::build failed: {error}"))?;
            let server = ServerBuilder::new("facade-http-legacy-filesystem", "1.0.0")
                .protocol_policy(ProtocolPolicy::LegacyOnly)
                .expect("LegacyOnly is available")
                .resource(handler)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message =
                        format!("legacy filesystem facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("legacy filesystem facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy filesystem HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("legacy filesystem facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("legacy filesystem facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => {
                panic!("legacy filesystem facade HTTP server failed to start: {error}")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("legacy filesystem facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn e2e_public_http_legacy_filesystem_provider_lists_and_reads_live_file() {
    let cx = Cx::for_request();
    let server = spawn_legacy_filesystem_http_server();
    let mut client = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 filesystem HTTP connect",
        legacy_2024::http_client_builder(
            public_http_target(server.address(), "/sse"),
            public_http_target(server.address(), "/messages"),
        )
        .expect("the exact-2024 filesystem HTTP endpoints form one public facade plan")
        .client_info("e2e-public-http-legacy-fs", "1.0.0")
        .connect_http_client_with_cx(&cx),
    )
    .expect("the LegacyOnly public facade connects to the filesystem HTTP server");

    let listed = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 resources/templates/list",
        client.list_resource_templates(&cx, legacy_2024::ListResourceTemplatesParams::default()),
    )
    .expect("live exact-2024 bind_http must list the FilesystemProvider template");
    assert!(
        listed
            .resource_templates
            .iter()
            .any(|template| template.uri_template == PUBLIC_HTTP_FS_TEMPLATE
                && template.name == PUBLIC_HTTP_FS_PREFIX),
        "FilesystemProvider must advertise its reversible file template: {:?}",
        listed.resource_templates
    );

    let unmatched = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 unmatched filesystem resources/read",
        client.read_resource(
            &cx,
            legacy_2024::ReadResourceParams {
                uri: "file:///other/note.txt".to_owned(),
                meta: None,
            },
        ),
    )
    .expect_err("changing only the prefix the template cannot bind must refuse before dispatch");
    assert!(
        matches!(
            unmatched,
            legacy_2024::HttpClientError::CoreResult(ref error)
                if error.code == McpErrorCode::ResourceNotFound
        ),
        "an unmatched filesystem URI must stay ResourceNotFound on exact-2024: {unmatched:?}"
    );

    let file = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 matched filesystem resources/read",
        client.read_resource(
            &cx,
            legacy_2024::ReadResourceParams {
                uri: PUBLIC_HTTP_FS_FILE_URI.to_owned(),
                meta: None,
            },
        ),
    )
    .expect("resources/read must expand the live file URI through the filesystem handler");
    let file_text = serde_json::to_value(&file)
        .ok()
        .and_then(|value| value["contents"][0]["text"].as_str().map(str::to_owned));
    assert_eq!(
        file_text.as_deref(),
        Some(PUBLIC_HTTP_FS_FILE_TEXT),
        "the live exact-2024 filesystem read must retain the file bytes: {file:?}"
    );

    drop(client);
    server.shutdown();
}

const PUBLIC_HTTP_SAMPLE_TOOL_NAME: &str = "public-http-e2e-sample";
const PUBLIC_HTTP_SAMPLED_TEXT: &str = "sampled-legacy-http";

/// Live exact-2024 HTTP tool that issues one reverse `sampling/createMessage`.
struct PublicHttpSampleTool;

impl ToolHandler for PublicHttpSampleTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_SAMPLE_TOOL_NAME.to_owned(),
            description: Some("Proves live exact-2024 HTTP sampling reverse JSON-RPC".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Err(McpError::internal_error(
            "public-http-e2e-sample is request-owned async",
        ))
    }

    fn call_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        _arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
        Box::pin(async move {
            match ctx.sample("echo", 16).await {
                Ok(response) => Outcome::Ok(vec![Content::text(response.text)]),
                Err(error) => Outcome::Err(error),
            }
        })
    }
}

fn spawn_legacy_sample_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy sample HTTP server control receiver went away".to_owned());
            }
            let server = ServerBuilder::new("facade-http-legacy-sample", "1.0.0")
                .protocol_policy(ProtocolPolicy::LegacyOnly)
                .expect("LegacyOnly is available")
                .tool(PublicHttpSampleTool)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("legacy sample facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("legacy sample facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy sample HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("legacy sample facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("legacy sample facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("legacy sample facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("legacy sample facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

fn spawn_legacy_complete_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let completion_counters = Arc::clone(&handler_calls);
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy complete HTTP server control receiver went away".to_owned());
            }
            let server = ServerBuilder::new("facade-http-legacy-complete", "1.0.0")
                .protocol_policy(ProtocolPolicy::LegacyOnly)
                .expect("LegacyOnly is available")
                .prompt(PublicHttpCatalogPrompt)
                .legacy_completion_handler(CountingPublicHttpCompletion {
                    counters: completion_counters,
                })
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message =
                        format!("legacy complete facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("legacy complete facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy complete HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("legacy complete facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("legacy complete facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("legacy complete facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("legacy complete facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

fn connect_legacy_http_client(cx: &Cx, address: SocketAddr, name: &str) -> legacy_2024::HttpClient {
    runtime_block_on_bounded_named(
        cx,
        "exact-2024 HTTP connect",
        legacy_2024::http_client_builder(
            public_http_target(address, "/sse"),
            public_http_target(address, "/messages"),
        )
        .expect("the exact-2024 HTTP endpoints form one public facade plan")
        .client_info(name, "1.0.0")
        .connect_http_client_with_cx(cx),
    )
    .expect("the LegacyOnly public facade connects")
}

#[test]
fn e2e_public_http_legacy_ping_is_admitted_and_missing_tool_stays_refused() {
    let cx = Cx::for_request();
    let server = spawn_legacy_instructions_http_server(false);
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-ping");

    runtime_block_on_bounded_named(&cx, "exact-2024 HTTP ping", client.ping(&cx))
        .expect("live exact-2024 HTTP SSE must admit ping");

    let missing = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 missing tools/call after ping",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: "public-http-e2e-missing".to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect_err("changing only the missing tool must keep the session refused");
    assert!(
        matches!(
            missing,
            legacy_2024::HttpClientError::CoreResult(ref error)
                if error.code == McpErrorCode::MethodNotFound
                    || error.code == McpErrorCode::InvalidParams
                    || error.code == McpErrorCode::InvalidRequest
        ),
        "a missing exact-2024 HTTP tool must stay a handler-visible refusal: {missing:?}"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_legacy_complete_is_retained_and_peer_without_handler_is_refused() {
    let cx = Cx::for_request();
    let advertised = spawn_legacy_complete_http_server();
    let omitted = spawn_legacy_instructions_http_server(false);
    let mut advertised_client =
        connect_legacy_http_client(&cx, advertised.address(), "e2e-public-http-legacy-complete");
    let mut omitted_client = connect_legacy_http_client(
        &cx,
        omitted.address(),
        "e2e-public-http-legacy-complete-omitted",
    );

    assert!(
        advertised_client
            .server_capabilities()
            .completions
            .is_some(),
        "installing a legacy completion handler must advertise completions: {:?}",
        advertised_client.server_capabilities()
    );
    assert!(
        omitted_client.server_capabilities().completions.is_none(),
        "changing only the missing completion handler must omit completions: {:?}",
        omitted_client.server_capabilities()
    );

    let params = legacy_2024::LegacyCompletionParams {
        reference: legacy_2024::LegacyCompletionReference::Prompt {
            name: PUBLIC_HTTP_CATALOG_PROMPT_NAME.to_owned(),
        },
        argument: legacy_2024::LegacyCompletionArgument {
            name: "subject".to_owned(),
            value: "cross-era".to_owned(),
        },
    };
    let completed = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP completion/complete",
        advertised_client.complete(&cx, params.clone()),
    )
    .expect("live exact-2024 HTTP SSE must complete when completions are advertised");
    assert_eq!(
        completed.completion.values,
        vec![PUBLIC_HTTP_COMPLETION_VALUE.to_owned()],
        "the advertised exact-2024 completion provider must retain its values: {completed:?}"
    );

    runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP complete without handler",
        omitted_client.complete(&cx, params),
    )
    .expect_err("changing only the missing completion handler must refuse complete");

    drop(advertised_client);
    drop(omitted_client);
    advertised.shutdown();
    omitted.shutdown();
}

#[test]
fn e2e_public_http_legacy_sampling_callback_reaches_context() {
    let cx = Cx::for_request();
    let server = spawn_legacy_sample_http_server();
    let callback_calls = Arc::new(AtomicUsize::new(0));
    let mut client = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 sampling HTTP connect",
        legacy_2024::http_client_builder(
            public_http_target(server.address(), "/sse"),
            public_http_target(server.address(), "/messages"),
        )
        .expect("the exact-2024 sampling HTTP endpoints form one public facade plan")
        .client_info("e2e-public-http-legacy-sample", "1.0.0")
        .capabilities(ClientCapabilities {
            sampling: Some(Default::default()),
            elicitation: None,
            roots: None,
        })
        .reverse_request_handlers(
            legacy_2024::LegacyReverseRequestHandlers::new().with_sampling_create_message({
                let callback_calls = Arc::clone(&callback_calls);
                move |_cx, _cancel, _params| {
                    callback_calls.fetch_add(1, Ordering::Relaxed);
                    Box::pin(async {
                        Ok(legacy_2024::LegacyCreateMessageResult::text(
                            PUBLIC_HTTP_SAMPLED_TEXT,
                            "e2e-legacy-http-model",
                        ))
                    })
                }
            }),
        )
        .connect_http_client_with_cx(&cx),
    )
    .expect("the sampling callback is configured before exact-2024 HTTP initialization");

    let sampled = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 sampling tools/call",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_SAMPLE_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("the sealed exact-2024 HTTP facade must service sampling/createMessage before its typed tool result");
    assert_eq!(
        legacy_http_tool_text(&sampled).as_deref(),
        Some(PUBLIC_HTTP_SAMPLED_TEXT),
        "live exact-2024 HTTP SSE sampling must retain the callback text: {sampled:?}"
    );
    assert_eq!(
        callback_calls.load(Ordering::Relaxed),
        1,
        "the tool's context authority issues exactly one sampling/createMessage callback"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_legacy_sampling_without_capability_has_no_callback_authority() {
    let cx = Cx::for_request();
    let server = spawn_legacy_sample_http_server();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-sample-bare");

    let missing = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 sampling tools/call without capability",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_SAMPLE_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("missing sampling authority remains a typed exact-2024 tool result");
    let text = legacy_http_tool_text(&missing).unwrap_or_default();
    assert!(
        missing.is_error || text.contains("does not support sampling capability"),
        "omitting only the sampling capability must fail closed: {missing:?}"
    );
    assert_ne!(
        text.as_str(),
        PUBLIC_HTTP_SAMPLED_TEXT,
        "a bare peer must not invent a sampling callback result: {missing:?}"
    );

    drop(client);
    server.shutdown();
}

const PUBLIC_HTTP_LEGACY_ROOTS_TOOL_NAME: &str = "public-http-e2e-legacy-roots";
const PUBLIC_HTTP_LEGACY_ROOT_URI: &str = "file:///workspace";

/// Live exact-2024 HTTP tool that issues one reverse `roots/list`.
struct PublicHttpLegacyRootsTool;

impl ToolHandler for PublicHttpLegacyRootsTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_LEGACY_ROOTS_TOOL_NAME.to_owned(),
            description: Some("Proves live exact-2024 HTTP roots/list reverse JSON-RPC".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Err(McpError::internal_error(
            "public-http-e2e-legacy-roots is request-owned async",
        ))
    }

    fn call_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        _arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
        Box::pin(async move {
            match ctx.list_roots().await {
                Ok(roots) => Outcome::Ok(vec![Content::text(
                    roots
                        .first()
                        .map(|root| root.uri.clone())
                        .unwrap_or_else(|| "<no client roots>".to_owned()),
                )]),
                Err(error) => Outcome::Err(error),
            }
        })
    }
}

fn spawn_legacy_roots_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy roots HTTP server control receiver went away".to_owned());
            }
            let server = ServerBuilder::new("facade-http-legacy-roots", "1.0.0")
                .protocol_policy(ProtocolPolicy::LegacyOnly)
                .expect("LegacyOnly is available")
                .tool(PublicHttpLegacyRootsTool)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("legacy roots facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("legacy roots facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy roots HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("legacy roots facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("legacy roots facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("legacy roots facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("legacy roots facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_legacy_roots_callback_reaches_context() {
    let cx = Cx::for_request();
    let server = spawn_legacy_roots_http_server();
    let callback_calls = Arc::new(AtomicUsize::new(0));
    let mut client = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 roots HTTP connect",
        legacy_2024::http_client_builder(
            public_http_target(server.address(), "/sse"),
            public_http_target(server.address(), "/messages"),
        )
        .expect("the exact-2024 roots HTTP endpoints form one public facade plan")
        .client_info("e2e-public-http-legacy-roots", "1.0.0")
        .capabilities(ClientCapabilities {
            sampling: None,
            elicitation: None,
            roots: Some(Default::default()),
        })
        .reverse_request_handlers(
            legacy_2024::LegacyReverseRequestHandlers::new().with_roots_list({
                let callback_calls = Arc::clone(&callback_calls);
                move |_cx, _cancel, _params| {
                    callback_calls.fetch_add(1, Ordering::Relaxed);
                    Box::pin(async {
                        Ok(legacy_2024::ListRootsResult::new(vec![
                            legacy_2024::Root::with_name(PUBLIC_HTTP_LEGACY_ROOT_URI, "workspace"),
                        ]))
                    })
                }
            }),
        )
        .connect_http_client_with_cx(&cx),
    )
    .expect("the roots callback is configured before exact-2024 HTTP initialization");

    let rooted = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 roots tools/call",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_LEGACY_ROOTS_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect(
        "the sealed exact-2024 HTTP facade must service roots/list before its typed tool result",
    );
    assert_eq!(
        legacy_http_tool_text(&rooted).as_deref(),
        Some(PUBLIC_HTTP_LEGACY_ROOT_URI),
        "live exact-2024 HTTP SSE roots must retain the callback URI: {rooted:?}"
    );
    assert_eq!(
        callback_calls.load(Ordering::Relaxed),
        1,
        "the tool's context authority issues exactly one roots/list callback"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_legacy_roots_without_capability_has_no_callback_authority() {
    let cx = Cx::for_request();
    let server = spawn_legacy_roots_http_server();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-roots-bare");

    let missing = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 roots tools/call without capability",
        client.call_tool(
            &cx,
            legacy_2024::CallToolParams {
                name: PUBLIC_HTTP_LEGACY_ROOTS_TOOL_NAME.to_owned(),
                arguments: Some(json!({})),
                meta: None,
            },
        ),
    )
    .expect("missing roots authority remains a typed exact-2024 tool result");
    let text = legacy_http_tool_text(&missing).unwrap_or_default();
    assert!(
        missing.is_error || text.contains("does not support roots capability"),
        "omitting only the roots capability must fail closed: {missing:?}"
    );
    assert_ne!(
        text.as_str(),
        PUBLIC_HTTP_LEGACY_ROOT_URI,
        "a bare peer must not invent a roots callback result: {missing:?}"
    );

    drop(client);
    server.shutdown();
}

fn spawn_legacy_http_server(
    label: &'static str,
    build: impl FnOnce() -> fastmcp_server::Server + Send + 'static,
) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err(format!("{label} HTTP server control receiver went away"));
            }
            let bound = match build().bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("{label} facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message = format!("{label} facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err(format!("{label} HTTP server startup receiver went away"));
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("{label} facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("{label} facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("{label} facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("{label} facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

fn spawn_legacy_timeout_http_server() -> HttpServerFixture {
    spawn_legacy_http_server("legacy timeout", || {
        ServerBuilder::new("facade-http-legacy-timeout", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .tool(PublicHttpSlowTool)
            .tool(PublicHttpFastTool)
            .build()
    })
}

fn spawn_legacy_surface_http_server() -> HttpServerFixture {
    spawn_legacy_http_server("legacy surface", || {
        ServerBuilder::new("facade-http-legacy-surface", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .tool(PublicHttpDefault)
            .tool(PublicHttpOutputTool)
            .tool(PublicHttpRichTool)
            .tool(PublicHttpPlainTool)
            .build()
    })
}

fn legacy_http_call(
    cx: &Cx,
    client: &mut legacy_2024::HttpClient,
    name: &str,
    arguments: serde_json::Value,
    label: &'static str,
) -> Result<legacy_2024::CallToolResult, legacy_2024::HttpClientError> {
    runtime_block_on_bounded_named(
        cx,
        label,
        client.call_tool(
            cx,
            legacy_2024::CallToolParams {
                name: name.to_owned(),
                arguments: Some(arguments),
                meta: None,
            },
        ),
    )
}

fn legacy_http_content_value(result: &legacy_2024::CallToolResult) -> serde_json::Value {
    serde_json::to_value(result).expect("exact-2024 HTTP tool result serializes")
}

#[test]
fn e2e_public_http_legacy_handler_timeout_refuses_late_tool_and_admits_fast_peer() {
    let cx = Cx::for_request();
    let server = spawn_legacy_timeout_http_server();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-timeout");

    let timed_out = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_SLOW_TOOL_NAME,
        json!({}),
        "exact-2024 HTTP slow tools/call",
    );
    let timed_out = match timed_out {
        Ok(result) => {
            assert!(
                result.is_error,
                "a handler that outlives its timeout must stay an error result: {result:?}"
            );
            format!("{result:?}")
        }
        Err(error) => format!("{error:?}"),
    };
    assert!(
        timed_out.contains("Request timeout exceeded") || timed_out.contains("RequestCancelled"),
        "the refused late exact-2024 HTTP tools/call must keep the handler-timeout error: {timed_out}"
    );

    let fast = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_FAST_TOOL_NAME,
        json!({}),
        "exact-2024 HTTP fast tools/call",
    )
    .expect("changing only the tool must still be admitted after a handler timeout");
    assert_eq!(
        legacy_http_tool_text(&fast).as_deref(),
        Some("fast"),
        "the fast exact-2024 HTTP peer tool must still complete: {fast:?}"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_legacy_default_parameter_is_injected_and_overridable() {
    let cx = Cx::for_request();
    let server = spawn_legacy_surface_http_server();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-default");

    let listed = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP tools/list defaults",
        client.list_tools(&cx, legacy_2024::ListToolsParams::default()),
    )
    .expect("live exact-2024 HTTP must list the default-parameter tool");
    let default_tool = listed
        .tools
        .iter()
        .find(|tool| tool.name == PUBLIC_HTTP_DEFAULT_TOOL_NAME)
        .expect("the default-parameter tool must remain on the live catalog");
    let required = default_tool
        .input_schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        required.iter().any(|value| value.as_str() == Some("name")),
        "the generated schema must still require name: {default_tool:?}"
    );
    assert!(
        !required
            .iter()
            .any(|value| value.as_str() == Some("suffix")),
        "the defaulted suffix must not stay required: {default_tool:?}"
    );
    assert_eq!(
        default_tool
            .input_schema
            .pointer("/properties/suffix/default")
            .and_then(serde_json::Value::as_str),
        Some(PUBLIC_HTTP_DEFAULT_SUFFIX),
        "exact-2024 HTTP tools/list must retain the generated default: {default_tool:?}"
    );

    let injected = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_DEFAULT_TOOL_NAME,
        json!({"name": "World"}),
        "exact-2024 HTTP default inject",
    )
    .expect("omitting the defaulted argument must still be admitted");
    assert_eq!(
        legacy_http_tool_text(&injected).as_deref(),
        Some("greet:World!"),
        "the generated default must be injected at exact-2024 HTTP call time: {injected:?}"
    );

    let overridden = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_DEFAULT_TOOL_NAME,
        json!({"name": "World", "suffix": "?"}),
        "exact-2024 HTTP default override",
    )
    .expect("supplying the defaulted argument must override the generated default");
    assert_eq!(
        legacy_http_tool_text(&overridden).as_deref(),
        Some("greet:World?"),
        "changing only the suffix must override the generated default: {overridden:?}"
    );

    let missing_name = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_DEFAULT_TOOL_NAME,
        json!({"suffix": "!"}),
        "exact-2024 HTTP missing required default sibling",
    );
    let missing_name = match missing_name {
        Ok(result) => {
            assert!(
                result.is_error,
                "a missing required generated argument must stay an error result: {result:?}"
            );
            format!("{result:?}")
        }
        Err(error) => format!("{error:?}"),
    };
    assert!(
        missing_name.contains("name")
            || missing_name.contains("required")
            || missing_name.contains("schema")
            || missing_name.contains("InvalidParams")
            || missing_name.contains("do not match"),
        "a missing required generated argument must stay a handler-visible refusal: {missing_name}"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_legacy_output_schema_is_listed_and_call_stays_unstructured() {
    let cx = Cx::for_request();
    let server = spawn_legacy_surface_http_server();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-output");

    let listed = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP tools/list output schema",
        client.list_tools(&cx, legacy_2024::ListToolsParams::default()),
    )
    .expect("live exact-2024 HTTP must list the output-schema tools");
    let output_tool = listed
        .tools
        .iter()
        .find(|tool| tool.name == PUBLIC_HTTP_OUTPUT_TOOL_NAME)
        .expect("the output-schema tool must remain on the live catalog");
    let plain_tool = listed
        .tools
        .iter()
        .find(|tool| tool.name == PUBLIC_HTTP_PLAIN_TOOL_NAME)
        .expect("the bare peer tool must remain on the live catalog");
    assert_eq!(
        output_tool
            .output_schema
            .as_ref()
            .and_then(|schema| schema.get("required")),
        Some(&json!(["value"])),
        "exact-2024 HTTP tools/list must retain the advertised output schema: {output_tool:?}"
    );
    assert_eq!(
        plain_tool.output_schema, None,
        "changing only the missing output schema must keep the peer bare: {plain_tool:?}"
    );

    let called = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_OUTPUT_TOOL_NAME,
        json!({"value": "alpha"}),
        "exact-2024 HTTP structured tools/call",
    )
    .expect("live exact-2024 HTTP must admit the structured output tool");
    assert_eq!(
        legacy_http_tool_text(&called).as_deref(),
        Some("tool:alpha"),
        "the structured tool must still author text content: {called:?}"
    );
    let called_value = legacy_http_content_value(&called);
    assert!(
        called_value.get("structuredContent").is_none()
            || called_value.get("structuredContent") == Some(&serde_json::Value::Null),
        "exact-2024 HTTP must not invent structuredContent: {called_value}"
    );

    let peer = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_PLAIN_TOOL_NAME,
        json!({}),
        "exact-2024 HTTP bare peer tools/call",
    )
    .expect("the bare peer tool must still be callable");
    assert_eq!(
        legacy_http_tool_text(&peer).as_deref(),
        Some("plain"),
        "the text-only peer tool must still complete: {peer:?}"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_legacy_rich_content_retains_image_and_peer_stays_text() {
    let cx = Cx::for_request();
    let server = spawn_legacy_surface_http_server();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-rich");

    let rich = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_RICH_TOOL_NAME,
        json!({}),
        "exact-2024 HTTP rich tools/call",
    )
    .expect("live exact-2024 HTTP must retain the representable image block");
    let rich_value = legacy_http_content_value(&rich);
    let content = rich_value
        .get("content")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        content.iter().any(|block| {
            block.get("type").and_then(serde_json::Value::as_str) == Some("image")
                && block.get("data").and_then(serde_json::Value::as_str)
                    == Some(PUBLIC_HTTP_IMAGE_DATA)
                && block.get("mimeType").and_then(serde_json::Value::as_str)
                    == Some(PUBLIC_HTTP_IMAGE_MIME)
        }),
        "exact-2024 HTTP tools/call must retain the authored image block: {rich_value}"
    );
    assert!(
        content.iter().all(|block| {
            block.get("type").and_then(serde_json::Value::as_str) != Some("audio")
        }),
        "exact-2024 HTTP must not invent an audio block: {rich_value}"
    );

    let peer = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_PLAIN_TOOL_NAME,
        json!({}),
        "exact-2024 HTTP text-only peer tools/call",
    )
    .expect("the text-only peer tool must still be callable");
    let peer_value = legacy_http_content_value(&peer);
    let peer_content = peer_value
        .get("content")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        peer_content
            .iter()
            .all(|block| { block.get("type").and_then(serde_json::Value::as_str) == Some("text") }),
        "changing only the missing rich content must keep the peer text-only: {peer_value}"
    );

    drop(client);
    server.shutdown();
}

fn spawn_legacy_lifespan_http_server(
    startup: Option<Arc<AtomicBool>>,
    shutdown: Option<Arc<AtomicBool>>,
) -> HttpServerFixture {
    spawn_legacy_http_server("legacy lifespan", move || {
        let builder = ServerBuilder::new("facade-http-legacy-lifespan", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .tool(PublicHttpValue);
        let builder = match startup {
            Some(flag) => builder.on_startup(move || -> Result<(), std::io::Error> {
                flag.store(true, Ordering::SeqCst);
                Ok(())
            }),
            None => builder,
        };
        let builder = match shutdown {
            Some(flag) => builder.on_shutdown(move || {
                flag.store(true, Ordering::SeqCst);
            }),
            None => builder,
        };
        builder.build()
    })
}

#[test]
fn e2e_public_http_legacy_lifespan_hooks_run_once_and_peer_stays_unhooked() {
    let cx = Cx::for_request();
    let hooked_startup = Arc::new(AtomicBool::new(false));
    let hooked_shutdown = Arc::new(AtomicBool::new(false));
    let bare_startup = Arc::new(AtomicBool::new(false));
    let bare_shutdown = Arc::new(AtomicBool::new(false));
    let hooked = spawn_legacy_lifespan_http_server(
        Some(Arc::clone(&hooked_startup)),
        Some(Arc::clone(&hooked_shutdown)),
    );
    let bare = spawn_legacy_lifespan_http_server(None, None);

    let mut hooked_client =
        connect_legacy_http_client(&cx, hooked.address(), "e2e-public-http-legacy-lifespan");
    let admitted = legacy_http_call(
        &cx,
        &mut hooked_client,
        PUBLIC_HTTP_TOOL_NAME,
        json!({"value": "alpha"}),
        "exact-2024 HTTP tools/call after startup hook",
    )
    .expect("tools/call must be admitted after the startup hook");
    assert_eq!(
        legacy_http_tool_text(&admitted).as_deref(),
        Some("tool:alpha"),
        "the hooked exact-2024 HTTP peer must still return its text: {admitted:?}"
    );
    assert!(
        hooked_startup.load(Ordering::SeqCst),
        "LegacyOnly bind_http serve must run the public startup hook before admitting traffic"
    );
    assert!(
        !hooked_shutdown.load(Ordering::SeqCst),
        "the shutdown hook must not run while the listener is still serving"
    );
    assert!(
        !bare_startup.load(Ordering::SeqCst) && !bare_shutdown.load(Ordering::SeqCst),
        "a peer without hooks must not invent lifespan events"
    );

    drop(hooked_client);
    hooked.shutdown();
    assert!(
        hooked_shutdown.load(Ordering::SeqCst),
        "cooperative exact-2024 HTTP shutdown must run the public shutdown hook"
    );

    let mut bare_client =
        connect_legacy_http_client(&cx, bare.address(), "e2e-public-http-legacy-lifespan-bare");
    legacy_http_call(
        &cx,
        &mut bare_client,
        PUBLIC_HTTP_TOOL_NAME,
        json!({"value": "alpha"}),
        "exact-2024 HTTP tools/call on unhooked peer",
    )
    .expect("the unhooked peer must still admit tools/call");
    drop(bare_client);
    bare.shutdown();
    assert!(
        !bare_startup.load(Ordering::SeqCst) && !bare_shutdown.load(Ordering::SeqCst),
        "changing only the missing hooks must leave the peer unhooked after shutdown"
    );
}

fn spawn_legacy_state_http_server() -> HttpServerFixture {
    spawn_legacy_http_server("legacy state", || {
        ServerBuilder::new("facade-http-legacy-state", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .tool(PublicHttpStateTool)
            .build()
    })
}

#[test]
fn e2e_public_http_legacy_session_state_is_retained_across_sse_calls() {
    let cx = Cx::for_request();
    let server = spawn_legacy_state_http_server();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-state");
    let mut peer =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-state-peer");

    let written = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_STATE_TOOL_NAME,
        json!({"action": "write", "value": "alpha"}),
        "exact-2024 HTTP session state write",
    )
    .expect("live exact-2024 HTTP must write session state");
    assert_eq!(
        legacy_http_tool_text(&written).as_deref(),
        Some("state:alpha"),
        "set_state then get_state on the same SSE session must retain the value: {written:?}"
    );

    let later_read = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_STATE_TOOL_NAME,
        json!({"action": "read"}),
        "exact-2024 HTTP session state later read",
    )
    .expect("a later exact-2024 HTTP tools/call must still be admitted");
    assert_eq!(
        legacy_http_tool_text(&later_read).as_deref(),
        Some("state:alpha"),
        "the same SSE session must reuse the previous bag: {later_read:?}"
    );

    let peer_read = legacy_http_call(
        &cx,
        &mut peer,
        PUBLIC_HTTP_STATE_TOOL_NAME,
        json!({"action": "read"}),
        "exact-2024 HTTP session state peer read",
    )
    .expect("a peer SSE session must still be admitted");
    assert_eq!(
        legacy_http_tool_text(&peer_read).as_deref(),
        Some("state:missing"),
        "changing only the SSE session must not reuse the other session bag: {peer_read:?}"
    );

    drop(client);
    drop(peer);
    server.shutdown();
}

fn spawn_legacy_mask_http_server(mask_error_details: bool) -> HttpServerFixture {
    spawn_legacy_http_server("legacy mask", move || {
        ServerBuilder::new("facade-http-legacy-mask", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .mask_error_details(mask_error_details)
            .resource(PublicHttpLeakResource)
            .build()
    })
}

fn spawn_legacy_rate_limit_http_server() -> HttpServerFixture {
    spawn_legacy_http_server("legacy rate-limit", || {
        ServerBuilder::new("facade-http-legacy-rate-limit", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .middleware(rate_limiting::RateLimitingMiddleware::new(1.0e-300).burst_capacity(1))
            .tool(PublicHttpTouchTool)
            .build()
    })
}

fn spawn_legacy_sliding_window_http_server() -> HttpServerFixture {
    spawn_legacy_http_server("legacy sliding-window", || {
        ServerBuilder::new("facade-http-legacy-sliding-window", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .middleware(rate_limiting::SlidingWindowRateLimitingMiddleware::new(
                1, 60,
            ))
            .tool(PublicHttpTouchTool)
            .build()
    })
}

fn spawn_legacy_strict_validation_http_server(strict: bool) -> HttpServerFixture {
    spawn_legacy_http_server("legacy strict", move || {
        ServerBuilder::new("facade-http-legacy-strict", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .strict_input_validation(strict)
            .tool(PublicHttpValue)
            .build()
    })
}

#[test]
fn e2e_public_http_legacy_mask_error_details_hides_resource_execution_secret() {
    let cx = Cx::for_request();
    let masked_server = spawn_legacy_mask_http_server(true);
    let mut masked_client =
        connect_legacy_http_client(&cx, masked_server.address(), "e2e-public-http-legacy-mask");
    let masked = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 masked resources/read",
        masked_client.read_resource(
            &cx,
            legacy_2024::ReadResourceParams {
                uri: PUBLIC_HTTP_LEAK_RESOURCE_URI.to_owned(),
                meta: None,
            },
        ),
    )
    .expect_err("a leaking resource must stay a resources/read error");
    let masked = format!("{masked:?}");
    assert!(
        masked.contains("Internal server error"),
        "exact-2024 HTTP mask_error_details must replace the execution secret: {masked}"
    );
    assert!(
        !masked.contains(PUBLIC_HTTP_LEAK_SECRET),
        "exact-2024 HTTP mask_error_details must not leak the execution secret: {masked}"
    );
    drop(masked_client);
    masked_server.shutdown();

    let unmasked_server = spawn_legacy_mask_http_server(false);
    let mut unmasked_client = connect_legacy_http_client(
        &cx,
        unmasked_server.address(),
        "e2e-public-http-legacy-unmask",
    );
    let unmasked = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 unmasked resources/read",
        unmasked_client.read_resource(
            &cx,
            legacy_2024::ReadResourceParams {
                uri: PUBLIC_HTTP_LEAK_RESOURCE_URI.to_owned(),
                meta: None,
            },
        ),
    )
    .expect_err("changing only mask_error_details must still refuse the leaking resource");
    let unmasked = format!("{unmasked:?}");
    assert!(
        unmasked.contains(PUBLIC_HTTP_LEAK_SECRET),
        "disabling exact-2024 HTTP mask_error_details must keep the execution secret: {unmasked}"
    );
    drop(unmasked_client);
    unmasked_server.shutdown();
}

#[test]
fn e2e_public_http_legacy_rate_limit_refuses_second_same_method_and_admits_another() {
    let cx = Cx::for_request();
    let server = spawn_legacy_rate_limit_http_server();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-rate-limit");

    let first = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_TOUCH_TOOL_NAME,
        json!({}),
        "exact-2024 first rate-limited tools/call",
    )
    .expect("the first exact-2024 HTTP tools/call must be admitted by the live rate limiter");
    let first_text = legacy_http_tool_text(&first);
    assert!(
        first_text.as_deref() == Some("notified") || first_text.as_deref() == Some("silent"),
        "the first live tools/call must reach the touch handler: {first:?}"
    );

    let limited = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_TOUCH_TOOL_NAME,
        json!({}),
        "exact-2024 second rate-limited tools/call",
    );
    let limited = match limited {
        Ok(result) => {
            assert!(
                result.is_error,
                "a second tools/call must stay an error result: {result:?}"
            );
            format!("{result:?}")
        }
        Err(error) => format!("{error:?}"),
    };
    assert!(
        limited.contains("Rate limit exceeded"),
        "the refused second exact-2024 HTTP tools/call must keep the rate-limit error: {limited}"
    );

    let listed = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 tools/list after rate limit",
        client.list_tools(&cx, legacy_2024::ListToolsParams::default()),
    )
    .expect("changing only the method must still be admitted by the live rate limiter");
    assert!(
        listed
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_TOUCH_TOOL_NAME),
        "exact-2024 HTTP tools/list must stay callable after tools/call is rate-limited: {listed:?}"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_legacy_sliding_window_refuses_second_same_method_and_admits_another() {
    let cx = Cx::for_request();
    let server = spawn_legacy_sliding_window_http_server();
    let mut client = connect_legacy_http_client(
        &cx,
        server.address(),
        "e2e-public-http-legacy-sliding-window",
    );

    let first = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_TOUCH_TOOL_NAME,
        json!({}),
        "exact-2024 first sliding-window tools/call",
    )
    .expect("the first exact-2024 HTTP tools/call must be admitted by the sliding window");
    let first_text = legacy_http_tool_text(&first);
    assert!(
        first_text.as_deref() == Some("notified") || first_text.as_deref() == Some("silent"),
        "the first live tools/call must reach the touch handler: {first:?}"
    );

    let limited = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_TOUCH_TOOL_NAME,
        json!({}),
        "exact-2024 second sliding-window tools/call",
    );
    let limited = match limited {
        Ok(result) => {
            assert!(
                result.is_error,
                "a second tools/call must stay an error result: {result:?}"
            );
            format!("{result:?}")
        }
        Err(error) => format!("{error:?}"),
    };
    assert!(
        limited.contains("Rate limit exceeded"),
        "the refused second exact-2024 HTTP tools/call must keep the sliding-window error: {limited}"
    );

    let listed = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 tools/list after sliding window",
        client.list_tools(&cx, legacy_2024::ListToolsParams::default()),
    )
    .expect("changing only the method must still be admitted by the sliding window");
    assert!(
        listed
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_TOUCH_TOOL_NAME),
        "exact-2024 HTTP tools/list must stay callable after tools/call is window-limited: {listed:?}"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_legacy_strict_input_validation_refuses_unknown_property_and_admits_declared_args()
 {
    let cx = Cx::for_request();
    let strict_server = spawn_legacy_strict_validation_http_server(true);
    let mut strict_client = connect_legacy_http_client(
        &cx,
        strict_server.address(),
        "e2e-public-http-legacy-strict-on",
    );

    let admitted = legacy_http_call(
        &cx,
        &mut strict_client,
        PUBLIC_HTTP_TOOL_NAME,
        json!({"value": "alpha"}),
        "exact-2024 strict declared tools/call",
    )
    .expect("strict validation must still admit declared arguments");
    assert!(
        !admitted.is_error,
        "declared arguments must not become a tool-level error: {admitted:?}"
    );
    assert_eq!(
        legacy_http_tool_text(&admitted).as_deref(),
        Some("tool:alpha"),
        "declared arguments must reach the handler under strict validation: {admitted:?}"
    );

    let refused = legacy_http_call(
        &cx,
        &mut strict_client,
        PUBLIC_HTTP_TOOL_NAME,
        json!({"value": "alpha", "extra": 1}),
        "exact-2024 strict extra-property tools/call",
    );
    let refused = match refused {
        Ok(result) => {
            assert!(
                result.is_error,
                "an unknown property must become a tool-level error when strict validation is on: {result:?}"
            );
            format!("{result:?}")
        }
        Err(error) => format!("{error:?}"),
    };
    assert!(
        refused.contains("do not match the declared input schema")
            || refused.contains("unknown")
            || refused.contains("InvalidParams")
            || refused.contains("extra"),
        "the strict refusal must name the input-schema mismatch: {refused}"
    );

    drop(strict_client);
    strict_server.shutdown();

    let lenient_server = spawn_legacy_strict_validation_http_server(false);
    let mut lenient_client = connect_legacy_http_client(
        &cx,
        lenient_server.address(),
        "e2e-public-http-legacy-strict-off",
    );
    let extra = legacy_http_call(
        &cx,
        &mut lenient_client,
        PUBLIC_HTTP_TOOL_NAME,
        json!({"value": "alpha", "extra": 1}),
        "exact-2024 lenient extra-property tools/call",
    )
    .expect("lenient validation must admit the same extra property");
    assert!(
        !extra.is_error,
        "changing only the strict flag must admit the extra property: {extra:?}"
    );
    assert_eq!(
        legacy_http_tool_text(&extra).as_deref(),
        Some("tool:alpha"),
        "the extra property must still reach the handler when strict validation is off: {extra:?}"
    );

    drop(lenient_client);
    lenient_server.shutdown();
}

fn spawn_legacy_auth_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let tool_calls = Arc::clone(&handler_calls);
    let mut server = spawn_legacy_http_server("legacy auth", move || {
        let verifier = StaticTokenVerifier::new([(
            "alpha",
            AuthContext::with_subject(PUBLIC_HTTP_AUTH_SUBJECT),
        )])
        .expect("the deterministic native bearer verifier is valid")
        .with_allowed_schemes(["Bearer"])
        .expect("the bearer scheme allowlist is valid");
        ServerBuilder::new("facade-http-legacy-auth", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .auth_provider(TokenAuthProvider::new(verifier))
            .tool(PublicHttpAuthSubject {
                counters: tool_calls,
            })
            .build()
    });
    server.handler_calls = handler_calls;
    server
}

const MAX_LEGACY_NATIVE_HTTP_RESPONSE_BYTES: usize = 1 << 20;

fn write_legacy_native_http(
    address: SocketAddr,
    method: &str,
    path: &str,
    authorization: Option<&str>,
    body: &[u8],
    keep_open: bool,
) -> (std::net::TcpStream, Vec<u8>) {
    let mut stream = std::net::TcpStream::connect_timeout(&address, HTTP_OPERATION_BOUND)
        .expect("native HTTP client connects to the exact-2024 listener");
    stream
        .set_read_timeout(Some(HTTP_OPERATION_BOUND))
        .expect("native HTTP client read deadline is configured");
    stream
        .set_write_timeout(Some(HTTP_OPERATION_BOUND))
        .expect("native HTTP client write deadline is configured");
    let authorization_header =
        authorization.map_or_else(String::new, |value| format!("Authorization: {value}\r\n"));
    let extra_headers = if body.is_empty() {
        String::new()
    } else {
        format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )
    };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\n{authorization_header}Accept: text/event-stream\r\n{extra_headers}\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.write_all(body))
        .expect("native HTTP request commits to the exact-2024 listener");
    if !keep_open {
        let _ = stream.shutdown(std::net::Shutdown::Write);
    }
    let mut response = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let deadline = Instant::now() + HTTP_OPERATION_BOUND;
    loop {
        if Instant::now() >= deadline {
            break;
        }
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                assert!(
                    response
                        .len()
                        .checked_add(read)
                        .is_some_and(|size| size <= MAX_LEGACY_NATIVE_HTTP_RESPONSE_BYTES),
                    "native HTTP response exceeds the test's bounded response budget"
                );
                response.extend_from_slice(&buffer[..read]);
                if !keep_open {
                    continue;
                }
                if response.windows(4).any(|window| window == b"\r\n\r\n")
                    && (response.starts_with(b"HTTP/1.1 401")
                        || response
                            .windows(b"event: endpoint".len())
                            .any(|window| window == b"event: endpoint"))
                {
                    break;
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(error) => {
                panic!("native HTTP response reads within its configured deadline: {error}")
            }
        }
    }
    (stream, response)
}

fn legacy_native_http_headers(response: &[u8]) -> &str {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(response.len());
    std::str::from_utf8(&response[..header_end]).unwrap_or("")
}

fn assert_legacy_bearer_challenge(response: &[u8], label: &str) {
    assert!(
        response.starts_with(b"HTTP/1.1 401"),
        "{label} must be refused before dispatch: {}",
        String::from_utf8_lossy(response)
    );
    assert!(
        legacy_native_http_headers(response)
            .lines()
            .any(
                |header| header.to_ascii_lowercase().starts_with("www-authenticate:")
                    && header.to_ascii_lowercase().contains("bearer")
            ),
        "{label} challenge must advertise Bearer: {}",
        String::from_utf8_lossy(response)
    );
}

fn legacy_sse_session_id(response: &[u8]) -> String {
    let text = String::from_utf8_lossy(response);
    let data = text
        .split("data:")
        .nth(1)
        .expect("exact-2024 SSE open emits an endpoint event");
    let endpoint = data
        .lines()
        .next()
        .expect("endpoint data is one line")
        .trim();
    endpoint
        .split("session_id=")
        .nth(1)
        .and_then(|rest| rest.split(['&', ' ', '\r', '\n']).next())
        .filter(|id| !id.is_empty())
        .expect("endpoint event carries session_id")
        .to_owned()
}

fn drain_legacy_sse(
    stream: &mut std::net::TcpStream,
    haystack: &mut Vec<u8>,
    bound: Duration,
) -> String {
    let previous = stream.read_timeout().ok().flatten();
    stream
        .set_read_timeout(Some(bound))
        .expect("legacy SSE drain deadline is configured");
    let mut buffer = [0_u8; 8 * 1024];
    let deadline = Instant::now() + bound;
    while Instant::now() < deadline {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                assert!(
                    haystack
                        .len()
                        .checked_add(read)
                        .is_some_and(|size| size <= MAX_LEGACY_NATIVE_HTTP_RESPONSE_BYTES),
                    "legacy SSE drain exceeds the test's bounded response budget"
                );
                haystack.extend_from_slice(&buffer[..read]);
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(error) => panic!("legacy SSE drain reads within its configured deadline: {error}"),
        }
    }
    if let Some(timeout) = previous {
        let _ = stream.set_read_timeout(Some(timeout));
    }
    String::from_utf8_lossy(haystack).into_owned()
}

fn read_legacy_sse_until(
    stream: &mut std::net::TcpStream,
    haystack: &mut Vec<u8>,
    needle: &str,
) -> String {
    let mut buffer = [0_u8; 8 * 1024];
    let deadline = Instant::now() + HTTP_OPERATION_BOUND;
    loop {
        if String::from_utf8_lossy(haystack).contains(needle) {
            return String::from_utf8_lossy(haystack).into_owned();
        }
        if Instant::now() >= deadline {
            panic!(
                "exact-2024 SSE did not retain {needle:?} within the bound: {}",
                String::from_utf8_lossy(haystack)
            );
        }
        match stream.read(&mut buffer) {
            Ok(0) => panic!(
                "exact-2024 SSE closed before retaining {needle:?}: {}",
                String::from_utf8_lossy(haystack)
            ),
            Ok(read) => {
                assert!(
                    haystack
                        .len()
                        .checked_add(read)
                        .is_some_and(|size| size <= MAX_LEGACY_NATIVE_HTTP_RESPONSE_BYTES),
                    "exact-2024 SSE exceeds the test's bounded response budget"
                );
                haystack.extend_from_slice(&buffer[..read]);
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => panic!("exact-2024 SSE read failed: {error}"),
        }
    }
}

fn initialize_legacy_native_session(
    address: SocketAddr,
    authorization: Option<&str>,
    client_name: &str,
) -> (std::net::TcpStream, Vec<u8>, String) {
    let (sse, opened) = write_legacy_native_http(address, "GET", "/sse", authorization, &[], true);
    assert!(
        opened.starts_with(b"HTTP/1.1 200"),
        "GET /sse must open the exact-2024 session: {}",
        String::from_utf8_lossy(&opened)
    );
    let session_id = legacy_sse_session_id(&opened);
    let messages = format!("/messages?session_id={session_id}");
    let initialize = JsonRpcRequest::new(
        "initialize",
        Some(json!({
            "protocolVersion": legacy_2024::PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": client_name, "version": "1.0.0" },
        })),
        1_i64,
    );
    let initialize_body =
        serde_json::to_vec(&initialize).expect("exact-2024 initialize serializes");
    let (_init_stream, init_response) = write_legacy_native_http(
        address,
        "POST",
        &messages,
        authorization,
        &initialize_body,
        false,
    );
    assert!(
        init_response.starts_with(b"HTTP/1.1 202") || init_response.starts_with(b"HTTP/1.1 200"),
        "initialize must be admitted: {}",
        String::from_utf8_lossy(&init_response)
    );
    let initialized = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    });
    let initialized_body =
        serde_json::to_vec(&initialized).expect("exact-2024 initialized serializes");
    let (_initialized_stream, initialized_response) = write_legacy_native_http(
        address,
        "POST",
        &messages,
        authorization,
        &initialized_body,
        false,
    );
    assert!(
        initialized_response.starts_with(b"HTTP/1.1 202")
            || initialized_response.starts_with(b"HTTP/1.1 200"),
        "initialized notification must be admitted: {}",
        String::from_utf8_lossy(&initialized_response)
    );
    (sse, opened, messages)
}

#[test]
fn e2e_public_http_legacy_static_token_refuses_missing_and_wrong_and_commits_subject() {
    let server = spawn_legacy_auth_http_server();

    let (_missing_stream, missing) =
        write_legacy_native_http(server.address(), "GET", "/sse", None, &[], false);
    assert_legacy_bearer_challenge(&missing, "missing Authorization on GET /sse");
    assert_eq!(
        server.handler_call_snapshot().tool,
        0,
        "missing Authorization must not invoke the authenticated handler"
    );

    let (_wrong_stream, wrong) = write_legacy_native_http(
        server.address(),
        "GET",
        "/sse",
        Some("Bearer beta"),
        &[],
        false,
    );
    assert_legacy_bearer_challenge(&wrong, "wrong bearer on GET /sse");
    assert_eq!(
        server.handler_call_snapshot().tool,
        0,
        "a wrong bearer token must not invoke the authenticated handler"
    );

    let (mut sse, opened, messages) = initialize_legacy_native_session(
        server.address(),
        Some("Bearer alpha"),
        "e2e-public-http-legacy-auth",
    );

    let tool = JsonRpcRequest::new(
        "tools/call",
        Some(json!({
            "name": PUBLIC_HTTP_AUTH_TOOL_NAME,
            "arguments": {},
        })),
        2_i64,
    );
    let tool_body = serde_json::to_vec(&tool).expect("exact-2024 tools/call serializes");

    let (_missing_post, missing_post) =
        write_legacy_native_http(server.address(), "POST", &messages, None, &tool_body, false);
    assert_legacy_bearer_challenge(&missing_post, "missing Authorization on POST /messages");
    assert_eq!(
        server.handler_call_snapshot().tool,
        0,
        "missing Authorization on POST /messages must not invoke the handler"
    );

    let (_wrong_post, wrong_post) = write_legacy_native_http(
        server.address(),
        "POST",
        &messages,
        Some("Bearer beta"),
        &tool_body,
        false,
    );
    assert_legacy_bearer_challenge(&wrong_post, "wrong bearer on POST /messages");
    assert_eq!(
        server.handler_call_snapshot().tool,
        0,
        "a wrong bearer token on POST /messages must not invoke the handler"
    );

    let (_tool_stream, tool_response) = write_legacy_native_http(
        server.address(),
        "POST",
        &messages,
        Some("Bearer alpha"),
        &tool_body,
        false,
    );
    assert!(
        tool_response.starts_with(b"HTTP/1.1 202") || tool_response.starts_with(b"HTTP/1.1 200"),
        "the matching bearer token must admit tools/call: {}",
        String::from_utf8_lossy(&tool_response)
    );

    let mut sse_body = opened;
    let retained = read_legacy_sse_until(
        &mut sse,
        &mut sse_body,
        &format!("subject:{PUBLIC_HTTP_AUTH_SUBJECT}"),
    );
    assert!(
        retained.contains(&format!("subject:{PUBLIC_HTTP_AUTH_SUBJECT}")),
        "admitted exact-2024 HTTP must commit the verifier subject into ctx.auth(): {retained}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "only the matching bearer token may invoke the authenticated handler"
    );

    drop(sse);
    server.shutdown();
}

fn spawn_legacy_custom_auth_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let tool_calls = Arc::clone(&handler_calls);
    let mut server = spawn_legacy_http_server("legacy custom auth", move || {
        ServerBuilder::new("facade-http-legacy-custom-auth", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .auth_provider(TokenAuthProvider::new(PublicHttpCustomVerifier))
            .tool(PublicHttpAuthSubject {
                counters: tool_calls,
            })
            .build()
    });
    server.handler_calls = handler_calls;
    server
}

#[test]
fn e2e_public_http_legacy_custom_token_refuses_wrong_and_commits_subject() {
    let server = spawn_legacy_custom_auth_http_server();
    let matching = format!("Bearer {PUBLIC_HTTP_CUSTOM_AUTH_TOKEN}");

    let (_missing_stream, missing) =
        write_legacy_native_http(server.address(), "GET", "/sse", None, &[], false);
    assert_legacy_bearer_challenge(&missing, "missing Authorization on custom GET /sse");
    assert_eq!(
        server.handler_call_snapshot().tool,
        0,
        "missing Authorization must not invoke the custom-verified handler"
    );

    let (_wrong_stream, wrong) = write_legacy_native_http(
        server.address(),
        "GET",
        "/sse",
        Some("Bearer alpha"),
        &[],
        false,
    );
    assert_legacy_bearer_challenge(&wrong, "static token on custom GET /sse");
    assert_eq!(
        server.handler_call_snapshot().tool,
        0,
        "changing only the custom verifier token must not invoke the handler"
    );

    let (mut sse, opened, messages) = initialize_legacy_native_session(
        server.address(),
        Some(matching.as_str()),
        "e2e-public-http-legacy-custom-auth",
    );

    let tool = JsonRpcRequest::new(
        "tools/call",
        Some(json!({
            "name": PUBLIC_HTTP_AUTH_TOOL_NAME,
            "arguments": {},
        })),
        2_i64,
    );
    let tool_body = serde_json::to_vec(&tool).expect("exact-2024 tools/call serializes");

    let (_wrong_post, wrong_post) = write_legacy_native_http(
        server.address(),
        "POST",
        &messages,
        Some("Bearer alpha"),
        &tool_body,
        false,
    );
    assert_legacy_bearer_challenge(&wrong_post, "static token on custom POST /messages");
    assert_eq!(
        server.handler_call_snapshot().tool,
        0,
        "a rejected custom verifier token must not invoke the handler"
    );

    let (_tool_stream, tool_response) = write_legacy_native_http(
        server.address(),
        "POST",
        &messages,
        Some(matching.as_str()),
        &tool_body,
        false,
    );
    assert!(
        tool_response.starts_with(b"HTTP/1.1 202") || tool_response.starts_with(b"HTTP/1.1 200"),
        "the matching custom verifier token must admit tools/call: {}",
        String::from_utf8_lossy(&tool_response)
    );

    let mut sse_body = opened;
    let retained = read_legacy_sse_until(
        &mut sse,
        &mut sse_body,
        &format!("subject:{PUBLIC_HTTP_CUSTOM_AUTH_SUBJECT}"),
    );
    assert!(
        retained.contains(&format!("subject:{PUBLIC_HTTP_CUSTOM_AUTH_SUBJECT}")),
        "admitted exact-2024 HTTP must commit the custom verifier subject: {retained}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "only the matching custom verifier token may invoke the handler"
    );

    drop(sse);
    server.shutdown();
}

const PUBLIC_HTTP_LEGACY_WAIT_TOOL_NAME: &str = "public-http-e2e-legacy-wait";

/// Cooperative wait tool so an in-flight exact-2024 HTTP cancel can be observed.
struct PublicHttpLegacyWaitTool {
    started: Arc<AtomicBool>,
    observed_cancellation: Arc<AtomicBool>,
}

impl ToolHandler for PublicHttpLegacyWaitTool {
    fn definition(&self) -> Tool {
        Tool {
            name: PUBLIC_HTTP_LEGACY_WAIT_TOOL_NAME.to_owned(),
            description: Some("Waits until cancelled or the bound elapses".to_owned()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        if ctx.is_cancelled() || ctx.checkpoint().is_err() {
            self.observed_cancellation.store(true, Ordering::Release);
            return Err(McpError::request_cancelled());
        }
        Ok(vec![Content::text("waited")])
    }

    fn call_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        _arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
        Box::pin(async move {
            self.started.store(true, Ordering::Release);
            // Stay well past the HTTP operation bound unless cancel arrives.
            for _ in 0..500 {
                if ctx.is_cancelled()
                    || ctx.checkpoint().is_err()
                    || request_cx.checkpoint().is_err()
                {
                    self.observed_cancellation.store(true, Ordering::Release);
                    return Outcome::Err(McpError::request_cancelled());
                }
                asupersync::time::sleep(request_cx.now(), Duration::from_millis(10)).await;
            }
            Outcome::Ok(vec![Content::text("waited")])
        })
    }
}

fn spawn_legacy_cancel_http_server() -> (HttpServerFixture, Arc<AtomicBool>, Arc<AtomicBool>) {
    let started = Arc::new(AtomicBool::new(false));
    let observed_cancellation = Arc::new(AtomicBool::new(false));
    let wait_started = Arc::clone(&started);
    let wait_observed = Arc::clone(&observed_cancellation);
    let server = spawn_legacy_http_server("legacy cancel", move || {
        ServerBuilder::new("facade-http-legacy-cancel", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .tool(PublicHttpLegacyWaitTool {
                started: wait_started,
                observed_cancellation: wait_observed,
            })
            .tool(PublicHttpFastTool)
            .build()
    });
    (server, started, observed_cancellation)
}

#[test]
fn e2e_public_http_legacy_cancel_stops_in_flight_tools_call_and_peer_stays_admitted() {
    let (server, started, observed_cancellation) = spawn_legacy_cancel_http_server();
    let (mut sse, opened, messages) =
        initialize_legacy_native_session(server.address(), None, "e2e-public-http-legacy-cancel");

    let tool = JsonRpcRequest::new(
        "tools/call",
        Some(json!({
            "name": PUBLIC_HTTP_LEGACY_WAIT_TOOL_NAME,
            "arguments": {},
        })),
        2_i64,
    );
    let tool_body = serde_json::to_vec(&tool).expect("exact-2024 wait tools/call serializes");
    let address = server.address();
    let messages_for_call = messages.clone();
    let call = thread::spawn(move || {
        write_legacy_native_http(address, "POST", &messages_for_call, None, &tool_body, false)
    });

    let start_deadline = Instant::now() + HTTP_OPERATION_BOUND;
    while !started.load(Ordering::Acquire) && Instant::now() < start_deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        started.load(Ordering::Acquire),
        "the exact-2024 wait tool must start before notifications/cancelled is posted"
    );

    let cancel = json!({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {
            "requestId": 2,
            "reason": "e2e-legacy-http-cancel",
        },
    });
    let cancel_body = serde_json::to_vec(&cancel).expect("exact-2024 cancel serializes");
    let (_cancel_stream, cancel_response) = write_legacy_native_http(
        server.address(),
        "POST",
        &messages,
        None,
        &cancel_body,
        false,
    );
    assert!(
        cancel_response.starts_with(b"HTTP/1.1 202")
            || cancel_response.starts_with(b"HTTP/1.1 200"),
        "notifications/cancelled must be admitted without waiting for the handler: {}",
        String::from_utf8_lossy(&cancel_response)
    );

    let (_call_stream, call_response) = call.join().expect("in-flight tools/call thread joins");
    assert!(
        call_response.starts_with(b"HTTP/1.1 202") || call_response.starts_with(b"HTTP/1.1 200"),
        "the cancelled tools/call POST must still complete its HTTP envelope: {}",
        String::from_utf8_lossy(&call_response)
    );
    assert!(
        observed_cancellation.load(Ordering::Acquire),
        "notifications/cancelled must reach the in-flight exact-2024 wait handler"
    );

    let mut sse_body = opened;
    let retained = drain_legacy_sse(&mut sse, &mut sse_body, Duration::from_millis(150));
    assert!(
        !retained.contains("waited"),
        "a cancelled wait tool must not publish its completion text: {retained}"
    );
    assert!(
        !retained.contains("\"id\":2"),
        "exact MCP 2024-11-05 suppresses the JSON-RPC result of a cancelled request: {retained}"
    );

    drop(sse);
    let cx = Cx::for_request();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-cancel-peer");
    let peer = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_FAST_TOOL_NAME,
        json!({}),
        "exact-2024 peer tools/call after cancel",
    )
    .expect("a peer tools/call must stay admitted after cancellation");
    assert_eq!(
        legacy_http_tool_text(&peer).as_deref(),
        Some("fast"),
        "changing only the cancelled request must not starve the peer: {peer:?}"
    );
    drop(client);
    server.shutdown();
}

fn spawn_legacy_duplicate_http_server(behavior: DuplicateBehavior) -> HttpServerFixture {
    spawn_legacy_http_server("legacy duplicate", move || {
        ServerBuilder::new("facade-http-legacy-duplicate", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .on_duplicate(behavior)
            .tool(PublicHttpValue)
            .tool(ReplacedPublicHttpValue)
            .build()
    })
}

fn spawn_legacy_cache_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let tool_calls = Arc::clone(&handler_calls);
    let mut server = spawn_legacy_http_server("legacy cache", move || {
        ServerBuilder::new("facade-http-legacy-cache", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .middleware(
                caching::ResponseCachingMiddleware::new()
                    .include_tools(vec![PUBLIC_HTTP_TOOL_NAME.to_owned()]),
            )
            .tool(CountingPublicHttpValue {
                counters: tool_calls,
            })
            .build()
    });
    server.handler_calls = handler_calls;
    server
}

#[test]
fn e2e_public_http_legacy_on_duplicate_error_keeps_first_and_replace_installs_second() {
    let cx = Cx::for_request();

    let keep_server = spawn_legacy_duplicate_http_server(DuplicateBehavior::Error);
    let mut keep_client = connect_legacy_http_client(
        &cx,
        keep_server.address(),
        "e2e-public-http-legacy-duplicate-error",
    );
    let kept = legacy_http_call(
        &cx,
        &mut keep_client,
        PUBLIC_HTTP_TOOL_NAME,
        json!({"value": "alpha"}),
        "exact-2024 duplicate-error tools/call",
    )
    .expect("Error must keep the first registration callable");
    assert_eq!(
        legacy_http_tool_text(&kept).as_deref(),
        Some("tool:alpha"),
        "on_duplicate Error must keep the first handler: {kept:?}"
    );
    drop(keep_client);
    keep_server.shutdown();

    let replace_server = spawn_legacy_duplicate_http_server(DuplicateBehavior::Replace);
    let mut replace_client = connect_legacy_http_client(
        &cx,
        replace_server.address(),
        "e2e-public-http-legacy-duplicate-replace",
    );
    let replaced = legacy_http_call(
        &cx,
        &mut replace_client,
        PUBLIC_HTTP_TOOL_NAME,
        json!({"value": "alpha"}),
        "exact-2024 duplicate-replace tools/call",
    )
    .expect("Replace must install the second registration");
    assert_eq!(
        legacy_http_tool_text(&replaced).as_deref(),
        Some("replaced:alpha"),
        "changing only on_duplicate to Replace must reach the second handler: {replaced:?}"
    );
    drop(replace_client);
    replace_server.shutdown();
}

#[test]
fn e2e_public_http_legacy_response_cache_hits_same_allowlisted_call_and_misses_changed_args() {
    let cx = Cx::for_request();
    let server = spawn_legacy_cache_http_server();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-cache");

    let first = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_TOOL_NAME,
        json!({"value": "alpha"}),
        "exact-2024 first cached tools/call",
    )
    .expect("the first allowlisted tools/call must miss and reach the handler");
    assert_eq!(
        legacy_http_tool_text(&first).as_deref(),
        Some("tool:alpha"),
        "the first live tools/call must return the handler result: {first:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the first allowlisted tools/call must invoke the counting handler"
    );

    let cached = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_TOOL_NAME,
        json!({"value": "alpha"}),
        "exact-2024 cached tools/call",
    )
    .expect("the second identical allowlisted tools/call must be a cache hit");
    assert_eq!(
        legacy_http_tool_text(&cached).as_deref(),
        Some("tool:alpha"),
        "the cache hit must keep the first complete result: {cached:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the second identical tools/call must not re-invoke the counting handler"
    );

    let missed = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_TOOL_NAME,
        json!({"value": "beta"}),
        "exact-2024 cache-miss tools/call",
    )
    .expect("changing only the arguments must miss the cache");
    assert_eq!(
        legacy_http_tool_text(&missed).as_deref(),
        Some("tool:beta"),
        "the cache miss must reach the handler with the new arguments: {missed:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        2,
        "changing only the arguments must increment the counting handler"
    );

    drop(client);
    server.shutdown();
}

fn spawn_legacy_transform_rename_http_server() -> HttpServerFixture {
    spawn_legacy_http_server("legacy transform rename", || {
        ServerBuilder::new("facade-http-legacy-transform-rename", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .tool(
                transform::TransformedTool::from_tool(PublicHttpValue)
                    .name(PUBLIC_HTTP_TRANSFORMED_TOOL_NAME)
                    .rename_arg("value", "query")
                    .build(),
            )
            .build()
    })
}

fn spawn_legacy_transform_hide_http_server() -> HttpServerFixture {
    spawn_legacy_http_server("legacy transform hide", || {
        ServerBuilder::new("facade-http-legacy-transform-hide", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .tool(
                transform::TransformedTool::from_tool(PublicHttpValue)
                    .name(PUBLIC_HTTP_HIDDEN_TOOL_NAME)
                    .hide_arg("value", "hidden-default")
                    .build(),
            )
            .build()
    })
}

#[test]
fn e2e_public_http_legacy_transformed_tool_renames_argument_and_keeps_parent_unknown() {
    let cx = Cx::for_request();
    let server = spawn_legacy_transform_rename_http_server();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-transform");

    let listed = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP transformed tools/list",
        client.list_tools(&cx, legacy_2024::ListToolsParams::default()),
    )
    .expect("live exact-2024 HTTP must list the renamed tool");
    let renamed = listed
        .tools
        .iter()
        .find(|tool| tool.name == PUBLIC_HTTP_TRANSFORMED_TOOL_NAME)
        .unwrap_or_else(|| {
            panic!("the transformed catalog must advertise the new name: {listed:?}")
        });
    let schema =
        serde_json::to_string(&renamed.input_schema).expect("the renamed input schema serializes");
    assert!(
        schema.contains("\"query\""),
        "the transformed schema must advertise the renamed argument: {schema}"
    );
    assert!(
        !schema.contains("\"value\""),
        "the transformed schema must drop the parent argument name: {schema}"
    );

    let called = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_TRANSFORMED_TOOL_NAME,
        json!({"query": "alpha"}),
        "exact-2024 renamed tools/call",
    )
    .expect("the renamed argument must reach the parent handler");
    assert_eq!(
        legacy_http_tool_text(&called).as_deref(),
        Some("tool:alpha"),
        "rename_arg must rewrite query back to the parent value: {called:?}"
    );

    let original = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_TOOL_NAME,
        json!({"value": "alpha"}),
        "exact-2024 parent name after rename",
    )
    .expect_err("the parent tool name must stay unadvertised");
    let original = format!("{original:?}");
    assert!(
        original.contains("Unknown tool")
            || original.contains("Method not found")
            || original.contains("MethodNotFound"),
        "calling the pre-transform name must stay unknown: {original}"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_legacy_transformed_tool_hides_argument_and_injects_default() {
    let cx = Cx::for_request();
    let server = spawn_legacy_transform_hide_http_server();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-hide-arg");

    let listed = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP hide-arg tools/list",
        client.list_tools(&cx, legacy_2024::ListToolsParams::default()),
    )
    .expect("live exact-2024 HTTP must list the hide-arg tool");
    let hidden = listed
        .tools
        .iter()
        .find(|tool| tool.name == PUBLIC_HTTP_HIDDEN_TOOL_NAME)
        .unwrap_or_else(|| panic!("the hide-arg catalog must advertise the new name: {listed:?}"));
    let schema =
        serde_json::to_string(&hidden.input_schema).expect("the hide-arg input schema serializes");
    assert!(
        !schema.contains("\"value\""),
        "the hide-arg schema must drop the hidden argument: {schema}"
    );

    let injected = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_HIDDEN_TOOL_NAME,
        json!({}),
        "exact-2024 hide-arg tools/call",
    )
    .expect("the hide-arg tools/call must inject the configured default");
    assert_eq!(
        legacy_http_tool_text(&injected).as_deref(),
        Some("tool:hidden-default"),
        "the hidden default must reach the parent handler: {injected:?}"
    );

    let original = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_TOOL_NAME,
        json!({"value": "alpha"}),
        "exact-2024 parent name after hide-arg",
    )
    .expect_err("the parent tool name must stay unadvertised");
    let original = format!("{original:?}");
    assert!(
        original.contains("Unknown tool")
            || original.contains("Method not found")
            || original.contains("MethodNotFound"),
        "calling the pre-transform name must stay unknown: {original}"
    );

    drop(client);
    server.shutdown();
}

const PUBLIC_HTTP_LEGACY_MOUNTED_TOOL_NAME: &str = "child/public-http-e2e-tool";
const PUBLIC_HTTP_LEGACY_MOUNTED_PROMPT_NAME: &str = "child/public-http-e2e-prompt";
const PUBLIC_HTTP_LEGACY_MOUNTED_RESOURCE_URI: &str = "child/test://public-http-e2e/resource";

fn spawn_legacy_mounted_http_server() -> HttpServerFixture {
    spawn_legacy_http_server("legacy mount", || {
        let child = ServerBuilder::new("facade-http-legacy-mounted-child", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .tool(PublicHttpValue)
            .prompt(PublicHttpInstructionPrompt)
            .resource(PublicHttpSnapshotResource)
            .build();
        ServerBuilder::new("facade-http-legacy-mounted-parent", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .mount(child, Some("child"))
            .build()
    })
}

#[test]
fn e2e_public_http_legacy_mount_prefixes_tool_prompt_and_resource() {
    let cx = Cx::for_request();
    let server = spawn_legacy_mounted_http_server();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-mount");

    let listed = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP mounted tools/list",
        client.list_tools(&cx, legacy_2024::ListToolsParams::default()),
    )
    .expect("live exact-2024 HTTP must list the prefixed child tool");
    assert!(
        listed
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_LEGACY_MOUNTED_TOOL_NAME),
        "legacy mount() must rewrite the child tool name: {listed:?}"
    );
    assert!(
        !listed
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_TOOL_NAME),
        "a nonempty mount prefix must not keep the unprefixed child tool: {listed:?}"
    );

    let called = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_LEGACY_MOUNTED_TOOL_NAME,
        json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
        "exact-2024 mounted tools/call",
    )
    .expect("the prefixed child tool must dispatch");
    assert_eq!(
        legacy_http_tool_text(&called).as_deref(),
        Some(PUBLIC_HTTP_TOOL_TEXT),
        "the mounted live tool must retain the child handler value: {called:?}"
    );

    let listed_prompts = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP mounted prompts/list",
        client.list_prompts(&cx, legacy_2024::ListPromptsParams::default()),
    )
    .expect("live exact-2024 HTTP must list the prefixed child prompt");
    assert!(
        listed_prompts
            .prompts
            .iter()
            .any(|prompt| prompt.name == PUBLIC_HTTP_LEGACY_MOUNTED_PROMPT_NAME),
        "legacy mount() must rewrite the child prompt name: {listed_prompts:?}"
    );

    let prompt = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP mounted prompts/get",
        client.get_prompt(
            &cx,
            legacy_2024::GetPromptParams {
                name: PUBLIC_HTTP_LEGACY_MOUNTED_PROMPT_NAME.to_owned(),
                arguments: Some(HashMap::from([(
                    "subject".to_owned(),
                    PUBLIC_HTTP_TOOL_ARGUMENT.to_owned(),
                )])),
                meta: None,
            },
        ),
    )
    .expect("the prefixed child prompt must dispatch");
    let prompt = serde_json::to_value(prompt)
        .expect("the mounted prompt result serializes for its observable assertion");
    assert_eq!(
        prompt["messages"][0]["content"]["text"],
        json!(PUBLIC_HTTP_PROMPT_TEXT),
        "the mounted live prompt must retain the child handler value: {prompt:?}"
    );

    let listed_resources = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP mounted resources/list",
        client.list_resources(&cx, legacy_2024::ListResourcesParams::default()),
    )
    .expect("live exact-2024 HTTP must list the prefixed child resource");
    assert!(
        listed_resources
            .resources
            .iter()
            .any(|resource| resource.uri == PUBLIC_HTTP_LEGACY_MOUNTED_RESOURCE_URI),
        "legacy mount() must prefix every resource key: {listed_resources:?}"
    );
    assert!(
        !listed_resources
            .resources
            .iter()
            .any(|resource| resource.uri == PUBLIC_HTTP_RESOURCE_URI),
        "legacy mount() must not keep the unprefixed child resource URI: {listed_resources:?}"
    );

    let resource = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP mounted resources/read",
        client.read_resource(
            &cx,
            legacy_2024::ReadResourceParams {
                uri: PUBLIC_HTTP_LEGACY_MOUNTED_RESOURCE_URI.to_owned(),
                meta: None,
            },
        ),
    )
    .expect("the prefixed child resource must dispatch");
    let resource_text = serde_json::to_value(&resource)
        .ok()
        .and_then(|value| value["contents"][0]["text"].as_str().map(str::to_owned));
    assert_eq!(
        resource_text.as_deref(),
        Some(PUBLIC_HTTP_RESOURCE_TEXT),
        "the mounted live resource must retain the child handler value: {resource:?}"
    );

    let original = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_TOOL_NAME,
        json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
        "exact-2024 unprefixed tool after mount",
    )
    .expect_err("the unprefixed child tool name must stay unknown");
    let original = format!("{original:?}");
    assert!(
        original.contains("Unknown tool")
            || original.contains("Method not found")
            || original.contains("MethodNotFound"),
        "calling the unprefixed child name must stay unknown: {original}"
    );

    drop(client);
    server.shutdown();
}

fn spawn_legacy_catalog_metadata_http_server() -> HttpServerFixture {
    spawn_legacy_http_server("legacy catalog metadata", || {
        let icons =
            vec![RawIcon::try_new(PUBLIC_HTTP_ICON_SRC).expect("the catalog icon source is valid")];
        ServerBuilder::new("facade-http-legacy-catalog-metadata", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .tool(PublicHttpIconTool { icons })
            .tool(PublicHttpPlainTool)
            .build()
    })
}

#[test]
fn e2e_public_http_legacy_list_tools_retains_version_tags_and_annotations() {
    let cx = Cx::for_request();
    let server = spawn_legacy_catalog_metadata_http_server();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-catalog");

    let listed = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP catalog tools/list",
        client.list_tools(&cx, legacy_2024::ListToolsParams::default()),
    )
    .expect("live exact-2024 HTTP must list the catalog metadata tools");
    let icon_tool = listed
        .tools
        .iter()
        .find(|tool| tool.name == PUBLIC_HTTP_ICON_TOOL_NAME)
        .expect("the annotated tool must remain on the live catalog");
    let plain_tool = listed
        .tools
        .iter()
        .find(|tool| tool.name == PUBLIC_HTTP_PLAIN_TOOL_NAME)
        .expect("the plain peer tool must remain on the live catalog");

    assert_eq!(icon_tool.version.as_deref(), Some("1.2.3"));
    assert!(
        icon_tool.tags.iter().any(|tag| tag == "catalog"),
        "the annotated tool must retain its tags: {icon_tool:?}"
    );
    let annotations = icon_tool
        .annotations
        .as_ref()
        .expect("the annotated tool must retain its projected annotations");
    assert_eq!(annotations.read_only, Some(true));
    assert_eq!(annotations.idempotent, Some(true));
    assert_eq!(annotations.destructive, None);

    assert_eq!(plain_tool.version, None);
    assert!(plain_tool.tags.is_empty());
    assert_eq!(plain_tool.annotations, None);

    drop(client);
    server.shutdown();
}

fn spawn_legacy_two_client_http_server() -> HttpServerFixture {
    spawn_legacy_http_server("legacy two-client", || {
        ServerBuilder::new("facade-http-legacy-two-client", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .tool(PublicHttpValue)
            .build()
    })
}

#[test]
fn e2e_public_http_legacy_two_clients_call_the_same_tool_independently() {
    let cx = Cx::for_request();
    let server = spawn_legacy_two_client_http_server();
    let mut first =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-two-a");
    let mut second =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-two-b");

    let first_result = legacy_http_call(
        &cx,
        &mut first,
        PUBLIC_HTTP_TOOL_NAME,
        json!({"value": "alpha"}),
        "exact-2024 first client tools/call",
    )
    .expect("the first live exact-2024 HTTP client must reach the shared tool");
    let second_result = legacy_http_call(
        &cx,
        &mut second,
        PUBLIC_HTTP_TOOL_NAME,
        json!({"value": "beta"}),
        "exact-2024 second client tools/call",
    )
    .expect("the second live exact-2024 HTTP client must reach the shared tool independently");
    assert_eq!(
        legacy_http_tool_text(&first_result).as_deref(),
        Some("tool:alpha"),
        "the first client must retain its own handler result: {first_result:?}"
    );
    assert_eq!(
        legacy_http_tool_text(&second_result).as_deref(),
        Some("tool:beta"),
        "changing only the peer arguments must not mix client results: {second_result:?}"
    );

    drop(first);
    drop(second);
    server.shutdown();
}

fn spawn_legacy_cursor_http_server() -> HttpServerFixture {
    spawn_legacy_http_server("legacy cursor", || {
        ServerBuilder::new("facade-http-legacy-cursor", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .list_page_size(1)
            .tool(PublicHttpValue)
            .tool(PublicHttpCursorSecondary)
            .tool(PublicHttpCursorOther)
            .resource(PublicHttpSnapshotResource)
            .resource(PublicHttpCursorResourceAResource)
            .resource(PublicHttpCursorResourceBResource)
            .prompt(PublicHttpCursorPromptAPrompt)
            .prompt(PublicHttpCursorPromptBPrompt)
            .build()
    })
}

#[test]
fn e2e_public_http_legacy_tools_list_cursor_continues_and_rejects_query_or_kind_change() {
    let cx = Cx::for_request();
    let server = spawn_legacy_cursor_http_server();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-cursor");

    let first = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP first cursor tools/list",
        client.list_tools(
            &cx,
            legacy_2024::ListToolsParams {
                cursor: None,
                include_tags: Some(vec!["cursor".to_owned()]),
                exclude_tags: None,
            },
        ),
    )
    .expect("live exact-2024 HTTP must page the cursor-tagged tools");
    assert_eq!(
        first.tools.len(),
        1,
        "page size 1 must create a real continuation: {first:?}"
    );
    assert_eq!(
        first.tools[0].name, PUBLIC_HTTP_TOOL_NAME,
        "the first cursor page must retain the primary tagged tool: {first:?}"
    );
    let cursor = first
        .next_cursor
        .clone()
        .expect("the first filtered page must carry an opaque cursor");

    let second = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP cursor continuation tools/list",
        client.list_tools(
            &cx,
            legacy_2024::ListToolsParams {
                cursor: Some(cursor.clone()),
                include_tags: Some(vec!["cursor".to_owned()]),
                exclude_tags: None,
            },
        ),
    )
    .expect("the exact cursor/query continuation must reach the second live page");
    assert_eq!(
        second.tools.len(),
        1,
        "the continuation must retain one remaining tagged tool: {second:?}"
    );
    assert_eq!(
        second.tools[0].name, PUBLIC_HTTP_CURSOR_SECONDARY_TOOL_NAME,
        "the continuation must retain the second tagged tool: {second:?}"
    );
    assert!(
        second.next_cursor.is_none(),
        "the last cursor page must not invent another continuation: {second:?}"
    );

    let query_rejection = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP cursor query mismatch",
        client.list_tools(
            &cx,
            legacy_2024::ListToolsParams {
                cursor: Some(cursor.clone()),
                include_tags: Some(vec!["other".to_owned()]),
                exclude_tags: None,
            },
        ),
    )
    .expect_err("changing only includeTags must reject the cursor before page projection");
    let query_rejection = format!("{query_rejection:?}");
    assert!(
        query_rejection.contains("InvalidParams") || query_rejection.contains("invalid"),
        "a query-mismatched cursor must stay InvalidParams: {query_rejection}"
    );

    let kind_rejection = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP cursor kind mismatch",
        client.list_resources(
            &cx,
            legacy_2024::ListResourcesParams {
                cursor: Some(cursor),
                include_tags: Some(vec!["cursor".to_owned()]),
                exclude_tags: None,
            },
        ),
    )
    .expect_err("changing only the catalog kind must reject the tools cursor");
    let kind_rejection = format!("{kind_rejection:?}");
    assert!(
        kind_rejection.contains("InvalidParams") || kind_rejection.contains("invalid"),
        "a tools cursor must not select a resources page: {kind_rejection}"
    );

    drop(client);
    server.shutdown();
}

const PUBLIC_HTTP_CURSOR_RESOURCE_A_URI: &str = "test://public-http-e2e/cursor-a";
const PUBLIC_HTTP_CURSOR_RESOURCE_B_URI: &str = "test://public-http-e2e/cursor-b";
const PUBLIC_HTTP_CURSOR_PROMPT_A_NAME: &str = "public-http-e2e-cursor-prompt-a";
const PUBLIC_HTTP_CURSOR_PROMPT_B_NAME: &str = "public-http-e2e-cursor-prompt-b";

#[test]
fn e2e_public_http_legacy_resources_and_prompts_list_cursor_continues() {
    let cx = Cx::for_request();
    let server = spawn_legacy_cursor_http_server();
    let mut client = connect_legacy_http_client(
        &cx,
        server.address(),
        "e2e-public-http-legacy-catalog-cursor",
    );

    let first_resources = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP first cursor resources/list",
        client.list_resources(
            &cx,
            legacy_2024::ListResourcesParams {
                cursor: None,
                include_tags: Some(vec!["cursor".to_owned()]),
                exclude_tags: None,
            },
        ),
    )
    .expect("live exact-2024 HTTP must page the cursor-tagged resources");
    assert_eq!(
        first_resources.resources.len(),
        1,
        "page size 1 must create a real resource continuation: {first_resources:?}"
    );
    let first_resource_uri = first_resources.resources[0].uri.clone();
    assert!(
        first_resource_uri == PUBLIC_HTTP_CURSOR_RESOURCE_A_URI
            || first_resource_uri == PUBLIC_HTTP_CURSOR_RESOURCE_B_URI,
        "the first resource page must retain a cursor-tagged URI: {first_resources:?}"
    );
    let resource_cursor = first_resources
        .next_cursor
        .clone()
        .expect("the first filtered resource page must carry an opaque cursor");

    let second_resources = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP cursor continuation resources/list",
        client.list_resources(
            &cx,
            legacy_2024::ListResourcesParams {
                cursor: Some(resource_cursor.clone()),
                include_tags: Some(vec!["cursor".to_owned()]),
                exclude_tags: None,
            },
        ),
    )
    .expect("the exact resource cursor continuation must reach the second live page");
    assert_eq!(
        second_resources.resources.len(),
        1,
        "the resource continuation must retain one remaining tagged URI: {second_resources:?}"
    );
    let second_resource_uri = second_resources.resources[0].uri.as_str();
    assert_ne!(
        second_resource_uri, first_resource_uri,
        "the resource continuation must retain the other tagged URI: {second_resources:?}"
    );
    assert!(
        second_resource_uri == PUBLIC_HTTP_CURSOR_RESOURCE_A_URI
            || second_resource_uri == PUBLIC_HTTP_CURSOR_RESOURCE_B_URI,
        "the resource continuation must stay inside the cursor tag: {second_resources:?}"
    );
    assert!(
        second_resources.next_cursor.is_none(),
        "the last resource cursor page must not invent another continuation: {second_resources:?}"
    );

    let resource_kind_rejection = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP resource cursor kind mismatch",
        client.list_prompts(
            &cx,
            legacy_2024::ListPromptsParams {
                cursor: Some(resource_cursor),
                include_tags: Some(vec!["cursor".to_owned()]),
                exclude_tags: None,
            },
        ),
    )
    .expect_err("changing only the catalog kind must reject the resources cursor");
    let resource_kind_rejection = format!("{resource_kind_rejection:?}");
    assert!(
        resource_kind_rejection.contains("InvalidParams")
            || resource_kind_rejection.contains("invalid"),
        "a resources cursor must not select a prompts page: {resource_kind_rejection}"
    );

    let first_prompts = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP first cursor prompts/list",
        client.list_prompts(
            &cx,
            legacy_2024::ListPromptsParams {
                cursor: None,
                include_tags: Some(vec!["cursor".to_owned()]),
                exclude_tags: None,
            },
        ),
    )
    .expect("live exact-2024 HTTP must page the cursor-tagged prompts");
    assert_eq!(
        first_prompts.prompts.len(),
        1,
        "page size 1 must create a real prompt continuation: {first_prompts:?}"
    );
    let first_prompt_name = first_prompts.prompts[0].name.clone();
    assert!(
        first_prompt_name == PUBLIC_HTTP_CURSOR_PROMPT_A_NAME
            || first_prompt_name == PUBLIC_HTTP_CURSOR_PROMPT_B_NAME,
        "the first prompt page must retain a cursor-tagged name: {first_prompts:?}"
    );
    let prompt_cursor = first_prompts
        .next_cursor
        .clone()
        .expect("the first filtered prompt page must carry an opaque cursor");

    let second_prompts = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP cursor continuation prompts/list",
        client.list_prompts(
            &cx,
            legacy_2024::ListPromptsParams {
                cursor: Some(prompt_cursor.clone()),
                include_tags: Some(vec!["cursor".to_owned()]),
                exclude_tags: None,
            },
        ),
    )
    .expect("the exact prompt cursor continuation must reach the second live page");
    assert_eq!(
        second_prompts.prompts.len(),
        1,
        "the prompt continuation must retain one remaining tagged name: {second_prompts:?}"
    );
    let second_prompt_name = second_prompts.prompts[0].name.as_str();
    assert_ne!(
        second_prompt_name, first_prompt_name,
        "the prompt continuation must retain the other tagged name: {second_prompts:?}"
    );
    assert!(
        second_prompt_name == PUBLIC_HTTP_CURSOR_PROMPT_A_NAME
            || second_prompt_name == PUBLIC_HTTP_CURSOR_PROMPT_B_NAME,
        "the prompt continuation must stay inside the cursor tag: {second_prompts:?}"
    );
    assert!(
        second_prompts.next_cursor.is_none(),
        "the last prompt cursor page must not invent another continuation: {second_prompts:?}"
    );

    let prompt_kind_rejection = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP prompt cursor kind mismatch",
        client.list_tools(
            &cx,
            legacy_2024::ListToolsParams {
                cursor: Some(prompt_cursor),
                include_tags: Some(vec!["cursor".to_owned()]),
                exclude_tags: None,
            },
        ),
    )
    .expect_err("changing only the catalog kind must reject the prompts cursor");
    let prompt_kind_rejection = format!("{prompt_kind_rejection:?}");
    assert!(
        prompt_kind_rejection.contains("InvalidParams")
            || prompt_kind_rejection.contains("invalid"),
        "a prompts cursor must not select a tools page: {prompt_kind_rejection}"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_legacy_composes_nested_tool_and_resource() {
    let cx = Cx::for_request();
    let server = spawn_legacy_compose_http_server();
    let mut client =
        connect_legacy_http_client(&cx, server.address(), "e2e-public-http-legacy-compose");

    let composed = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_COMPOSE_TOOL_NAME,
        json!({"value": "alpha"}),
        "exact-2024 HTTP compose tools/call",
    )
    .expect("live exact-2024 HTTP must compose a nested tool call and resource read");
    assert_eq!(
        legacy_http_tool_text(&composed).as_deref(),
        Some("compose:tool:alpha|resource:deterministic"),
        "exact-2024 HTTP dispatch must attach request-scoped callers: {composed:?}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the nested tools/call must invoke the peer tool exactly once"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "the nested resources/read must invoke the peer resource exactly once"
    );

    let missing = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_COMPOSE_TOOL_NAME,
        json!({"value": "alpha", "tool": "public-http-e2e-missing"}),
        "exact-2024 HTTP compose missing nested tool",
    );
    let missing = match missing {
        Ok(result) => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        missing.contains("public-http-e2e-missing")
            || missing.contains("compose-nested-tool")
            || missing.contains("Unknown tool")
            || missing.contains("not found"),
        "the nested unknown tool must stay a handler-visible refusal: {missing}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "an unknown nested tool name must not invoke the peer tool"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_legacy_prompt_composes_nested_tool_and_resource() {
    let cx = Cx::for_request();
    let server = spawn_legacy_compose_http_server();
    let mut client = connect_legacy_http_client(
        &cx,
        server.address(),
        "e2e-public-http-legacy-prompt-compose",
    );

    let prompt = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP compose prompts/get",
        client.get_prompt(
            &cx,
            legacy_2024::GetPromptParams {
                name: PUBLIC_HTTP_COMPOSE_PROMPT_NAME.to_owned(),
                arguments: Some(HashMap::from([("value".to_owned(), "alpha".to_owned())])),
                meta: None,
            },
        ),
    )
    .expect(
        "live exact-2024 HTTP must compose a nested tool call and resource read from prompts/get",
    );
    let prompt =
        serde_json::to_value(prompt).expect("the exact-2024 HTTP prompt result serializes");
    assert_eq!(
        prompt["messages"][0]["content"]["text"],
        json!("compose:tool:alpha|resource:deterministic"),
        "exact-2024 HTTP prompt dispatch must attach request-scoped callers: {prompt}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the nested tools/call must invoke the peer tool exactly once"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "the nested resources/read must invoke the peer resource exactly once"
    );

    let missing = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP compose missing nested tool from prompts/get",
        client.get_prompt(
            &cx,
            legacy_2024::GetPromptParams {
                name: PUBLIC_HTTP_COMPOSE_PROMPT_NAME.to_owned(),
                arguments: Some(HashMap::from([
                    ("value".to_owned(), "alpha".to_owned()),
                    ("tool".to_owned(), "public-http-e2e-missing".to_owned()),
                ])),
                meta: None,
            },
        ),
    );
    let missing = match missing {
        Ok(result) => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        missing.contains("public-http-e2e-missing")
            || missing.contains("compose-nested-tool")
            || missing.contains("Unknown tool")
            || missing.contains("not found"),
        "the nested unknown tool must stay a handler-visible refusal: {missing}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "an unknown nested tool name must not invoke the peer tool"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_legacy_resource_composes_nested_tool_and_resource() {
    let cx = Cx::for_request();
    let server = spawn_legacy_compose_http_server();
    let mut client = connect_legacy_http_client(
        &cx,
        server.address(),
        "e2e-public-http-legacy-resource-compose",
    );

    let resource = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP compose resources/read",
        client.read_resource(
            &cx,
            legacy_2024::ReadResourceParams {
                uri: PUBLIC_HTTP_COMPOSE_RESOURCE_URI.to_owned(),
                meta: None,
            },
        ),
    )
    .expect(
        "live exact-2024 HTTP must compose a nested tool call and resource read from resources/read",
    );
    let resource =
        serde_json::to_value(resource).expect("the exact-2024 HTTP resource result serializes");
    assert_eq!(
        resource["contents"][0]["text"],
        json!("compose:tool:alpha|resource:deterministic"),
        "exact-2024 HTTP resource dispatch must attach request-scoped callers: {resource}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "the nested tools/call must invoke the peer tool exactly once"
    );
    assert_eq!(
        server.handler_call_snapshot().resource,
        1,
        "the nested resources/read must invoke the peer resource exactly once"
    );

    let missing = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP compose missing nested tool from resources/read",
        client.read_resource(
            &cx,
            legacy_2024::ReadResourceParams {
                uri: PUBLIC_HTTP_COMPOSE_MISSING_TOOL_RESOURCE_URI.to_owned(),
                meta: None,
            },
        ),
    );
    let missing = match missing {
        Ok(result) => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        missing.contains("public-http-e2e-missing")
            || missing.contains("compose-nested-tool")
            || missing.contains("Unknown tool")
            || missing.contains("not found"),
        "the nested unknown tool must stay a handler-visible refusal: {missing}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "an unknown nested tool name must not invoke the peer tool"
    );

    drop(client);
    server.shutdown();
}

#[cfg(feature = "proxy")]
const PUBLIC_HTTP_LEGACY_PROXY_TOOL_NAME: &str = "child/public-http-e2e-tool";
#[cfg(feature = "proxy")]
const PUBLIC_HTTP_LEGACY_PROXY_PROMPT_NAME: &str = "child/public-http-e2e-prompt";
#[cfg(feature = "proxy")]
const PUBLIC_HTTP_LEGACY_PROXY_RESOURCE_URI: &str = "child/test://public-http-e2e/resource";

#[cfg(feature = "proxy")]
fn spawn_legacy_upstream_http_server() -> HttpServerFixture {
    spawn_legacy_http_server("legacy as_proxy upstream", || {
        ServerBuilder::new("facade-http-legacy-proxy-upstream", "1.0.0")
            .protocol_policy(ProtocolPolicy::LegacyOnly)
            .expect("LegacyOnly is available")
            .tool(PublicHttpValue)
            .prompt(PublicHttpInstructionPrompt)
            .resource(PublicHttpSnapshotResource)
            .build()
    })
}

#[cfg(feature = "proxy")]
fn spawn_legacy_as_proxy_http_gateway(upstream: SocketAddr) -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(
                asupersync::runtime::reactor::create_reactor()
                    .expect("legacy as_proxy gateway HTTP server reactor initializes"),
            )
            .build()
            .expect("legacy as_proxy gateway HTTP server installs an owned runtime");
        let outcome = runtime.block_on(async move {
            let cx =
                Cx::current().expect("owned gateway runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("legacy as_proxy gateway HTTP server control receiver went away".to_owned());
            }
            let plan = ClientProtocolPlan::http(
                ProtocolPolicy::LegacyOnly,
                None,
                Some(public_http_target(upstream, "/sse")),
                Some(public_http_target(upstream, "/messages")),
                "e2e-legacy-http-proxy-gateway".to_owned(),
                "e2e-legacy-http-proxy-gateway".to_owned(),
                "legacy-http-sse".to_owned(),
                1,
                1,
                1,
            )
            .map_err(|error| format!("legacy as_proxy HTTP plan failed: {error}"))?;
            let mut registry = ProxyClient::upstream_binding_registry();
            let proxy = registry
                .connect_http_with_protocol_plan(
                    "e2e-legacy-live-upstream",
                    "native-h1:e2e-legacy-live-upstream",
                    1,
                    plan,
                    ClientInfo {
                        name: "e2e-legacy-http-proxy".to_owned(),
                        version: "1.0.0".to_owned(),
                    },
                    ClientCapabilities::default(),
                    cx.clone(),
                )
                .map_err(|error| format!("live exact-2024 HTTP proxy upstream connect failed: {error}"))?;
            let catalog = proxy
                .catalog_typed()
                .map_err(|error| format!("live exact-2024 HTTP proxy catalog failed: {error}"))?;
            let ProxyToolCatalog::Legacy(tools) = &catalog.tools else {
                return Err(
                    "exact-2024 HTTP as_proxy catalog must stay on the 2024 tool model".to_owned(),
                );
            };
            if !tools.iter().any(|tool| tool.name == PUBLIC_HTTP_TOOL_NAME) {
                return Err(format!(
                    "live exact-2024 HTTP proxy catalog omitted {PUBLIC_HTTP_TOOL_NAME}: {tools:?}"
                ));
            }
            let ProxyPromptCatalog::Legacy(prompts) = &catalog.prompts else {
                return Err(
                    "exact-2024 HTTP as_proxy catalog must stay on the 2024 prompt model".to_owned(),
                );
            };
            if !prompts
                .iter()
                .any(|prompt| prompt.name == PUBLIC_HTTP_PROMPT_NAME)
            {
                return Err(format!(
                    "live exact-2024 HTTP proxy catalog omitted {PUBLIC_HTTP_PROMPT_NAME}: {prompts:?}"
                ));
            }
            let ProxyResourceCatalog::Legacy(resources) = &catalog.resources else {
                return Err(
                    "exact-2024 HTTP as_proxy catalog must stay on the 2024 resource model"
                        .to_owned(),
                );
            };
            if !resources
                .iter()
                .any(|resource| resource.uri == PUBLIC_HTTP_RESOURCE_URI)
            {
                return Err(format!(
                    "live exact-2024 HTTP proxy catalog omitted {PUBLIC_HTTP_RESOURCE_URI}: {resources:?}"
                ));
            }
            let server = ServerBuilder::new("e2e-legacy-http-gateway", "1.0.0")
                .protocol_policy(ProtocolPolicy::LegacyOnly)
                .expect("LegacyOnly is available")
                .as_proxy_typed("child", proxy, catalog)
                .map_err(|error| format!("legacy as_proxy_typed install failed: {error}"))?
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("legacy as_proxy gateway HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("legacy as_proxy gateway HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err(
                    "legacy as_proxy gateway HTTP server startup receiver went away".to_owned(),
                );
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("legacy as_proxy gateway HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("legacy as_proxy gateway HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => {
                panic!("legacy as_proxy gateway HTTP server failed to start: {error}")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("legacy as_proxy gateway HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[cfg(feature = "proxy")]
#[test]
fn e2e_public_http_legacy_as_proxy_prefixes_tool_prompt_and_resource() {
    let cx = Cx::for_request();
    let upstream = spawn_legacy_upstream_http_server();
    let gateway = spawn_legacy_as_proxy_http_gateway(upstream.address());
    let mut client =
        connect_legacy_http_client(&cx, gateway.address(), "e2e-public-http-legacy-as-proxy");

    let listed = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP as_proxy tools/list",
        client.list_tools(&cx, legacy_2024::ListToolsParams::default()),
    )
    .expect("live exact-2024 HTTP as_proxy must list the prefixed upstream tool");
    assert!(
        listed
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_LEGACY_PROXY_TOOL_NAME),
        "legacy as_proxy_typed must rewrite the upstream tool name: {listed:?}"
    );
    assert!(
        !listed
            .tools
            .iter()
            .any(|tool| tool.name == PUBLIC_HTTP_TOOL_NAME),
        "a nonempty as_proxy prefix must not keep the unprefixed upstream tool: {listed:?}"
    );

    let called = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_LEGACY_PROXY_TOOL_NAME,
        json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
        "exact-2024 as_proxy tools/call",
    )
    .expect("the prefixed upstream tool must dispatch through the live as_proxy gateway");
    assert_eq!(
        legacy_http_tool_text(&called).as_deref(),
        Some(PUBLIC_HTTP_TOOL_TEXT),
        "the proxied live tool must retain the upstream handler value: {called:?}"
    );

    let listed_prompts = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP as_proxy prompts/list",
        client.list_prompts(&cx, legacy_2024::ListPromptsParams::default()),
    )
    .expect("live exact-2024 HTTP as_proxy must list the prefixed upstream prompt");
    assert!(
        listed_prompts
            .prompts
            .iter()
            .any(|prompt| prompt.name == PUBLIC_HTTP_LEGACY_PROXY_PROMPT_NAME),
        "legacy as_proxy_typed must rewrite the upstream prompt name: {listed_prompts:?}"
    );

    let prompt = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP as_proxy prompts/get",
        client.get_prompt(
            &cx,
            legacy_2024::GetPromptParams {
                name: PUBLIC_HTTP_LEGACY_PROXY_PROMPT_NAME.to_owned(),
                arguments: Some(HashMap::from([(
                    "subject".to_owned(),
                    PUBLIC_HTTP_TOOL_ARGUMENT.to_owned(),
                )])),
                meta: None,
            },
        ),
    )
    .expect("the prefixed upstream prompt must dispatch through the live as_proxy gateway");
    let prompt = serde_json::to_value(prompt)
        .expect("the proxied prompt result serializes for its observable assertion");
    assert_eq!(
        prompt["messages"][0]["content"]["text"],
        json!(PUBLIC_HTTP_PROMPT_TEXT),
        "the proxied live prompt must retain the upstream handler value: {prompt:?}"
    );

    let listed_resources = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP as_proxy resources/list",
        client.list_resources(&cx, legacy_2024::ListResourcesParams::default()),
    )
    .expect("live exact-2024 HTTP as_proxy must list the prefixed upstream resource");
    assert!(
        listed_resources
            .resources
            .iter()
            .any(|resource| resource.uri == PUBLIC_HTTP_LEGACY_PROXY_RESOURCE_URI),
        "legacy as_proxy_typed must prefix every resource key: {listed_resources:?}"
    );
    assert!(
        !listed_resources
            .resources
            .iter()
            .any(|resource| resource.uri == PUBLIC_HTTP_RESOURCE_URI),
        "legacy as_proxy_typed must not keep the unprefixed upstream resource URI: {listed_resources:?}"
    );

    let resource = runtime_block_on_bounded_named(
        &cx,
        "exact-2024 HTTP as_proxy resources/read",
        client.read_resource(
            &cx,
            legacy_2024::ReadResourceParams {
                uri: PUBLIC_HTTP_LEGACY_PROXY_RESOURCE_URI.to_owned(),
                meta: None,
            },
        ),
    )
    .expect("the prefixed upstream resource must dispatch through the live as_proxy gateway");
    let resource_text = serde_json::to_value(&resource)
        .ok()
        .and_then(|value| value["contents"][0]["text"].as_str().map(str::to_owned));
    assert_eq!(
        resource_text.as_deref(),
        Some(PUBLIC_HTTP_RESOURCE_TEXT),
        "the proxied live resource must retain the upstream handler value: {resource:?}"
    );

    let original = legacy_http_call(
        &cx,
        &mut client,
        PUBLIC_HTTP_TOOL_NAME,
        json!({ "value": PUBLIC_HTTP_TOOL_ARGUMENT }),
        "exact-2024 unprefixed tool after as_proxy",
    )
    .expect_err("the unprefixed upstream tool name must stay unknown");
    let original = format!("{original:?}");
    assert!(
        original.contains("Unknown tool")
            || original.contains("Method not found")
            || original.contains("MethodNotFound"),
        "calling the unprefixed upstream name must stay unknown: {original}"
    );

    drop(client);
    gateway.shutdown();
    upstream.shutdown();
}

#[test]
fn e2e_public_http_lifespan_hooks_run_once_and_peer_stays_unhooked() {
    let cx = Cx::for_request();
    let hooked_startup = Arc::new(AtomicBool::new(false));
    let hooked_shutdown = Arc::new(AtomicBool::new(false));
    let bare_startup = Arc::new(AtomicBool::new(false));
    let bare_shutdown = Arc::new(AtomicBool::new(false));
    let hooked = spawn_modern_lifespan_http_server(
        Some(Arc::clone(&hooked_startup)),
        Some(Arc::clone(&hooked_shutdown)),
    );
    let bare = spawn_modern_lifespan_http_server(None, None);

    let mut hooked_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-lifespan", "1.0.0")
            .connect_http_with_cx(public_http_target(hooked.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects after the startup hook");
    runtime_block_on_bounded(
        &cx,
        hooked_client.call_tool(&cx, PUBLIC_HTTP_TOOL_NAME, json!({"value": "alpha"})),
    )
    .expect("tools/call must be admitted after the startup hook");
    assert!(
        hooked_startup.load(Ordering::SeqCst),
        "bind_http serve must run the public startup hook before admitting traffic"
    );
    assert!(
        !hooked_shutdown.load(Ordering::SeqCst),
        "the shutdown hook must not run while the listener is still serving"
    );
    assert!(
        !bare_startup.load(Ordering::SeqCst) && !bare_shutdown.load(Ordering::SeqCst),
        "a peer without hooks must not invent lifespan events"
    );

    drop(hooked_client);
    hooked.shutdown();
    assert!(
        hooked_shutdown.load(Ordering::SeqCst),
        "cooperative HTTP shutdown must run the public shutdown hook"
    );

    let mut bare_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-lifespan-bare", "1.0.0")
            .connect_http_with_cx(public_http_target(bare.address(), "/mcp"), &cx),
    )
    .expect("the unhooked peer must still admit a client");
    runtime_block_on_bounded(
        &cx,
        bare_client.call_tool(&cx, PUBLIC_HTTP_TOOL_NAME, json!({"value": "alpha"})),
    )
    .expect("the unhooked peer must still admit tools/call");
    drop(bare_client);
    bare.shutdown();
    assert!(
        !bare_startup.load(Ordering::SeqCst) && !bare_shutdown.load(Ordering::SeqCst),
        "changing only the missing hooks must leave the peer unhooked after shutdown"
    );
}

fn discover_capability_map(client: &modern::HttpClient) -> serde_json::Value {
    serde_json::to_value(client.server_discovery().capabilities())
        .expect("final discovery capabilities serialize")
}

#[test]
fn e2e_public_http_discovery_advertises_completions_only_when_handler_is_installed() {
    let cx = Cx::for_request();
    let advertised = spawn_modern_facade_http_server(false, None, false);
    let omitted = spawn_modern_instructions_http_server(false);
    let mut advertised_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-completions", "1.0.0")
            .connect_http_with_cx(public_http_target(advertised.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the completion HTTP server");
    let mut omitted_client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-completions-omitted", "1.0.0")
            .connect_http_with_cx(public_http_target(omitted.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the completion-omitted HTTP server");

    let advertised_caps = discover_capability_map(&advertised_client);
    assert!(
        advertised_caps.get("completions").is_some(),
        "installing a completion handler must advertise completions: {advertised_caps}"
    );
    let omitted_caps = discover_capability_map(&omitted_client);
    assert!(
        omitted_caps.get("completions").is_none(),
        "changing only the missing completion handler must omit completions: {omitted_caps}"
    );

    let params = modern::CompletionParams {
        reference: modern::CompletionReference::PromptWithTitle {
            name: PUBLIC_HTTP_PROMPT_NAME.to_owned(),
            title: "Public HTTP E2E Prompt".to_owned(),
        },
        argument: modern::FinalCompletionArgument {
            name: "subject".to_owned(),
            value: "cross-era".to_owned(),
        },
        context: Some(modern::FinalCompletionContext {
            arguments: Some(std::collections::BTreeMap::from([(
                "region".to_owned(),
                "us-east-1".to_owned(),
            )])),
        }),
    };
    let completed = runtime_block_on_bounded(&cx, advertised_client.complete(&cx, params.clone()))
        .expect("live bind_http must complete when completions are advertised");
    assert_eq!(
        completed.completion.values,
        vec![PUBLIC_HTTP_COMPLETION_VALUE.to_owned()],
        "the advertised completion provider must retain its values: {completed:?}"
    );

    let missing_subject = runtime_block_on_bounded(
        &cx,
        advertised_client.get_prompt(&cx, PUBLIC_HTTP_PROMPT_NAME, HashMap::new()),
    )
    .expect_err("changing only the missing required prompt argument must refuse");
    let missing_subject = format!("{missing_subject:?}");
    assert!(
        missing_subject.contains("subject")
            || missing_subject.contains("required")
            || missing_subject.contains("InvalidParams")
            || missing_subject.contains("invalid"),
        "a missing required prompt argument must stay a handler-visible refusal: {missing_subject}"
    );

    let prompted = runtime_block_on_bounded(
        &cx,
        advertised_client.get_prompt(
            &cx,
            PUBLIC_HTTP_PROMPT_NAME,
            HashMap::from([("subject".to_owned(), PUBLIC_HTTP_TOOL_ARGUMENT.to_owned())]),
        ),
    )
    .expect("supplying the required prompt argument must still be admitted");
    assert!(
        prompted
            .messages
            .iter()
            .any(|message| match &message.content {
                ContentBlock::Text { text, .. } => text == PUBLIC_HTTP_PROMPT_TEXT,
                _ => false,
            }),
        "prompts/get with the required argument must retain the handler text: {prompted:?}"
    );

    runtime_block_on_bounded(&cx, omitted_client.complete(&cx, params))
        .expect_err("changing only the missing completion handler must refuse complete");

    drop(advertised_client);
    drop(omitted_client);
    advertised.shutdown();
    omitted.shutdown();
}

fn spawn_modern_default_and_rich_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("default/rich HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-default-rich", "1.0.0")
                .tool(PublicHttpDefault)
                .tool(PublicHttpRichTool)
                .tool(PublicHttpPlainTool)
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("default/rich facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("default/rich facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("default/rich HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("default/rich facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("default/rich facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("default/rich facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("default/rich facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_tool_default_parameter_is_injected_and_overridable() {
    let cx = Cx::for_request();
    let server = spawn_modern_default_and_rich_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-default", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the default-parameter HTTP server");

    let listed = runtime_block_on_bounded(&cx, client.list_tools(&cx, None))
        .expect("live bind_http must list the default-parameter tool");
    let default_tool = listed
        .tools
        .iter()
        .find(|tool| tool.name == PUBLIC_HTTP_DEFAULT_TOOL_NAME)
        .expect("the default-parameter tool must remain on the live catalog");
    let required = default_tool
        .input_schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        required.iter().any(|value| value.as_str() == Some("name")),
        "the generated schema must still require name: {default_tool:?}"
    );
    assert!(
        !required
            .iter()
            .any(|value| value.as_str() == Some("suffix")),
        "the defaulted suffix must not stay required: {default_tool:?}"
    );
    assert_eq!(
        default_tool
            .input_schema
            .pointer("/properties/suffix/default")
            .and_then(serde_json::Value::as_str),
        Some(PUBLIC_HTTP_DEFAULT_SUFFIX),
        "tools/list must retain the generated default: {default_tool:?}"
    );

    let injected = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_DEFAULT_TOOL_NAME, json!({"name": "World"})),
    )
    .expect("omitting the defaulted argument must still be admitted");
    assert!(
        injected.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "greet:World!",
            _ => false,
        }),
        "the generated default must be injected at call time: {injected:?}"
    );

    let overridden = runtime_block_on_bounded(
        &cx,
        client.call_tool(
            &cx,
            PUBLIC_HTTP_DEFAULT_TOOL_NAME,
            json!({"name": "World", "suffix": "?"}),
        ),
    )
    .expect("supplying the defaulted argument must override the generated default");
    assert!(
        overridden.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "greet:World?",
            _ => false,
        }),
        "changing only the suffix must override the generated default: {overridden:?}"
    );

    let missing_name = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_DEFAULT_TOOL_NAME, json!({"suffix": "!"})),
    );
    let missing_name = match missing_name {
        Ok(result) => {
            assert!(
                result.is_error,
                "a missing required generated argument must stay an error result: {result:?}"
            );
            format!("{result:?}")
        }
        Err(error) => format!("{error:?}"),
    };
    assert!(
        missing_name.contains("name")
            || missing_name.contains("required")
            || missing_name.contains("schema")
            || missing_name.contains("InvalidParams")
            || missing_name.contains("do not match"),
        "a missing required generated argument must stay a handler-visible refusal: {missing_name}"
    );

    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_rich_content_retains_image_and_audio_blocks() {
    let cx = Cx::for_request();
    let server = spawn_modern_default_and_rich_http_server();
    let mut client = runtime_block_on_bounded(
        &cx,
        modern::ClientBuilder::new()
            .client_info("e2e-public-http-rich", "1.0.0")
            .connect_http_with_cx(public_http_target(server.address(), "/mcp"), &cx),
    )
    .expect("the ModernOnly public facade connects to the rich-content HTTP server");

    let rich = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_RICH_TOOL_NAME, json!({})),
    )
    .expect("live bind_http must retain image and audio content blocks");
    assert!(
        rich.content.iter().any(|content| match content {
            ContentBlock::Image {
                data, mime_type, ..
            } => data == PUBLIC_HTTP_IMAGE_DATA && mime_type == PUBLIC_HTTP_IMAGE_MIME,
            _ => false,
        }),
        "tools/call must retain the authored image block: {rich:?}"
    );
    assert!(
        rich.content.iter().any(|content| match content {
            ContentBlock::Audio {
                data, mime_type, ..
            } => data == PUBLIC_HTTP_AUDIO_DATA && mime_type == PUBLIC_HTTP_AUDIO_MIME,
            _ => false,
        }),
        "tools/call must retain the authored audio block: {rich:?}"
    );

    let peer = runtime_block_on_bounded(
        &cx,
        client.call_tool(&cx, PUBLIC_HTTP_PLAIN_TOOL_NAME, json!({})),
    )
    .expect("the text-only peer tool must still be callable");
    assert!(
        peer.content
            .iter()
            .all(|content| matches!(content, ContentBlock::Text { .. })),
        "changing only the missing rich content must keep the peer text-only: {peer:?}"
    );
    assert!(
        !peer.content.iter().any(|content| matches!(
            content,
            ContentBlock::Image { .. } | ContentBlock::Audio { .. }
        )),
        "the text-only peer must not invent image or audio blocks: {peer:?}"
    );

    drop(client);
    server.shutdown();
}

fn spawn_modern_custom_token_http_server() -> HttpServerFixture {
    let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
    let tool_calls = Arc::clone(&handler_calls);
    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
    let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<HttpServerShutdown, String>>(1);
    let join = Some(thread::spawn(move || {
        let ready_for_spawn_failure = ready_tx.clone();
        let finished_for_spawn_failure = finished_tx.clone();
        let outcome = runtime_block_on(async move {
            let cx = Cx::current().expect("facade runtime installs an ambient server context");
            if server_cx_tx.send(cx.clone()).is_err() {
                cx.set_cancel_requested(true);
                return Err("custom token HTTP server control receiver went away".to_owned());
            }
            let server = modern::ServerBuilder::new("facade-http-custom-token", "1.0.0")
                .auth_provider(TokenAuthProvider::new(PublicHttpCustomVerifier))
                .tool(PublicHttpAuthSubject {
                    counters: tool_calls,
                })
                .build();
            let bound = match server.bind_http(&cx, "127.0.0.1:0").await {
                Ok(bound) => bound,
                Err(error) => {
                    let message = format!("custom token facade HTTP server bind failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            let address = match bound.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let message =
                        format!("custom token facade HTTP server address failed: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    return Err(message);
                }
            };
            if ready_tx.send(Ok(address)).is_err() {
                cx.set_cancel_requested(true);
                return Err("custom token HTTP server startup receiver went away".to_owned());
            }
            bound.serve(&cx).await.map_err(|error| {
                format!("custom token facade HTTP server stopped unexpectedly: {error}")
            })
        });
        if let Err(message) = &outcome {
            let _ = ready_for_spawn_failure.send(Err(message.clone()));
        }
        let _ = finished_for_spawn_failure.send(outcome);
    }));

    let mut startup = HttpServerStartupGuard {
        server_cx: None,
        server_cx_rx: Some(server_cx_rx),
        finished: Some(finished_rx),
        join,
    };
    let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
    let address = loop {
        startup.capture_server_cx();
        let remaining = startup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("custom token facade HTTP server startup exceeded its bound");
        }
        match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Ok(address)) => break address,
            Ok(Err(error)) => panic!("custom token facade HTTP server failed to start: {error}"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                startup.resume_thread_panic_if_finished();
                panic!("custom token facade HTTP server readiness channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    startup.capture_server_cx();
    let (server_cx, finished, join) = startup.into_parts();

    HttpServerFixture {
        address,
        server_cx,
        finished,
        shutdown_completion: None,
        join,
        nonquiescent: None,
        handler_calls,
    }
}

#[test]
fn e2e_public_http_custom_token_verifier_refuses_wrong_and_commits_subject() {
    const MAX_NATIVE_HTTP_RESPONSE_BYTES: usize = 1 << 20;

    fn exchange(address: SocketAddr, authorization: Option<&str>, body: &[u8]) -> Vec<u8> {
        let mut stream = std::net::TcpStream::connect_timeout(&address, HTTP_OPERATION_BOUND)
            .expect("native HTTP client connects to the custom token listener");
        stream
            .set_read_timeout(Some(HTTP_OPERATION_BOUND))
            .expect("native HTTP client read deadline is configured");
        stream
            .set_write_timeout(Some(HTTP_OPERATION_BOUND))
            .expect("native HTTP client write deadline is configured");
        let authorization_header =
            authorization.map_or_else(String::new, |value| format!("Authorization: {value}\r\n"));
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: {address}\r\n{authorization_header}Accept: application/json\r\nContent-Type: application/json\r\nMCP-Protocol-Version: {}\r\nMcp-Method: tools/call\r\nMcp-Name: {PUBLIC_HTTP_AUTH_TOOL_NAME}\r\nContent-Length: {}\r\n\r\n",
            modern::PROTOCOL_VERSION,
            body.len(),
        );
        stream
            .write_all(request.as_bytes())
            .and_then(|()| stream.write_all(body))
            .expect("native HTTP request commits to the custom token listener");
        let mut response = Vec::new();
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let read = stream
                .read(&mut buffer)
                .expect("native HTTP response reads within its configured deadline");
            if read == 0 {
                break;
            }
            assert!(
                response
                    .len()
                    .checked_add(read)
                    .is_some_and(|size| size <= MAX_NATIVE_HTTP_RESPONSE_BYTES),
                "native HTTP response exceeds the test's bounded response budget"
            );
            response.extend_from_slice(&buffer[..read]);
        }
        response
    }

    fn response_headers(response: &[u8]) -> &str {
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("native HTTP response contains a complete header terminator");
        std::str::from_utf8(&response[..header_end])
            .expect("native HTTP response headers are ASCII")
    }

    fn response_json_body(response: &[u8]) -> serde_json::Value {
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("native HTTP response contains a complete header terminator");
        let headers = std::str::from_utf8(&response[..header_end])
            .expect("native HTTP response headers are ASCII");
        let mut content_length = None;
        let mut chunked = false;
        for header in headers.lines().skip(1) {
            let (name, value) = header
                .split_once(':')
                .expect("native HTTP response header has a field delimiter");
            if name.eq_ignore_ascii_case("content-length") {
                content_length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .expect("native HTTP Content-Length is a valid byte count"),
                );
            }
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"))
            {
                chunked = true;
            }
        }
        let body = &response[header_end + 4..];
        let decoded = if chunked {
            let mut cursor = 0;
            let mut decoded = Vec::new();
            loop {
                let size_end = body[cursor..]
                    .windows(2)
                    .position(|window| window == b"\r\n")
                    .map(|offset| cursor + offset)
                    .expect("chunked response contains a complete chunk-size line");
                let size_line = std::str::from_utf8(&body[cursor..size_end])
                    .expect("chunked response chunk size is ASCII");
                let size =
                    usize::from_str_radix(size_line.split(';').next().unwrap_or_default(), 16)
                        .expect("chunked response chunk size is hexadecimal");
                cursor = size_end + 2;
                if size == 0 {
                    return serde_json::from_slice(&decoded)
                        .expect("authenticated tool response is JSON-RPC");
                }
                let chunk_end = cursor
                    .checked_add(size)
                    .expect("chunked response chunk length does not overflow");
                decoded.extend_from_slice(&body[cursor..chunk_end]);
                cursor = chunk_end + 2;
            }
        } else {
            let content_length = content_length
                .expect("native HTTP response uses Content-Length or chunked framing");
            body[..content_length].to_vec()
        };
        serde_json::from_slice(&decoded).expect("authenticated tool response is JSON-RPC")
    }

    let server = spawn_modern_custom_token_http_server();
    let tool = JsonRpcRequest::new(
        "tools/call",
        Some(json!({
            "name": PUBLIC_HTTP_AUTH_TOOL_NAME,
            "arguments": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": modern::PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        })),
        2_i64,
    );
    let tool_body = serde_json::to_vec(&tool).expect("exact-modern tool request serializes");

    let missing = exchange(server.address(), None, &tool_body);
    assert!(
        missing.starts_with(b"HTTP/1.1 401"),
        "missing Authorization must be refused before the custom verifier runs: {}",
        String::from_utf8_lossy(&missing)
    );
    assert!(
        response_headers(&missing).lines().any(|header| header
            .to_ascii_lowercase()
            .starts_with("www-authenticate:")
            && header.to_ascii_lowercase().contains("bearer")),
        "the missing-token challenge must advertise Bearer: {}",
        String::from_utf8_lossy(&missing)
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        0,
        "missing Authorization must not invoke the authenticated handler"
    );

    let wrong = exchange(server.address(), Some("Bearer alpha"), &tool_body);
    assert!(
        wrong.starts_with(b"HTTP/1.1 401"),
        "changing only the custom verifier token must be refused before dispatch: {}",
        String::from_utf8_lossy(&wrong)
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        0,
        "a rejected custom verifier token must not invoke the authenticated handler"
    );

    let admitted = exchange(
        server.address(),
        Some(&format!("Bearer {PUBLIC_HTTP_CUSTOM_AUTH_TOKEN}")),
        &tool_body,
    );
    assert!(
        admitted.starts_with(b"HTTP/1.1 200"),
        "the matching custom verifier token must admit tools/call: {}",
        String::from_utf8_lossy(&admitted)
    );
    let admitted = response_json_body(&admitted);
    assert!(
        admitted.get("error").is_none(),
        "the matching custom verifier token must reach the handler: {admitted}"
    );
    let content = admitted["result"]["content"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        content.iter().any(|block| {
            block["text"].as_str() == Some(&format!("subject:{PUBLIC_HTTP_CUSTOM_AUTH_SUBJECT}"))
        }),
        "admitted native HTTP must commit the custom verifier subject into ctx.auth(): {admitted}"
    );
    assert_eq!(
        server.handler_call_snapshot().tool,
        1,
        "only the matching custom verifier token may invoke the authenticated handler"
    );
    server.shutdown();
}

#[cfg(feature = "websocket-experimental")]
mod live_websocket_bind {
    use super::*;

    const PUBLIC_WS_LOG_TOOL_NAME: &str = "public-ws-e2e-log";
    const PUBLIC_WS_HANDLER_LOG_TEXT: &str = "public-ws-handler-info";
    const WS_SERVER_TEARDOWN_BOUND: Duration = Duration::from_secs(6);

    /// Live modern WebSocket tool that emits `ctx.info` and optional progress.
    struct PublicWebSocketLogTool;

    impl ToolHandler for PublicWebSocketLogTool {
        fn definition(&self) -> Tool {
            Tool {
                name: PUBLIC_WS_LOG_TOOL_NAME.to_owned(),
                description: Some(
                    "Proves live facade WebSocket handler log and progress".to_owned(),
                ),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
            ctx.info(PUBLIC_WS_HANDLER_LOG_TEXT);
            ctx.report_progress(0.5, Some("halfway"));
            Ok(vec![Content::text("logged")])
        }
    }

    const PUBLIC_WS_TOUCH_TOOL_NAME: &str = "public-ws-e2e-touch";
    const PUBLIC_WS_HIDE_TOOL_NAME: &str = "public-ws-e2e-hide";

    struct PublicWebSocketTouchTool;

    impl ToolHandler for PublicWebSocketTouchTool {
        fn definition(&self) -> Tool {
            Tool {
                name: PUBLIC_WS_TOUCH_TOOL_NAME.to_owned(),
                description: Some("Catalog subject for live WebSocket list_changed".to_owned()),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn call(
            &self,
            _ctx: &McpContext,
            _arguments: serde_json::Value,
        ) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text("touched")])
        }
    }

    struct PublicWebSocketHideTool;

    impl ToolHandler for PublicWebSocketHideTool {
        fn definition(&self) -> Tool {
            Tool {
                name: PUBLIC_WS_HIDE_TOOL_NAME.to_owned(),
                description: Some("Disables the live WebSocket catalog subject".to_owned()),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
            let delivered = ctx.disable_tool(PUBLIC_WS_TOUCH_TOOL_NAME);
            Ok(vec![Content::text(if delivered {
                "hidden"
            } else {
                "silent"
            })])
        }
    }

    /// Owns one real public `bind_websocket` listener and proves its teardown.
    #[allow(dead_code)]
    struct WebSocketServerFixture {
        address: SocketAddr,
        server_cx: Cx,
        finished: mpsc::Receiver<Result<WebSocketServerShutdown, String>>,
        shutdown_completion: Option<Result<WebSocketServerShutdown, String>>,
        join: Option<JoinHandle<()>>,
        nonquiescent: Option<WebSocketNonquiescentShutdown>,
    }

    #[allow(dead_code)]
    impl Drop for WebSocketServerFixture {
        fn drop(&mut self) {
            if self.join.is_none() && self.nonquiescent.is_none() {
                return;
            }
            if let Err(error) = self.settle() {
                eprintln!("public WebSocket server fixture drop failed: {error}");
                std::process::abort();
            }
        }
    }

    #[allow(dead_code)]
    impl WebSocketServerFixture {
        fn address(&self) -> SocketAddr {
            self.address
        }

        fn settle(&mut self) -> Result<(), String> {
            if let Some(shutdown) = self.nonquiescent.as_mut() {
                return match runtime_block_on(shutdown.settle_for(WS_SERVER_TEARDOWN_BOUND)) {
                    Ok(true) => {
                        self.nonquiescent = None;
                        Err(
                        "facade WebSocket server stopped nonquiescently but settled during fixture cleanup"
                            .to_owned(),
                    )
                    }
                    Ok(false) => Err(format!(
                        "facade WebSocket server remains nonquiescent after bounded fixture cleanup ({} retained connections)",
                        shutdown.remaining_connections()
                    )),
                    Err(error) => Err(format!(
                        "facade WebSocket server child settlement failed: {error}"
                    )),
                };
            }
            self.server_cx.set_cancel_requested(true);
            match await_websocket_server_shutdown(
                &self.finished,
                &mut self.shutdown_completion,
                &mut self.join,
            )? {
                WebSocketServerShutdown::Quiescent => Ok(()),
                WebSocketServerShutdown::Nonquiescent(shutdown) => {
                    self.nonquiescent = Some(shutdown);
                    self.settle()
                }
            }
        }

        fn shutdown(mut self) {
            self.settle()
                .unwrap_or_else(|error| panic!("public WebSocket server teardown failed: {error}"));
        }
    }

    #[allow(dead_code)]
    fn await_websocket_server_shutdown(
        finished: &mpsc::Receiver<Result<WebSocketServerShutdown, String>>,
        completion: &mut Option<Result<WebSocketServerShutdown, String>>,
        join: &mut Option<JoinHandle<()>>,
    ) -> Result<WebSocketServerShutdown, String> {
        let completion_result = if completion.is_some() {
            Ok(())
        } else {
            finished
                .recv_timeout(WS_SERVER_TEARDOWN_BOUND)
                .map(|shutdown| *completion = Some(shutdown))
                .map_err(|error| {
                    format!("public WebSocket server teardown exceeded its bound: {error}")
                })
        };
        let join_result = join_finished_thread(join, WS_SERVER_TEARDOWN_BOUND, "WebSocket server");
        match (completion_result, join_result) {
            (Ok(()), Ok(())) => match completion
                .take()
                .expect("a completed WebSocket shutdown retains its completion report")
            {
                Ok(shutdown) => Ok(shutdown),
                Err(completion) => Err(format!(
                    "public WebSocket server teardown failed: {completion}"
                )),
            },
            (Ok(()), Err(join)) => Err(join),
            (Err(completion), Ok(())) => Err(completion),
            (Err(completion), Err(join)) => Err(format!(
                "{completion}; owned thread settlement failed: {join}"
            )),
        }
    }

    #[allow(dead_code)]
    fn spawn_modern_log_websocket_server() -> WebSocketServerFixture {
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
        let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
        let (finished_tx, finished_rx) =
            mpsc::sync_channel::<Result<WebSocketServerShutdown, String>>(1);
        let join = Some(thread::spawn(move || {
            let ready_for_spawn_failure = ready_tx.clone();
            let finished_for_spawn_failure = finished_tx.clone();
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .with_reactor(
                    asupersync::runtime::reactor::create_reactor()
                        .expect("log facade WebSocket server reactor initializes"),
                )
                .blocking_threads(4, 64)
                .build()
                .expect("log facade WebSocket server installs an owned runtime");
            let outcome = runtime.block_on(async move {
                let cx = Cx::current()
                    .expect("owned WebSocket runtime installs an ambient server context");
                if server_cx_tx.send(cx.clone()).is_err() {
                    cx.set_cancel_requested(true);
                    return Err("log WebSocket server control receiver went away".to_owned());
                }
                let server = modern::ServerBuilder::new("facade-ws-log", "1.0.0")
                    .tool(PublicWebSocketLogTool)
                    .build();
                let bound = match server.bind_websocket(&cx, "127.0.0.1:0").await {
                    Ok(bound) => bound,
                    Err(error) => {
                        let message = format!("log facade WebSocket server bind failed: {error}");
                        let _ = ready_tx.send(Err(message.clone()));
                        return Err(message);
                    }
                };
                let address = match bound.local_addr() {
                    Ok(address) => address,
                    Err(error) => {
                        let message =
                            format!("log facade WebSocket server address failed: {error}");
                        let _ = ready_tx.send(Err(message.clone()));
                        return Err(message);
                    }
                };
                if ready_tx.send(Ok(address)).is_err() {
                    cx.set_cancel_requested(true);
                    return Err("log WebSocket server startup receiver went away".to_owned());
                }
                bound.serve(&cx).await.map_err(|error| {
                    format!("log facade WebSocket server stopped unexpectedly: {error}")
                })
            });
            if let Err(message) = &outcome {
                let _ = ready_for_spawn_failure.send(Err(message.clone()));
            }
            let _ = finished_for_spawn_failure.send(outcome);
        }));

        let mut server_cx = None;
        let startup_deadline = Instant::now() + HTTP_SERVER_STARTUP_BOUND;
        let address = loop {
            if server_cx.is_none() {
                if let Ok(cx) = server_cx_rx.try_recv() {
                    server_cx = Some(cx);
                }
            }
            let remaining = startup_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                if let Some(cx) = server_cx.as_ref() {
                    cx.set_cancel_requested(true);
                }
                panic!("log facade WebSocket server startup exceeded its bound");
            }
            match ready_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
                Ok(Ok(address)) => break address,
                Ok(Err(error)) => panic!("log facade WebSocket server failed to start: {error}"),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("log facade WebSocket server readiness channel disconnected")
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        };
        if server_cx.is_none() {
            if let Ok(cx) = server_cx_rx.try_recv() {
                server_cx = Some(cx);
            }
        }

        WebSocketServerFixture {
            address,
            server_cx: server_cx.expect("startup retains the runtime-installed server context"),
            finished: finished_rx,
            shutdown_completion: None,
            join,
            nonquiescent: None,
        }
    }

    async fn websocket_client_bounded<F: std::future::Future>(
        cx: &Cx,
        operation: &str,
        future: F,
    ) -> F::Output {
        asupersync::time::timeout(cx.now(), HTTP_OPERATION_BOUND, future)
            .await
            .unwrap_or_else(|_| panic!("{operation} stays within its caller-owned deadline"))
    }

    fn websocket_test_runtime() -> asupersync::runtime::Runtime {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(
                asupersync::runtime::reactor::create_reactor()
                    .expect("live bind_websocket reactor initializes"),
            )
            .blocking_threads(4, 64)
            .build()
            .expect("live bind_websocket installs an owned runtime")
    }

    const PUBLIC_WS_WATCH_RESOURCE_URI: &str = "test://public-ws-e2e/watched";
    const PUBLIC_WS_NOTIFY_TOOL_NAME: &str = "public-ws-e2e-notify";
    const PUBLIC_WS_MISS_TOOL_NAME: &str = "public-ws-e2e-miss";

    struct PublicWebSocketWatchResource;

    impl ResourceHandler for PublicWebSocketWatchResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: PUBLIC_WS_WATCH_RESOURCE_URI.to_owned(),
                name: "public-ws-e2e-watched".to_owned(),
                description: Some("Proves live facade WebSocket resources/updated".to_owned()),
                mime_type: Some("text/plain".to_owned()),
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![ResourceContent {
                uri: PUBLIC_WS_WATCH_RESOURCE_URI.to_owned(),
                mime_type: None,
                text: Some("watched".to_owned()),
                blob: None,
            }])
        }
    }

    struct PublicWebSocketNotifyTool;

    impl ToolHandler for PublicWebSocketNotifyTool {
        fn definition(&self) -> Tool {
            Tool {
                name: PUBLIC_WS_NOTIFY_TOOL_NAME.to_owned(),
                description: Some("Publishes resources/updated for the watched URI".to_owned()),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
            let delivered = ctx.notify_resource_updated(PUBLIC_WS_WATCH_RESOURCE_URI);
            Ok(vec![Content::text(if delivered {
                "notified"
            } else {
                "silent"
            })])
        }
    }

    struct PublicWebSocketMissTool;

    impl ToolHandler for PublicWebSocketMissTool {
        fn definition(&self) -> Tool {
            Tool {
                name: PUBLIC_WS_MISS_TOOL_NAME.to_owned(),
                description: Some("Publishes resources/updated for an unwatched URI".to_owned()),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
            let delivered = ctx.notify_resource_updated("test://public-ws-e2e/unwatched");
            Ok(vec![Content::text(if delivered {
                "notified"
            } else {
                "silent"
            })])
        }
    }

    async fn websocket_upgrade_status(
        cx: &Cx,
        address: SocketAddr,
        authorization: Option<&str>,
    ) -> (Vec<u8>, asupersync::net::TcpStream) {
        use asupersync::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = asupersync::net::TcpStream::connect(address.to_string())
            .await
            .expect("public bind_websocket upgrade client connects");
        let authorization_header = authorization
            .map(|value| format!("Authorization: {value}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "GET /mcp HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n{authorization_header}\r\n"
        );
        websocket_client_bounded(cx, "live bind_websocket upgrade write", async {
            stream
                .write_all(request.as_bytes())
                .await
                .expect("public bind_websocket upgrade request writes");
            stream
                .flush()
                .await
                .expect("public bind_websocket upgrade request flushes");
        })
        .await;
        let mut received = Vec::new();
        let mut byte = [0_u8; 1];
        while !received.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = websocket_client_bounded(cx, "live bind_websocket upgrade read", async {
                stream
                    .read(&mut byte)
                    .await
                    .expect("public bind_websocket upgrade response reads")
            })
            .await;
            if read == 0 {
                break;
            }
            received.push(byte[0]);
        }
        (received, stream)
    }

    #[test]
    fn e2e_public_websocket_bind_retains_ping_log_and_progress() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(
                asupersync::runtime::reactor::create_reactor()
                    .expect("live bind_websocket reactor initializes"),
            )
            .blocking_threads(4, 64)
            .build()
            .expect("live bind_websocket installs an owned runtime");

        runtime.block_on(async {
            let cx = Cx::current()
                .expect("owned WebSocket runtime installs an ambient context");
            let server = modern::ServerBuilder::new("facade-ws-log", "1.0.0")
                .tool(PublicWebSocketLogTool)
                .build();
            let bound = server
                .bind_websocket(&cx, "127.0.0.1:0")
                .await
                .expect("public bind_websocket must bind a localhost listener");
            let address = bound
                .local_addr()
                .expect("public bind_websocket publishes its bound address");
            let scope = cx.scope();
            let listener = cx
                .spawn_in(&scope, move |serve_cx| async move { bound.serve(&serve_cx).await })
                .expect("public bind_websocket serve must be admitted");

            let transport = websocket_client_bounded(
                &cx,
                "live bind_websocket handshake",
                AsyncWsClientTransport::connect(&cx, &format!("ws://{address}/mcp")),
            )
            .await
            .expect("public bind_websocket must complete RFC 6455 upgrade");
            let mut client = websocket_client_bounded(
                &cx,
                "live bind_websocket initialize",
                modern::ClientBuilder::new()
                    .client_info("e2e-public-ws-bind", "1.0.0")
                    .connect_websocket_with_cx(&cx, transport),
            )
            .await
            .expect("the ModernOnly public facade negotiates over bind_websocket");

            websocket_client_bounded(&cx, "live bind_websocket ping", client.ping(&cx))
                .await
                .expect("live bind_websocket must answer modern ping");

            client
                .set_log_level(modern::LoggingLevel::Info)
                .expect("info logLevel is stored as request metadata");
            websocket_client_bounded(
                &cx,
                "live bind_websocket tools/call",
                client.call_tool(&cx, PUBLIC_WS_LOG_TOOL_NAME, json!({})),
            )
            .await
            .expect("ctx.info must not prevent the same tools/call from completing");
            let info_notifications = client.take_server_notifications();
            assert!(
                info_notifications.iter().any(|notification| matches!(
                    notification,
                    modern::ServerNotification::Message(message)
                        if message.level == modern::LoggingLevel::Info
                            && message.data == json!(PUBLIC_WS_HANDLER_LOG_TEXT)
                )),
                "live bind_websocket must retain ctx.info after set_log_level(Info): {info_notifications:?}"
            );
            assert!(
                client.take_progress_notifications().is_empty(),
                "without a progressToken the handler must not emit request-scoped progress"
            );

            let marker = modern::ProgressMarker::from("ws-progress");
            websocket_client_bounded(
                &cx,
                "live bind_websocket progress tools/call",
                client.call_tool_with_progress_marker(
                    &cx,
                    PUBLIC_WS_LOG_TOOL_NAME,
                    json!({}),
                    marker.clone(),
                ),
            )
            .await
            .expect("a progressToken must not prevent the same tools/call from completing");
            let progress = client.take_progress_notifications();
            assert!(
                progress.iter().any(|notification| {
                    notification.progress_token == marker
                        && notification.message.as_deref() == Some("halfway")
                }),
                "live bind_websocket must retain notifications/progress after a progressToken: {progress:?}"
            );
            assert!(
                client.take_progress_notifications().is_empty(),
                "take_progress_notifications must drain the retained queue"
            );
            let _ = client.take_server_notifications();

            client
                .set_log_level(modern::LoggingLevel::Emergency)
                .expect("emergency logLevel still stores request metadata locally");
            websocket_client_bounded(
                &cx,
                "live bind_websocket emergency tools/call",
                client.call_tool(&cx, PUBLIC_WS_LOG_TOOL_NAME, json!({})),
            )
            .await
            .expect("raising only the logLevel floor cannot break the same public tools/call");
            let emergency_notifications = client.take_server_notifications();
            assert!(
                !emergency_notifications.iter().any(|notification| matches!(
                    notification,
                    modern::ServerNotification::Message(message)
                        if message.data == json!(PUBLIC_WS_HANDLER_LOG_TEXT)
                )),
                "raising only the logLevel floor must suppress ctx.info: {emergency_notifications:?}"
            );

            websocket_client_bounded(&cx, "live bind_websocket close", client.close(&cx))
                .await
                .expect("the public WebSocket client closes after the live bind proof");
            drop(client);
            cx.set_cancel_requested(true);
            listener.abort();
        });
    }

    #[test]
    fn e2e_public_websocket_bind_retains_tools_list_changed_on_incremental_listen() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(
                asupersync::runtime::reactor::create_reactor()
                    .expect("live bind_websocket listen reactor initializes"),
            )
            .blocking_threads(4, 64)
            .build()
            .expect("live bind_websocket listen installs an owned runtime");

        runtime.block_on(async {
            let cx = Cx::current()
                .expect("owned WebSocket listen runtime installs an ambient context");
            let server = modern::ServerBuilder::new("facade-ws-listen", "1.0.0")
                .tool(PublicWebSocketTouchTool)
                .tool(PublicWebSocketHideTool)
                .build();
            let bound = server
                .bind_websocket(&cx, "127.0.0.1:0")
                .await
                .expect("public bind_websocket listen must bind a localhost listener");
            let address = bound
                .local_addr()
                .expect("public bind_websocket listen publishes its bound address");
            let scope = cx.scope();
            let listener = cx
                .spawn_in(&scope, move |serve_cx| async move { bound.serve(&serve_cx).await })
                .expect("public bind_websocket listen serve must be admitted");

            let transport = websocket_client_bounded(
                &cx,
                "live bind_websocket listen handshake",
                AsyncWsClientTransport::connect(&cx, &format!("ws://{address}/mcp")),
            )
            .await
            .expect("public bind_websocket listen must complete RFC 6455 upgrade");
            let mut client = websocket_client_bounded(
                &cx,
                "live bind_websocket listen initialize",
                modern::ClientBuilder::new()
                    .client_info("e2e-public-ws-listen", "1.0.0")
                    .connect_websocket_with_cx(&cx, transport),
            )
            .await
            .expect("the ModernOnly public facade negotiates listen over bind_websocket");

            websocket_client_bounded(
                &cx,
                "live bind_websocket subscriptions/listen",
                client.open_subscriptions_listener(
                    &cx,
                    modern::SubscriptionFilter {
                        tools_list_changed: Some(true),
                        ..modern::SubscriptionFilter::default()
                    },
                ),
            )
            .await
            .expect("live bind_websocket must admit an incremental subscriptions/listen");

            let cancellation = modern::McpRequestCancellation::new();
            let acknowledgement = websocket_client_bounded(
                &cx,
                "live bind_websocket listen acknowledgement",
                client.next_subscription_event(&cx, &cancellation),
            )
            .await
            .expect("subscriptions/listen must emit its acknowledgement");
            assert!(
                matches!(
                    acknowledgement,
                    StdioSubscriptionEvent::Acknowledged(ref filter)
                        if filter.tools_list_changed == Some(true)
                ),
                "the first incremental WebSocket listen record must be the accepted filter: {acknowledgement:?}"
            );

            let hidden = websocket_client_bounded(
                &cx,
                "live bind_websocket hide tools/call",
                client.call_tool(&cx, PUBLIC_WS_HIDE_TOOL_NAME, json!({})),
            )
            .await
            .expect("disabling a peer tool must complete");
            assert!(
                hidden.content.iter().any(|content| match content {
                    ContentBlock::Text { text, .. } => text == "hidden",
                    _ => false,
                }),
                "request-local SessionState must let disable_tool publish list_changed: {hidden:?}"
            );

            let changed = websocket_client_bounded(
                &cx,
                "live bind_websocket list_changed event",
                client.next_subscription_event(&cx, &cancellation),
            )
            .await
            .expect("subscriptions/listen must retain tools/list_changed after the handler mutation");
            assert!(
                matches!(
                    changed,
                    StdioSubscriptionEvent::Notification(
                        modern::ServerNotification::ToolsListChanged(_)
                    )
                ),
                "live bind_websocket must retain notifications/tools/list_changed on the incremental listener: {changed:?}"
            );

            websocket_client_bounded(&cx, "live bind_websocket listen tools/list", client.list_tools(&cx, None))
                .await
                .expect("a later tools/list on the same WebSocket client must still complete");

            websocket_client_bounded(&cx, "live bind_websocket listen close", client.close(&cx))
                .await
                .expect("the public WebSocket listen client closes after the live proof");
            drop(client);
            cx.set_cancel_requested(true);
            listener.abort();
        });
    }

    #[test]
    fn e2e_public_websocket_bind_composes_nested_tool_and_resource() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(
                asupersync::runtime::reactor::create_reactor()
                    .expect("live bind_websocket compose reactor initializes"),
            )
            .blocking_threads(4, 64)
            .build()
            .expect("live bind_websocket compose installs an owned runtime");

        runtime.block_on(async {
            let cx =
                Cx::current().expect("owned WebSocket compose runtime installs an ambient context");
            let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
            let server = modern::ServerBuilder::new("facade-ws-compose", "1.0.0")
                .tool(CountingPublicHttpValue {
                    counters: Arc::clone(&handler_calls),
                })
                .tool(PublicHttpComposeTool)
                .resource(CountingPublicHttpSnapshot {
                    counters: Arc::clone(&handler_calls),
                })
                .build();
            let bound = server
                .bind_websocket(&cx, "127.0.0.1:0")
                .await
                .expect("public bind_websocket compose must bind a localhost listener");
            let address = bound
                .local_addr()
                .expect("public bind_websocket compose publishes its bound address");
            let scope = cx.scope();
            let listener = cx
                .spawn_in(&scope, move |serve_cx| async move {
                    bound.serve(&serve_cx).await
                })
                .expect("public bind_websocket compose serve must be admitted");

            let transport = websocket_client_bounded(
                &cx,
                "live bind_websocket compose handshake",
                AsyncWsClientTransport::connect(&cx, &format!("ws://{address}/mcp")),
            )
            .await
            .expect("public bind_websocket compose must complete RFC 6455 upgrade");
            let mut client = websocket_client_bounded(
                &cx,
                "live bind_websocket compose initialize",
                modern::ClientBuilder::new()
                    .client_info("e2e-public-ws-compose", "1.0.0")
                    .connect_websocket_with_cx(&cx, transport),
            )
            .await
            .expect("the ModernOnly public facade negotiates compose over bind_websocket");

            let composed = websocket_client_bounded(
                &cx,
                "live bind_websocket compose tools/call",
                client.call_tool(
                    &cx,
                    PUBLIC_HTTP_COMPOSE_TOOL_NAME,
                    json!({"value": "alpha"}),
                ),
            )
            .await
            .expect("live bind_websocket must compose a nested tool call and resource read");
            assert!(
                composed.content.iter().any(|content| match content {
                    ContentBlock::Text { text, .. } => {
                        text == "compose:tool:alpha|resource:deterministic"
                    }
                    _ => false,
                }),
                "live bind_websocket dispatch must attach request-scoped callers: {composed:?}"
            );
            assert_eq!(
                handler_calls.snapshot().tool,
                1,
                "the nested tools/call must invoke the peer tool exactly once"
            );
            assert_eq!(
                handler_calls.snapshot().resource,
                1,
                "the nested resources/read must invoke the peer resource exactly once"
            );

            let missing = websocket_client_bounded(
                &cx,
                "live bind_websocket compose missing nested tool",
                client.call_tool(
                    &cx,
                    PUBLIC_HTTP_COMPOSE_TOOL_NAME,
                    json!({"value": "alpha", "tool": "public-http-e2e-missing"}),
                ),
            )
            .await;
            let missing = match missing {
                Ok(result) => format!("{result:?}"),
                Err(error) => format!("{error:?}"),
            };
            assert!(
                missing.contains("public-http-e2e-missing")
                    || missing.contains("compose-nested-tool")
                    || missing.contains("Unknown tool")
                    || missing.contains("not found"),
                "the nested unknown tool must stay a handler-visible refusal: {missing}"
            );
            assert_eq!(
                handler_calls.snapshot().tool,
                1,
                "an unknown nested tool name must not invoke the peer tool"
            );

            websocket_client_bounded(&cx, "live bind_websocket compose close", client.close(&cx))
                .await
                .expect("the public WebSocket compose client closes after the live proof");
            drop(client);
            cx.set_cancel_requested(true);
            listener.abort();
        });
    }

    #[test]
    fn e2e_public_websocket_bind_retains_resource_updated_on_incremental_listen() {
        let runtime = websocket_test_runtime();
        runtime.block_on(async {
            let cx = Cx::current()
                .expect("owned WebSocket updated runtime installs an ambient context");
            let server = modern::ServerBuilder::new("facade-ws-updated", "1.0.0")
                .resource(PublicWebSocketWatchResource)
                .tool(PublicWebSocketNotifyTool)
                .tool(PublicWebSocketMissTool)
                .build();
            let bound = server
                .bind_websocket(&cx, "127.0.0.1:0")
                .await
                .expect("public bind_websocket updated must bind a localhost listener");
            let address = bound
                .local_addr()
                .expect("public bind_websocket updated publishes its bound address");
            let scope = cx.scope();
            let listener = cx
                .spawn_in(&scope, move |serve_cx| async move { bound.serve(&serve_cx).await })
                .expect("public bind_websocket updated serve must be admitted");

            let transport = websocket_client_bounded(
                &cx,
                "live bind_websocket updated handshake",
                AsyncWsClientTransport::connect(&cx, &format!("ws://{address}/mcp")),
            )
            .await
            .expect("public bind_websocket updated must complete RFC 6455 upgrade");
            let mut client = websocket_client_bounded(
                &cx,
                "live bind_websocket updated initialize",
                modern::ClientBuilder::new()
                    .client_info("e2e-public-ws-updated", "1.0.0")
                    .connect_websocket_with_cx(&cx, transport),
            )
            .await
            .expect("the ModernOnly public facade negotiates updated listen over bind_websocket");

            websocket_client_bounded(
                &cx,
                "live bind_websocket updated subscriptions/listen",
                client.open_subscriptions_listener(
                    &cx,
                    modern::SubscriptionFilter {
                        resource_subscriptions: Some(vec![PUBLIC_WS_WATCH_RESOURCE_URI.to_owned()]),
                        ..modern::SubscriptionFilter::default()
                    },
                ),
            )
            .await
            .expect("live bind_websocket must admit a resource subscription listen");

            let cancellation = modern::McpRequestCancellation::new();
            let acknowledgement = websocket_client_bounded(
                &cx,
                "live bind_websocket updated acknowledgement",
                client.next_subscription_event(&cx, &cancellation),
            )
            .await
            .expect("subscriptions/listen must emit its acknowledgement");
            assert!(
                matches!(
                    acknowledgement,
                    StdioSubscriptionEvent::Acknowledged(ref filter)
                        if filter.resource_subscriptions.as_deref()
                            == Some(&[PUBLIC_WS_WATCH_RESOURCE_URI.to_owned()][..])
                ),
                "the first incremental WebSocket listen record must be the accepted resource filter: {acknowledgement:?}"
            );

            let missed = websocket_client_bounded(
                &cx,
                "live bind_websocket unmatched notify",
                client.call_tool(&cx, PUBLIC_WS_MISS_TOOL_NAME, json!({})),
            )
            .await
            .expect("notifying an unwatched URI must complete");
            assert!(
                missed.content.iter().any(|content| match content {
                    ContentBlock::Text { text, .. } => text == "silent",
                    _ => false,
                }),
                "an unwatched URI must not count as notify_resource_updated delivery: {missed:?}"
            );

            let touched = websocket_client_bounded(
                &cx,
                "live bind_websocket matching notify",
                client.call_tool(&cx, PUBLIC_WS_NOTIFY_TOOL_NAME, json!({})),
            )
            .await
            .expect("notifying the watched URI must complete");
            assert!(
                touched.content.iter().any(|content| match content {
                    ContentBlock::Text { text, .. } => text == "notified",
                    _ => false,
                }),
                "a matching incremental listener must count as notify_resource_updated delivery: {touched:?}"
            );

            let updated = websocket_client_bounded(
                &cx,
                "live bind_websocket resources/updated event",
                client.next_subscription_event(&cx, &cancellation),
            )
            .await
            .expect("subscriptions/listen must retain resources/updated after the matching publish");
            assert!(
                matches!(
                    updated,
                    StdioSubscriptionEvent::Notification(
                        modern::ServerNotification::ResourceUpdated(ref params)
                    ) if params.uri.as_str() == PUBLIC_WS_WATCH_RESOURCE_URI
                ),
                "live bind_websocket must retain notifications/resources/updated on the incremental listener: {updated:?}"
            );

            websocket_client_bounded(&cx, "live bind_websocket updated close", client.close(&cx))
                .await
                .expect("the public WebSocket updated client closes after the live proof");
            drop(client);
            cx.set_cancel_requested(true);
            listener.abort();
        });
    }

    #[test]
    fn e2e_public_websocket_bind_handler_timeout_refuses_late_tool_and_admits_fast_peer() {
        let runtime = websocket_test_runtime();
        runtime.block_on(async {
            let cx =
                Cx::current().expect("owned WebSocket timeout runtime installs an ambient context");
            let server = modern::ServerBuilder::new("facade-ws-timeout", "1.0.0")
                .tool(PublicHttpSlowTool)
                .tool(PublicHttpFastTool)
                .build();
            let bound = server
                .bind_websocket(&cx, "127.0.0.1:0")
                .await
                .expect("public bind_websocket timeout must bind a localhost listener");
            let address = bound
                .local_addr()
                .expect("public bind_websocket timeout publishes its bound address");
            let scope = cx.scope();
            let listener = cx
                .spawn_in(&scope, move |serve_cx| async move {
                    bound.serve(&serve_cx).await
                })
                .expect("public bind_websocket timeout serve must be admitted");

            let transport = websocket_client_bounded(
                &cx,
                "live bind_websocket timeout handshake",
                AsyncWsClientTransport::connect(&cx, &format!("ws://{address}/mcp")),
            )
            .await
            .expect("public bind_websocket timeout must complete RFC 6455 upgrade");
            let mut client = websocket_client_bounded(
                &cx,
                "live bind_websocket timeout initialize",
                modern::ClientBuilder::new()
                    .client_info("e2e-public-ws-timeout", "1.0.0")
                    .connect_websocket_with_cx(&cx, transport),
            )
            .await
            .expect("the ModernOnly public facade negotiates timeout over bind_websocket");

            let timed_out = websocket_client_bounded(
                &cx,
                "live bind_websocket late tools/call",
                client.call_tool(&cx, PUBLIC_HTTP_SLOW_TOOL_NAME, json!({})),
            )
            .await
            .expect_err("a handler that outlives its timeout must be refused");
            let timed_out = format!("{timed_out:?}");
            assert!(
                timed_out.contains("Request timeout exceeded")
                    || timed_out.contains("RequestCancelled"),
                "the refused late tools/call must keep the handler-timeout error: {timed_out}"
            );

            let fast = websocket_client_bounded(
                &cx,
                "live bind_websocket fast tools/call",
                client.call_tool(&cx, PUBLIC_HTTP_FAST_TOOL_NAME, json!({})),
            )
            .await
            .expect("changing only the tool must still be admitted after a handler timeout");
            assert!(
                fast.content.iter().any(|content| match content {
                    ContentBlock::Text { text, .. } => text == "fast",
                    _ => false,
                }),
                "the fast peer tool must still complete: {fast:?}"
            );

            websocket_client_bounded(&cx, "live bind_websocket timeout close", client.close(&cx))
                .await
                .expect("the public WebSocket timeout client closes after the live proof");
            drop(client);
            cx.set_cancel_requested(true);
            listener.abort();
        });
    }

    #[test]
    fn e2e_public_websocket_bind_static_token_refuses_missing_and_wrong_and_commits_subject() {
        let runtime = websocket_test_runtime();
        runtime.block_on(async {
            let cx = Cx::current()
                .expect("owned WebSocket auth runtime installs an ambient context");
            let handler_calls = Arc::new(PublicHttpHandlerCallCounters::default());
            let verifier = StaticTokenVerifier::new([(
                "alpha",
                AuthContext::with_subject(PUBLIC_HTTP_AUTH_SUBJECT),
            )])
            .expect("the deterministic WebSocket bearer verifier is valid")
            .with_allowed_schemes(["Bearer"])
            .expect("the bearer scheme allowlist is valid");
            let server = modern::ServerBuilder::new("facade-ws-auth", "1.0.0")
                .auth_provider(TokenAuthProvider::new(verifier))
                .tool(PublicHttpAuthSubject {
                    counters: Arc::clone(&handler_calls),
                })
                .build();
            let bound = server
                .bind_websocket(&cx, "127.0.0.1:0")
                .await
                .expect("public bind_websocket auth must bind a localhost listener");
            let address = bound
                .local_addr()
                .expect("public bind_websocket auth publishes its bound address");
            let scope = cx.scope();
            let listener = cx
                .spawn_in(&scope, move |serve_cx| async move { bound.serve(&serve_cx).await })
                .expect("public bind_websocket auth serve must be admitted");

            let (missing, _missing_stream) =
                websocket_upgrade_status(&cx, address, None).await;
            assert!(
                missing.starts_with(b"HTTP/1.1 401"),
                "omitting Authorization must refuse the WebSocket upgrade: {}",
                String::from_utf8_lossy(&missing)
            );
            assert!(
                String::from_utf8_lossy(&missing).to_ascii_lowercase().contains("www-authenticate"),
                "the missing-token WebSocket upgrade must challenge Bearer: {}",
                String::from_utf8_lossy(&missing)
            );

            let (wrong, _wrong_stream) =
                websocket_upgrade_status(&cx, address, Some("Bearer wrong")).await;
            assert!(
                wrong.starts_with(b"HTTP/1.1 401"),
                "a wrong bearer token must refuse the WebSocket upgrade: {}",
                String::from_utf8_lossy(&wrong)
            );

            let (accepted, stream) =
                websocket_upgrade_status(&cx, address, Some("Bearer alpha")).await;
            assert!(
                accepted.starts_with(b"HTTP/1.1 101"),
                "the matching bearer token must complete RFC 6455 upgrade: {}",
                String::from_utf8_lossy(&accepted)
            );
            let transport = AsyncWsClientTransport::from_upgraded(stream);
            let mut client = websocket_client_bounded(
                &cx,
                "live bind_websocket auth initialize",
                modern::ClientBuilder::new()
                    .client_info("e2e-public-ws-auth", "1.0.0")
                    .connect_websocket_with_cx(&cx, transport),
            )
            .await
            .expect("an admitted WebSocket upgrade must negotiate ModernOnly");

            let admitted = websocket_client_bounded(
                &cx,
                "live bind_websocket auth tools/call",
                client.call_tool(&cx, PUBLIC_HTTP_AUTH_TOOL_NAME, json!({})),
            )
            .await
            .expect("the matching bearer token must reach the authenticated handler");
            assert!(
                admitted.content.iter().any(|content| match content {
                    ContentBlock::Text { text, .. } => {
                        text == &format!("subject:{PUBLIC_HTTP_AUTH_SUBJECT}")
                    }
                    _ => false,
                }),
                "admitted WebSocket must commit the static token subject into ctx.auth(): {admitted:?}"
            );
            assert_eq!(
                handler_calls.snapshot().tool,
                1,
                "only the matching bearer token may invoke the authenticated handler"
            );

            websocket_client_bounded(&cx, "live bind_websocket auth close", client.close(&cx))
                .await
                .expect("the public WebSocket auth client closes after the live proof");
            drop(client);
            cx.set_cancel_requested(true);
            listener.abort();
        });
    }

    #[test]
    fn e2e_public_websocket_bind_result_verbs_return_live_input_required() {
        let runtime = websocket_test_runtime();
        runtime.block_on(async {
            let cx =
                Cx::current().expect("owned WebSocket MRTR runtime installs an ambient context");
            let server = modern::ServerBuilder::new("facade-ws-mrtr", "1.0.0")
                .tool(PublicHttpSamplingTool)
                .tool(PublicHttpRootsTool)
                .build();
            let bound = server
                .bind_websocket(&cx, "127.0.0.1:0")
                .await
                .expect("public bind_websocket MRTR must bind a localhost listener");
            let address = bound
                .local_addr()
                .expect("public bind_websocket MRTR publishes its bound address");
            let scope = cx.scope();
            let listener = cx
                .spawn_in(&scope, move |serve_cx| async move {
                    bound.serve(&serve_cx).await
                })
                .expect("public bind_websocket MRTR serve must be admitted");

            let transport = websocket_client_bounded(
                &cx,
                "live bind_websocket MRTR handshake",
                AsyncWsClientTransport::connect(&cx, &format!("ws://{address}/mcp")),
            )
            .await
            .expect("public bind_websocket MRTR must complete RFC 6455 upgrade");
            let mut capabilities = ClientCapabilities::default();
            capabilities.sampling = Some(Default::default());
            capabilities.roots =
                serde_json::from_value(json!({})).expect("roots capability is valid");
            let mut client = websocket_client_bounded(
                &cx,
                "live bind_websocket MRTR initialize",
                modern::ClientBuilder::new()
                    .client_info("e2e-public-ws-mrtr", "1.0.0")
                    .capabilities(capabilities)
                    .connect_websocket_with_cx(&cx, transport),
            )
            .await
            .expect("the ModernOnly public facade negotiates MRTR over bind_websocket");

            let sampled = websocket_client_bounded(
                &cx,
                "live bind_websocket sampling tools/call",
                client.call_tool_result(&cx, PUBLIC_HTTP_SAMPLING_TOOL_NAME, json!({})),
            )
            .await
            .expect("live bind_websocket final sampling must return a typed tools/call result");
            let FinalCoreResult::ToolsCallInputRequired { result, .. } = sampled else {
                panic!("live bind_websocket final sampling must keep input_required: {sampled:?}");
            };
            assert_live_input_required(&result, "sample", "tools/call");

            let rooted = websocket_client_bounded(
                &cx,
                "live bind_websocket roots tools/call",
                client.call_tool_result(&cx, PUBLIC_HTTP_ROOTS_TOOL_NAME, json!({})),
            )
            .await
            .expect("live bind_websocket final roots must return a typed tools/call result");
            let FinalCoreResult::ToolsCallInputRequired { result, .. } = rooted else {
                panic!("live bind_websocket final roots must keep input_required: {rooted:?}");
            };
            assert_live_input_required(&result, "roots", "tools/call");

            websocket_client_bounded(&cx, "live bind_websocket MRTR close", client.close(&cx))
                .await
                .expect("the advertised MRTR WebSocket client closes after the live proof");
            drop(client);

            let missing_transport = websocket_client_bounded(
                &cx,
                "live bind_websocket MRTR missing-roots handshake",
                AsyncWsClientTransport::connect(&cx, &format!("ws://{address}/mcp")),
            )
            .await
            .expect("a second WebSocket client must complete RFC 6455 upgrade");
            let mut no_roots = ClientCapabilities::default();
            no_roots.sampling = Some(Default::default());
            let mut no_roots_client = websocket_client_bounded(
                &cx,
                "live bind_websocket MRTR missing-roots initialize",
                modern::ClientBuilder::new()
                    .client_info("e2e-public-ws-mrtr-no-roots", "1.0.0")
                    .capabilities(no_roots)
                    .connect_websocket_with_cx(&cx, missing_transport),
            )
            .await
            .expect("the ModernOnly public facade connects without advertising roots");
            let missing_roots = websocket_client_bounded(
                &cx,
                "live bind_websocket missing roots tools/call",
                no_roots_client.call_tool_result(&cx, PUBLIC_HTTP_ROOTS_TOOL_NAME, json!({})),
            )
            .await;
            let missing_roots = match missing_roots {
                Ok(result) => format!("{result:?}"),
                Err(error) => format!("{error:?}"),
            };
            assert!(
                missing_roots.contains("not advertised by the client")
                    || missing_roots.contains("InvalidRequest")
                    || missing_roots.contains("roots"),
                "omitting only the roots capability must fail closed: {missing_roots}"
            );

            websocket_client_bounded(
                &cx,
                "live bind_websocket MRTR missing-roots close",
                no_roots_client.close(&cx),
            )
            .await
            .expect("the no-roots WebSocket client closes after the fail-closed proof");
            drop(no_roots_client);
            cx.set_cancel_requested(true);
            listener.abort();
        });
    }
}
