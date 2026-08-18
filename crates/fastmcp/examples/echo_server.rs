//! Example: Echo Server
//!
//! A simple MCP server demonstrating tools, resources, and prompts.
//!
//! Run with:
//! ```bash
//! cargo run -p fastmcp-rust --example echo_server
//! ```
//!
//! Test with MCP Inspector:
//! ```bash
//! npx @modelcontextprotocol/inspector cargo run -p fastmcp-rust --example echo_server
//! ```

// MCP handlers receive String from JSON deserialization, so this is intentional.
#![allow(clippy::needless_pass_by_value)]

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fastmcp_rust::modern::{FinalMethodOutcome, MrtrCompletedInputs};
use fastmcp_rust::prelude::*;
use fastmcp_rust::{
    ApplicationTaskSupervisor, AuthorizedTaskServiceRunner, CacheScope, CompleteResult,
    ContentBlock, EmbeddedResourceContents, FinalAbsoluteUri, FinalCallToolResult,
    FinalCompletionParams, FinalCompletionReference, FinalCompletionValues,
    FinalElicitationContextExt, FinalEmbeddedRootsListParams, FinalPromptMessage,
    FinalRootsContextExt, FinalSamplingContextExt, FinalTaskInputRequests, FinalTaskRuntime,
    FinalTaskRuntimeConfig, FinalTaskSupervisorFuture, FinalTaskSupervisorHandoff,
    FinalTaskWorkDescriptor, FinalToolOutcome, InputRequiredResult, RawIcon, ResultMeta,
    StdioTransport, ToolErrorKind, ToolHandler,
};
use fastmcp_server::ServerBuilder;
use fastmcp_server::caching::ResponseCachingMiddleware;
use fastmcp_server::rate_limiting::{RateLimitingMiddleware, SlidingWindowRateLimitingMiddleware};
use fastmcp_server::transform::TransformedTool;

// ============================================================================
// Tools
// ============================================================================

/// Echo the input message back.
#[tool(tags = ["demo"])]
fn echo(ctx: &McpContext, message: String) -> String {
    // Check for cancellation (optional but recommended)
    if ctx.is_cancelled() {
        return "Cancelled".to_string();
    }
    ctx.report_progress(1.0, Some("echoed"));
    ctx.info("echo-handler-info");
    message
}

/// Replacement `echo` used only when `FASTMCP_REPLACE_ECHO=1` sets
/// `DuplicateBehavior::Replace`.
#[tool(name = "echo")]
fn echo_replaced(_ctx: &McpContext, message: String) -> String {
    format!("replaced:{message}")
}

/// Publishes `notifications/resources/updated` for the shipped server info resource.
#[tool]
fn touch_server_info(ctx: &McpContext) -> String {
    if ctx.notify_resource_updated("info://server") {
        "notified".to_owned()
    } else {
        "silent".to_owned()
    }
}

/// Reports the self-reported modern client Implementation identity.
#[tool]
fn client_identity(ctx: &McpContext) -> String {
    match ctx.client_implementation() {
        Some(identity) => format!(
            "name={}|title={}",
            identity.name,
            identity.title.as_deref().unwrap_or("none")
        ),
        None => "missing".to_owned(),
    }
}

/// Disables the shipped echo tool and publishes `notifications/tools/list_changed`.
#[tool]
fn hide_echo(ctx: &McpContext) -> String {
    if ctx.disable_tool("echo") {
        "hidden".to_owned()
    } else {
        "silent".to_owned()
    }
}

/// Disables a shipped resource and prompt and publishes both list_changed events.
#[tool]
fn hide_catalog(ctx: &McpContext) -> String {
    let resource = ctx.disable_resource("info://server");
    let prompt = ctx.disable_prompt("greeting");
    if resource && prompt {
        "hidden".to_owned()
    } else {
        "silent".to_owned()
    }
}

/// Re-enables the shipped echo tool and publishes `notifications/tools/list_changed`.
#[tool]
fn show_echo(ctx: &McpContext) -> String {
    if ctx.enable_tool("echo") {
        "shown".to_owned()
    } else {
        "silent".to_owned()
    }
}

/// Re-enables a shipped resource and prompt and publishes both list_changed events.
#[tool]
fn show_catalog(ctx: &McpContext) -> String {
    let resource = ctx.enable_resource("info://server");
    let prompt = ctx.enable_prompt("greeting");
    if resource && prompt {
        "shown".to_owned()
    } else {
        "silent".to_owned()
    }
}

/// Add two numbers together.
#[tool(description = "Calculate the sum of two numbers", tags = ["math"])]
fn add(_ctx: &McpContext, a: i64, b: i64) -> String {
    format!("{}", a + b)
}

/// Greets a name and injects an omitted suffix from the generated default.
#[tool(defaults(suffix = "!"))]
fn greet(_ctx: &McpContext, name: String, suffix: String) -> String {
    format!("greet:{name}{suffix}")
}

/// Reverse a string.
#[tool]
fn reverse(_ctx: &McpContext, text: String) -> String {
    text.chars().rev().collect()
}

/// Count words in text.
#[tool(name = "word_count", description = "Count the number of words in text")]
fn count_words(_ctx: &McpContext, text: String) -> String {
    let count = text.split_whitespace().count();
    format!("{count}")
}

static CACHE_PROBE_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Increments a process-local counter so `FASTMCP_CACHE_TOOLS=1` can prove
/// live stdio cache hits without re-invoking the handler.
#[tool]
fn cache_probe(_ctx: &McpContext, token: String) -> String {
    let n = CACHE_PROBE_CALLS.fetch_add(1, Ordering::SeqCst);
    format!("{token}:{n}")
}

const ECHO_STATE_KEY: &str = "e2e-echo-session-state";

/// Reads and writes session state so as_proxy stdio can prove the
/// upstream-binding bag (one shared stdio session).
#[tool]
fn state_probe(ctx: &McpContext, action: String, value: String) -> String {
    if !ctx.has_session_state() {
        return "state:none".to_owned();
    }
    match action.as_str() {
        "write" => {
            if !ctx.set_state(ECHO_STATE_KEY, value.clone()) {
                return "state:set-failed".to_owned();
            }
            format!(
                "state:{}",
                ctx.get_state::<String>(ECHO_STATE_KEY)
                    .unwrap_or_else(|| "missing".to_owned())
            )
        }
        "remove" => {
            let _ = ctx.remove_state(ECHO_STATE_KEY);
            format!(
                "state:{}",
                ctx.get_state::<String>(ECHO_STATE_KEY)
                    .unwrap_or_else(|| "missing".to_owned())
            )
        }
        _ => format!(
            "state:{}",
            ctx.get_state::<String>(ECHO_STATE_KEY)
                .unwrap_or_else(|| "missing".to_owned())
        ),
    }
}

/// Env-gated panic so live stdio can prove the handler unwind boundary.
///
/// Registered only when `FASTMCP_PANIC_TOOL=1`. The distinctive payload must
/// never reach the peer: dispatch sanitizes `Outcome::Panicked` to a fixed
/// InternalError.
#[tool]
fn panic_probe(_ctx: &McpContext) -> String {
    panic!("planted-handler-panic-payload")
}

/// Env-gated resource panic. Registered only when `FASTMCP_PANIC_CATALOG=1`.
#[resource(uri = "info://panic")]
fn panic_info(_ctx: &McpContext) -> String {
    panic!("planted-handler-panic-payload")
}

/// Env-gated prompt panic. Registered only when `FASTMCP_PANIC_CATALOG=1`.
#[prompt]
fn panic_greeting(_ctx: &McpContext) -> Vec<PromptMessage> {
    panic!("planted-handler-panic-payload")
}

async fn compose_nested_echo(
    ctx: &McpContext,
    message: &str,
    tool: &str,
    resource: &str,
) -> McpResult<String> {
    let echoed = ctx
        .call_tool_text(tool, serde_json::json!({ "message": message }))
        .await
        .map_err(|error| {
            McpError::invalid_request(format!("compose-nested-tool:{tool}:{}", error.message))
        })?;
    let info = ctx.read_resource_text(resource).await.map_err(|error| {
        McpError::invalid_request(format!(
            "compose-nested-resource:{resource}:{}",
            error.message
        ))
    })?;
    Ok(format!("compose:{echoed}|{info}"))
}

/// Composes the shipped `echo` tool and `info://server` resource.
///
/// Optional `tool` / `resource` arguments default to those peers so a
/// near-identical missing-name call is the planted negative.
#[tool(defaults(tool = "echo", resource = "info://server"))]
async fn compose_echo(
    ctx: &McpContext,
    message: String,
    tool: String,
    resource: String,
) -> McpResult<String> {
    compose_nested_echo(ctx, &message, &tool, &resource).await
}

/// Composes the shipped `greeting` prompt through `ctx.get_prompt`.
///
/// Optional `prompt` defaults to `greeting` so a near-identical missing-name
/// call is the planted negative.
#[tool(defaults(prompt = "greeting"))]
async fn compose_prompt(ctx: &McpContext, name: String, prompt: String) -> McpResult<String> {
    compose_nested_prompt(ctx, &name, &prompt).await
}

async fn compose_nested_prompt(ctx: &McpContext, name: &str, prompt: &str) -> McpResult<String> {
    let text = ctx
        .get_prompt_text(
            prompt,
            HashMap::from([("name".to_owned(), name.to_owned())]),
        )
        .await
        .map_err(|error| {
            McpError::invalid_request(format!("compose-nested-prompt:{prompt}:{}", error.message))
        })?;
    Ok(format!("compose-prompt:{text}"))
}

/// Handler whose per-tool timeout expires before its blocking delay finishes.
struct SlowEcho;

impl ToolHandler for SlowEcho {
    fn definition(&self) -> Tool {
        Tool {
            name: "slow_echo".to_owned(),
            description: Some("Proves live stdio handler timeout".to_owned()),
            input_schema: serde_json::json!({"type": "object"}),
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
        std::thread::sleep(Duration::from_millis(80));
        Ok(vec![Content::text("late")])
    }
}

/// Peer tool that stays inside the same request budget as `slow_echo`.
struct FastEcho;

impl ToolHandler for FastEcho {
    fn definition(&self) -> Tool {
        Tool {
            name: "fast_echo".to_owned(),
            description: Some("Proves live stdio handler timeout does not starve peers".to_owned()),
            input_schema: serde_json::json!({"type": "object"}),
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

/// Sleeps longer than a 1s gateway `request_timeout` and has no handler `timeout()`.
struct HoldEcho;

impl ToolHandler for HoldEcho {
    fn definition(&self) -> Tool {
        Tool {
            name: "hold_echo".to_owned(),
            description: Some(
                "Proves live stdio request_timeout of a tool without timeout()".to_owned(),
            ),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        std::thread::sleep(Duration::from_millis(1500));
        Ok(vec![Content::text("held")])
    }
}

/// Advertises an output schema and authors matching structured content.
struct StructuredEcho;

impl ToolHandler for StructuredEcho {
    fn definition(&self) -> Tool {
        Tool {
            name: "structured_echo".to_owned(),
            description: Some(
                "Returns structured output matching the advertised schema".to_owned(),
            ),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"]
            }),
            output_schema: Some(serde_json::json!({
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
        Some(serde_json::json!({
            "value": match kind {
                ToolErrorKind::InputValidation => "input-error",
                ToolErrorKind::Handler => "handler-error",
            }
        }))
    }

    fn call(&self, _ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let value = arguments
            .get("value")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("missing");
        Ok(vec![Content::text(format!("tool:{value}"))])
    }

    fn call_final(
        &self,
        _ctx: &McpContext,
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
                structured_content: Some(serde_json::json!({"value": value})),
            },
            ResultMeta::empty(),
        ))
    }
}

/// Returns image and audio content blocks on a live tools/call.
struct RichEcho;

impl ToolHandler for RichEcho {
    fn definition(&self) -> Tool {
        Tool {
            name: "rich_echo".to_owned(),
            description: Some("Returns image and audio content blocks".to_owned()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        // Exact 2024-11-05 has image but not audio. Keep the representable
        // block here; the final hook below authors both.
        Ok(vec![Content::image_base64("e2eimage", "image/png")])
    }

    fn call_final(
        &self,
        _ctx: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<CompleteResult<FinalCallToolResult>> {
        Ok(CompleteResult::new(
            FinalCallToolResult {
                content: vec![
                    ContentBlock::Image {
                        data: "e2eimage".to_owned(),
                        mime_type: "image/png".to_owned(),
                        annotations: None,
                        meta: None,
                        additional: BTreeMap::new(),
                    },
                    ContentBlock::Audio {
                        data: "e2eaudio".to_owned(),
                        mime_type: "audio/wav".to_owned(),
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

/// Returns the first filesystem root exposed by the connected client.
#[tool]
async fn client_root_uri(ctx: &McpContext) -> McpResult<String> {
    let roots = ctx.list_roots().await?;
    Ok(roots
        .first()
        .map(|root| root.uri.clone())
        .unwrap_or_else(|| "<no client roots>".to_string()))
}

/// Requests one exact-2024 reverse-JSON-RPC sample from the connected client.
#[tool]
async fn sample_text(ctx: &McpContext) -> McpResult<String> {
    let response = ctx.sample("echo", 16).await?;
    Ok(response.text)
}

fn complete_text_tool(text: impl Into<String>) -> FinalToolOutcome {
    FinalToolOutcome::Complete(CompleteResult::new(
        FinalCallToolResult {
            content: vec![ContentBlock::text(text.into())],
            is_error: false,
            structured_content: None,
        },
        ResultMeta::empty(),
    ))
}

/// Returns framework-issued MRTR sampling input, then completes from the retry.
#[tool]
fn sample_echo(
    ctx: &McpContext,
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    if let Some(completed_inputs) = completed_inputs {
        let sampled = completed_inputs
            .sampling("sample")?
            .ok_or_else(|| McpError::internal_error("sampling input was not preserved"))?;
        return Ok(complete_text_tool(format!("sampled:{}", sampled.model)));
    }
    let sampling = ctx.final_sampling(
        "sample",
        serde_json::from_value(serde_json::json!({
            "messages": [{
                "role": "user",
                "content": { "type": "text", "text": "echo" },
            }],
            "maxTokens": 16,
        }))
        .map_err(|error| McpError::internal_error(error.to_string()))?,
    )?;
    Ok(FinalToolOutcome::InputRequired(
        sampling.into_input_required()?,
    ))
}

/// Returns framework-issued MRTR URL elicitation, then completes from the retry.
#[tool]
fn url_elicit_echo(
    ctx: &McpContext,
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    if let Some(completed_inputs) = completed_inputs {
        let elicitation = completed_inputs
            .elicitation("approval")?
            .ok_or_else(|| McpError::internal_error("URL elicitation input was not preserved"))?;
        let action = if elicitation.is_accepted() {
            "accept"
        } else if elicitation.is_declined() {
            "decline"
        } else {
            "cancel"
        };
        return Ok(complete_text_tool(format!("url-elicit:{action}")));
    }
    let elicitation = ctx.final_elicitation_url(
        "approval",
        "Approve this operation",
        "https://example.com/approve",
    )?;
    Ok(FinalToolOutcome::InputRequired(
        elicitation.into_input_required()?,
    ))
}

/// Returns framework-issued MRTR roots input, then completes from the retry.
#[tool]
fn roots_echo(
    ctx: &McpContext,
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    if let Some(completed_inputs) = completed_inputs {
        let roots_len = completed_mrtr_roots_len(completed_inputs, "roots")?;
        return Ok(complete_text_tool(format!("roots:{roots_len}")));
    }
    let roots = ctx.final_roots("roots", FinalEmbeddedRootsListParams::default())?;
    Ok(FinalToolOutcome::InputRequired(
        roots.into_input_required()?,
    ))
}

// ============================================================================
// Resources
// ============================================================================

/// Returns server information.
#[resource(uri = "note://{name}", tags = ["notes"])]
fn note_card(_ctx: &McpContext, name: String) -> String {
    format!("note:{name}")
}

#[resource(uri = "memo://{name}", tags = ["memos"])]
fn memo_card(_ctx: &McpContext, name: String) -> String {
    format!("memo:{name}")
}

#[resource(
    uri = "info://server",
    tags = ["server"],
    icon = "https://example.test/echo-server.png"
)]
fn server_info(ctx: &McpContext) -> String {
    ctx.report_progress(1.0, Some("info"));
    r#"{
    "name": "echo-server",
    "version": "1.0.0",
    "description": "A simple example MCP server"
}"#
    .to_string()
}

/// Composes the shipped `echo` tool and `info://server` resource from a resource.
#[resource(uri = "info://compose")]
async fn compose_info(ctx: &McpContext) -> McpResult<String> {
    compose_nested_echo(ctx, "alpha", "echo", "info://server").await
}

/// Near-identical resource whose only change is the nested tool name.
#[resource(uri = "info://compose-missing-tool")]
async fn compose_info_missing_tool(ctx: &McpContext) -> McpResult<String> {
    compose_nested_echo(ctx, "alpha", "stdio-e2e-missing", "info://server").await
}

/// Composes the shipped `greeting` prompt from a resource.
#[resource(uri = "info://compose-prompt")]
async fn compose_info_prompt(ctx: &McpContext) -> McpResult<String> {
    compose_nested_prompt(ctx, "alpha", "greeting").await
}

/// Near-identical resource whose only change is the nested prompt name.
#[resource(uri = "info://compose-prompt-missing")]
async fn compose_info_prompt_missing(ctx: &McpContext) -> McpResult<String> {
    compose_nested_prompt(ctx, "alpha", "stdio-e2e-missing").await
}

/// Near-identical resource whose only change is the nested resource URI.
#[resource(uri = "info://compose-missing-resource")]
async fn compose_info_missing_resource(ctx: &McpContext) -> McpResult<String> {
    compose_nested_echo(ctx, "alpha", "echo", "info://stdio-e2e-missing").await
}

fn form_elicitation_input_required(ctx: &McpContext) -> McpResult<InputRequiredResult> {
    ctx.final_elicitation_form(
        "approval",
        "Approve this operation",
        serde_json::json!({
            "type": "object",
            "properties": {"approved": {"type": "boolean"}},
            "required": ["approved"],
        }),
    )?
    .into_input_required()
}

fn form_elicitation_action(completed_inputs: &MrtrCompletedInputs) -> McpResult<String> {
    let elicitation = completed_inputs
        .elicitation("approval")?
        .ok_or_else(|| McpError::internal_error("form elicitation input was not preserved"))?;
    if elicitation.is_accepted() {
        Ok(format!(
            "form-elicit:{}",
            elicitation.get_bool("approved").unwrap_or(false)
        ))
    } else if elicitation.is_declined() {
        Ok("form-elicit:decline".to_owned())
    } else {
        Ok("form-elicit:cancel".to_owned())
    }
}

/// Returns framework-issued MRTR form elicitation, then completes from the retry.
#[resource(uri = "info://elicit-form")]
fn elicit_form_info(
    ctx: &McpContext,
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<FinalMethodOutcome<FinalReadResourceResult>> {
    if let Some(completed_inputs) = completed_inputs {
        let text = form_elicitation_action(completed_inputs)?;
        return Ok(FinalMethodOutcome::Complete(CompleteResult::new(
            FinalReadResourceResult {
                contents: vec![EmbeddedResourceContents::Text {
                    uri: FinalAbsoluteUri::parse("info://elicit-form/result")
                        .expect("the shipped form-elicitation resource URI is absolute"),
                    text,
                    mime_type: Some("text/plain".to_owned()),
                    meta: None,
                    additional: BTreeMap::new(),
                }],
                ttl_ms: CacheTtl::milliseconds(7),
                cache_scope: CacheScope::Private,
            },
            ResultMeta::empty(),
        )));
    }
    form_elicitation_input_required(ctx).map(FinalMethodOutcome::InputRequired)
}

/// Returns an execution error that carries an internal secret so
/// `FASTMCP_MASK_ERROR_DETAILS=1` can prove live stdio masking.
#[resource(uri = "info://leak", tags = ["secret"])]
fn leak_info(_ctx: &McpContext) -> McpResult<String> {
    Err(McpError::tool_error("secret-db-dsn"))
}

/// Returns current timestamp.
#[resource(
    uri = "info://time",
    name = "Current Time",
    description = "Returns the current Unix timestamp"
)]
fn current_time(_ctx: &McpContext) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{timestamp}")
}

fn mrtr_roots_input_required(
    keys: impl IntoIterator<Item = String>,
) -> McpResult<InputRequiredResult> {
    let mut input_requests = serde_json::Map::new();
    for key in keys {
        input_requests.insert(key, serde_json::json!({"method": "roots/list"}));
    }
    let exact_input_requests =
        fastmcp_rust::exact_json_from_serde(&serde_json::Value::Object(input_requests))
            .map_err(|error| McpError::invalid_params(error.to_string()))?;
    let fastmcp_rust::ExactJsonValue::Object(exact_input_requests) = exact_input_requests else {
        return Err(McpError::internal_error(
            "MRTR input requests must encode as an object",
        ));
    };
    InputRequiredResult::new(Some(exact_input_requests), None, ResultMeta::empty())
        .map_err(|error| McpError::invalid_params(error.to_string()))
}

fn completed_mrtr_roots_len(completed_inputs: &MrtrCompletedInputs, key: &str) -> McpResult<usize> {
    completed_inputs
        .roots(key)?
        .map(|roots| roots.roots.len())
        .ok_or_else(|| McpError::internal_error("MRTR roots input was not preserved"))
}

fn mrtr_resource_complete(roots_len: usize) -> CompleteResult<FinalReadResourceResult> {
    CompleteResult::new(
        FinalReadResourceResult {
            contents: vec![EmbeddedResourceContents::Text {
                uri: FinalAbsoluteUri::parse("info://mrtr-resource/result")
                    .expect("the shipped MRTR resource URI is absolute"),
                text: format!("typed resource roots={roots_len}"),
                mime_type: Some("text/plain".to_owned()),
                meta: None,
                additional: BTreeMap::new(),
            }],
            ttl_ms: CacheTtl::milliseconds(7),
            cache_scope: CacheScope::Private,
        },
        ResultMeta::empty(),
    )
}

/// Requires one typed embedded roots result before returning a final resource.
/// A sentinel root asks for another round so the public client can prove its
/// continuation bound without changing server configuration.
#[resource(uri = "info://mrtr-resource")]
fn mrtr_resource(
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<FinalMethodOutcome<FinalReadResourceResult>> {
    let Some(completed_inputs) = completed_inputs else {
        return Ok(FinalMethodOutcome::InputRequired(
            mrtr_roots_input_required(["roots".to_owned()])?,
        ));
    };
    let roots_len = completed_mrtr_roots_len(completed_inputs, "roots")?;
    let repeats = completed_inputs
        .roots("roots")?
        .expect("the checked MRTR roots result remains available")
        .roots
        .iter()
        .any(|root| root.uri == "file:///mrtr/retry");
    if repeats {
        return Ok(FinalMethodOutcome::InputRequired(
            mrtr_roots_input_required(["roots".to_owned()])?,
        ));
    }
    Ok(FinalMethodOutcome::Complete(mrtr_resource_complete(
        roots_len,
    )))
}

// ============================================================================
// Prompts
// ============================================================================

/// A simple greeting prompt.
#[prompt(
    description = "Generate a friendly greeting",
    tags = ["onboarding"],
    icon = "https://example.test/echo-greeting.png"
)]
fn greeting(ctx: &McpContext, name: String) -> Vec<PromptMessage> {
    ctx.report_progress(1.0, Some("greeted"));
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("Please greet {name} in a friendly way."),
        },
    }]
}

/// Composes the shipped `echo` tool and `info://server` resource from a prompt.
///
/// Optional `tool` / `resource` arguments default to those peers so a
/// near-identical missing-name call is the planted negative.
#[prompt(defaults(tool = "echo", resource = "info://server"), tags = ["compose"])]
async fn compose_greeting(
    ctx: &McpContext,
    name: String,
    tool: String,
    resource: String,
) -> McpResult<Vec<PromptMessage>> {
    let composed = compose_nested_echo(ctx, &name, &tool, &resource).await?;
    Ok(vec![PromptMessage {
        role: Role::User,
        content: Content::text(composed),
    }])
}

/// Composes the shipped `greeting` prompt through `ctx.get_prompt`.
#[prompt(defaults(prompt = "greeting"), tags = ["compose"])]
async fn compose_from_prompt(
    ctx: &McpContext,
    name: String,
    prompt: String,
) -> McpResult<Vec<PromptMessage>> {
    let composed = compose_nested_prompt(ctx, &name, &prompt).await?;
    Ok(vec![PromptMessage {
        role: Role::User,
        content: Content::text(composed),
    }])
}

/// Returns framework-issued MRTR form elicitation, then completes from the retry.
#[prompt]
fn elicit_form_greeting(
    ctx: &McpContext,
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<FinalMethodOutcome<FinalGetPromptResult>> {
    if let Some(completed_inputs) = completed_inputs {
        let text = form_elicitation_action(completed_inputs)?;
        return Ok(FinalMethodOutcome::Complete(CompleteResult::new(
            FinalGetPromptResult {
                description: Some("typed form elicitation prompt result".to_owned()),
                messages: vec![FinalPromptMessage {
                    role: Role::Assistant,
                    content: ContentBlock::Text {
                        text,
                        annotations: None,
                        meta: None,
                        additional: BTreeMap::new(),
                    },
                }],
            },
            ResultMeta::empty(),
        )));
    }
    form_elicitation_input_required(ctx).map(FinalMethodOutcome::InputRequired)
}

/// A code review prompt.
#[prompt(name = "review_code")]
fn code_review_prompt(_ctx: &McpContext, code: String, language: String) -> Vec<PromptMessage> {
    let lang_hint = if language.is_empty() {
        String::new()
    } else {
        format!(" (written in {language})")
    };

    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!(
                "Please review the following code{lang_hint} and provide feedback:\n\n```\n{code}\n```"
            ),
        },
    }]
}

fn mrtr_prompt_complete(roots_len: usize) -> CompleteResult<FinalGetPromptResult> {
    CompleteResult::new(
        FinalGetPromptResult {
            description: Some("typed MRTR prompt result".to_owned()),
            messages: vec![FinalPromptMessage {
                role: Role::Assistant,
                content: ContentBlock::Text {
                    text: format!("typed prompt roots={roots_len}"),
                    annotations: None,
                    meta: None,
                    additional: BTreeMap::new(),
                },
            }],
        },
        ResultMeta::empty(),
    )
}

/// Uses a terminal mode for the exact typed-result proof and bounded modes
/// for public client cancellation, round, and total-input guards.
#[prompt(name = "mrtr_prompt")]
fn mrtr_prompt(
    completed_inputs: Option<&MrtrCompletedInputs>,
    mode: String,
) -> McpResult<FinalMethodOutcome<FinalGetPromptResult>> {
    let keys = match mode.as_str() {
        "terminal" | "round-bound" => vec!["roots".to_owned()],
        "input-bound" => (0..128).map(|index| format!("roots-{index}")).collect(),
        _ => return Err(McpError::invalid_params("unknown MRTR prompt mode")),
    };

    if let Some(completed_inputs) = completed_inputs {
        match mode.as_str() {
            "terminal" => {
                return Ok(FinalMethodOutcome::Complete(mrtr_prompt_complete(
                    completed_mrtr_roots_len(completed_inputs, "roots")?,
                )));
            }
            "round-bound" => {
                completed_mrtr_roots_len(completed_inputs, "roots")?;
            }
            "input-bound" => {
                for key in &keys {
                    completed_mrtr_roots_len(completed_inputs, key)?;
                }
            }
            _ => unreachable!("the mode was admitted above"),
        }
    }

    Ok(FinalMethodOutcome::InputRequired(
        mrtr_roots_input_required(keys)?,
    ))
}

// ============================================================================
// Completion
// ============================================================================

static GREETING_COMPLETION_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Completion provider for the public modern stdio integration path.
struct GreetingCompletion;

impl CompletionHandler for GreetingCompletion {
    fn complete_legacy(
        &self,
        ctx: &McpContext,
        params: fastmcp_rust::legacy_2024::LegacyCompletionParams,
    ) -> McpResult<fastmcp_rust::legacy_2024::CompletionValues> {
        match &params.reference {
            fastmcp_rust::legacy_2024::LegacyCompletionReference::Prompt { name }
                if name == "greeting" => {}
            _ => {
                return Err(McpError::invalid_params(
                    "greeting completion requires the greeting prompt",
                ));
            }
        }
        ctx.report_progress(0.5, Some("stdio-completion-legacy-halfway"));
        Ok(fastmcp_rust::legacy_2024::CompletionValues {
            values: vec!["stdio-completion-legacy".to_owned()],
            total: Some(1),
            has_more: Some(false),
        })
    }

    fn complete_final(
        &self,
        ctx: &McpContext,
        params: FinalCompletionParams,
    ) -> McpResult<FinalCompletionValues> {
        let call_count = GREETING_COMPLETION_CALLS.fetch_add(1, Ordering::SeqCst) + 1;
        if !matches!(
            &params.reference,
            FinalCompletionReference::PromptWithTitle { name, title }
                if name == "greeting" && title == "Greeting"
        ) || params.argument.name != "name"
            || params.argument.value != "co"
            || params
                .context
                .as_ref()
                .and_then(|context| context.arguments.as_ref())
                .and_then(|arguments| arguments.get("locale"))
                .map(String::as_str)
                != Some("en-US")
        {
            return Err(McpError::invalid_params(
                "greeting completion requires the exact modern request shape",
            ));
        }

        ctx.report_progress(0.5, Some("stdio-completion-halfway"));
        Ok(FinalCompletionValues {
            values: vec![format!("stdio-completion-{call_count}")],
            total: Some(JsonInteger::from(
                u64::try_from(call_count).expect("the process-local call counter fits in u64"),
            )),
            has_more: Some(false),
        })
    }
}

/// Completion provider for the shipped `note://{name}` resource template.
struct NoteCompletion;

impl CompletionHandler for NoteCompletion {
    fn complete_legacy(
        &self,
        _ctx: &McpContext,
        params: fastmcp_rust::legacy_2024::LegacyCompletionParams,
    ) -> McpResult<fastmcp_rust::legacy_2024::CompletionValues> {
        match &params.reference {
            fastmcp_rust::legacy_2024::LegacyCompletionReference::Resource { uri }
                if uri == "note://{name}" && params.argument.name == "name" => {}
            _ => {
                return Err(McpError::invalid_params(
                    "note completion requires the exact resource template",
                ));
            }
        }
        Ok(fastmcp_rust::legacy_2024::CompletionValues {
            values: vec!["stdio-note-completion-legacy".to_owned()],
            total: Some(1),
            has_more: Some(false),
        })
    }

    fn complete_final(
        &self,
        _ctx: &McpContext,
        params: FinalCompletionParams,
    ) -> McpResult<FinalCompletionValues> {
        if !matches!(
            &params.reference,
            FinalCompletionReference::Resource { uri } if uri == "note://{name}"
        ) || params.argument.name != "name"
            || params.argument.value != "al"
        {
            return Err(McpError::invalid_params(
                "note completion requires the exact modern request shape",
            ));
        }
        Ok(FinalCompletionValues {
            values: vec!["alice".to_owned()],
            total: Some(JsonInteger::from(1_u64)),
            has_more: Some(false),
        })
    }
}

/// Env-gated completion panic. Installed only when `FASTMCP_PANIC_COMPLETE=1`.
struct PanicCompletion;

impl CompletionHandler for PanicCompletion {
    fn complete_legacy(
        &self,
        _ctx: &McpContext,
        _params: fastmcp_rust::legacy_2024::LegacyCompletionParams,
    ) -> McpResult<fastmcp_rust::legacy_2024::CompletionValues> {
        panic!("planted-handler-panic-payload")
    }

    fn complete_final(
        &self,
        _ctx: &McpContext,
        _params: FinalCompletionParams,
    ) -> McpResult<FinalCompletionValues> {
        panic!("planted-handler-panic-payload")
    }
}

// ============================================================================
// Caller-owned Tasks service
// ============================================================================

static DURABLE_TASK_TOOL_CALLS: AtomicUsize = AtomicUsize::new(0);

/// A task-capable tool whose durable work is advanced by the embedding-owned
/// service below. Its exact-2024 implementation remains an ordinary tool.
struct DurableTaskTool;

impl ToolHandler for DurableTaskTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "durable_task".to_owned(),
            description: Some("Creates one caller-supervised modern Task".to_owned()),
            input_schema: serde_json::json!({"type": "object"}),
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
        let call = DURABLE_TASK_TOOL_CALLS.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(FinalToolOutcome::CreateTask {
            work_descriptor: FinalTaskWorkDescriptor::new(serde_json::json!({
                "operation": "echo-stdio-durable-task",
                "call": call,
            }))?,
            status_message: Some(format!("durable stdio task call {call}")),
        })
    }
}

/// Advances initial Task work to `input_required`, then waits for caller
/// input or cancellation. The framework never creates this service or its
/// runtime; the embedding owns both in `run_tasks_stdio`.
struct DurableTaskSupervisor;

impl ApplicationTaskSupervisor for DurableTaskSupervisor {
    fn resume<'a>(
        &'a self,
        cx: &'a Cx,
        handoff: FinalTaskSupervisorHandoff,
    ) -> FinalTaskSupervisorFuture<'a> {
        Box::pin(async move {
            match handoff {
                FinalTaskSupervisorHandoff::Initial(initial) => {
                    let requests: FinalTaskInputRequests = serde_json::from_value(
                        serde_json::json!({"roots": {"method": "roots/list"}}),
                    )
                    .map_err(|_| McpError::internal_error("Task input descriptor is invalid"))?;
                    initial.require_input(
                        requests,
                        Some("awaiting roots from the caller-owned stdio service".to_owned()),
                    )?;
                }
                FinalTaskSupervisorHandoff::Resumed(accepted) => loop {
                    if accepted.is_cancellation_requested()? {
                        accepted.honor_cancellation(Some(
                            "cancelled by the caller-owned stdio service".to_owned(),
                        ))?;
                        break;
                    }
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                },
            }
            Ok(())
        })
    }
}

const TASK_SERVICE_STARTUP_BOUND: Duration = Duration::from_secs(2);
const TASK_SERVICE_SETTLEMENT_BOUND: Duration = Duration::from_secs(4);

async fn run_tasks_stdio(
    server: fastmcp_server::Server,
    runtime: FinalTaskRuntime,
    runner: AuthorizedTaskServiceRunner,
    cx: &Cx,
) -> McpResult<()> {
    let mut service = cx
        .spawn(move |service_cx| async move { runner.run(&service_cx).await })
        .map_err(|error| {
            McpError::internal_error(format!("Task service admission failed: {error}"))
        })?;
    let readiness_deadline = cx.now() + TASK_SERVICE_STARTUP_BOUND;
    while !runtime.is_task_service_ready() {
        if service.is_finished() {
            return Err(McpError::internal_error(
                "Caller-owned Task service stopped before publishing readiness",
            ));
        }
        asupersync::time::timeout_at(
            readiness_deadline,
            asupersync::time::sleep(cx.now(), Duration::from_millis(1)),
        )
        .await
        .map_err(|_| {
            McpError::internal_error("Caller-owned Task service did not become ready within bound")
        })?;
    }

    let mut stdio = cx
        .spawn_blocking(move |stdio_cx| {
            let (recv_half, send_half) = StdioTransport::stdio().into_split();
            server.run_split_transport_returning_with_cx(&stdio_cx, recv_half, send_half)
        })
        .map_err(|error| {
            McpError::internal_error(format!("stdio service admission failed: {error}"))
        })?;
    let server_result = stdio.join(cx).await.map_err(|error| {
        McpError::internal_error(format!("stdio service join failed: {error:?}"))
    })?;

    service.abort();
    match asupersync::time::timeout(cx.now(), TASK_SERVICE_SETTLEMENT_BOUND, service.join(cx)).await
    {
        Ok(Ok(result)) => result?,
        Ok(Err(asupersync::runtime::JoinError::Cancelled(_))) => {}
        Ok(Err(error)) => {
            return Err(McpError::internal_error(format!(
                "Task service join failed: {error:?}"
            )));
        }
        Err(_) => {
            return Err(McpError::internal_error(
                "Task service did not settle within bound",
            ));
        }
    }
    server_result
}

async fn run_stdio(server: fastmcp_server::Server, cx: &Cx) -> McpResult<()> {
    let mut stdio = cx
        .spawn_blocking(move |stdio_cx| {
            let (recv_half, send_half) = StdioTransport::stdio().into_split();
            server.run_split_transport_returning_with_cx(&stdio_cx, recv_half, send_half)
        })
        .map_err(|error| {
            McpError::internal_error(format!("stdio service admission failed: {error}"))
        })?;
    stdio.join(cx).await.map_err(|error| {
        McpError::internal_error(format!("stdio service join failed: {error:?}"))
    })?
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let task_runtime = FinalTaskRuntime::in_memory_with_capacity(
        1,
        FinalTaskRuntimeConfig::new(60_000, Some(1_000))
            .expect("the example Task retention policy is finite"),
        std::sync::Arc::new(|_| {}),
    )
    .expect("the example Task store has a positive capacity");
    let task_runner = task_runtime
        .install_task_service(1, std::sync::Arc::new(DurableTaskSupervisor))
        .expect("the caller-owned example Task service installs once");

    let builder = ServerBuilder::new("echo-server", "1.0.0")
        // Register tools
        .tool(Echo)
        .tool(ClientIdentity)
        .tool(TouchServerInfo)
        .tool(HideEcho)
        .tool(HideCatalog)
        .tool(ShowEcho)
        .tool(ShowCatalog)
        .tool(Add)
        .tool(Greet)
        .tool(Reverse)
        .tool(CountWords)
        .tool(CacheProbe)
        .tool(StateProbe)
        .tool(ComposeEcho)
        .tool(ComposePrompt)
        .tool(SlowEcho)
        .tool(FastEcho)
        .tool(HoldEcho)
        .tool(StructuredEcho)
        .tool(RichEcho)
        .tool(ClientRootUri)
        .tool(SampleText)
        .tool(SampleEcho)
        .tool(UrlElicitEcho)
        .tool(RootsEcho)
        // Register resources
        .resource(ServerInfoResource)
        .resource(NoteCardResource)
        .resource(MemoCardResource)
        .resource(ComposeInfoResource)
        .resource(ComposeInfoMissingToolResource)
        .resource(ComposeInfoMissingResourceResource)
        .resource(ComposeInfoPromptResource)
        .resource(ComposeInfoPromptMissingResource)
        .resource(ElicitFormInfoResource)
        .resource(LeakInfoResource)
        .resource(CurrentTimeResource)
        .resource(MrtrResourceResource)
        // Register prompts
        .prompt(GreetingPrompt)
        .prompt(ComposeGreetingPrompt)
        .prompt(ComposeFromPromptPrompt)
        .prompt(ElicitFormGreetingPrompt)
        .prompt(CodeReviewPromptPrompt)
        .prompt(MrtrPromptPrompt)
        // Set timeout (30 seconds per request)
        .request_timeout(30);
    let builder = if std::env::var("FASTMCP_PANIC_COMPLETE").as_deref() == Ok("1") {
        builder
            .prompt_completion_handler("greeting", PanicCompletion)
            .legacy_completion_handler(PanicCompletion)
    } else if std::env::var("FASTMCP_NO_COMPLETIONS").as_deref() == Ok("1") {
        builder
    } else {
        builder
            .prompt_completion_handler("greeting", GreetingCompletion)
            .legacy_completion_handler(GreetingCompletion)
            .resource_template_completion_handler("note://{name}", NoteCompletion)
            .legacy_resource_template_completion_handler("note://{name}", NoteCompletion)
    };
    let builder = if std::env::var("FASTMCP_NO_INSTRUCTIONS").as_deref() == Ok("1") {
        builder
    } else {
        builder.instructions(
            "A simple echo server for testing FastMCP. Try calling the 'echo' tool with a message!",
        )
    };
    let builder = if std::env::var("FASTMCP_NO_IDENTITY").as_deref() == Ok("1") {
        builder
    } else {
        builder
            .title("FastMCP Echo")
            .description("A simple echo server for testing FastMCP.")
            .website_url("https://example.test/fastmcp")
            .icons(vec![
                RawIcon::try_new("https://example.test/echo-icon.png")
                    .expect("the echo identity icon source is an absolute URI"),
            ])
    };
    let builder = if std::env::var("FASTMCP_MASK_ERROR_DETAILS").as_deref() == Ok("1") {
        builder.mask_error_details(true)
    } else {
        builder
    };
    let builder = if std::env::var("FASTMCP_STRICT_INPUT").as_deref() == Ok("1") {
        builder.strict_input_validation(true)
    } else {
        builder
    };
    let builder = if std::env::var("FASTMCP_SLIDING_WINDOW").as_deref() == Ok("1") {
        builder.middleware(SlidingWindowRateLimitingMiddleware::new(1, 60))
    } else {
        builder
    };
    let builder = if std::env::var("FASTMCP_RATE_LIMIT").as_deref() == Ok("1") {
        builder.middleware(RateLimitingMiddleware::new(1.0e-300).burst_capacity(1))
    } else {
        builder
    };
    let builder = if std::env::var("FASTMCP_REPLACE_ECHO").as_deref() == Ok("1") {
        builder
            .on_duplicate(DuplicateBehavior::Replace)
            .tool(EchoReplaced)
    } else {
        builder
    };
    let builder = if std::env::var("FASTMCP_TRANSFORM_ECHO").as_deref() == Ok("1") {
        builder.tool(
            TransformedTool::from_tool(Echo)
                .name("echo_text")
                .rename_arg("message", "text")
                .build(),
        )
    } else {
        builder
    };
    let builder = if std::env::var("FASTMCP_TRANSFORM_HIDE").as_deref() == Ok("1") {
        builder.tool(
            TransformedTool::from_tool(Echo)
                .name("echo_hidden")
                .hide_arg("message", "hidden-default")
                .build(),
        )
    } else {
        builder
    };
    let builder = match std::env::var("FASTMCP_LIST_PAGE_SIZE") {
        Ok(value) if !value.is_empty() => builder.list_page_size(
            value
                .parse::<usize>()
                .expect("FASTMCP_LIST_PAGE_SIZE must be a usize"),
        ),
        _ => builder,
    };
    let builder = if std::env::var("FASTMCP_CACHE_TOOLS").as_deref() == Ok("1") {
        builder.middleware(
            ResponseCachingMiddleware::new().include_tools(vec!["cache_probe".to_owned()]),
        )
    } else {
        builder
    };
    let builder = if std::env::var("FASTMCP_PANIC_TOOL").as_deref() == Ok("1") {
        builder.tool(PanicProbe)
    } else {
        builder
    };
    let builder = if std::env::var("FASTMCP_PANIC_CATALOG").as_deref() == Ok("1") {
        builder
            .resource(PanicInfoResource)
            .prompt(PanicGreetingPrompt)
    } else {
        builder
    };
    let builder = match std::env::var("FASTMCP_FS_ROOT") {
        Ok(root) if !root.is_empty() => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                let prefix =
                    std::env::var("FASTMCP_FS_PREFIX").unwrap_or_else(|_| "e2e".to_owned());
                let handler = FilesystemProvider::new(root)
                    .with_prefix(prefix)
                    .with_exclude(&[])
                    .build()
                    .expect("FASTMCP_FS_ROOT installs a live FilesystemProvider on linux/macos");
                builder.resource(handler)
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                let _ = root;
                builder
            }
        }
        _ => builder,
    };
    let server = builder
        .tool(DurableTaskTool)
        .final_tasks(task_runtime.clone())
        .expect("the official Tasks extension installs on the modern-capable example server")
        .build();
    let protocol_policy = server.protocol_policy();

    let application_runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(
            asupersync::runtime::reactor::create_reactor()
                .expect("the example caller runtime reactor initializes"),
        )
        .blocking_threads(4, 64)
        .build()
        .expect("the example caller runtime initializes");
    application_runtime
        .block_on(async move {
            let cx = Cx::current().expect("the example caller runtime installs its Cx");
            match protocol_policy {
                // The component builder read FASTMCP_PROTOCOL_POLICY before
                // registration. Exact 2024 gets no Task service and its
                // dispatch remains blind to the modern Tasks extension.
                ProtocolPolicy::LegacyOnly => run_stdio(server, &cx).await,
                ProtocolPolicy::Auto | ProtocolPolicy::ModernOnly => {
                    run_tasks_stdio(server, task_runtime, task_runner, &cx).await
                }
            }
        })
        .expect("the caller-owned stdio server and Task service settle cleanly");
}
