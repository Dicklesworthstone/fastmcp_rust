//! Conformance adapter: serves the official MCP conformance fixture contract
//! over modern HTTP so the official suite can be run against this codebase.
//!
//! # Why this exists
//!
//! Plan section 2.6 permits an MCP 2026-07-28 support claim only once "the
//! official conformance harness passes in both client and server modes". That
//! harness is `@modelcontextprotocol/conformance`, it requires the caller to own
//! the server lifecycle, and it connects as an MCP client to a URL. This binary
//! is the server it connects to.
//!
//! # Running it
//!
//! ```bash
//! cargo run -p fastmcp-rust --bin conformance_server -- 127.0.0.1:3001
//! # then, with the suite PINNED (see the pin note below):
//! npx @modelcontextprotocol/conformance@0.2.0-alpha.10 server \
//!   --url http://127.0.0.1:3001/mcp --spec-version 2026-07-28 --suite all
//! ```
//!
//! PIN NOTE: `@latest` resolves to 0.1.16, which rejects
//! `--spec-version 2026-07-28` outright because npm's `latest` tag excludes
//! prereleases. Pinning `0.2.0-alpha.10` matters: it is also the anchor named by
//! upstream `requirements/2026-07-28.yaml`. The default `active` suite runs only
//! 20 scenarios and omits every 2026-only one; pass `--suite all`.
//!
//! # Scope
//!
//! Every fixture below is named and shaped by the suite's own scenario
//! requirements (tools, resources, prompts, completion, progress, logging, the
//! JSON Schema 2020-12 tool, the `x-mcp-header` tool, the `server-stateless`
//! diagnostic tools, and the SEP-2322 `input_required` tools). Fixtures carry
//! no conformance-specific behavior in the library: they use only the public
//! handler APIs an application would use. Not served: the list-mutation
//! triggers (`test_trigger_tool_change` / `test_trigger_prompt_change`, SHOULD
//! level), because the server has no runtime catalog-mutation API, and the
//! 2025-era scenarios this 2026-07-28 server does not claim.

#![allow(clippy::needless_pass_by_value)]

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use fastmcp_protocol::http_headers::{NonSensitiveHeaderExposure, ToolSchemaRevision};
use fastmcp_protocol::{MissingRequiredClientCapabilityError, ResourceContent};
use fastmcp_rust::modern::{FinalMethodOutcome, MrtrCompletedInputs};
use fastmcp_rust::prelude::*;
use fastmcp_rust::{
    ApplicationTaskSupervisor, CompleteResult, ContentBlock, FinalCallToolResult,
    FinalCompletionParams, FinalCompletionValues, FinalElicitationContextExt,
    FinalEmbeddedRootsListParams, FinalPromptMessage, FinalRootsContextExt,
    FinalTaskCallToolResult, FinalTaskError, FinalTaskInputRequests, FinalTaskSupervisorFuture,
    FinalTaskSupervisorHandoff, FinalTaskWorkDescriptor, FinalToolOutcome, InputRequiredResult,
    McpErrorCode, PromptHandler, ResultMeta, ToolHandler,
};
use fastmcp_server::ServerBuilder;

/// Tiny opaque payloads. The scenarios assert on content SHAPE — type, mime
/// type, presence — not on these bytes, so a minimal valid base64 body is
/// correct here and a large realistic asset would only slow the suite.
const TEST_IMAGE_BASE64: &str = "iVBORw0KGgo=";
const TEST_AUDIO_BASE64: &str = "UklGRgA=";

// ============================================================================
// Shared helpers
// ============================================================================

fn complete_text(text: impl Into<String>) -> FinalToolOutcome {
    FinalToolOutcome::Complete(CompleteResult::new(
        FinalCallToolResult {
            content: vec![ContentBlock::text(text.into())],
            is_error: false,
            structured_content: None,
        },
        ResultMeta::empty(),
    ))
}

/// Builds one `input_required` result carrying several input requests.
/// The router validates every descriptor and mints the protected
/// `requestState` itself.
fn input_required(requests: serde_json::Value) -> McpResult<InputRequiredResult> {
    let exact = fastmcp_rust::exact_json_from_serde(&requests)
        .map_err(|error| McpError::invalid_params(error.to_string()))?;
    let fastmcp_rust::ExactJsonValue::Object(map) = exact else {
        return Err(McpError::internal_error(
            "input requests must encode as an object",
        ));
    };
    InputRequiredResult::new(Some(map), None, ResultMeta::empty())
        .map_err(|error| McpError::invalid_params(error.to_string()))
}

fn name_form(message: &str) -> serde_json::Value {
    serde_json::json!({
        "method": "elicitation/create",
        "params": {
            "mode": "form",
            "message": message,
            "requestedSchema": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
        },
    })
}

fn sampling_request(text: &str, max_tokens: u32) -> serde_json::Value {
    serde_json::json!({
        "method": "sampling/createMessage",
        "params": {
            "messages": [{"role": "user", "content": {"type": "text", "text": text}}],
            "maxTokens": max_tokens,
        },
    })
}

fn roots_request() -> serde_json::Value {
    serde_json::json!({"method": "roots/list", "params": {}})
}

fn elicited_string(
    inputs: &MrtrCompletedInputs,
    key: &str,
    field: &str,
) -> McpResult<Option<String>> {
    Ok(inputs
        .elicitation(key)?
        .and_then(|result| result.get_string(field).map(str::to_owned)))
}

/// Extracts the first text block of a sampling response without depending on
/// its exact content-block representation.
fn sampled_text(inputs: &MrtrCompletedInputs, key: &str) -> McpResult<Option<String>> {
    let Some(result) = inputs.sampling(key)? else {
        return Ok(None);
    };
    let wire = serde_json::to_value(&result)
        .map_err(|error| McpError::internal_error(error.to_string()))?;
    let content = &wire["content"];
    let text = content["text"].as_str().or_else(|| {
        content
            .as_array()
            .and_then(|blocks| blocks.iter().find_map(|block| block["text"].as_str()))
    });
    Ok(Some(text.unwrap_or("").to_owned()))
}

// ============================================================================
// Tier 1: content tools
// ============================================================================

#[tool(name = "test_simple_text", description = "Returns simple text content")]
fn test_simple_text(ctx: &McpContext) -> McpResult<Vec<Content>> {
    ctx.checkpoint()?;
    Ok(vec![Content::text(
        "This is a simple text response for testing.",
    )])
}

#[tool(
    name = "test_image_content",
    description = "Tests image content response"
)]
fn test_image_content(ctx: &McpContext) -> McpResult<Vec<Content>> {
    ctx.checkpoint()?;
    Ok(vec![Content::image_base64(TEST_IMAGE_BASE64, "image/png")])
}

#[tool(
    name = "test_audio_content",
    description = "Tests audio content response"
)]
fn test_audio_content(ctx: &McpContext) -> McpResult<Vec<Content>> {
    ctx.checkpoint()?;
    Ok(vec![Content::audio_base64(TEST_AUDIO_BASE64, "audio/wav")])
}

#[tool(
    name = "test_embedded_resource",
    description = "Tests embedded resource content response"
)]
fn test_embedded_resource(ctx: &McpContext) -> McpResult<Vec<Content>> {
    ctx.checkpoint()?;
    Ok(vec![Content::resource_text(
        "test://embedded-resource",
        Some("text/plain".to_owned()),
        "This is an embedded resource content.",
    )])
}

#[tool(
    name = "test_multiple_content_types",
    description = "Tests a result carrying text, image, and resource content"
)]
fn test_multiple_content_types(ctx: &McpContext) -> McpResult<Vec<Content>> {
    ctx.checkpoint()?;
    Ok(vec![
        Content::text("Multiple content types test:"),
        Content::image_base64(TEST_IMAGE_BASE64, "image/png"),
        Content::resource_text(
            "test://mixed-content-resource",
            Some("application/json".to_owned()),
            r#"{"test":"data","value":123}"#,
        ),
    ])
}

/// Always fails with a tool *execution* error, which MCP reports in-band as
/// `isError: true`. `McpError::tool_error` is the in-band constructor;
/// `McpError::internal_error` is deliberately an opaque protocol failure
/// (framework guards such as the nested-call depth limit rely on it staying
/// terminal).
#[tool(
    name = "test_error_handling",
    description = "Tests tool error reporting"
)]
fn test_error_handling(ctx: &McpContext) -> McpResult<Vec<Content>> {
    ctx.checkpoint()?;
    Err(McpError::tool_error(
        "This tool intentionally returns an error for testing",
    ))
}

// ============================================================================
// Tier 2: progress and logging
// ============================================================================

#[tool(
    name = "test_tool_with_progress",
    description = "Reports progress 0/100, 50/100, 100/100"
)]
fn test_tool_with_progress(ctx: &McpContext) -> McpResult<Vec<Content>> {
    ctx.report_progress_with_total(0.0, 100.0, Some("started"));
    std::thread::sleep(Duration::from_millis(50));
    ctx.checkpoint()?;
    ctx.report_progress_with_total(50.0, 100.0, Some("halfway"));
    std::thread::sleep(Duration::from_millis(50));
    ctx.checkpoint()?;
    ctx.report_progress_with_total(100.0, 100.0, Some("done"));
    Ok(vec![Content::text("Progress test completed")])
}

fn log_three_steps(ctx: &McpContext) -> McpResult<()> {
    ctx.info("Tool execution started");
    std::thread::sleep(Duration::from_millis(50));
    ctx.checkpoint()?;
    ctx.info("Tool processing data");
    std::thread::sleep(Duration::from_millis(50));
    ctx.checkpoint()?;
    ctx.info("Tool execution completed");
    Ok(())
}

#[tool(
    name = "test_tool_with_logging",
    description = "Sends three info log messages during execution"
)]
fn test_tool_with_logging(ctx: &McpContext) -> McpResult<Vec<Content>> {
    log_three_steps(ctx)?;
    Ok(vec![Content::text("Logging test completed")])
}

/// `server-stateless` diagnostic: logs only reach the client when its request
/// set `_meta.io.modelcontextprotocol/logLevel`.
#[tool(
    name = "test_logging_tool",
    description = "Emits log messages; none may be sent without a request logLevel"
)]
fn test_logging_tool(ctx: &McpContext) -> McpResult<Vec<Content>> {
    log_three_steps(ctx)?;
    Ok(vec![Content::text("logging tool completed")])
}

// ============================================================================
// server-stateless diagnostics
// ============================================================================

/// Requires the `sampling` client capability for this request. Without it the
/// request fails with the canonical `-32021` and its `requiredCapabilities`.
#[tool(
    name = "test_missing_capability",
    description = "Requires the sampling client capability"
)]
fn test_missing_capability(
    ctx: &McpContext,
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    if !ctx.client_supports_sampling() {
        let missing =
            MissingRequiredClientCapabilityError::new(serde_json::json!({"sampling": {}}))
                .map_err(|_| McpError::internal_error("required capabilities must encode"))?;
        return Err(McpError::with_data(
            McpErrorCode::Custom(missing.jsonrpc_error_code()),
            "Required client capability is missing",
            missing.canonical_error_data(),
        ));
    }
    if let Some(inputs) = completed_inputs {
        let text = sampled_text(inputs, "sample")?.unwrap_or_default();
        return Ok(complete_text(format!("sampled: {text}")));
    }
    Ok(FinalToolOutcome::InputRequired(input_required(
        serde_json::json!({"sample": sampling_request("Say hello", 16)}),
    )?))
}

/// `server-stateless` diagnostic: the request-scoped response stream must
/// carry only the `input_required` result, never an independent request.
#[tool(
    name = "test_streaming_elicitation",
    description = "Returns an elicitation input_required result"
)]
fn test_streaming_elicitation(
    ctx: &McpContext,
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    if let Some(inputs) = completed_inputs {
        let name = elicited_string(inputs, "user_name", "name")?.unwrap_or_default();
        return Ok(complete_text(format!("Hello, {name}!")));
    }
    Ok(FinalToolOutcome::InputRequired(
        ctx.final_elicitation_form(
            "user_name",
            "What is your name?",
            serde_json::json!({
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            }),
        )?
        .into_input_required()?,
    ))
}

// ============================================================================
// JSON Schema 2020-12 and x-mcp-header tools
// ============================================================================

struct JsonSchema202012Tool;

impl ToolHandler for JsonSchema202012Tool {
    fn definition(&self) -> Tool {
        Tool {
            name: "json_schema_2020_12_tool".to_owned(),
            description: Some("Tool with JSON Schema 2020-12 features".to_owned()),
            input_schema: serde_json::json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "$defs": {
                    "address": {
                        "$anchor": "addressDef",
                        "type": "object",
                        "properties": {
                            "street": {"type": "string"},
                            "city": {"type": "string"},
                        },
                    },
                },
                "properties": {
                    "name": {"type": "string"},
                    "address": {"$ref": "#/$defs/address"},
                    "contactMethod": {"type": "string", "enum": ["phone", "email"]},
                    "phone": {"type": "string"},
                    "email": {"type": "string"},
                },
                "allOf": [
                    {"anyOf": [{"required": ["phone"]}, {"required": ["email"]}]}
                ],
                "if": {
                    "properties": {"contactMethod": {"const": "phone"}},
                    "required": ["contactMethod"],
                },
                "then": {"required": ["phone"]},
                "else": {"required": ["email"]},
                "additionalProperties": false,
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        ctx.checkpoint()?;
        Ok(vec![Content::text(format!("received: {arguments}"))])
    }
}

/// A tool whose `region` argument is mirrored into an `Mcp-Param-Region`
/// header (SEP-2243). The server compares the decoded header with the body
/// before the handler runs.
struct HeaderMirroredTool;

impl ToolHandler for HeaderMirroredTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "test_header_mirrored_param".to_owned(),
            description: Some("Mirrors its region argument into Mcp-Param-Region".to_owned()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "region": {"type": "string", "x-mcp-header": "Region"},
                },
                "required": ["region"],
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn header_exposure_reviews(&self) -> Vec<NonSensitiveHeaderExposure> {
        let definition = self.definition();
        ToolSchemaRevision::of(&definition.input_schema)
            .map(|revision| {
                vec![NonSensitiveHeaderExposure::new(
                    definition.name,
                    revision,
                    ["region"],
                )]
            })
            .unwrap_or_default()
    }

    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        ctx.checkpoint()?;
        let region = arguments["region"].as_str().unwrap_or_default();
        Ok(vec![Content::text(format!("region: {region}"))])
    }
}

// ============================================================================
// Tier 3: SEP-2322 input_required tools
// ============================================================================

#[tool(
    name = "test_input_required_result_elicitation",
    description = "Asks for the user's name, then greets them"
)]
fn test_input_required_result_elicitation(
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    if let Some(inputs) = completed_inputs
        && let Some(name) = elicited_string(inputs, "user_name", "name")?
    {
        return Ok(complete_text(format!("Hello, {name}!")));
    }
    // A missing or unusable answer is re-requested, never a protocol error.
    Ok(FinalToolOutcome::InputRequired(input_required(
        serde_json::json!({"user_name": name_form("What is your name?")}),
    )?))
}

#[tool(
    name = "test_input_required_result_sampling",
    description = "Asks the client to sample an answer"
)]
fn test_input_required_result_sampling(
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    if let Some(inputs) = completed_inputs
        && let Some(text) = sampled_text(inputs, "capital_question")?
    {
        return Ok(complete_text(format!("The model answered: {text}")));
    }
    Ok(FinalToolOutcome::InputRequired(input_required(
        serde_json::json!({"capital_question": sampling_request("What is the capital of France?", 100)}),
    )?))
}

#[tool(
    name = "test_input_required_result_list_roots",
    description = "Asks the client for its roots"
)]
fn test_input_required_result_list_roots(
    ctx: &McpContext,
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    if let Some(inputs) = completed_inputs
        && let Some(roots) = inputs.roots("client_roots")?
    {
        let uris: Vec<&str> = roots.roots.iter().map(|root| root.uri.as_str()).collect();
        return Ok(complete_text(format!(
            "Received {} root(s): {}",
            uris.len(),
            uris.join(", ")
        )));
    }
    Ok(FinalToolOutcome::InputRequired(
        ctx.final_roots("client_roots", FinalEmbeddedRootsListParams::default())?
            .into_input_required()?,
    ))
}

/// The framework mints, protects, and validates `requestState`; reaching the
/// resumed branch means the echoed state passed that validation.
#[tool(
    name = "test_input_required_result_request_state",
    description = "Round-trips framework-protected requestState"
)]
fn test_input_required_result_request_state(
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    if let Some(inputs) = completed_inputs
        && inputs.elicitation("confirm")?.is_some()
    {
        return Ok(complete_text("state-ok: requestState validated"));
    }
    Ok(FinalToolOutcome::InputRequired(input_required(
        serde_json::json!({
            "confirm": {
                "method": "elicitation/create",
                "params": {
                    "mode": "form",
                    "message": "Please confirm",
                    "requestedSchema": {
                        "type": "object",
                        "properties": {"ok": {"type": "boolean"}},
                        "required": ["ok"],
                    },
                },
            },
        }),
    )?))
}

#[tool(
    name = "test_input_required_result_multiple_inputs",
    description = "Asks for elicitation, sampling, and roots in one round"
)]
fn test_input_required_result_multiple_inputs(
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    if let Some(inputs) = completed_inputs {
        let name = elicited_string(inputs, "user_name", "name")?;
        let greeting = sampled_text(inputs, "greeting")?;
        let roots = inputs.roots("client_roots")?;
        if let (Some(name), Some(greeting), Some(roots)) = (name, greeting, roots) {
            return Ok(complete_text(format!(
                "{greeting} {name}; roots={}",
                roots.roots.len()
            )));
        }
    }
    Ok(FinalToolOutcome::InputRequired(input_required(
        serde_json::json!({
            "user_name": name_form("What is your name?"),
            "greeting": sampling_request("Generate a greeting", 50),
            "client_roots": roots_request(),
        }),
    )?))
}

#[tool(
    name = "test_input_required_result_multi_round",
    description = "Two elicitation rounds before completing"
)]
fn test_input_required_result_multi_round(
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    if let Some(inputs) = completed_inputs {
        if let Some(color) = elicited_string(inputs, "step2", "color")? {
            return Ok(complete_text(format!("Favorite color recorded: {color}")));
        }
        if elicited_string(inputs, "step1", "name")?.is_some() {
            return Ok(FinalToolOutcome::InputRequired(input_required(
                serde_json::json!({
                    "step2": {
                        "method": "elicitation/create",
                        "params": {
                            "mode": "form",
                            "message": "Step 2: What is your favorite color?",
                            "requestedSchema": {
                                "type": "object",
                                "properties": {"color": {"type": "string"}},
                                "required": ["color"],
                            },
                        },
                    },
                }),
            )?));
        }
    }
    Ok(FinalToolOutcome::InputRequired(input_required(
        serde_json::json!({"step1": name_form("Step 1: What is your name?")}),
    )?))
}

#[tool(
    name = "test_input_required_result_tampered_state",
    description = "Rejects a tampered requestState"
)]
fn test_input_required_result_tampered_state(
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    if completed_inputs.is_some() {
        return Ok(complete_text("state accepted"));
    }
    Ok(FinalToolOutcome::InputRequired(input_required(
        serde_json::json!({"user_name": name_form("What is your name?")}),
    )?))
}

/// Requests only the inputs whose client capability this request declared.
#[tool(
    name = "test_input_required_result_capabilities",
    description = "Requests only inputs the client declared capabilities for"
)]
fn test_input_required_result_capabilities(
    ctx: &McpContext,
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    if completed_inputs.is_some() {
        return Ok(complete_text("capability-scoped inputs received"));
    }
    let mut requests = serde_json::Map::new();
    if ctx.client_supports_elicitation_form() {
        requests.insert("user_name".to_owned(), name_form("What is your name?"));
    }
    if ctx.client_supports_sampling() {
        requests.insert(
            "greeting".to_owned(),
            sampling_request("Generate a greeting", 50),
        );
    }
    if ctx.client_supports_roots() {
        requests.insert("client_roots".to_owned(), roots_request());
    }
    if requests.is_empty() {
        return Ok(complete_text("no input capabilities declared"));
    }
    Ok(FinalToolOutcome::InputRequired(input_required(
        serde_json::Value::Object(requests),
    )?))
}

// ============================================================================
// Resources
// ============================================================================

#[resource(
    uri = "test://static-text",
    description = "Static text resource",
    mime_type = "text/plain"
)]
fn static_text(ctx: &McpContext) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok("This is the content of the static text resource.".to_owned())
}

#[resource(uri = "test://static-binary", description = "Static binary resource")]
fn static_binary(ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
    ctx.checkpoint()?;
    Ok(vec![ResourceContent {
        uri: "test://static-binary".to_owned(),
        mime_type: Some("image/png".to_owned()),
        text: None,
        blob: Some(TEST_IMAGE_BASE64.to_owned()),
    }])
}

#[resource(uri = "test://template/{id}/data", description = "Templated resource")]
fn template_resource(ctx: &McpContext, id: String) -> McpResult<Vec<ResourceContent>> {
    ctx.checkpoint()?;
    let text = serde_json::json!({
        "id": id,
        "templateTest": true,
        "data": format!("Data for ID: {id}"),
    })
    .to_string();
    Ok(vec![ResourceContent {
        uri: format!("test://template/{id}/data"),
        mime_type: Some("application/json".to_owned()),
        text: Some(text),
        blob: None,
    }])
}

// ============================================================================
// Prompts
// ============================================================================

#[prompt(name = "test_simple_prompt", description = "A simple prompt")]
fn test_simple_prompt(ctx: &McpContext) -> McpResult<Vec<PromptMessage>> {
    ctx.checkpoint()?;
    Ok(vec![PromptMessage {
        role: Role::User,
        content: Content::text("This is a simple prompt for testing."),
    }])
}

#[prompt(
    name = "test_prompt_with_arguments",
    description = "A prompt with two required arguments"
)]
fn test_prompt_with_arguments(
    ctx: &McpContext,
    arg1: String,
    arg2: String,
) -> McpResult<Vec<PromptMessage>> {
    ctx.checkpoint()?;
    Ok(vec![PromptMessage {
        role: Role::User,
        content: Content::text(format!(
            "Prompt with arguments: arg1='{arg1}', arg2='{arg2}'"
        )),
    }])
}

#[prompt(
    name = "test_prompt_with_image",
    description = "A prompt with an image"
)]
fn test_prompt_with_image(ctx: &McpContext) -> McpResult<Vec<PromptMessage>> {
    ctx.checkpoint()?;
    Ok(vec![
        PromptMessage {
            role: Role::User,
            content: Content::image_base64(TEST_IMAGE_BASE64, "image/png"),
        },
        PromptMessage {
            role: Role::User,
            content: Content::text("Please analyze the image above."),
        },
    ])
}

/// Implemented directly because its argument is the camelCase `resourceUri`,
/// which a `#[prompt]` function parameter cannot spell idiomatically.
struct EmbeddedResourcePrompt;

impl PromptHandler for EmbeddedResourcePrompt {
    fn definition(&self) -> Prompt {
        Prompt {
            name: "test_prompt_with_embedded_resource".to_owned(),
            description: Some("A prompt embedding the named resource".to_owned()),
            arguments: vec![PromptArgument {
                name: "resourceUri".to_owned(),
                description: Some("URI of the resource to embed".to_owned()),
                required: true,
            }],
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn get(
        &self,
        ctx: &McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        ctx.checkpoint()?;
        let uri = arguments
            .get("resourceUri")
            .cloned()
            .ok_or_else(|| McpError::invalid_params("Missing required argument: resourceUri"))?;
        Ok(vec![
            PromptMessage {
                role: Role::User,
                content: Content::resource_text(
                    uri,
                    Some("text/plain".to_owned()),
                    "Embedded resource content for testing.",
                ),
            },
            PromptMessage {
                role: Role::User,
                content: Content::text("Please process the embedded resource above."),
            },
        ])
    }
}

/// SEP-2322 on a non-tool method: `prompts/get` returns `input_required`.
#[prompt(
    name = "test_input_required_result_prompt",
    description = "Asks for context before rendering the prompt"
)]
fn test_input_required_result_prompt(
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<FinalMethodOutcome<FinalGetPromptResult>> {
    if let Some(inputs) = completed_inputs
        && let Some(context) = elicited_string(inputs, "user_context", "context")?
    {
        return Ok(FinalMethodOutcome::Complete(CompleteResult::new(
            FinalGetPromptResult {
                description: Some("Prompt rendered from elicited context".to_owned()),
                messages: vec![FinalPromptMessage {
                    role: Role::User,
                    content: ContentBlock::text(format!("Use this context: {context}")),
                }],
            },
            ResultMeta::empty(),
        )));
    }
    Ok(FinalMethodOutcome::InputRequired(input_required(
        serde_json::json!({
            "user_context": {
                "method": "elicitation/create",
                "params": {
                    "mode": "form",
                    "message": "What context should the prompt use?",
                    "requestedSchema": {
                        "type": "object",
                        "properties": {"context": {"type": "string"}},
                        "required": ["context"],
                    },
                },
            },
        }),
    )?))
}

// ============================================================================
// Completion
// ============================================================================

const ARG1_SUGGESTIONS: &[&str] = &["paris", "park", "party"];

fn suggestions(prefix: &str) -> Vec<String> {
    ARG1_SUGGESTIONS
        .iter()
        .filter(|value| value.starts_with(prefix))
        .map(|value| (*value).to_owned())
        .collect()
}

struct PromptArgumentCompletion;

impl CompletionHandler for PromptArgumentCompletion {
    fn complete_legacy(
        &self,
        _ctx: &McpContext,
        params: fastmcp_rust::legacy_2024::LegacyCompletionParams,
    ) -> McpResult<fastmcp_rust::legacy_2024::CompletionValues> {
        let values = suggestions(&params.argument.value);
        Ok(fastmcp_rust::legacy_2024::CompletionValues {
            total: i64::try_from(values.len()).ok(),
            values,
            has_more: Some(false),
        })
    }

    fn complete_final(
        &self,
        _ctx: &McpContext,
        params: FinalCompletionParams,
    ) -> McpResult<FinalCompletionValues> {
        Ok(FinalCompletionValues {
            values: suggestions(&params.argument.value),
            total: None,
            has_more: Some(false),
        })
    }
}

// ============================================================================
// Tasks extension (SEP-2663) fixtures
// ============================================================================
//
// A task-supporting tool only returns `CreateTask` with an opaque work
// descriptor; the work itself runs in the one `ApplicationTaskSupervisor`
// below, which the framework drives through `tasks/get`, `tasks/update` and
// `tasks/cancel`. MCP 2026-07-28 tools carry no wire-level task-support
// declaration, so "optional" and "required" are expressed as behaviour: an
// optional tool falls back to a synchronous result for a client that did not
// declare the extension, and a required tool always creates a task, which the
// router refuses with -32021 for such a client.

fn create_task(descriptor: serde_json::Value) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    Ok(FinalToolOutcome::CreateTask {
        work_descriptor: FinalTaskWorkDescriptor::new(descriptor)?,
        status_message: None,
    })
}

#[tool(name = "greet", description = "Greets someone synchronously")]
fn greet(name: String) -> McpResult<String> {
    Ok(format!("Hello, {name}!"))
}

#[tool(
    tasks,
    name = "slow_compute",
    description = "Task-supporting: sleeps `seconds` then returns a result"
)]
fn slow_compute(
    ctx: &McpContext,
    seconds: u64,
    label: Option<String>,
) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    let label = label.unwrap_or_default();
    if !ctx.client_supports_tasks() {
        // Optional task support: a client without the extension gets the
        // synchronous result instead of a task.
        return Ok(complete_text(format!("computed {label}")));
    }
    create_task(serde_json::json!({"op": "compute", "seconds": seconds, "label": label}))
}

#[tool(
    tasks,
    name = "failing_job",
    description = "Task-required: reports a tool execution error after about a second"
)]
fn failing_job() -> McpResult<fastmcp_rust::FinalToolOutcome> {
    create_task(serde_json::json!({"op": "fail"}))
}

#[tool(
    tasks,
    name = "protocol_error_job",
    description = "Task-required: ends in a protocol-level failure"
)]
fn protocol_error_job() -> McpResult<fastmcp_rust::FinalToolOutcome> {
    create_task(serde_json::json!({"op": "protocol_error"}))
}

#[tool(
    tasks,
    name = "confirm_delete",
    description = "Task-required: asks the client to confirm before completing"
)]
fn confirm_delete(filename: String) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    create_task(serde_json::json!({"op": "confirm", "filename": filename}))
}

#[tool(
    tasks,
    name = "multi_input",
    description = "Task-required: asks the client for two inputs at once"
)]
fn multi_input() -> McpResult<fastmcp_rust::FinalToolOutcome> {
    create_task(serde_json::json!({"op": "multi"}))
}

#[tool(
    tasks,
    name = "test_tool_with_task",
    description = "Gathers a name over MRTR, then escalates to a task"
)]
fn test_tool_with_task(
    ctx: &McpContext,
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    if !ctx.client_supports_tasks() {
        // Required task support: the router answers -32021.
        return create_task(serde_json::json!({"op": "greet", "name": ""}));
    }
    if let Some(inputs) = completed_inputs
        && let Some(name) = elicited_string(inputs, "user_name", "name")?
    {
        return create_task(serde_json::json!({"op": "greet", "name": name}));
    }
    Ok(FinalToolOutcome::InputRequired(input_required(
        serde_json::json!({"user_name": name_form("What is your name?")}),
    )?))
}

fn task_result(text: &str, is_error: bool) -> McpResult<FinalTaskCallToolResult> {
    serde_json::from_value(serde_json::json!({
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }))
    .map_err(|error| McpError::internal_error(error.to_string()))
}

fn task_input_requests(requests: serde_json::Value) -> McpResult<FinalTaskInputRequests> {
    serde_json::from_value(requests).map_err(|error| McpError::internal_error(error.to_string()))
}

fn confirm_form(message: &str) -> serde_json::Value {
    serde_json::json!({
        "method": "elicitation/create",
        "params": {
            "mode": "form",
            "message": message,
            "requestedSchema": {
                "type": "object",
                "properties": {"confirm": {"type": "boolean"}},
                "required": ["confirm"],
            },
        },
    })
}

/// Runs every fixture's task work, keyed by the descriptor's `op`.
struct ConformanceTaskSupervisor;

impl ConformanceTaskSupervisor {
    /// Waits `duration` in short slices, honoring `tasks/cancel` between
    /// them. Returns false when the task was cancelled.
    async fn wait(
        cx: &Cx,
        duration: Duration,
        cancelled: impl Fn() -> McpResult<bool>,
        honor: impl FnOnce() -> McpResult<()>,
    ) -> McpResult<bool> {
        let mut waited = Duration::ZERO;
        while waited < duration {
            if cancelled()? {
                honor()?;
                return Ok(false);
            }
            let step = (duration - waited).min(Duration::from_millis(50));
            asupersync::time::sleep(cx.now(), step).await;
            waited += step;
        }
        Ok(true)
    }
}

impl ApplicationTaskSupervisor for ConformanceTaskSupervisor {
    fn resume<'a>(
        &'a self,
        cx: &'a Cx,
        handoff: FinalTaskSupervisorHandoff,
    ) -> FinalTaskSupervisorFuture<'a> {
        Box::pin(async move {
            match handoff {
                FinalTaskSupervisorHandoff::Initial(work) => {
                    let descriptor = work.work_descriptor().as_value().clone();
                    let cancelled = || work.is_cancellation_requested();
                    let honor = || {
                        work.honor_cancellation(Some("cancelled".to_owned()))
                            .map(drop)
                    };
                    match descriptor["op"].as_str() {
                        Some("compute") => {
                            let seconds = descriptor["seconds"].as_u64().unwrap_or(0);
                            let label = descriptor["label"].as_str().unwrap_or_default();
                            if Self::wait(cx, Duration::from_secs(seconds), cancelled, honor)
                                .await?
                            {
                                work.complete_task(
                                    task_result(&format!("computed {label}"), false)?,
                                    None,
                                )?;
                            }
                        }
                        Some("fail") => {
                            if Self::wait(cx, Duration::from_secs(1), cancelled, honor).await? {
                                work.complete_task(task_result("job failed", true)?, None)?;
                            }
                        }
                        Some("confirm") => {
                            let filename = descriptor["filename"].as_str().unwrap_or_default();
                            work.require_input(
                                task_input_requests(serde_json::json!({
                                    "confirm": confirm_form(&format!("Delete {filename}?")),
                                }))?,
                                Some("awaiting confirmation".to_owned()),
                            )?;
                        }
                        Some("multi") => {
                            let form = |message: &str| {
                                serde_json::json!({
                                    "method": "elicitation/create",
                                    "params": {
                                        "mode": "form",
                                        "message": message,
                                        "requestedSchema": {
                                            "type": "object",
                                            "properties": {
                                                "name": {"type": "string"},
                                                "confirm": {"type": "boolean"},
                                            },
                                        },
                                    },
                                })
                            };
                            work.require_input(
                                task_input_requests(serde_json::json!({
                                    "first": form("First input?"),
                                    "second": form("Second input?"),
                                }))?,
                                Some("awaiting two inputs".to_owned()),
                            )?;
                        }
                        Some("greet") => {
                            let name = descriptor["name"].as_str().unwrap_or_default();
                            work.complete_task(
                                task_result(&format!("Hello, {name}!"), false)?,
                                None,
                            )?;
                        }
                        // "protocol_error" and anything unrecognized end in a
                        // protocol-level failure, never a tool error.
                        _ => {
                            let error: FinalTaskError = serde_json::from_value(serde_json::json!({
                                "code": -32603,
                                "message": "protocol_error_job failed",
                            }))
                            .map_err(|error| McpError::internal_error(error.to_string()))?;
                            work.fail_task(error, None)?;
                        }
                    }
                }
                FinalTaskSupervisorHandoff::Resumed(accepted) => {
                    let descriptor = accepted.work_descriptor().as_value().clone();
                    let responses = serde_json::to_value(accepted.input_responses())
                        .map_err(|error| McpError::internal_error(error.to_string()))?;
                    let text = match descriptor["op"].as_str() {
                        Some("confirm") => {
                            let filename = descriptor["filename"].as_str().unwrap_or_default();
                            let answer = &responses["confirm"];
                            if answer["action"] == "accept" && answer["content"]["confirm"] == true
                            {
                                format!("deleted {filename}")
                            } else {
                                format!("kept {filename}")
                            }
                        }
                        _ => {
                            let names: Vec<&str> = ["first", "second"]
                                .iter()
                                .filter_map(|key| responses[*key]["content"]["name"].as_str())
                                .collect();
                            format!("received {}", names.join(" and "))
                        }
                    };
                    accepted.complete_task(task_result(&text, false)?, None)?;
                }
            }
            Ok(())
        })
    }
}

// ============================================================================
// Server
// ============================================================================

fn main() -> ExitCode {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:3001".to_owned());

    let runtime = match asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(match asupersync::runtime::reactor::create_reactor() {
            Ok(reactor) => reactor,
            Err(error) => {
                eprintln!("conformance server: reactor failed: {error}");
                return ExitCode::FAILURE;
            }
        })
        .blocking_threads(0, 16)
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("conformance server: runtime failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    let outcome = runtime.block_on(async {
        let cx = Cx::current().ok_or("conformance server: no ambient context")?;
        let server = ServerBuilder::new("fastmcp-rust-conformance", "0.10.0")
            .tool(TestSimpleText)
            .tool(TestImageContent)
            .tool(TestAudioContent)
            .tool(TestEmbeddedResource)
            .tool(TestMultipleContentTypes)
            .tool(TestErrorHandling)
            .tool(TestToolWithProgress)
            .tool(TestToolWithLogging)
            .tool(TestLoggingTool)
            .tool(TestMissingCapability)
            .tool(TestStreamingElicitation)
            .tool(JsonSchema202012Tool)
            .tool(HeaderMirroredTool)
            .tool(TestInputRequiredResultElicitation)
            .tool(TestInputRequiredResultSampling)
            .tool(TestInputRequiredResultListRoots)
            .tool(TestInputRequiredResultRequestState)
            .tool(TestInputRequiredResultMultipleInputs)
            .tool(TestInputRequiredResultMultiRound)
            .tool(TestInputRequiredResultTamperedState)
            .tool(TestInputRequiredResultCapabilities)
            .resource(StaticTextResource)
            .resource(StaticBinaryResource)
            .resource(TemplateResourceResource)
            .prompt(TestSimplePromptPrompt)
            .prompt(TestPromptWithArgumentsPrompt)
            .prompt(TestPromptWithImagePrompt)
            .prompt(EmbeddedResourcePrompt)
            .prompt(TestInputRequiredResultPromptPrompt)
            .prompt_completion_handler("test_prompt_with_arguments", PromptArgumentCompletion)
            .tool(Greet)
            .tool(SlowCompute)
            .tool(FailingJob)
            .tool(ProtocolErrorJob)
            .tool(ConfirmDelete)
            .tool(MultiInput)
            .tool(TestToolWithTask)
            .task_supervisor(Arc::new(ConformanceTaskSupervisor))
            .build();

        let bound = server
            .bind_http(&cx, &address)
            .await
            .map_err(|error| format!("bind {address} failed: {error}"))?;
        let local = bound
            .local_addr()
            .map_err(|error| format!("local_addr failed: {error}"))?;
        // The suite health-checks before running, so announce readiness on a
        // stream the harness does not parse as protocol traffic.
        eprintln!("conformance server listening on http://{local}/mcp");
        bound
            .serve(&cx)
            .await
            .map(|_| ())
            .map_err(|error| format!("serve stopped: {error}"))
    });

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("conformance server: {message}");
            ExitCode::FAILURE
        }
    }
}
