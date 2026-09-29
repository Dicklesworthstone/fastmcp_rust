//! Conformance adapter: serves the official MCP conformance fixture contract
//! over modern HTTP so the official suite can be run against this codebase.
//!
//! # Why this exists
//!
//! Plan section 2.6 permits an MCP 2026-07-28 support claim only once "the
//! official conformance harness passes in both client and server modes". That
//! harness is `@modelcontextprotocol/conformance`, it requires the caller to own
//! the server lifecycle, and it connects as an MCP client to a URL. Nothing in
//! this workspace served the fixtures its scenarios call, so the harness could
//! not be pointed at fastmcp-rust at all.
//!
//! # Running it
//!
//! ```bash
//! cargo run -p fastmcp-rust --bin conformance_server -- 127.0.0.1:3001
//! # then, with the suite PINNED (see the pin note below):
//! npx @modelcontextprotocol/conformance@0.2.0-alpha.10 server \
//!   --url http://127.0.0.1:3001/mcp --spec-version 2026-07-28
//! ```
//!
//! PIN NOTE: `@latest` resolves to 0.1.16, which rejects
//! `--spec-version 2026-07-28` outright because npm's `latest` tag excludes
//! prereleases. Pinning `0.2.0-alpha.10` matters: it is also the anchor named by
//! upstream `requirements/2026-07-28.yaml`, the frozen list of what conformance
//! to this revision requires.
//!
//! # Scope: TIER 1 ONLY, and the boundary is deliberate
//!
//! The fixture contract extracted from upstream
//! `examples/servers/typescript/everything-server.ts` is 14 tools, 4 resources
//! and 4 prompts. This adapter implements the subset that needs neither
//! server-to-client requests nor streaming:
//!
//!   tools     test_simple_text, test_image_content, test_audio_content,
//!             test_embedded_resource, test_multiple_content_types,
//!             test_error_handling
//!   resources test://static-text, test://static-binary, test://template/{id}/data
//!   prompts   test_simple_prompt, test_prompt_with_arguments,
//!             test_prompt_with_image, test_prompt_with_embedded_resource
//!
//! NOT implemented here, and no scenario depending on them is claimed:
//! test_tool_with_progress, test_tool_with_logging, test_reconnection and
//! test://watched-resource (streaming/notifications, Tier 2); test_sampling and
//! the three elicitation tools (reverse requests, Tier 3 — these drive the 13
//! `input-required-result-*` scenarios, 35% of server conformance on their own,
//! and they exercise bidirectional paths this project still documents as only
//! partly qualified). A Tier 1 pass count says nothing about those.

#![allow(clippy::needless_pass_by_value)]

use std::process::ExitCode;

use fastmcp_rust::prelude::*;
use fastmcp_server::ServerBuilder;

/// Tiny opaque payloads. The scenarios assert on content SHAPE — type, mime
/// type, presence — not on these bytes, so a minimal valid base64 body is
/// correct here and a large realistic asset would only slow the suite.
const TEST_IMAGE_BASE64: &str = "iVBORw0KGgo=";
const TEST_AUDIO_BASE64: &str = "UklGRgA=";

#[tool(name = "test_simple_text", description = "Returns simple text content")]
fn test_simple_text(ctx: &McpContext) -> McpResult<Vec<Content>> {
    ctx.checkpoint()?;
    Ok(vec![Content::text("Hello from fastmcp-rust")])
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
        "test://static-text",
        Some("text/plain".to_owned()),
        "embedded resource text",
    )])
}

#[tool(
    name = "test_multiple_content_types",
    description = "Tests a result carrying several content types"
)]
fn test_multiple_content_types(ctx: &McpContext) -> McpResult<Vec<Content>> {
    ctx.checkpoint()?;
    Ok(vec![
        Content::text("mixed content"),
        Content::image_base64(TEST_IMAGE_BASE64, "image/png"),
    ])
}

/// Returns a tool-level error. The scenario requires the FAILURE to be reported
/// as a tool result rather than as a transport or protocol fault, so this must
/// return `Err` from the handler and not panic.
#[tool(
    name = "test_error_handling",
    description = "Tests tool error reporting"
)]
fn test_error_handling(ctx: &McpContext) -> McpResult<Vec<Content>> {
    ctx.checkpoint()?;
    Err(McpError::internal_error(
        "intentional conformance fixture error",
    ))
}

#[resource(uri = "test://static-text", description = "Static text resource")]
fn static_text(ctx: &McpContext) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok("static text resource contents".to_owned())
}

#[resource(uri = "test://static-binary", description = "Static binary resource")]
fn static_binary(ctx: &McpContext) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok(TEST_IMAGE_BASE64.to_owned())
}

#[resource(uri = "test://template/{id}/data", description = "Templated resource")]
fn template_resource(ctx: &McpContext) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok("templated resource contents".to_owned())
}

#[prompt(name = "test_simple_prompt", description = "A simple prompt")]
fn test_simple_prompt(ctx: &McpContext) -> McpResult<Vec<PromptMessage>> {
    ctx.checkpoint()?;
    Ok(vec![PromptMessage {
        role: Role::User,
        content: Content::text("simple prompt text"),
    }])
}

#[prompt(
    name = "test_prompt_with_arguments",
    description = "A prompt taking arguments"
)]
// The macro extracts NAMED parameters and generates the argument schema from
// them, so a `HashMap<String, String>` catch-all does not work: it makes the
// generated code try to pull a single `String` for a parameter literally called
// `arguments` (E0308). One declared parameter per argument is the idiom, and it
// is also what gives `prompts/list` a real schema for the scenario to inspect.
fn test_prompt_with_arguments(ctx: &McpContext, name: String) -> McpResult<Vec<PromptMessage>> {
    ctx.checkpoint()?;
    let named = if name.is_empty() {
        "world".to_owned()
    } else {
        name
    };
    Ok(vec![PromptMessage {
        role: Role::User,
        content: Content::text(format!("prompt for {named}")),
    }])
}

#[prompt(
    name = "test_prompt_with_image",
    description = "A prompt with an image"
)]
fn test_prompt_with_image(ctx: &McpContext) -> McpResult<Vec<PromptMessage>> {
    ctx.checkpoint()?;
    Ok(vec![PromptMessage {
        role: Role::User,
        content: Content::image_base64(TEST_IMAGE_BASE64, "image/png"),
    }])
}

#[prompt(
    name = "test_prompt_with_embedded_resource",
    description = "A prompt with an embedded resource"
)]
fn test_prompt_with_embedded_resource(ctx: &McpContext) -> McpResult<Vec<PromptMessage>> {
    ctx.checkpoint()?;
    Ok(vec![PromptMessage {
        role: Role::User,
        content: Content::resource_text(
            "test://static-text",
            Some("text/plain".to_owned()),
            "embedded prompt resource",
        ),
    }])
}

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
            .resource(StaticTextResource)
            .resource(StaticBinaryResource)
            .resource(TemplateResourceResource)
            .prompt(TestSimplePromptPrompt)
            .prompt(TestPromptWithArgumentsPrompt)
            .prompt(TestPromptWithImagePrompt)
            .prompt(TestPromptWithEmbeddedResourcePrompt)
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
