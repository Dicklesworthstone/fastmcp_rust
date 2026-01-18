//! Example: Echo Server
//!
//! A simple MCP server demonstrating tools, resources, and prompts.
//!
//! Run with:
//! ```bash
//! cargo run --example echo_server
//! ```
//!
//! Test with MCP Inspector:
//! ```bash
//! npx @anthropic-ai/mcp-inspector cargo run --example echo_server
//! ```

// MCP handlers receive String from JSON deserialization, so this is intentional.
#![allow(clippy::needless_pass_by_value)]

use fastmcp::prelude::*;

// ============================================================================
// Tools
// ============================================================================

/// Echo the input message back.
#[tool]
fn echo(ctx: &McpContext, message: String) -> String {
    // Check for cancellation (optional but recommended)
    if ctx.is_cancelled() {
        return "Cancelled".to_string();
    }
    message
}

/// Add two numbers together.
#[tool(description = "Calculate the sum of two numbers")]
fn add(_ctx: &McpContext, a: i64, b: i64) -> String {
    format!("{}", a + b)
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

// ============================================================================
// Resources
// ============================================================================

/// Returns server information.
#[resource(uri = "info://server")]
fn server_info(_ctx: &McpContext) -> String {
    r#"{
    "name": "echo-server",
    "version": "1.0.0",
    "description": "A simple example MCP server"
}"#
    .to_string()
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

// ============================================================================
// Prompts
// ============================================================================

/// A simple greeting prompt.
#[prompt(description = "Generate a friendly greeting")]
fn greeting(_ctx: &McpContext, name: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("Please greet {name} in a friendly way."),
        },
    }]
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

// ============================================================================
// Main
// ============================================================================

fn main() {
    // Build and run the server
    Server::new("echo-server", "1.0.0")
        // Register tools
        .tool(Echo)
        .tool(Add)
        .tool(Reverse)
        .tool(CountWords)
        // Register resources
        .resource(ServerInfoResource)
        .resource(CurrentTimeResource)
        // Register prompts
        .prompt(GreetingPrompt)
        .prompt(CodeReviewPromptPrompt)
        // Set timeout (30 seconds per request)
        .request_timeout(30)
        // Set server instructions
        .instructions(
            "A simple echo server for testing FastMCP. Try calling the 'echo' tool with a message!",
        )
        // Build and run on stdio
        .build()
        .run_stdio();
}
