//! Compiled framework-level server fixture for CLI interoperability tests.

#![allow(clippy::needless_pass_by_value)]

use fastmcp_rust::{auto::ServerBuilder, prelude::*};

#[tool]
fn echo(ctx: &McpContext, message: String) -> String {
    ctx.report_progress(0.5, Some(&message));
    message
}

#[tool]
fn sized_output(_ctx: &McpContext, bytes: usize) -> String {
    const MAX_FIXTURE_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
    "x".repeat(bytes.min(MAX_FIXTURE_OUTPUT_BYTES))
}

#[resource(uri = "test://status")]
fn status(_ctx: &McpContext) -> String {
    "ready".to_owned()
}

#[prompt]
fn greeting(_ctx: &McpContext, name: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("Hello, {name}!"),
        },
    }]
}

fn main() {
    ServerBuilder::new("fastmcp-cli-e2e-server", "1.0.0")
        .tool(Echo)
        .tool(SizedOutput)
        .resource(StatusResource)
        .prompt(GreetingPrompt)
        .build()
        .run_stdio();
}
