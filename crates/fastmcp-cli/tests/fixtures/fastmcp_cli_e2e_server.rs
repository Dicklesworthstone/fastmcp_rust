//! Compiled framework-level server fixture for CLI interoperability tests.

#![allow(clippy::needless_pass_by_value)]

use fastmcp_rust::{auto::Server, prelude::*};

#[tool]
fn echo(ctx: &McpContext, message: String) -> String {
    ctx.report_progress(0.5, Some(&message));
    message
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
    Server::new("fastmcp-cli-e2e-server", "1.0.0")
        .tool(Echo)
        .resource(StatusResource)
        .prompt(GreetingPrompt)
        .build()
        .run_stdio();
}
