//! The README "Quick Example" server, compiled from the block's exact text
//! below the allow line. tests/readme_examples.rs fails if the two differ and
//! drives this binary over stdio with the modern facade client.
// A user's crate does not enable clippy::pedantic, and the README shows the
// async handler form without awaiting anything.
#![allow(clippy::unused_async)]

use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_rust::{modern::ServerBuilder, prelude::*};

// Define a tool with automatic JSON schema generation
#[tool(description = "Calculate the sum of two numbers")]
async fn add(ctx: &McpContext, a: i64, b: i64) -> McpResult<String> {
    ctx.checkpoint()?;  // Check the local cancellation token and budget
    Ok((a + b).to_string())
}

// Define an in-memory resource. Potentially blocking filesystem work is not
// performed inline on the dispatch worker.
#[resource(uri = "config://settings", description = "Application config")]
fn config(ctx: &McpContext) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok(r#"{"theme":"dark"}"#.to_owned())
}

// Define a prompt template
#[prompt(description = "Generate a greeting message")]
async fn greeting(ctx: &McpContext, name: String) -> McpResult<Vec<PromptMessage>> {
    ctx.checkpoint()?;
    Ok(vec![PromptMessage {
        role: Role::User,
        content: Content::text(format!("Please greet {name} warmly.")),
    }])
}

fn main() {
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().expect("create I/O reactor"))
        .blocking_threads(0, 16)
        .build()
        .expect("create application runtime");
    runtime.block_on(async {
        let cx = Cx::current().expect("application context");
        ServerBuilder::new("example-server", "1.0.0")
            .tool(Add)
            .resource(ConfigResource)
            .prompt(GreetingPrompt)
            .request_timeout(30)  // 30-second budget per request
            .build()
            .run_stdio_with_cx(&cx)
            .await
    });
}
