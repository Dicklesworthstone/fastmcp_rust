//! The README "TL;DR / The Solution" server, compiled from the block's exact
//! text below the allow line. tests/readme_examples.rs fails if the two differ
//! and drives this binary over stdio with the modern facade client.
// A user's crate does not enable clippy::pedantic, and the README shows the
// async handler form without awaiting anything.
#![allow(clippy::unused_async)]

use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_rust::{modern::ServerBuilder, prelude::*};

#[tool]
async fn greet(ctx: &McpContext, name: String) -> McpResult<String> {
    ctx.checkpoint()?;  // Cancellation point
    Ok(format!("Hello, {name}!"))
}

fn main() {
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().expect("create I/O reactor"))
        .blocking_threads(0, 16)
        .build()
        .expect("create application runtime");
    runtime.block_on(async {
        let cx = Cx::current().expect("application context");
        ServerBuilder::new("my-server", "1.0.0")
            // Attribute macros generate PascalCase handler values.
            .tool(Greet)
            .build()
            .run_stdio_with_cx(&cx)
            .await
    });
}
