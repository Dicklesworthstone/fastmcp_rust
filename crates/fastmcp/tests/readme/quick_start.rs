//! The README "Quick Start" server, compiled from the block's exact text below
//! the allow line. tests/readme_examples.rs fails if the two differ and drives
//! this binary over stdio with the modern facade client.
// A user's crate does not enable clippy::pedantic, and the README shows the
// async handler form without awaiting anything.
#![allow(clippy::unused_async)]

// src/main.rs
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_rust::{modern::ServerBuilder, prelude::*};

#[tool(description = "Echo the input message")]
async fn echo(ctx: &McpContext, message: String) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok(message)
}

fn main() {
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().expect("create I/O reactor"))
        .blocking_threads(0, 16)
        .build()
        .expect("create application runtime");
    runtime.block_on(async {
        let cx = Cx::current().expect("application context");
        ServerBuilder::new("echo-server", "1.0.0")
            .tool(Echo)
            .instructions("A simple echo server for testing")
            .build()
            .run_stdio_with_cx(&cx)
            .await
    });
}
