//! Modern MCP server on real process pipes, with no blocking-pool workers.
//!
//! Build this example through the project's approved DSR/RCH runner. An MCP
//! host then launches `target/debug/examples/native_stdio` with piped stdin
//! AND stdout. Terminals / file redirection are deliberately refused. The
//! process dedicates both streams to MCP for the entire serving lifetime;
//! diagnostics go to stderr and it exits after the bounded input-EOF drain.
//!
//! The `echo` tool accepts `text` and optional `delay_ms` (0..=2000). A delayed
//! call does not block later requests or wire cancellation. The small example
//! does not configure OAuth, task supervision, or legacy negotiation.
//!
//! After building, `python3 scripts/check_native_process_stdio.py
//! target/debug/examples/native_stdio` exercises the executable's actual
//! process streams. Those smoke checks are not aggregate conformance evidence.

#![forbid(unsafe_code)]

#[cfg(unix)]
mod unix {
    use std::future::Future;
    use std::io;
    use std::pin::Pin;
    use std::time::Duration;

    use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
    use asupersync::{Cx, Outcome};
    use fastmcp_core::{McpContext, McpError, McpOutcome, McpResult};
    use fastmcp_protocol::protocol_policy::ProtocolPolicy;
    use fastmcp_protocol::{CompleteResult, Content, FinalCallToolResult, ResultMeta, Tool};
    use fastmcp_server::{FinalToolOutcome, Server, ToolExecutionMode, ToolHandler};
    use fastmcp_transport::{NativePipeReader, NativePipeWriter};

    struct Echo;

    impl ToolHandler for Echo {
        fn definition(&self) -> Tool {
            Tool {
                name: "echo".to_owned(),
                description: Some("Echo text after an optional nonblocking delay".to_owned()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "maxLength": 4096},
                        "delay_ms": {"type": "integer", "minimum": 0, "maximum": 2000},
                    },
                    "required": ["text"],
                    "additionalProperties": false,
                }),
                output_schema: None,
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn execution_mode(&self) -> ToolExecutionMode {
            ToolExecutionMode::Async
        }

        fn call(&self, _: &McpContext, _: serde_json::Value) -> McpResult<Vec<Content>> {
            Err(McpError::invalid_request("native echo requires asynchronous final dispatch"))
        }

        fn call_final_outcome_async<'a>(
            &'a self,
            ctx: &'a McpContext,
            arguments: serde_json::Value,
        ) -> Pin<Box<dyn Future<Output = McpOutcome<FinalToolOutcome>> + Send + 'a>> {
            Box::pin(async move {
                // `McpContext::checkpoint` yields `CancelledError`, not
                // `McpError`. Without the conversion the first arm fixes this
                // block's error type to `CancelledError` and every later
                // `McpError` arm fails to unify.
                if let Err(error) = ctx.checkpoint() {
                    return Outcome::Err(error.into());
                }
                let Some(text) = arguments.get("text").and_then(serde_json::Value::as_str) else {
                    return Outcome::Err(McpError::invalid_params("text must be a string"));
                };
                if text.len() > 16_384 {
                    return Outcome::Err(McpError::invalid_params("text exceeds the byte bound"));
                }
                let delay = match arguments.get("delay_ms") {
                    None => 0,
                    Some(value) => match value.as_u64().filter(|delay| *delay <= 2000) {
                        Some(delay) => delay,
                        None => return Outcome::Err(McpError::invalid_params("invalid delay_ms")),
                    },
                };
                if delay != 0 {
                    asupersync::time::sleep(ctx.cx().now(), Duration::from_millis(delay)).await;
                }
                // `McpContext::checkpoint` yields `CancelledError`, not
                // `McpError`. Without the conversion the first arm fixes this
                // block's error type to `CancelledError` and every later
                // `McpError` arm fails to unify.
                if let Err(error) = ctx.checkpoint() {
                    return Outcome::Err(error.into());
                }
                let payload: FinalCallToolResult = match serde_json::from_value(serde_json::json!({
                    "content": [{"type": "text", "text": text}],
                    "isError": false,
                })) {
                    Ok(payload) => payload,
                    Err(_) => return Outcome::Err(McpError::internal_error("echo result encoding failed")),
                };
                // `ResultMeta` derives only (Debug, Clone); `empty()` is its
                // constructor and is what preserves the absence of the
                // optional `_meta` member on the wire.
                Outcome::Ok(FinalToolOutcome::Complete(CompleteResult::new(
                    payload,
                    ResultMeta::empty(),
                )))
            })
        }
    }

    pub fn run() -> io::Result<()> {
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(create_reactor()?)
            .blocking_threads(0, 0)
            .build()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let result = runtime.block_on(async {
            let cx = Cx::current().ok_or_else(|| io::Error::other("caller context unavailable"))?;
            let server = Server::new("native-process-stdio", "1.0")
                .protocol_policy(ProtocolPolicy::ModernOnly)
                .map_err(|error| io::Error::other(error.to_string()))?
                .tool(Echo)
                .build();
            let mut input = NativePipeReader::from_stdin(&cx)?;
            let output = match NativePipeWriter::from_stdout(&cx) {
                Ok(output) => output,
                Err(error) => {
                    // Preserve explicit cleanup failure rather than claiming
                    // that a partially acquired process binding was restored.
                    input.close()?;
                    return Err(error);
                }
            };
            server.serve_stdio_io(&cx, input, output).await
                .map_err(|error| io::Error::other(error.to_string()))
        });
        // The runtime is owned by this executable, not hidden in the library.
        // Even an admission/serve error must settle it before process exit.
        if !runtime.shutdown_timeout(Duration::from_secs(6)) {
            return Err(io::Error::other("native stdio runtime shutdown did not settle"));
        }
        result
    }
}

fn main() -> std::process::ExitCode {
    #[cfg(unix)]
    match unix::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("native stdio server failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
    #[cfg(not(unix))]
    {
        eprintln!("native process stdio requires Unix pipe and reactor support");
        std::process::ExitCode::FAILURE
    }
}
