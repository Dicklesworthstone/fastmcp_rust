//! The README's user-facing code, compiled from its exact text and driven the
//! way a user runs it: as a stdio server behind the modern facade client.
//!
//! `tests/readme/*.rs` hold the README blocks verbatim (the three servers
//! below a lint header). They are built as this package's `readme_*` binaries.

const README: &str = include_str!("../../../README.md");

/// Everything after this line in a README server source is the README block.
const README_BODY_START: &str = "#![allow(clippy::unused_async)]\n\n";

// The README snippet tests the handler directly and never registers `MyTool`.
#[allow(dead_code)]
mod faq {
    include!("readme/faq_handler_test.rs");
}

fn readme_body(source: &'static str) -> &'static str {
    source
        .split_once(README_BODY_START)
        .expect("a README server source starts with its lint header")
        .1
}

#[test]
fn readme_code_blocks_are_the_compiled_sources() {
    for (section, body) in [
        ("TL;DR", readme_body(include_str!("readme/tldr.rs"))),
        (
            "Quick Example",
            readme_body(include_str!("readme/quick_example.rs")),
        ),
        (
            "Quick Start",
            readme_body(include_str!("readme/quick_start.rs")),
        ),
        ("FAQ handler test", include_str!("readme/faq_handler_test.rs")),
    ] {
        assert!(
            README.contains(&format!("```rust\n{body}```")),
            "the README {section} block no longer matches its compiled source"
        );
    }
}

#[cfg(unix)]
mod live {
    use std::collections::HashMap;
    use std::time::Duration;

    use fastmcp_core::block_on;
    use fastmcp_rust::{
        ContentBlock, Cx, EmbeddedResourceContents, McpError, RequestTimeoutPolicy, modern,
    };
    use serde_json::json;

    /// Liveness bounds for a subprocess spawn plus its handshake, not a
    /// performance expectation.
    fn connect(binary: &str) -> modern::Client {
        let policy = RequestTimeoutPolicy::new(Duration::from_secs(15), Duration::from_secs(30))
            .expect("the liveness bounds form a valid policy");
        block_on(
            modern::client_builder()
                .request_timeout_policy(policy)
                .connect_stdio_with_cx(&Cx::for_request(), binary, &[]),
        )
        .unwrap_or_else(|error| panic!("{binary} completes modern discovery: {error}"))
    }

    fn texts(content: &[ContentBlock]) -> Vec<&str> {
        content
            .iter()
            .filter_map(|block| match block {
                ContentBlock::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Arguments that fail a tool's input schema are refused before the handler
    /// runs, as an MCP tool error result (`isError`), not a JSON-RPC error.
    fn assert_schema_refused(outcome: Result<modern::FinalCallToolResult, McpError>) {
        let result = outcome.expect("argument validation answers with a tool result");
        assert!(result.is_error, "{result:?}");
        assert_eq!(
            texts(&result.content),
            ["Tool arguments do not match the declared input schema."]
        );
    }

    fn assert_refused(outcome: Result<impl std::fmt::Debug, McpError>, expected: &str) {
        match outcome {
            Err(error) => assert!(error.message.contains(expected), "{error}"),
            Ok(value) => panic!("expected a refusal naming {expected:?}: {value:?}"),
        }
    }

    #[test]
    fn readme_tldr_server_greets() {
        let mut client = connect(env!("CARGO_BIN_EXE_readme_tldr"));
        let greeting = client
            .call_tool("greet", json!({"name": "Ada"}))
            .expect("the README greet tool answers");
        assert!(!greeting.is_error, "{greeting:?}");
        assert_eq!(texts(&greeting.content), ["Hello, Ada!"]);
        // Near-identical negative: the same call without its required argument.
        assert_schema_refused(client.call_tool("greet", json!({})));
        client.close().expect("the README TL;DR client closes cleanly");
    }

    #[test]
    fn readme_quick_example_serves_its_tool_resource_and_prompt() {
        let mut client = connect(env!("CARGO_BIN_EXE_readme_quick_example"));
        let sum = client
            .call_tool("add", json!({"a": 2, "b": 40}))
            .expect("the README add tool answers");
        assert!(!sum.is_error, "{sum:?}");
        assert_eq!(texts(&sum.content), ["42"]);
        // Near-identical negative: the same arguments to a tool the README
        // never registered.
        assert_refused(
            client.call_tool("subtract", json!({"a": 2, "b": 40})),
            "Unknown tool: subtract",
        );

        let config = client
            .read_resource("config://settings")
            .expect("the README config resource answers");
        let config: Vec<&str> = config
            .contents
            .iter()
            .filter_map(|content| match content {
                EmbeddedResourceContents::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(config, [r#"{"theme":"dark"}"#]);
        assert!(client.read_resource("config://other").is_err());

        let prompt = client
            .get_prompt(
                "greeting",
                HashMap::from([("name".to_owned(), "Ada".to_owned())]),
            )
            .expect("the README greeting prompt answers");
        let messages: Vec<&str> = prompt
            .messages
            .iter()
            .filter_map(|message| match &message.content {
                ContentBlock::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(messages, ["Please greet Ada warmly."]);
        assert!(
            client
                .get_prompt(
                    "farewell",
                    HashMap::from([("name".to_owned(), "Ada".to_owned())]),
                )
                .is_err()
        );
        client
            .close()
            .expect("the README Quick Example client closes cleanly");
    }

    #[test]
    fn readme_quick_start_server_echoes_with_its_instructions() {
        let mut client = connect(env!("CARGO_BIN_EXE_readme_quick_start"));
        assert_eq!(
            client
                .instructions()
                .expect("modern discovery carries instructions"),
            Some("A simple echo server for testing")
        );
        let echoed = client
            .call_tool("echo", json!({"message": "hello from the README"}))
            .expect("the README echo tool answers");
        assert!(!echoed.is_error, "{echoed:?}");
        assert_eq!(texts(&echoed.content), ["hello from the README"]);
        // Near-identical negative: the same call with a non-string message.
        assert_schema_refused(client.call_tool("echo", json!({"message": 7})));
        client
            .close()
            .expect("the README Quick Start client closes cleanly");
    }
}

/// The README "Troubleshooting" and "Limitations" tables, as behaviour: every
/// claim that is observable in-process through the shipped facade, each
/// against a near-identical negative. Requests travel as JSON lines through
/// the public `StdioTransport` and the returning custom-transport runner, so
/// the server under test is the one a downstream crate builds.
mod troubleshooting_and_limitations {
    use std::io::{Cursor, Read, Write};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use fastmcp_core::block_on;
    use fastmcp_rust::{
        Content, Cx, JsonRpcMessage, McpContext, McpErrorCode, McpResult, StdioTransport,
        Transport, TransportError, modern, tool,
    };
    use serde_json::{Value, json};

    /// Cooperative work that outlives a one-second deadline but fits well
    /// inside a thirty-second one.
    const SLOW_WORK: Duration = Duration::from_secs(3);

    #[tool(description = "Returns its text as a String")]
    fn echo_string(text: String) -> String {
        text
    }

    #[tool(description = "Returns its text as content blocks")]
    fn echo_content(text: String) -> Vec<Content> {
        vec![Content::text(text)]
    }

    #[tool(description = "Returns its text as a fallible String")]
    #[allow(
        clippy::unnecessary_wraps,
        reason = "demonstrates the fallible McpResult tool return type"
    )]
    fn echo_result(text: String) -> McpResult<String> {
        Ok(text)
    }

    #[tool(description = "Returns its text as fallible content blocks")]
    #[allow(
        clippy::unnecessary_wraps,
        reason = "demonstrates the fallible McpResult tool return type"
    )]
    fn echo_result_content(text: String) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text(text)])
    }

    #[tool(description = "Works cooperatively for SLOW_WORK, then finishes")]
    fn slow(ctx: &McpContext) -> McpResult<String> {
        let started = Instant::now();
        while started.elapsed() < SLOW_WORK {
            ctx.checkpoint()?;
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok("finished".to_owned())
    }

    fn meta(client_capabilities: &Value) -> Value {
        json!({
            "io.modelcontextprotocol/protocolVersion": modern::PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": client_capabilities,
            "io.modelcontextprotocol/clientInfo": {"name": "readme-claims", "version": "0.0.1"},
        })
    }

    fn request(id: i64, method: &str, mut params: Value, client_capabilities: &Value) -> String {
        params["_meta"] = meta(client_capabilities);
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
    }

    fn call(id: i64, name: &str, arguments: Value) -> String {
        request(
            id,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
            &json!({}),
        )
    }

    /// The stdout half of the transport: every written line, retained.
    #[derive(Clone, Default)]
    struct Output(Arc<Mutex<Vec<u8>>>);

    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("output buffer is not poisoned")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn run_returning<T>(server: modern::Server, transport: T) -> McpResult<()>
    where
        T: Transport + Send + 'static,
    {
        block_on(async move {
            let cx = Cx::current().expect("block_on installs a current Cx");
            let mut pump = cx
                .spawn_blocking(move |pump_cx| {
                    server.run_transport_returning_with_cx(&pump_cx, transport)
                })
                .expect("the caller runtime admits the transport pump");
            pump.join(&cx)
                .await
                .expect("the transport pump reports its result")
        })
    }

    /// Serves `lines` (after modern discovery) and then EOF over stdio, and
    /// returns the run result with every JSON-RPC response written.
    fn serve(server: modern::Server, lines: &[String]) -> (McpResult<()>, Vec<Value>) {
        let mut input = request(1, "server/discover", json!({}), &json!({}));
        input.push('\n');
        for line in lines {
            input.push_str(line);
            input.push('\n');
        }
        let output = Output::default();
        let run = run_returning(
            server,
            StdioTransport::new(Cursor::new(input.into_bytes()), output.clone()),
        );
        let written = String::from_utf8(output.0.lock().expect("output").clone())
            .expect("the server writes UTF-8 JSON lines");
        let responses = written
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("each line is JSON"))
            .filter(|message| message.get("id").is_some() && message.get("method").is_none())
            .collect();
        (run, responses)
    }

    fn response(responses: &[Value], id: i64) -> &Value {
        responses
            .iter()
            .find(|response| response["id"] == id)
            .unwrap_or_else(|| panic!("no response for request {id}: {responses:?}"))
    }

    fn error_code(code: McpErrorCode) -> i64 {
        i64::from(i32::from(code))
    }

    /// Troubleshooting: a `tools/call` for an unregistered tool is refused as
    /// JSON-RPC InvalidParams naming the tool (MCP's unknown-tool error), not
    /// as MethodNotFound; registering the handler serves the same call.
    #[test]
    fn unregistered_tool_is_invalid_params_and_registration_serves_it() {
        let server = modern::ServerBuilder::new("readme-claims", "1.0.0")
            .tool(EchoString)
            .build();
        let (run, responses) = serve(
            server,
            &[
                call(2, "echo_string", json!({"text": "hi"})),
                call(3, "unregistered", json!({"text": "hi"})),
            ],
        );
        assert!(run.is_ok(), "{run:?}");
        let served = response(&responses, 2);
        assert_eq!(served["result"]["content"][0]["text"], "hi", "{served}");
        let refused = response(&responses, 3);
        assert_eq!(
            refused["error"]["code"],
            error_code(McpErrorCode::InvalidParams),
            "{refused}"
        );
        assert_ne!(
            refused["error"]["code"],
            error_code(McpErrorCode::MethodNotFound),
            "{refused}"
        );
        assert_eq!(
            refused["error"]["message"], "Unknown tool: unregistered",
            "{refused}"
        );
    }

    /// Troubleshooting: work that outlives `.request_timeout(...)` ends as
    /// RequestCancelled "Request timeout exceeded", even though the handler's
    /// own checkpoint observes the deadline first; the same work under a
    /// longer deadline finishes. Both runs complete before any assertion, so
    /// a failure reports the pair and their elapsed times.
    #[test]
    fn request_timeout_bounds_the_same_work_that_a_longer_deadline_completes() {
        let run_with_timeout = |seconds| {
            let server = modern::ServerBuilder::new("readme-claims", "1.0.0")
                .tool(Slow)
                .request_timeout(seconds)
                .build();
            let started = Instant::now();
            let (run, responses) = serve(server, &[call(2, "slow", json!({}))]);
            assert!(run.is_ok(), "{run:?}");
            (response(&responses, 2).clone(), started.elapsed())
        };

        let (bounded, bounded_elapsed) = run_with_timeout(1);
        let (completed, completed_elapsed) = run_with_timeout(30);
        let evidence = format!(
            "1s deadline after {bounded_elapsed:?}: {bounded}; \
             30s deadline after {completed_elapsed:?}: {completed}"
        );
        assert_eq!(
            bounded["error"]["code"],
            error_code(McpErrorCode::RequestCancelled),
            "{evidence}"
        );
        assert_eq!(
            bounded["error"]["message"], "Request timeout exceeded",
            "{evidence}"
        );
        assert_eq!(
            completed["result"]["content"][0]["text"], "finished",
            "{evidence}"
        );
    }

    /// Troubleshooting: the four recommended `#[tool]` return shapes all
    /// serve; the same calls with a non-string argument are refused by the
    /// generated argument schema. (Unsupported return types are compile
    /// errors, which `trybuild_tests` covers.)
    #[test]
    fn recommended_tool_return_types_serve_and_their_argument_schema_is_enforced() {
        let server = modern::ServerBuilder::new("readme-claims", "1.0.0")
            .tool(EchoString)
            .tool(EchoContent)
            .tool(EchoResult)
            .tool(EchoResultContent)
            .build();
        let tools = [
            "echo_string",
            "echo_content",
            "echo_result",
            "echo_result_content",
        ];
        let mut lines = Vec::new();
        for (offset, tool) in (0_i64..).zip(tools) {
            lines.push(call(10 + offset, tool, json!({"text": "hi"})));
            lines.push(call(20 + offset, tool, json!({"text": 7})));
        }
        let (run, responses) = serve(server, &lines);
        assert!(run.is_ok(), "{run:?}");
        for (offset, tool) in (0_i64..).zip(tools) {
            let served = response(&responses, 10 + offset);
            assert_eq!(
                served["result"]["content"][0]["text"], "hi",
                "{tool}: {served}"
            );
            let refused = response(&responses, 20 + offset);
            assert!(
                refused.get("error").is_some() || refused["result"]["isError"] == Value::Bool(true),
                "{tool}: {refused}"
            );
        }
    }

    /// A reader that fails the way an unavailable stdin does.
    struct UnavailableStdin;

    impl Read for UnavailableStdin {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "stdin unavailable",
            ))
        }
    }

    /// Troubleshooting: an unreadable stdin is `TransportError::Io`, and the
    /// returning runner reports it as a fatal receive failure; an ordinary
    /// empty stdin is a clean EOF instead.
    #[test]
    fn unavailable_stdin_is_transport_io_while_empty_stdin_is_clean_eof() {
        let cx = Cx::for_request();
        let mut unavailable = StdioTransport::new(UnavailableStdin, Vec::new());
        assert!(
            matches!(unavailable.recv(&cx), Err(TransportError::Io(_))),
            "an unreadable stdin must surface as TransportError::Io"
        );
        let mut empty = StdioTransport::new(Cursor::new(Vec::new()), Vec::new());
        assert!(matches!(empty.recv(&cx), Err(TransportError::Closed)));

        let failed = run_returning(
            modern::ServerBuilder::new("readme-claims", "1.0.0").build(),
            StdioTransport::new(UnavailableStdin, Vec::new()),
        )
        .expect_err("an unreadable stdin fails the server at startup");
        let data = failed.data.as_ref().expect("typed run failure");
        assert_eq!(data["stage"], "receive", "{failed:?}");
        assert_eq!(data["kind"], "io", "{failed:?}");

        let clean = run_returning(
            modern::ServerBuilder::new("readme-claims", "1.0.0").build(),
            StdioTransport::new(Cursor::new(Vec::new()), Vec::new()),
        );
        assert!(clean.is_ok(), "{clean:?}");
    }

    /// A transport whose receive fails and whose close optionally fails too.
    struct FailingTransport {
        close_fails: bool,
    }

    impl Transport for FailingTransport {
        fn send(&mut self, _cx: &Cx, _message: &JsonRpcMessage) -> Result<(), TransportError> {
            Ok(())
        }

        fn recv(&mut self, _cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
            Err(TransportError::Io(std::io::Error::other("receive failed")))
        }

        fn close(&mut self, _cx: &Cx) -> Result<(), TransportError> {
            if self.close_fails {
                return Err(TransportError::Io(std::io::Error::other("close failed")));
            }
            Ok(())
        }
    }

    /// Limitations ("Returning transport runners"): a receive failure and a
    /// close failure together are both preserved; with a clean close only the
    /// receive failure is reported.
    #[test]
    fn returning_runner_preserves_run_and_close_failures_together() {
        let both = run_returning(
            modern::ServerBuilder::new("readme-claims", "1.0.0").build(),
            FailingTransport { close_fails: true },
        )
        .expect_err("a receive failure is fatal");
        let data = both.data.as_ref().expect("typed run failure");
        assert_eq!(data["run"]["data"]["stage"], "receive", "{both:?}");
        assert_eq!(data["close"]["data"]["stage"], "close", "{both:?}");

        let receive_only = run_returning(
            modern::ServerBuilder::new("readme-claims", "1.0.0").build(),
            FailingTransport { close_fails: false },
        )
        .expect_err("a receive failure is fatal");
        let data = receive_only.data.as_ref().expect("typed run failure");
        assert_eq!(data["stage"], "receive", "{receive_only:?}");
        assert!(data.get("close").is_none(), "{receive_only:?}");
    }

    /// Limitations ("Protocol Modernization"): the root compatibility
    /// constant is the exact 2024 version and the modern facade's is the
    /// 2026 version.
    #[test]
    fn root_and_modern_protocol_versions_differ_as_documented() {
        assert_eq!(fastmcp_rust::PROTOCOL_VERSION, "2024-11-05");
        assert_eq!(modern::PROTOCOL_VERSION, "2026-07-28");
        assert_ne!(fastmcp_rust::PROTOCOL_VERSION, modern::PROTOCOL_VERSION);
    }

    /// Limitations ("Tasks RPC"): `tasks/list` and `tasks/submit` stay
    /// MethodNotFound, while the official `tasks/get` is served by the default
    /// in-memory store. All three carry identical parameters and capabilities.
    #[cfg(feature = "tasks")]
    #[test]
    fn legacy_task_methods_are_method_not_found_while_tasks_get_is_served() {
        let capabilities = json!({"extensions": {"io.modelcontextprotocol/tasks": {}}});
        let params = json!({"taskId": "readme-missing-task"});
        let server = modern::ServerBuilder::new("readme-claims", "1.0.0").build();
        let (run, responses) = serve(
            server,
            &[
                request(2, "tasks/list", params.clone(), &capabilities),
                request(3, "tasks/submit", params.clone(), &capabilities),
                request(4, "tasks/get", params, &capabilities),
            ],
        );
        assert!(run.is_ok(), "{run:?}");
        for id in [2, 3] {
            let refused = response(&responses, id);
            assert_eq!(
                refused["error"]["code"],
                error_code(McpErrorCode::MethodNotFound),
                "{refused}"
            );
        }
        let served = response(&responses, 4);
        assert_ne!(
            served["error"]["code"],
            error_code(McpErrorCode::MethodNotFound),
            "tasks/get must reach the default Tasks store: {served}"
        );
    }
}
