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
                .connect_stdio_with_cx(binary, &[], &Cx::for_request()),
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
        assert!(client.call_tool("greet", json!({})).is_err());
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
        assert!(client.call_tool("echo", json!({"message": 7})).is_err());
        client
            .close()
            .expect("the README Quick Start client closes cleanly");
    }
}
