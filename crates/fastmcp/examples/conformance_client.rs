//! Conformance adapter (client mode) for the official MCP conformance suite.
//!
//! Plan section 2.6 requires the official harness to pass in both server and
//! client modes. In client mode the suite starts a scenario server, then runs
//! this binary with the server URL as its last argument and the scenario name
//! in `MCP_CONFORMANCE_SCENARIO`.
//!
//! ```bash
//! cargo build -p fastmcp-rust --bin conformance_client
//! npx @modelcontextprotocol/conformance@0.2.0-alpha.10 client \
//!   --command target/debug/conformance_client --spec-version 2026-07-28 \
//!   --scenario tools_call
//! ```
//!
//! # Behaviour
//!
//! One generic, scenario-agnostic flow drives the public modern HTTP client:
//! connect (stateless `server/discover`), list every tool, and call each one
//! with arguments synthesized from its input schema (or the exact arguments
//! the harness names in `MCP_CONFORMANCE_CONTEXT`), then read every listed
//! resource and get every listed prompt. Installed reverse
//! handlers answer any `input_required` round (sampling, roots, form or URL
//! elicitation), so the client's MRTR loop, per-request `_meta`, routing and
//! parameter headers, and schema handling are all exercised by real traffic.
//! The adapter never branches on the scenario name: what the suite measures
//! is the library's behaviour, not fixture-specific code.
//!
//! Not covered: the authorization scenarios (`auth/*`), which need an
//! interactive OAuth driver configuration this adapter does not supply.

use std::collections::HashMap;
use std::process::ExitCode;

use fastmcp_protocol::{ElicitContentValue, ElicitRequestParams, ElicitResult};
use fastmcp_rust::modern::{
    CanonicalHttpUrl, ClientBuilder, ClientCapabilities, Cx, McpError, ReverseRequestHandlers,
};
use serde_json::{Value, json};

/// A schema-shaped placeholder for one property.
fn placeholder(schema: &Value) -> Value {
    if let Some(constant) = schema.get("const") {
        return constant.clone();
    }
    if let Some(first) = schema
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
    {
        return first.clone();
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("number" | "integer") => json!(1),
        Some("boolean") => json!(true),
        Some("array") => json!([]),
        Some("object") => arguments_for(schema),
        _ => json!("conformance"),
    }
}

/// Synthesizes an argument object for every declared property.
fn arguments_for(schema: &Value) -> Value {
    let mut arguments = serde_json::Map::new();
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (name, property) in properties {
            arguments.insert(name.clone(), placeholder(property));
        }
    }
    Value::Object(arguments)
}

fn handlers() -> ReverseRequestHandlers {
    ReverseRequestHandlers::new()
        .with_modern_sampling_create_message(|_cx, _cancellation, _params| {
            Box::pin(async move {
                serde_json::from_value(json!({
                    "content": {"type": "text", "text": "Paris"},
                    "model": "fastmcp-conformance-client",
                    "role": "assistant",
                }))
                .map_err(|error| McpError::internal_error(error.to_string()))
            })
        })
        .with_modern_roots_list(|_cx, _cancellation, _params| {
            Box::pin(async move {
                serde_json::from_value(json!({
                    "roots": [{"uri": "file:///conformance", "name": "conformance"}],
                }))
                .map_err(|error| McpError::internal_error(error.to_string()))
            })
        })
        .with_modern_elicitation_create(|_cx, _cancellation, params| {
            Box::pin(async move {
                Ok(match params {
                    ElicitRequestParams::Url(_) => ElicitResult::accept_url(),
                    ElicitRequestParams::Form(form) => {
                        let schema = serde_json::to_value(&form.requested_schema)
                            .map_err(|error| McpError::internal_error(error.to_string()))?;
                        let content: HashMap<String, ElicitContentValue> =
                            serde_json::from_value(arguments_for(&schema))
                                .map_err(|error| McpError::internal_error(error.to_string()))?;
                        ElicitResult::accept(content)
                    }
                })
            })
        })
}

async fn run(cx: &Cx, url: &str) -> Result<(), String> {
    let endpoint =
        CanonicalHttpUrl::parse(url).map_err(|error| format!("bad URL {url}: {error}"))?;
    let capabilities: ClientCapabilities = serde_json::from_value(json!({
        "sampling": {},
        "roots": {},
        "elicitation": {"form": {}, "url": {}},
    }))
    .map_err(|error| format!("client capabilities: {error}"))?;
    let mut client = ClientBuilder::new()
        .client_info("fastmcp-rust-conformance-client", "0.10.0")
        .capabilities(capabilities)
        .modern_reverse_request_handlers(handlers())
        .connect_http_with_cx(cx, endpoint)
        .await
        .map_err(|error| format!("connect: {error:?}"))?;

    let listed = client
        .list_tools(cx, None)
        .await
        .map_err(|error| format!("tools/list: {error:?}"))?;
    let tools = serde_json::to_value(&listed.tools).map_err(|error| error.to_string())?;
    let mut calls: Vec<(String, Value)> = Vec::new();
    for tool in tools.as_array().into_iter().flatten() {
        let Some(name) = tool.get("name").and_then(Value::as_str) else {
            continue;
        };
        let arguments = tool
            .get("inputSchema")
            .map_or_else(|| json!({}), arguments_for);
        calls.push((name.to_owned(), arguments));
    }
    // The harness may name exact arguments for a listed tool; a call it names
    // for a tool the library did not list is never made.
    for (name, arguments) in context_tool_calls() {
        if let Some(call) = calls.iter_mut().find(|(listed, _)| *listed == name) {
            call.1 = arguments;
        }
    }
    for (name, arguments) in calls {
        match client.call_tool(cx, &name, arguments).await {
            Ok(result) => println!(
                "tools/call {name}: {}",
                serde_json::to_string(&result.content).unwrap_or_default()
            ),
            // A refused tool is reported, not fatal: scenarios may advertise
            // tools the client must decline to call.
            Err(error) => eprintln!("tools/call {name} refused: {error:?}"),
        }
    }

    // Resources and prompts are optional server features: a refusal is
    // reported and the run continues.
    match client.list_resources(cx, None).await {
        Ok(listed) => {
            let resources = serde_json::to_value(&listed.resources).unwrap_or_default();
            for uri in resources
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|resource| resource.get("uri").and_then(Value::as_str))
            {
                match client.read_resource(cx, uri).await {
                    Ok(_) => println!("resources/read {uri}: ok"),
                    Err(error) => eprintln!("resources/read {uri} refused: {error:?}"),
                }
            }
        }
        Err(error) => eprintln!("resources/list refused: {error:?}"),
    }
    match client.list_prompts(cx, None).await {
        Ok(listed) => {
            let prompts = serde_json::to_value(&listed.prompts).unwrap_or_default();
            for prompt in prompts.as_array().into_iter().flatten() {
                let Some(name) = prompt.get("name").and_then(Value::as_str) else {
                    continue;
                };
                let arguments: HashMap<String, String> = prompt
                    .get("arguments")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|argument| argument.get("name").and_then(Value::as_str))
                    .map(|argument| (argument.to_owned(), "conformance".to_owned()))
                    .collect();
                match client.get_prompt(cx, name, arguments).await {
                    Ok(_) => println!("prompts/get {name}: ok"),
                    Err(error) => eprintln!("prompts/get {name} refused: {error:?}"),
                }
            }
        }
        Err(error) => eprintln!("prompts/list refused: {error:?}"),
    }
    // Stateless HTTP holds no session, so there is nothing to close.
    Ok(())
}

/// Tool calls the harness names in `MCP_CONFORMANCE_CONTEXT` (`toolCalls`).
fn context_tool_calls() -> Vec<(String, Value)> {
    let Some(context) = std::env::var("MCP_CONFORMANCE_CONTEXT")
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
    else {
        return Vec::new();
    };
    context
        .get("toolCalls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|call| {
            let name = call.get("name")?.as_str()?.to_owned();
            let arguments = call.get("arguments").cloned().unwrap_or_else(|| json!({}));
            Some((name, arguments))
        })
        .collect()
}

fn main() -> ExitCode {
    let Some(url) = std::env::args()
        .last()
        .filter(|arg| arg.starts_with("http"))
    else {
        eprintln!("usage: conformance_client <server-url>");
        return ExitCode::FAILURE;
    };
    let runtime = match asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(match asupersync::runtime::reactor::create_reactor() {
            Ok(reactor) => reactor,
            Err(error) => {
                eprintln!("conformance client: reactor failed: {error}");
                return ExitCode::FAILURE;
            }
        })
        .blocking_threads(0, 16)
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("conformance client: runtime failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    let outcome = runtime.block_on(async {
        let cx = Cx::current().ok_or_else(|| "no ambient context".to_owned())?;
        run(&cx, &url).await
    });
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("conformance client: {message}");
            ExitCode::FAILURE
        }
    }
}
