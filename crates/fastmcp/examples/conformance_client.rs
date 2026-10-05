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
//! One generic, scenario-agnostic flow drives the published high-level HTTP
//! client with an explicit ModernOnly plan: connect (`server/discover`), list
//! tools, and call each listed tool with schema-shaped arguments or the exact
//! arguments named in `MCP_CONFORMANCE_CONTEXT`. Then read listed resources
//! and get listed prompts. Installed reverse handlers answer `input_required`
//! rounds (sampling, roots, form or URL elicitation). No scenario name selects
//! a different implementation, and no private/raw transport bypass is used.
//!
//! Invalid `x-mcp-header` annotations exclude a tool through the library's
//! schema admission. Valid annotated tools get an explicitly reviewed plan
//! bound to the configured HTTPS or numeric-loopback HTTP endpoint. Calls use
//! `HttpClient::call_tool_with_reviewed_headers`, including its bounded schema
//! repair and MRTR handling. Unannotated tools retain ordinary tool calls.
//! Projection reads the actual outgoing body, including harness overrides.
//!
//! This executable explicitly approves disclosure of its synthetic fixture
//! arguments (including harness-supplied test values); that is an adapter
//! policy, NOT a production recommendation to trust server annotations. A
//! loopback HTTP endpoint must be controlled by the harness operator. Remote
//! cleartext endpoints cannot acquire a reviewed plan, and the library's
//! ordinary constructor remains HTTPS-only.
//!
//! Not covered: authorization scenarios (`auth/*`), which need an interactive
//! OAuth driver configuration this adapter does not supply. Source wiring and
//! local regression tests do not establish official conformance results.

use std::collections::HashMap;
use std::process::ExitCode;

use fastmcp_client::http_executor::parameter_headers::ReviewedToolHeaders;
use fastmcp_client::{ClientBuilder, ClientProtocolPlan, ProtocolPolicy, ReverseRequestHandlers};
use fastmcp_core::{CanonicalHttpUrl, Cx, McpError};
use fastmcp_protocol::http_headers::{
    AdmittedToolHeaderSchema, ParameterHeaderBinding, admit_final_tool_input_schema,
};
use fastmcp_protocol::{
    ClientCapabilities, CoreResult, ElicitContentValue, ElicitRequestParams, ElicitResult,
    FinalCoreResult,
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

struct PreparedToolCall {
    name: String,
    arguments: Value,
    headers: Option<ReviewedToolHeaders>,
}

/// The operator runs this adapter against synthetic conformance fixtures.
/// Production hosts must substitute their own per-binding disclosure policy.
fn approve_fixture_header(_binding: &ParameterHeaderBinding) -> bool {
    true
}

fn prepare_tool_call(
    endpoint: &CanonicalHttpUrl,
    tool: &Value,
) -> Result<PreparedToolCall, String> {
    let name = tool
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "listed tool has no name".to_owned())?;
    let schema = tool
        .get("inputSchema")
        .cloned()
        .unwrap_or_else(|| json!({"type":"object"}));
    // Keep exclusion before argument synthesis or invocation. In particular,
    // invalid annotations cannot fall back to an unmirrored ordinary call.
    admit_final_tool_input_schema(schema.clone())
        .map_err(|error| format!("invalid parameter-header schema: {error}"))?;
    // Annotation-aware admission above has already checked every annotated
    // schema through this compiler. Ordinary unannotated schemas may use the
    // broader generic admission route; they do not authorize any headers.
    let annotated = AdmittedToolHeaderSchema::admit(schema.clone())
        .is_ok_and(|admitted| !admitted.header_plan().bindings().is_empty());
    let headers = if annotated {
        let reviewed = if endpoint.scheme() == "https" {
            ReviewedToolHeaders::new(
                endpoint.clone(),
                name,
                schema.clone(),
                approve_fixture_header,
            )
        } else {
            ReviewedToolHeaders::new_for_loopback_http(
                endpoint.clone(),
                name,
                schema.clone(),
                approve_fixture_header,
            )
        }
        .map_err(|error| format!("parameter-header disclosure refused: {error}"));
        // A refused DISCLOSURE PLAN must not exclude the tool. Only an invalid
        // `x-mcp-header` schema may, and that was decided above. SEP-2243 is
        // explicit that one malformed tool definition must not prevent other
        // valid tools from being used, and the harness fails
        // `sep-2243-client-reject-invalid-tool` when a valid tool goes
        // uncalled. So a plan failure degrades to an ordinary unmirrored call
        // and says so, rather than silently dropping the tool.
        match reviewed {
            Ok(reviewed) => Some(reviewed),
            Err(error) => {
                eprintln!("tools/call {name}: {error}; calling without header mirrors");
                None
            }
        }
    } else {
        None
    };
    Ok(PreparedToolCall {
        name: name.to_owned(),
        arguments: arguments_for(&schema),
        headers,
    })
}

fn apply_context_tool_calls(calls: &mut [PreparedToolCall], overrides: Vec<(String, Value)>) {
    // A name absent from the admitted catalog cannot introduce a new call.
    // Overrides change only the body arguments, never the reviewed schema.
    for (name, arguments) in overrides {
        if let Some(call) = calls.iter_mut().find(|call| call.name == name) {
            call.arguments = arguments;
        }
    }
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

/// Rewrites an `http://localhost[:port]` target to its IPv4 loopback literal.
///
/// `ReviewedToolHeaders::new_for_loopback_http` admits only canonical loopback
/// LITERALS and deliberately refuses DNS names, `localhost` included, because a
/// name can be rebound and is therefore not proof of a loopback peer. The
/// official harness hands every scenario URL out as
/// `http://localhost:<port>/mcp`, so without this the library's rule makes
/// parameter-header mirroring unreachable in conformance.
///
/// Resolving the name is the HOST's decision to make, not the library's, which
/// is exactly why it happens here: this adapter asserts that it trusts
/// `localhost` on the machine running the harness, and the library's literal
/// -only boundary stays intact. The rewrite is applied ONCE, before connecting,
/// so the connection and the plan are bound to the same canonical URL -- a plan
/// built for a different authority than the connection would be refused at
/// dispatch.
fn normalize_loopback_target(url: &str) -> String {
    for prefix in ["http://localhost:", "http://localhost/"] {
        if let Some(rest) = url.strip_prefix(prefix) {
            let separator = &prefix["http://localhost".len()..];
            return format!("http://127.0.0.1{separator}{rest}");
        }
    }
    if url == "http://localhost" {
        return "http://127.0.0.1".to_owned();
    }
    url.to_owned()
}

async fn run(cx: &Cx, url: &str) -> Result<(), String> {
    let target = normalize_loopback_target(url);
    if target != url {
        eprintln!("normalized loopback target {url} -> {target}");
    }
    let endpoint =
        CanonicalHttpUrl::parse(&target).map_err(|error| format!("bad URL {target}: {error}"))?;
    let capabilities: ClientCapabilities = serde_json::from_value(json!({
        "sampling": {},
        "roots": {},
        "elicitation": {"form": {}, "url": {}},
    }))
    .map_err(|error| format!("client capabilities: {error}"))?;
    let plan = ClientProtocolPlan::http(
        ProtocolPolicy::ModernOnly,
        Some(endpoint.clone()),
        None,
        None,
        "conformance-anonymous".to_owned(),
        "conformance-fixture".to_owned(),
        "native-http".to_owned(),
        0,
        0,
        0,
    )
    .map_err(|error| format!("HTTP protocol plan: {error}"))?;
    let mut client = ClientBuilder::new()
        .protocol_plan(plan)
        .client_info("fastmcp-rust-conformance-client", "0.10.0")
        .capabilities(capabilities)
        .reverse_request_handlers(handlers())
        .connect_http_client_with_cx(cx)
        .await
        .map_err(|error| format!("connect: {error:?}"))?;

    let listed = client
        .list_tools(cx, None)
        .await
        .map_err(|error| format!("tools/list: {error:?}"))?;
    let CoreResult::Final(FinalCoreResult::ToolsList { result: listed, .. }) = listed else {
        return Err("tools/list did not return a final tools catalog".to_owned());
    };
    let tools = serde_json::to_value(&listed.payload.tools).map_err(|error| error.to_string())?;
    let mut calls = Vec::new();
    for tool in tools.as_array().into_iter().flatten() {
        match prepare_tool_call(&endpoint, tool) {
            Ok(call) => calls.push(call),
            Err(error) => eprintln!(
                "tools/list {} excluded: {error}",
                tool.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("<unnamed>")
            ),
        }
    }
    apply_context_tool_calls(&mut calls, context_tool_calls());
    for PreparedToolCall {
        name,
        arguments,
        headers,
    } in calls
    {
        let outcome = match headers {
            Some(reviewed) => {
                client
                    .call_tool_with_reviewed_headers(
                        cx,
                        arguments,
                        &reviewed,
                        &approve_fixture_header,
                    )
                    .await
            }
            None => client.call_tool(cx, &name, arguments).await,
        };
        match outcome {
            Ok(result) => println!("tools/call {name}: {result:?}"),
            // A refused tool is reported, not fatal: scenarios may advertise
            // tools the client must decline to call.
            Err(error) => eprintln!("tools/call {name} refused: {error:?}"),
        }
    }

    // Resources and prompts are optional server features: a refusal is
    // reported and the run continues.
    match client.list_resources(cx, None).await {
        Ok(CoreResult::Final(FinalCoreResult::ResourcesList { result: listed, .. })) => {
            let resources = serde_json::to_value(&listed.payload.resources).unwrap_or_default();
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
        Ok(_) => eprintln!("resources/list refused: unexpected result type"),
        Err(error) => eprintln!("resources/list refused: {error:?}"),
    }
    match client.list_prompts(cx, None).await {
        Ok(CoreResult::Final(FinalCoreResult::PromptsList { result: listed, .. })) => {
            let prompts = serde_json::to_value(&listed.payload.prompts).unwrap_or_default();
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
        Ok(_) => eprintln!("prompts/list refused: unexpected result type"),
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
        .next_back()
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

#[cfg(test)]
mod tests {
    use fastmcp_client::http_executor::ModernHttpRequest;
    use fastmcp_protocol::http_headers::decode_mcp_header_value;
    use fastmcp_protocol::{FINAL_PROTOCOL_VERSION, FinalRequestMeta};

    use super::*;

    fn annotated_tool() -> Value {
        json!({"name":"lookup","inputSchema":{"type":"object","properties":{
            "region":{"type":"string","x-mcp-header":"Region"},
            "private":{"type":"string"}
        }}})
    }

    #[test]
    fn annotated_catalog_tools_receive_exact_https_or_loopback_plans() {
        for target in [
            "https://tools.example/mcp",
            "http://127.0.0.1:8123/mcp",
            "http://[::1]:8123/mcp",
        ] {
            let endpoint = CanonicalHttpUrl::parse(target).unwrap();
            let call = prepare_tool_call(&endpoint, &annotated_tool()).unwrap();
            let reviewed = call.headers.unwrap();
            assert_eq!(reviewed.resource(), &endpoint);
            assert_eq!(reviewed.tool_name(), "lookup");
            assert_eq!(reviewed.bindings().len(), 1);
            assert_eq!(reviewed.bindings()[0].header_name(), "Mcp-Param-Region");
        }
    }

    #[test]
    fn denied_cleartext_review_never_falls_back_to_an_unmirrored_call() {
        for target in ["http://192.0.2.1/mcp", "http://localhost/mcp"] {
            let endpoint = CanonicalHttpUrl::parse(target).unwrap();
            assert!(prepare_tool_call(&endpoint, &annotated_tool()).is_err());
            // No annotation means no disclosure plan is required. Do not make
            // the explicit header constructor a new general transport rule.
            let ordinary = json!({"name":"plain","inputSchema":{
                "type":"object","properties":{"value":{"type":"string"}}
            }});
            let call = prepare_tool_call(&endpoint, &ordinary).unwrap();
            assert!(call.headers.is_none());
            assert_eq!(call.arguments, json!({"value":"conformance"}));
        }
    }

    #[test]
    fn invalid_header_annotations_stay_excluded_before_invocation() {
        let endpoint = CanonicalHttpUrl::parse("http://127.0.0.1:8123/mcp").unwrap();
        for annotation in ["", "bad name", "bad:name", "bad\r\nname", "雪"] {
            let mut tool = annotated_tool();
            tool["inputSchema"]["properties"]["region"]["x-mcp-header"] = json!(annotation);
            assert!(prepare_tool_call(&endpoint, &tool).is_err());
        }
        let mut duplicate = annotated_tool();
        duplicate["inputSchema"]["properties"]["private"]["x-mcp-header"] = json!("region");
        assert!(prepare_tool_call(&endpoint, &duplicate).is_err());
        let mut nonprimitive = annotated_tool();
        nonprimitive["inputSchema"]["properties"]["region"]["type"] = json!("object");
        assert!(prepare_tool_call(&endpoint, &nonprimitive).is_err());
    }

    #[test]
    fn context_override_is_projected_from_actual_body_without_changing_review() {
        let endpoint = CanonicalHttpUrl::parse("http://127.0.0.1:8123/mcp").unwrap();
        let mut calls = vec![prepare_tool_call(&endpoint, &annotated_tool()).unwrap()];
        let arguments = json!({"region":"雪\r\n", "private":"body-only-canary"});
        apply_context_tool_calls(
            &mut calls,
            vec![
                ("unlisted".to_owned(), json!({"region":"must-not-run"})),
                ("lookup".to_owned(), arguments.clone()),
            ],
        );
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].arguments, arguments);
        let call = calls.pop().unwrap();
        let reviewed = call.headers.unwrap();
        let body = serde_json::to_vec(&json!({
            "jsonrpc":"2.0", "id":1, "method":"tools/call",
            "params":{
                "name":call.name, "arguments":call.arguments,
                "_meta":FinalRequestMeta::new(ClientCapabilities::default())
            }
        }))
        .unwrap();
        let request = ModernHttpRequest::new(
            endpoint.as_str(),
            body.clone(),
            FINAL_PROTOCOL_VERSION,
            "tools/call",
            Some("lookup".to_owned()),
        )
        .unwrap()
        .with_reviewed_tool_headers(&reviewed)
        .unwrap();
        assert_eq!(request.body(), body);
        let fields: Vec<_> = request
            .headers()
            .into_iter()
            .filter(|(name, _)| name.starts_with("Mcp-Param-"))
            .collect();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "Mcp-Param-Region");
        assert_eq!(
            decode_mcp_header_value(fields[0].1.as_bytes()).unwrap(),
            "雪\r\n"
        );
        assert!(!fields[0].1.contains(['\r', '\n']));
        assert!(
            !request
                .headers()
                .iter()
                .any(|(_, value)| value.contains("body-only-canary"))
        );
    }

    #[test]
    fn ordinary_argument_synthesis_keeps_constants_enums_and_nested_types() {
        let endpoint = CanonicalHttpUrl::parse("http://127.0.0.1:8123/mcp").unwrap();
        let tool = json!({"name":"plain","inputSchema":{"type":"object","properties":{
            "constant":{"type":"string","const":"fixed"},
            "enum":{"type":"string","enum":["first","second"]},
            "nested":{"type":"object","properties":{
                "flag":{"type":"boolean"},"number":{"type":"integer"}
            }}
        }}});
        let call = prepare_tool_call(&endpoint, &tool).unwrap();
        assert!(call.headers.is_none());
        assert_eq!(
            call.arguments,
            json!({
                "constant":"fixed", "enum":"first", "nested":{"flag":true,"number":1}
            })
        );
    }
}
