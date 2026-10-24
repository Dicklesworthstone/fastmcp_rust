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
//! schema admission. Valid annotated tools request an explicitly reviewed plan
//! bound to the configured HTTPS or numeric-loopback HTTP endpoint. Accepted
//! plans use `HttpClient::call_tool_with_reviewed_headers`, including bounded
//! schema repair and MRTR handling. A refused disclosure plan preserves the
//! valid tool as an ordinary unmirrored call; it never installs refused fields.
//! Unannotated tools retain ordinary calls. Projection reads the actual body.
//!
//! This executable explicitly approves disclosure of its synthetic fixture
//! arguments (including harness-supplied test values); that is an adapter
//! policy, NOT a production recommendation to trust server annotations. A
//! loopback HTTP endpoint must be controlled by the harness operator. Remote
//! cleartext endpoints cannot acquire a reviewed plan, and the library's
//! ordinary constructor remains HTTPS-only.
//!
//! # Explicit HTTPS OAuth fixtures
//!
//! Set `FASTMCP_CONFORMANCE_OAUTH` to a JSON object with
//! `preauthorized_redirect: true`, `issuer`, `authorization_endpoint`,
//! `resource`, and optional `scopes` and `timeout_seconds` (1..=900, default 60).
//! The resource must equal the command-line HTTPS endpoint. The authorization
//! endpoint is a local front-channel pin, not a URL selected from a challenge.
//!
//! Without `discovery`, supply `client_id` and `token_endpoint` as before.
//! Optional `authorization_root_pem`, `token_root_pem`, and `resource_root_pem`
//! each contain one CA certificate for that endpoint's role only.
//!
//! With `discovery`, omit `token_endpoint` and `token_root_pem`. The configured
//! issuer is the sole trusted issuer for PRM and issuer-metadata discovery.
//! `discovery: {}` with `client_id` selects preregistered discovery. To use a
//! published CIMD identity, supply `discovery.client_metadata` with `url` and
//! `document_json` strings and omit `client_id`. The exact JSON bytes go through
//! native metadata admission; this executable never publishes the document.
//! A supplied preregistered ID takes precedence over a supplied CIMD identity.
//!
//! DCR fallback requires BOTH `discovery.allow_dynamic_registration: true` and
//! `discovery.client_name`. Without that explicit permission, unsupported CIMD
//! never causes a registration write. With permission, the library selects
//! preregistration, supported CIMD, or one DCR attempt before login. Failed
//! registration or login never selects another identity or anonymous access.
//! A registration may already exist remotely when a later step fails.
//!
//! Optional `discovery.issuer_root_pem` trusts issuer metadata and token/DCR
//! endpoints. Authorization trust remains separate; resource trust covers PRM
//! and MCP POSTs. No key or bearer-token input or peer-derived trust is accepted.
//! Discovery, registration, callbacks and redemption share an absolute deadline.
//!
//! The issuer must already permit this fixture's authorization; login pages
//! and consent forms are refused. After login, the same generic MCP flow uses
//! the admitted credential. By default, traffic ends at the configured limit
//! or original access expiry; dropping the run revokes local credential clones.
//! Protected names, payloads and error details are omitted from diagnostics.
//!
//! Set `FASTMCP_CONFORMANCE_MANAGED_REFRESH=1` (or `true`) alongside the OAuth
//! configuration to retain the refresh grant in a `ManagedOAuthSession` and
//! drive these same operations through `ManagedHttpClient`. Renewal happens
//! before a new operation, never as replay of a failed request or silent login.
//! Credential changes discard old discovery/cache state and cursor custody.
//! Every active operation stays bound to its original token's lifetime; the
//! overall traffic timeout never restarts when a token rotates. The run owner
//! closes every generation on drop. `0`, `false` and absence keep the original
//! fixed-token mode; other flag values or enabling without OAuth are errors.
//!
//! This is NOT a complete auth-suite driver: HTTP-only authorization fixtures,
//! consent UI and other authorization profiles remain outside this executable.
//! Source wiring and local tests are not official-conformance results.

use std::collections::HashMap;
use std::future::Future;
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

mod conformance_oauth;
use conformance_oauth::managed::{self, ClientError, FixtureClient};

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
    header_review_refused: bool,
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
    let (headers, header_review_refused) = if annotated {
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
        };
        // The fixture's execution permission is independent of permission to
        // disclose arguments through headers. Preserve the existing ordinary
        // fallback for a valid tool, but do not log here: only the caller knows
        // whether the peer-controlled name is protected information.
        match reviewed {
            Ok(reviewed) => (Some(reviewed), false),
            Err(_) => (None, true),
        }
    } else {
        (None, false)
    };
    Ok(PreparedToolCall {
        name: name.to_owned(),
        arguments: arguments_for(&schema),
        headers,
        header_review_refused,
    })
}

fn header_review_notice(name: &str, protected: bool) -> String {
    if protected {
        "tools/call: parameter-header review refused; calling without header mirrors".to_owned()
    } else {
        format!(
            "tools/call {name}: parameter-header review refused; calling without header mirrors"
        )
    }
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

fn failure(operation: &str, error: &impl std::fmt::Debug, protected: bool) -> String {
    if protected {
        format!("{operation} failed during authenticated MCP traffic")
    } else {
        format!("{operation}: {error:?}")
    }
}

fn optional_catalog_failure(
    operation: &str,
    error: &ClientError,
    protected: bool,
) -> Result<(), String> {
    if protected && !error.is_method_not_found() {
        return Err(failure(operation, error, true));
    }
    eprintln!("{}", failure(operation, error, protected));
    Ok(())
}

async fn run(cx: &Cx, url: &str) -> Result<(), String> {
    let target = normalize_loopback_target(url);
    if target != url {
        eprintln!("normalized loopback target {url} -> {target}");
    }
    let endpoint =
        CanonicalHttpUrl::parse(&target).map_err(|error| format!("bad URL {target}: {error}"))?;
    let oauth = match std::env::var(conformance_oauth::ENVIRONMENT) {
        Ok(raw) => Some(raw),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => return Err("OAuth fixture configuration is not UTF-8".to_owned()),
    };
    let refresh_flag = match std::env::var(managed::ENVIRONMENT) {
        Ok(flag) => Some(flag),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => return Err("managed-refresh flag is not UTF-8".to_owned()),
    };
    let managed_refresh = managed::selected(refresh_flag.as_deref(), oauth.is_some())?;
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
        if oauth.is_some() {
            "conformance-oauth"
        } else {
            "conformance-anonymous"
        }
        .to_owned(),
        "conformance-fixture".to_owned(),
        "native-http".to_owned(),
        0,
        0,
        0,
    )
    .map_err(|error| format!("HTTP protocol plan: {error}"))?;
    let builder = ClientBuilder::new()
        .protocol_plan(plan)
        .client_info("fastmcp-rust-conformance-client", "0.10.0")
        .capabilities(capabilities)
        .reverse_request_handlers(handlers());
    if managed_refresh {
        let raw = oauth
            .as_deref()
            .ok_or_else(|| "managed refresh requires OAuth".to_owned())?;
        let grant = managed::configure(cx, &endpoint, builder, raw).await?;
        let mut client = grant.client()?;
        return grant
            .run(cx, exercise(cx, &endpoint, &mut client, true))
            .await;
    }
    let (builder, authorization) =
        conformance_oauth::configure(cx, &endpoint, builder, oauth.as_deref()).await?;
    let protected = authorization.is_some();
    // Keep connection/discovery inside the fixed lease's lifetime too.
    let flow = async {
        let mut client = FixtureClient::ordinary(cx, builder)
            .await
            .map_err(|error| failure("connect", &error, protected))?;
        exercise(cx, &endpoint, &mut client, protected).await
    };
    match authorization {
        Some(grant) => grant.run(cx, flow).await,
        None => flow.await,
    }
}

// Boxed return, not an `async fn`. This is the whole MCP exercise flow and was
// the last `large_future` in the workspace at ~27 KB: both of its callers
// materialised it on their own frame, and at the `grant.run(cx, exercise(..))`
// site that happened even though `run` now boxes internally, because the
// ARGUMENT is built on the caller's stack before being moved into the box.
// Boxing here fixes both call sites at source (bd-y2xoc).
fn exercise<'a>(
    cx: &'a Cx,
    endpoint: &'a CanonicalHttpUrl,
    client: &'a mut FixtureClient,
    protected: bool,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
    Box::pin(exercise_inner(cx, endpoint, client, protected))
}

async fn exercise_inner(
    cx: &Cx,
    endpoint: &CanonicalHttpUrl,
    client: &mut FixtureClient,
    protected: bool,
) -> Result<(), String> {
    let listed = client
        .list_tools(cx, None)
        .await
        .map_err(|error| failure("tools/list", &error, protected))?;
    let CoreResult::Final(FinalCoreResult::ToolsList { result: listed, .. }) = listed else {
        return Err("tools/list did not return a final tools catalog".to_owned());
    };
    let tools = serde_json::to_value(&listed.payload.tools)
        .map_err(|error| failure("tools catalog encoding", &error, protected))?;
    let mut calls = Vec::new();
    for tool in tools.as_array().into_iter().flatten() {
        match prepare_tool_call(endpoint, tool) {
            Ok(call) => {
                if call.header_review_refused {
                    eprintln!("{}", header_review_notice(&call.name, protected));
                }
                calls.push(call);
            }
            Err(_) if protected => eprintln!("tools/list excluded an inadmissible tool"),
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
        ..
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
            Ok(_) if protected => println!("tools/call: ok"),
            Ok(result) => println!("tools/call {name}: {result:?}"),
            Err(error) if protected => return Err(failure("tools/call", &error, true)),
            // Ordinary fixtures may advertise tools the client must decline.
            Err(error) => eprintln!("tools/call {name} refused: {error:?}"),
        }
    }

    // Resources and prompts are optional server features. Never include
    // protected peer-controlled identities, payloads, or errors in diagnostics.
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
                    Ok(_) if protected => println!("resources/read: ok"),
                    Ok(_) => println!("resources/read {uri}: ok"),
                    Err(error) if protected => return Err(failure("resources/read", &error, true)),
                    Err(error) => eprintln!("resources/read {uri} refused: {error:?}"),
                }
            }
        }
        Ok(_) if protected => {
            return Err("resources/list returned an unexpected result type".to_owned());
        }
        Ok(_) => eprintln!("resources/list refused: unexpected result type"),
        Err(error) => optional_catalog_failure("resources/list", &error, protected)?,
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
                    Ok(_) if protected => println!("prompts/get: ok"),
                    Ok(_) => println!("prompts/get {name}: ok"),
                    Err(error) if protected => return Err(failure("prompts/get", &error, true)),
                    Err(error) => eprintln!("prompts/get {name} refused: {error:?}"),
                }
            }
        }
        Ok(_) if protected => {
            return Err("prompts/list returned an unexpected result type".to_owned());
        }
        Ok(_) => eprintln!("prompts/list refused: unexpected result type"),
        Err(error) => optional_catalog_failure("prompts/list", &error, protected)?,
    }
    // Stateless HTTP has no session. The outer OAuth lease, when configured,
    // revokes installed local credential clones on every return/drop path.
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
        // Boxed at the single site that owns it. `run` is this binary's whole
        // entry flow and has exactly one caller, so there is no root further
        // in to box and nothing is relocated by doing it here (bd-y2xoc).
        Box::pin(run(&cx, &url)).await
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
            assert!(!call.header_review_refused);
            let reviewed = call.headers.unwrap();
            assert_eq!(reviewed.resource(), &endpoint);
            assert_eq!(reviewed.tool_name(), "lookup");
            assert_eq!(reviewed.bindings().len(), 1);
            assert_eq!(reviewed.bindings()[0].header_name(), "Mcp-Param-Region");
        }
    }

    #[test]
    fn refused_header_review_preserves_valid_tools_without_installing_mirrors() {
        for target in ["http://192.0.2.1/mcp", "http://localhost/mcp"] {
            let endpoint = CanonicalHttpUrl::parse(target).unwrap();
            let call = prepare_tool_call(&endpoint, &annotated_tool()).unwrap();
            assert_eq!(call.name, "lookup");
            assert!(call.headers.is_none());
            assert!(call.header_review_refused);
            assert_eq!(
                call.arguments,
                json!({"region":"conformance","private":"conformance"})
            );
            // No annotation means no disclosure review was attempted. These
            // ordinary tools must not acquire either a plan or a refusal notice.
            let ordinary = json!({"name":"plain","inputSchema":{
                "type":"object","properties":{"value":{"type":"string"}}
            }});
            let call = prepare_tool_call(&endpoint, &ordinary).unwrap();
            assert!(call.headers.is_none());
            assert!(!call.header_review_refused);
            assert_eq!(call.arguments, json!({"value":"conformance"}));
        }
    }

    #[test]
    fn header_review_notice_redacts_protected_names_and_preserves_the_refusal() {
        let name = "private-tool-and-token-canary";
        let protected = header_review_notice(name, true);
        assert!(!protected.contains(name));
        assert!(protected.contains("review refused"));
        assert!(protected.contains("without header mirrors"));
        assert!(header_review_notice(name, false).contains(name));
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

    #[test]
    fn authenticated_diagnostics_do_not_include_reflected_credentials() {
        let secret = "reflected-code-and-token";
        assert_eq!(
            failure("tools/call", &secret, true),
            "tools/call failed during authenticated MCP traffic"
        );
        assert!(!failure("connect", &secret, true).contains(secret));
        assert!(failure("connect", &secret, false).contains(secret));
        let denied: ClientError =
            fastmcp_client::HttpClientError::CoreResult(McpError::invalid_request(secret)).into();
        assert!(
            !optional_catalog_failure("resources/list", &denied, true)
                .unwrap_err()
                .contains(secret)
        );
        let unsupported: ClientError = fastmcp_client::HttpClientError::CoreResult(
            McpError::method_not_found("resources/list"),
        )
        .into();
        assert!(optional_catalog_failure("resources/list", &unsupported, true).is_ok());
    }
}
