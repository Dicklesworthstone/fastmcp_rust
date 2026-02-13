//! E2E Client-Server Protocol Integration Tests (bd-22q)
//!
//! Comprehensive tests for full client-server protocol flows using
//! MemoryTransport with real handler implementations. No mocks.
//!
//! Coverage:
//! - Initialize handshake
//! - Tool listing and invocation
//! - Resource listing and reading
//! - Prompt listing and retrieval
//! - Error handling (unknown tool, invalid params, method not found)
//! - JSON-RPC 2.0 compliance

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::thread::JoinHandle;

use fastmcp_rust::testing::prelude::*;
use fastmcp_rust::{
    AuthContext, McpContext, McpErrorCode, McpResult, PromptMessage, Role, StaticTokenVerifier,
    TokenAuthProvider,
};
use serde_json::json;

// ============================================================================
// Test handler implementations
// ============================================================================

/// A simple greeting tool handler.
#[fastmcp_rust::tool(
    name = "greeting",
    description = "Returns a greeting for the given name",
    version = "1.0.0",
    tags = ["greeting"],
    annotations(read_only)
)]
fn greeting_tool_handler(name: String) -> String {
    format!("Hello, {name}!")
}

/// A calculator tool handler.
#[fastmcp_rust::tool(name = "calculator", description = "Performs arithmetic operations")]
fn calculator_tool_handler(a: f64, b: f64, operation: String) -> McpResult<String> {
    let result = match operation.as_str() {
        "add" => a + b,
        "subtract" => a - b,
        "multiply" => a * b,
        "divide" => {
            if b == 0.0 {
                return Err(McpError::tool_error("Division by zero"));
            }
            a / b
        }
        _ => {
            return Err(McpError::tool_error(format!(
                "Unknown operation: {operation}"
            )));
        }
    };

    Ok(result.to_string())
}

/// An error-producing tool handler.
#[fastmcp_rust::tool(name = "error_tool", description = "Always returns an error")]
fn error_tool_handler() -> McpResult<String> {
    Err(McpError::tool_error("Intentional error for testing"))
}

/// A tool that returns the current request authentication context as JSON text.
#[fastmcp_rust::tool(
    name = "auth_info",
    description = "Returns auth context for E2E verification",
    tags = ["auth", "testing"],
    annotations(read_only)
)]
fn auth_info_tool_handler(ctx: &McpContext) -> String {
    let auth = ctx.auth().unwrap_or_else(AuthContext::anonymous);
    let access = auth.token.as_ref();

    let payload = json!({
        "subject": auth.subject,
        "scopes": auth.scopes,
        "scheme": access.map(|t| t.scheme.clone()),
        "token": access.map(|t| t.token.clone()),
    });

    payload.to_string()
}

/// A text file resource handler.
#[fastmcp_rust::resource(
    uri = "file:///test/sample.txt",
    name = "sample.txt",
    description = "A sample text file",
    mime_type = "text/plain",
    version = "1.0.0",
    tags = ["text"]
)]
fn text_file_resource_handler() -> String {
    "Hello, World!\nThis is sample text content.".to_string()
}

/// A JSON config resource handler.
#[fastmcp_rust::resource(
    uri = "file:///config/settings.json",
    name = "settings.json",
    description = "Application configuration",
    mime_type = "application/json"
)]
fn json_config_resource_handler() -> String {
    json!({
        "version": "1.0.0",
        "debug": false,
        "max_connections": 100
    })
    .to_string()
}

/// A greeting prompt handler.
#[fastmcp_rust::prompt(
    name = "greeting",
    description = "Generate a greeting",
    version = "1.0.0",
    tags = ["greeting"]
)]
fn greeting_prompt_handler(name: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("Please greet {name} warmly."),
        },
    }]
}

/// A code review prompt handler with multiple arguments.
#[fastmcp_rust::prompt(name = "code_review", description = "Review code for quality")]
fn code_review_prompt_handler(code: String, language: String) -> Vec<PromptMessage> {
    vec![
        PromptMessage {
            role: Role::User,
            content: Content::Text {
                text: format!("Review this {language} code:\n```{language}\n{code}\n```"),
            },
        },
        PromptMessage {
            role: Role::Assistant,
            content: Content::Text {
                text: "I'll review this code for quality, bugs, and improvements.".to_string(),
            },
        },
    ]
}

// ============================================================================
// Helper: build server + client pair
// ============================================================================

struct TestHarness {
    client: Option<TestClient>,
    server_thread: Option<JoinHandle<()>>,
}

impl TestHarness {
    fn new(client: TestClient, server_thread: JoinHandle<()>) -> Self {
        Self {
            client: Some(client),
            server_thread: Some(server_thread),
        }
    }
}

impl Deref for TestHarness {
    type Target = TestClient;

    fn deref(&self) -> &Self::Target {
        self.client.as_ref().expect("client missing")
    }
}

impl DerefMut for TestHarness {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.client.as_mut().expect("client missing")
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        // Drop the client first so the transport closes and the server thread can exit.
        self.client.take();

        if let Some(handle) = self.server_thread.take() {
            // If the server thread panicked, fail the test (assert! is acceptable in test-only Drop).
            assert!(handle.join().is_ok(), "server thread panicked");
        }
    }
}

fn spawn_thread(f: impl FnOnce() + Send + 'static) -> JoinHandle<()> {
    std::thread::spawn(f)
}

/// Spawns a server with all test handlers and returns a connected TestClient.
///
/// The server runs in a background thread and is cleaned up when the
/// transport is closed.
fn setup_test_server_and_client() -> TestHarness {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name("e2e-test-server")
        .with_version("1.0.0")
        .build_server_builder();

    let server = builder
        .tool(GreetingToolHandler)
        .tool(CalculatorToolHandler)
        .tool(ErrorToolHandler)
        .resource(TextFileResourceHandlerResource)
        .resource(JsonConfigResourceHandlerResource)
        .prompt(GreetingPromptHandlerPrompt)
        .prompt(CodeReviewPromptHandlerPrompt)
        .build();

    // Run server in background thread
    let handle = spawn_thread(move || {
        server.run_transport(server_transport);
    });

    TestHarness::new(TestClient::new(client_transport), handle)
}

fn setup_auth_server_and_client<P: fastmcp_rust::AuthProvider + 'static>(
    provider: P,
    server_name: &str,
) -> TestHarness {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name(server_name)
        .with_version("1.0.0")
        .build_server_builder();

    let server = builder
        .tool(GreetingToolHandler)
        .tool(AuthInfoToolHandler)
        .auth_provider(provider)
        .build();

    let handle = spawn_thread(move || server.run_transport(server_transport));

    TestHarness::new(TestClient::new(client_transport), handle)
}

// ============================================================================
// Initialize handshake tests
// ============================================================================

#[test]
fn e2e_initialize_handshake() {
    let mut client = setup_test_server_and_client();
    let result = client.initialize();
    assert!(result.is_ok(), "Initialization failed: {result:?}");

    let init_result = result.unwrap();
    assert_eq!(init_result.server_info.name, "e2e-test-server");
    assert_eq!(init_result.server_info.version, "1.0.0");
    assert_eq!(init_result.protocol_version, fastmcp_rust::PROTOCOL_VERSION);
}

#[test]
fn e2e_initialize_reports_capabilities() {
    let mut client = setup_test_server_and_client();
    let init_result = client.initialize().unwrap();

    // Server registered tools, resources, and prompts, so all should be Some
    assert!(
        init_result.capabilities.tools.is_some(),
        "Server should advertise tool capabilities"
    );
    assert!(
        init_result.capabilities.resources.is_some(),
        "Server should advertise resource capabilities"
    );
    assert!(
        init_result.capabilities.prompts.is_some(),
        "Server should advertise prompt capabilities"
    );
}

#[test]
fn e2e_initialize_stores_server_info() {
    let mut client = setup_test_server_and_client();
    assert!(!client.is_initialized());
    assert!(client.server_info().is_none());

    client.initialize().unwrap();

    assert!(client.is_initialized());
    assert_eq!(client.server_info().unwrap().name, "e2e-test-server");
    assert!(client.server_capabilities().is_some());
    assert_eq!(
        client.protocol_version().unwrap(),
        fastmcp_rust::PROTOCOL_VERSION
    );
}

// ============================================================================
// Authentication flow tests (bd-21q)
// ============================================================================

#[test]
fn e2e_auth_static_token_flow_allows_and_denies() {
    let verifier = StaticTokenVerifier::new([("good-token", AuthContext::with_subject("user-1"))])
        .with_allowed_schemes(["Bearer"]);
    let provider = TokenAuthProvider::new(verifier);

    let mut client = setup_auth_server_and_client(provider, "e2e-auth-static");
    client.initialize().unwrap();

    let mut trace = TestTrace::new("e2e-auth-static-token");

    // Unauthorized tools/list.
    let params = json!({ "cursor": null });
    let corr = trace.log_request("tools/list", Some(&params));
    let err = client.send_request_json("tools/list", params).unwrap_err();
    trace.log_response(
        &corr,
        None::<&serde_json::Value>,
        Some(&json!({"error": err.message})),
    );
    assert_eq!(err.code, McpErrorCode::ResourceForbidden);

    // Invalid token should be rejected.
    let params = json!({ "cursor": null, "auth": "Bearer bad-token" });
    let corr = trace.log_request("tools/list", Some(&params));
    let err = client.send_request_json("tools/list", params).unwrap_err();
    trace.log_response(
        &corr,
        None::<&serde_json::Value>,
        Some(&json!({"error": err.message})),
    );
    assert_eq!(err.code, McpErrorCode::ResourceForbidden);

    // Authorized tools/list.
    let params = json!({ "cursor": null, "auth": "Bearer good-token" });
    let corr = trace.log_request("tools/list", Some(&params));
    let value = client.send_request_json("tools/list", params).unwrap();
    trace.log_response(&corr, Some(&value), None::<&serde_json::Value>);

    let tools: fastmcp_protocol::ListToolsResult = serde_json::from_value(value).unwrap();
    assert!(
        tools.tools.iter().any(|t| t.name == "greeting"),
        "expected greeting tool to be listed"
    );

    // Authorized tools/call.
    let params = json!({
        "name": "greeting",
        "arguments": { "name": "Ada" },
        "auth": "Bearer good-token",
    });
    let corr = trace.log_request("tools/call", Some(&params));
    let value = client.send_request_json("tools/call", params).unwrap();
    trace.log_response(&corr, Some(&value), None::<&serde_json::Value>);

    let call: fastmcp_protocol::CallToolResult = serde_json::from_value(value).unwrap();
    assert!(!call.is_error);
    assert!(
        matches!(call.content.first(), Some(Content::Text { .. })),
        "expected text content"
    );
    let Some(Content::Text { text }) = call.content.first() else {
        return;
    };
    assert_eq!(text, "Hello, Ada!");

    // Verify the server stored auth context into McpContext (subject + token).
    let params = json!({
        "name": "auth_info",
        "arguments": {},
        "auth": "Bearer good-token",
    });
    let corr = trace.log_request("tools/call(auth_info)", Some(&params));
    let value = client.send_request_json("tools/call", params).unwrap();
    trace.log_response(&corr, Some(&value), None::<&serde_json::Value>);

    let call: fastmcp_protocol::CallToolResult = serde_json::from_value(value).unwrap();
    assert!(
        matches!(call.content.first(), Some(Content::Text { .. })),
        "expected text content"
    );
    let Some(Content::Text { text }) = call.content.first() else {
        return;
    };
    let auth_json: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(
        auth_json.get("subject").and_then(|v| v.as_str()),
        Some("user-1")
    );
    assert_eq!(
        auth_json.get("token").and_then(|v| v.as_str()),
        Some("good-token")
    );
}

#[cfg(feature = "jwt")]
#[test]
fn e2e_auth_jwt_flow_allows_and_denies() {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use std::time::{SystemTime, UNIX_EPOCH};

    let signing_bytes = b"e2e-jwt-bytes";
    let verifier = fastmcp_rust::JwtTokenVerifier::hs256(signing_bytes);
    let provider = TokenAuthProvider::new(verifier);

    let mut client = setup_auth_server_and_client(provider, "e2e-auth-jwt");
    client.initialize().unwrap();

    let mut trace = TestTrace::new("e2e-auth-jwt");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let exp_ok = i64::try_from(now + 10 * 60).unwrap();
    let token_ok = encode(
        &Header::new(Algorithm::HS256),
        &json!({
            "sub": "user123",
            "scope": "read write",
            "exp": exp_ok,
        }),
        &EncodingKey::from_secret(signing_bytes),
    )
    .unwrap();

    // Unauthorized tools/list.
    let params = json!({ "cursor": null });
    let corr = trace.log_request("tools/list", Some(&params));
    let err = client.send_request_json("tools/list", params).unwrap_err();
    trace.log_response(
        &corr,
        None::<&serde_json::Value>,
        Some(&json!({"error": err.message})),
    );
    assert_eq!(err.code, McpErrorCode::ResourceForbidden);

    // Expired token should be rejected.
    let exp_expired = i64::try_from(now.saturating_sub(60)).unwrap();
    let token_expired = encode(
        &Header::new(Algorithm::HS256),
        &json!({
            "sub": "user123",
            "scope": "read write",
            "exp": exp_expired,
        }),
        &EncodingKey::from_secret(signing_bytes),
    )
    .unwrap();
    let params = json!({ "cursor": null, "auth": format!("Bearer {token_expired}") });
    let corr = trace.log_request("tools/list(expired)", Some(&params));
    let err = client.send_request_json("tools/list", params).unwrap_err();
    trace.log_response(
        &corr,
        None::<&serde_json::Value>,
        Some(&json!({"error": err.message})),
    );
    assert_eq!(err.code, McpErrorCode::ResourceForbidden);

    // Invalid signature should be rejected.
    let token_bad_sig = encode(
        &Header::new(Algorithm::HS256),
        &json!({
            "sub": "user123",
            "scope": "read write",
            "exp": exp_ok,
        }),
        &EncodingKey::from_secret(b"wrong-secret"),
    )
    .unwrap();
    let params = json!({ "cursor": null, "auth": format!("Bearer {token_bad_sig}") });
    let corr = trace.log_request("tools/list(bad_sig)", Some(&params));
    let err = client.send_request_json("tools/list", params).unwrap_err();
    trace.log_response(
        &corr,
        None::<&serde_json::Value>,
        Some(&json!({"error": err.message})),
    );
    assert_eq!(err.code, McpErrorCode::ResourceForbidden);

    // Authorized tools/call.
    let params = json!({
        "name": "greeting",
        "arguments": { "name": "Linus" },
        "auth": format!("Bearer {token_ok}"),
    });
    let corr = trace.log_request("tools/call", Some(&params));
    let value = client.send_request_json("tools/call", params).unwrap();
    trace.log_response(&corr, Some(&value), None::<&serde_json::Value>);

    let call: fastmcp_protocol::CallToolResult = serde_json::from_value(value).unwrap();
    assert!(!call.is_error);
    assert!(
        matches!(call.content.first(), Some(Content::Text { .. })),
        "expected text content"
    );
    let Some(Content::Text { text }) = call.content.first() else {
        return;
    };
    assert_eq!(text, "Hello, Linus!");

    // Verify claims extracted to auth context.
    let params = json!({
        "name": "auth_info",
        "arguments": {},
        "auth": format!("Bearer {token_ok}"),
    });
    let corr = trace.log_request("tools/call(auth_info)", Some(&params));
    let value = client.send_request_json("tools/call", params).unwrap();
    trace.log_response(&corr, Some(&value), None::<&serde_json::Value>);

    let call: fastmcp_protocol::CallToolResult = serde_json::from_value(value).unwrap();
    assert!(
        matches!(call.content.first(), Some(Content::Text { .. })),
        "expected text content"
    );
    let Some(Content::Text { text }) = call.content.first() else {
        return;
    };
    let auth_json: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(
        auth_json.get("subject").and_then(|v| v.as_str()),
        Some("user123")
    );
    let scopes = auth_json
        .get("scopes")
        .and_then(|v| v.as_array())
        .expect("scopes array");
    let scopes: Vec<_> = scopes.iter().filter_map(|v| v.as_str()).collect();
    assert!(scopes.contains(&"read"));
    assert!(scopes.contains(&"write"));
}

#[test]
fn e2e_auth_oauth_token_verifier_revocation_and_refresh() {
    use fastmcp_rust::oauth::{
        AuthorizationRequest, CodeChallengeMethod, OAuthClient, OAuthServer, OAuthServerConfig,
        TokenRequest,
    };

    let oauth = Arc::new(OAuthServer::new(OAuthServerConfig::default()));
    let client_def = OAuthClient::builder("test-client")
        .redirect_uri("http://localhost:3000/callback")
        .scope("read")
        .build()
        .unwrap();
    oauth.register_client(client_def).unwrap();

    // OAuth 2.1 requires PKCE. Use the plain method for a fully deterministic test.
    let code_verifier = "verifier-verifier-verifier-verifier-verifier-verifier-123";
    let auth_request = AuthorizationRequest {
        response_type: "code".to_string(),
        client_id: "test-client".to_string(),
        redirect_uri: "http://localhost:3000/callback".to_string(),
        scopes: vec!["read".to_string()],
        state: None,
        code_challenge: code_verifier.to_string(),
        code_challenge_method: CodeChallengeMethod::Plain,
    };
    let (code, _redirect) = oauth
        .authorize(&auth_request, Some("user123".to_string()))
        .unwrap();

    let token_response = oauth
        .token(&TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code),
            redirect_uri: Some("http://localhost:3000/callback".to_string()),
            client_id: "test-client".to_string(),
            client_secret: None,
            code_verifier: Some(code_verifier.to_string()),
            refresh_token: None,
            scopes: None,
        })
        .unwrap();

    let access = token_response.access_token.clone();
    let refresh = token_response.refresh_token.clone().expect("refresh token");

    let provider = TokenAuthProvider::new(oauth.token_verifier());
    let mut mcp_client = setup_auth_server_and_client(provider, "e2e-auth-oauth");
    mcp_client.initialize().unwrap();

    let mut trace = TestTrace::new("e2e-auth-oauth");

    // Access token allows request.
    let params = json!({
        "name": "greeting",
        "arguments": { "name": "Grace" },
        "auth": format!("Bearer {access}"),
    });
    let corr = trace.log_request("tools/call", Some(&params));
    let value = mcp_client.send_request_json("tools/call", params).unwrap();
    trace.log_response(&corr, Some(&value), None::<&serde_json::Value>);
    let call: fastmcp_protocol::CallToolResult = serde_json::from_value(value).unwrap();
    assert!(!call.is_error);

    // Verify auth context propagated from OAuth subject/scopes.
    let params = json!({
        "name": "auth_info",
        "arguments": {},
        "auth": format!("Bearer {access}"),
    });
    let corr = trace.log_request("tools/call(auth_info)", Some(&params));
    let value = mcp_client.send_request_json("tools/call", params).unwrap();
    trace.log_response(&corr, Some(&value), None::<&serde_json::Value>);
    let call: fastmcp_protocol::CallToolResult = serde_json::from_value(value).unwrap();
    assert!(
        matches!(call.content.first(), Some(Content::Text { .. })),
        "expected text content"
    );
    let Some(Content::Text { text }) = call.content.first() else {
        return;
    };
    let auth_json: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(
        auth_json.get("subject").and_then(|v| v.as_str()),
        Some("user123")
    );

    // Revoke access token: request should now be forbidden.
    oauth.revoke(&access, "test-client", None).unwrap();
    let params = json!({ "cursor": null, "auth": format!("Bearer {access}") });
    let corr = trace.log_request("tools/list(revoked)", Some(&params));
    let err = mcp_client
        .send_request_json("tools/list", params)
        .unwrap_err();
    trace.log_response(
        &corr,
        None::<&serde_json::Value>,
        Some(&json!({"error": err.message})),
    );
    assert_eq!(err.code, McpErrorCode::ResourceForbidden);

    // Refresh: new access token should be accepted.
    let refreshed = oauth
        .token(&TokenRequest {
            grant_type: "refresh_token".to_string(),
            code: None,
            redirect_uri: None,
            client_id: "test-client".to_string(),
            client_secret: None,
            code_verifier: None,
            refresh_token: Some(refresh),
            scopes: None,
        })
        .unwrap();

    let new_access = refreshed.access_token;
    let params = json!({
        "name": "greeting",
        "arguments": { "name": "Grace" },
        "auth": format!("Bearer {new_access}"),
    });
    let corr = trace.log_request("tools/call(refreshed)", Some(&params));
    let value = mcp_client.send_request_json("tools/call", params).unwrap();
    trace.log_response(&corr, Some(&value), None::<&serde_json::Value>);
    let call: fastmcp_protocol::CallToolResult = serde_json::from_value(value).unwrap();
    assert!(!call.is_error);
}

// ============================================================================
// Tool listing tests
// ============================================================================

#[test]
fn e2e_list_tools() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let tools = client.list_tools().unwrap();
    assert_eq!(tools.len(), 3, "Expected 3 tools, got {}", tools.len());

    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"greeting"), "Missing greeting tool");
    assert!(names.contains(&"calculator"), "Missing calculator tool");
    assert!(names.contains(&"error_tool"), "Missing error_tool");
}

#[test]
fn e2e_list_tools_returns_definitions() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let tools = client.list_tools().unwrap();
    let greeting = tools.iter().find(|t| t.name == "greeting").unwrap();

    assert_eq!(
        greeting.description.as_deref(),
        Some("Returns a greeting for the given name")
    );
    assert!(greeting.input_schema.get("properties").is_some());
    assert_eq!(greeting.version.as_deref(), Some("1.0.0"));
}

// ============================================================================
// Tool invocation tests
// ============================================================================

#[test]
fn e2e_call_tool_greeting() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let result = client
        .call_tool("greeting", json!({"name": "Alice"}))
        .unwrap();
    assert_eq!(result.len(), 1);

    assert!(
        matches!(result.first(), Some(Content::Text { .. })),
        "expected text content"
    );
    let Some(Content::Text { text }) = result.first() else {
        return;
    };
    assert_eq!(text, "Hello, Alice!");
}

#[test]
fn e2e_call_tool_calculator_add() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let result = client
        .call_tool("calculator", json!({"a": 10, "b": 20, "operation": "add"}))
        .unwrap();
    assert_eq!(result.len(), 1);

    assert!(
        matches!(result.first(), Some(Content::Text { .. })),
        "expected text content"
    );
    let Some(Content::Text { text }) = result.first() else {
        return;
    };
    assert_eq!(text, "30");
}

#[test]
fn e2e_call_tool_calculator_multiply() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let result = client
        .call_tool(
            "calculator",
            json!({"a": 7, "b": 6, "operation": "multiply"}),
        )
        .unwrap();

    assert!(
        matches!(result.first(), Some(Content::Text { .. })),
        "expected text content"
    );
    let Some(Content::Text { text }) = result.first() else {
        return;
    };
    assert_eq!(text, "42");
}

#[test]
fn e2e_call_tool_calculator_divide() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let result = client
        .call_tool(
            "calculator",
            json!({"a": 100, "b": 4, "operation": "divide"}),
        )
        .unwrap();

    assert!(
        matches!(result.first(), Some(Content::Text { .. })),
        "expected text content"
    );
    let Some(Content::Text { text }) = result.first() else {
        return;
    };
    assert_eq!(text, "25");
}

#[test]
fn e2e_call_tool_error_handler() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let result = client.call_tool("error_tool", json!({}));
    assert!(result.is_err(), "Error tool should return an error");
}

#[test]
fn e2e_call_tool_division_by_zero() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let result = client.call_tool(
        "calculator",
        json!({"a": 10, "b": 0, "operation": "divide"}),
    );
    assert!(result.is_err(), "Division by zero should return an error");
}

#[test]
fn e2e_call_unknown_tool() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let result = client.call_tool("nonexistent_tool", json!({}));
    assert!(result.is_err(), "Unknown tool should return an error");
}

// ============================================================================
// Resource listing and reading tests
// ============================================================================

#[test]
fn e2e_list_resources() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let resources = client.list_resources().unwrap();
    assert_eq!(
        resources.len(),
        2,
        "Expected 2 resources, got {}",
        resources.len()
    );

    let uris: Vec<&str> = resources.iter().map(|r| r.uri.as_str()).collect();
    assert!(
        uris.contains(&"file:///test/sample.txt"),
        "Missing text file resource"
    );
    assert!(
        uris.contains(&"file:///config/settings.json"),
        "Missing config resource"
    );
}

#[test]
fn e2e_list_resources_returns_metadata() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let resources = client.list_resources().unwrap();
    let text_file = resources.iter().find(|r| r.name == "sample.txt").unwrap();

    assert_eq!(text_file.mime_type.as_deref(), Some("text/plain"));
    assert_eq!(text_file.description.as_deref(), Some("A sample text file"));
}

#[test]
fn e2e_read_text_resource() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let contents = client.read_resource("file:///test/sample.txt").unwrap();
    assert_eq!(contents.len(), 1);
    assert_eq!(contents[0].uri, "file:///test/sample.txt");
    assert_eq!(contents[0].mime_type.as_deref(), Some("text/plain"));
    assert!(
        contents[0].text.as_ref().unwrap().contains("Hello, World!"),
        "Text content should contain greeting"
    );
}

#[test]
fn e2e_read_json_resource() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let contents = client
        .read_resource("file:///config/settings.json")
        .unwrap();
    assert_eq!(contents.len(), 1);
    assert_eq!(contents[0].mime_type.as_deref(), Some("application/json"));

    // Parse the JSON content to verify structure
    let json_text = contents[0].text.as_ref().unwrap();
    let config: serde_json::Value = serde_json::from_str(json_text).unwrap();
    assert_eq!(config.get("version").unwrap(), "1.0.0");
    assert_eq!(config.get("max_connections").unwrap(), 100);
}

#[test]
fn e2e_read_unknown_resource() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let result = client.read_resource("file:///nonexistent");
    assert!(
        result.is_err(),
        "Reading unknown resource should return an error"
    );
}

// ============================================================================
// Prompt listing and retrieval tests
// ============================================================================

#[test]
fn e2e_list_prompts() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let prompts = client.list_prompts().unwrap();
    assert_eq!(
        prompts.len(),
        2,
        "Expected 2 prompts, got {}",
        prompts.len()
    );

    let names: Vec<&str> = prompts.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"greeting"), "Missing greeting prompt");
    assert!(names.contains(&"code_review"), "Missing code_review prompt");
}

#[test]
fn e2e_list_prompts_returns_arguments() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let prompts = client.list_prompts().unwrap();
    let greeting = prompts.iter().find(|p| p.name == "greeting").unwrap();

    assert_eq!(greeting.arguments.len(), 1);
    assert_eq!(greeting.arguments[0].name, "name");
    assert!(greeting.arguments[0].required);
}

#[test]
fn e2e_get_prompt_greeting() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let mut args = HashMap::new();
    args.insert("name".to_string(), "Bob".to_string());

    let messages = client.get_prompt("greeting", args).unwrap();
    assert_eq!(messages.len(), 1);

    let Some(first) = messages.first() else {
        return;
    };
    assert!(
        matches!(&first.content, Content::Text { .. }),
        "expected text content"
    );
    let Content::Text { text } = &first.content else {
        return;
    };
    assert!(
        text.contains("Bob"),
        "Greeting should contain the name, got: {text}"
    );
}

#[test]
fn e2e_get_prompt_code_review() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let mut args = HashMap::new();
    args.insert("code".to_string(), "fn main() {}".to_string());
    args.insert("language".to_string(), "rust".to_string());

    let messages = client.get_prompt("code_review", args).unwrap();
    assert_eq!(messages.len(), 2, "Expected 2 messages (user + assistant)");

    // First message should be user with the code
    assert!(matches!(messages[0].role, Role::User));
    let Some(first) = messages.first() else {
        return;
    };
    assert!(
        matches!(&first.content, Content::Text { .. }),
        "expected text content"
    );
    let Content::Text { text } = &first.content else {
        return;
    };
    assert!(text.contains("rust"), "Should mention language");
    assert!(text.contains("fn main()"), "Should contain the code");

    // Second message should be assistant
    assert!(matches!(messages[1].role, Role::Assistant));
}

#[test]
fn e2e_get_unknown_prompt() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let result = client.get_prompt("nonexistent_prompt", HashMap::new());
    assert!(
        result.is_err(),
        "Getting unknown prompt should return an error"
    );
}

// ============================================================================
// Pre-initialization error tests
// ============================================================================

#[test]
fn e2e_call_before_initialize() {
    let mut client = setup_test_server_and_client();
    // Don't call initialize()

    let result = client.list_tools();
    assert!(
        result.is_err(),
        "Operations before initialization should fail"
    );
}

// ============================================================================
// Raw request tests (JSON-RPC compliance)
// ============================================================================

#[test]
fn e2e_raw_request_unknown_method() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    let result = client.send_raw_request("nonexistent/method", json!({}));
    assert!(result.is_err(), "Unknown method should return an error");
}

// ============================================================================
// Multiple sequential operations
// ============================================================================

#[test]
fn e2e_full_workflow() {
    let mut client = setup_test_server_and_client();

    // Step 1: Initialize
    let init = client.initialize().unwrap();
    assert_eq!(init.server_info.name, "e2e-test-server");

    // Step 2: List tools
    let tools = client.list_tools().unwrap();
    assert_eq!(tools.len(), 3);

    // Step 3: Call a tool
    let greeting = client
        .call_tool("greeting", json!({"name": "E2E"}))
        .unwrap();
    assert!(
        matches!(greeting.first(), Some(Content::Text { .. })),
        "expected text content"
    );
    let Some(Content::Text { text }) = greeting.first() else {
        return;
    };
    assert_eq!(text, "Hello, E2E!");

    // Step 4: List resources
    let resources = client.list_resources().unwrap();
    assert_eq!(resources.len(), 2);

    // Step 5: Read a resource
    let content = client.read_resource("file:///test/sample.txt").unwrap();
    assert!(content[0].text.as_ref().unwrap().contains("Hello"));

    // Step 6: List prompts
    let prompts = client.list_prompts().unwrap();
    assert_eq!(prompts.len(), 2);

    // Step 7: Get a prompt
    let mut args = HashMap::new();
    args.insert("name".to_string(), "Test".to_string());
    let messages = client.get_prompt("greeting", args).unwrap();
    assert!(!messages.is_empty());
}

#[test]
fn e2e_multiple_tool_calls() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    // Make several tool calls in sequence
    for i in 0..5 {
        let name = format!("User{i}");
        let result = client.call_tool("greeting", json!({"name": name})).unwrap();
        assert!(
            matches!(result.first(), Some(Content::Text { .. })),
            "expected text content"
        );
        let Some(Content::Text { text }) = result.first() else {
            return;
        };
        assert_eq!(text, &format!("Hello, {name}!"));
    }
}

#[test]
fn e2e_mixed_operations() {
    let mut client = setup_test_server_and_client();
    client.initialize().unwrap();

    // Interleave tool calls, resource reads, and prompt gets
    let tools = client.list_tools().unwrap();
    assert!(!tools.is_empty());

    let result = client
        .call_tool("calculator", json!({"a": 2, "b": 3, "operation": "add"}))
        .unwrap();
    assert!(
        matches!(result.first(), Some(Content::Text { .. })),
        "expected text content"
    );
    let Some(Content::Text { text }) = result.first() else {
        return;
    };
    assert_eq!(text, "5");

    let resources = client.list_resources().unwrap();
    assert!(!resources.is_empty());

    let content = client
        .read_resource("file:///config/settings.json")
        .unwrap();
    assert!(!content.is_empty());

    let prompts = client.list_prompts().unwrap();
    assert!(!prompts.is_empty());

    let mut args = HashMap::new();
    args.insert("name".to_string(), "Mixed".to_string());
    let messages = client.get_prompt("greeting", args).unwrap();
    assert!(!messages.is_empty());

    // Another tool call after all the interleaving
    let result = client
        .call_tool(
            "calculator",
            json!({"a": 10, "b": 5, "operation": "subtract"}),
        )
        .unwrap();
    assert!(
        matches!(result.first(), Some(Content::Text { .. })),
        "expected text content"
    );
    let Some(Content::Text { text }) = result.first() else {
        return;
    };
    assert_eq!(text, "5");
}

// ============================================================================
// Server with minimal configuration
// ============================================================================

#[test]
fn e2e_server_with_tools_only() {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name("tools-only")
        .build_server_builder();

    let server = builder.tool(GreetingToolHandler).build();

    let handle = spawn_thread(move || {
        server.run_transport(server_transport);
    });

    let mut client = TestHarness::new(TestClient::new(client_transport), handle);
    let init = client.initialize().unwrap();

    // Should have tools but not resources or prompts
    assert!(init.capabilities.tools.is_some());
    assert!(init.capabilities.resources.is_none());
    assert!(init.capabilities.prompts.is_none());

    let tools = client.list_tools().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "greeting");
}

#[test]
fn e2e_server_with_resources_only() {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name("resources-only")
        .build_server_builder();

    let server = builder.resource(TextFileResourceHandlerResource).build();

    let handle = spawn_thread(move || {
        server.run_transport(server_transport);
    });

    let mut client = TestHarness::new(TestClient::new(client_transport), handle);
    let init = client.initialize().unwrap();

    assert!(init.capabilities.tools.is_none());
    assert!(init.capabilities.resources.is_some());
    assert!(init.capabilities.prompts.is_none());

    let resources = client.list_resources().unwrap();
    assert_eq!(resources.len(), 1);
}

#[test]
fn e2e_server_with_prompts_only() {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name("prompts-only")
        .build_server_builder();

    let server = builder.prompt(GreetingPromptHandlerPrompt).build();

    let handle = spawn_thread(move || {
        server.run_transport(server_transport);
    });

    let mut client = TestHarness::new(TestClient::new(client_transport), handle);
    let init = client.initialize().unwrap();

    assert!(init.capabilities.tools.is_none());
    assert!(init.capabilities.resources.is_none());
    assert!(init.capabilities.prompts.is_some());

    let prompts = client.list_prompts().unwrap();
    assert_eq!(prompts.len(), 1);
}

#[test]
fn e2e_empty_server() {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name("empty-server")
        .build_server_builder();

    let server = builder.build();

    let handle = spawn_thread(move || {
        server.run_transport(server_transport);
    });

    let mut client = TestHarness::new(TestClient::new(client_transport), handle);
    let init = client.initialize().unwrap();

    // Empty server should not advertise any capabilities
    assert!(init.capabilities.tools.is_none());
    assert!(init.capabilities.resources.is_none());
    assert!(init.capabilities.prompts.is_none());
}

// ============================================================================
// Custom client info
// ============================================================================

#[test]
fn e2e_custom_client_info() {
    let (builder, client_transport, server_transport) =
        TestServer::builder().build_server_builder();

    let server = builder.tool(GreetingToolHandler).build();

    let handle = spawn_thread(move || {
        server.run_transport(server_transport);
    });

    let client = TestClient::new(client_transport).with_client_info("custom-client", "3.0.0");
    let mut client = TestHarness::new(client, handle);

    let init = client.initialize().unwrap();
    // Initialization should succeed with custom client info
    assert!(init.capabilities.tools.is_some());
}
