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
#[cfg(unix)]
use std::time::{Duration, Instant};

use fastmcp_protocol::{LegacyContent, LegacyResourceContent};
use fastmcp_rust::testing::prelude::*;
use fastmcp_rust::{
    AuthContext, CacheScope, CacheTtl, ContentBlock, EmbeddedResourceContents, McpContext,
    McpErrorCode, McpResult, PromptMessage, Role, StaticTokenVerifier, TokenAuthProvider,
};
#[cfg(unix)]
use fastmcp_rust::{
    Client, Cx, ProtocolEra, ProtocolPolicy, RequestTimeoutPolicy, auto, legacy_2024, modern,
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

    let payload = json!({
        "subject": auth.subject,
        "scopes": auth.scopes,
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
        .expect("valid verifier configuration")
        .with_allowed_schemes(["Bearer"])
        .expect("valid scheme configuration");
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
        matches!(call.content.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = call.content.first() else {
        return;
    };
    assert_eq!(text, "Hello, Ada!");

    // Verify handlers receive verified identity facts, never the raw token.
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
        matches!(call.content.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = call.content.first() else {
        return;
    };
    let auth_json: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(
        auth_json.get("subject").and_then(|v| v.as_str()),
        Some("user-1")
    );
    assert!(auth_json.get("token").is_none());
    assert!(!text.contains("good-token"));
}

// FND-01: JWT e2e removed — undeclared cfg(feature="jwt") is fatal under -D warnings,
// and production JWT is not a facade/server feature (FACADE-NO-JSONWEBTOKEN).

#[test]
fn e2e_auth_oauth_token_verifier_revocation_and_refresh() {
    use fastmcp_rust::oauth::{
        AuthorizationApprovalBackend, AuthorizationApprovalDisposition,
        AuthorizationApprovalGeneration, AuthorizationApprovalRequest, AuthorizationRequest,
        CodeChallengeMethod, OAuthClient, OAuthServer, OAuthServerConfig, TokenRequest,
    };

    const CLIENT_SECRET: &str = "e2e-approval-client-secret-canary";
    struct E2eApprovalBackend(std::sync::Mutex<Option<String>>);
    impl AuthorizationApprovalBackend for E2eApprovalBackend {
        fn generation(&self) -> AuthorizationApprovalGeneration {
            AuthorizationApprovalGeneration::from_bytes([0xE2; 32])
        }

        fn approve(
            &self,
            request: &AuthorizationApprovalRequest,
        ) -> AuthorizationApprovalDisposition {
            *self.0.lock().expect("approval observation") = Some(format!("{request:?}"));
            AuthorizationApprovalDisposition::Approved(
                request
                    .approve(
                        "user123".to_string(),
                        request.scopes().to_vec(),
                        request.resource().map(str::to_string),
                        self.generation(),
                    )
                    .expect("validated approval request"),
            )
        }
    }

    let approval = Arc::new(E2eApprovalBackend(std::sync::Mutex::new(None)));
    let approval_backend: Arc<dyn AuthorizationApprovalBackend> = approval.clone();
    let oauth = Arc::new(OAuthServer::with_approval_backend(
        OAuthServerConfig::default(),
        approval_backend,
    ));
    let client_def = OAuthClient::builder("test-client")
        .secret(CLIENT_SECRET)
        .redirect_uri("http://127.0.0.1:3000/callback")
        .scope("read")
        .build()
        .unwrap();
    oauth.register_client(client_def).unwrap();

    // RFC 7636 Appendix B verifier/challenge pair.
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let auth_request = AuthorizationRequest {
        response_type: "code".to_string(),
        client_id: "test-client".to_string(),
        redirect_uri: "http://127.0.0.1:3000/callback".to_string(),
        scopes: vec!["read".to_string()],
        resource: None,
        state: None,
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
        code_challenge_method: CodeChallengeMethod::S256,
    };
    let (code, _redirect) = oauth.authorize(&auth_request).unwrap();
    let approval_debug = approval
        .0
        .lock()
        .expect("approval observation")
        .clone()
        .expect("approval backend called");
    assert!(!approval_debug.contains(CLIENT_SECRET));
    assert!(!approval_debug.contains(&code));

    let token_response = oauth
        .token(&TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code),
            redirect_uri: Some("http://127.0.0.1:3000/callback".to_string()),
            client_id: "test-client".to_string(),
            client_secret: Some(CLIENT_SECRET.to_string()),
            code_verifier: Some(code_verifier.to_string()),
            refresh_token: None,
            scopes: None,
            resource: None,
        })
        .unwrap();

    assert!(!approval_debug.contains(&token_response.access_token));
    assert!(
        !approval_debug.contains(
            token_response
                .refresh_token
                .as_deref()
                .expect("refresh token")
        )
    );

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
        matches!(call.content.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = call.content.first() else {
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
            resource: None,
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
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
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
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
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
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
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
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
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
    let LegacyResourceContent::Text {
        uri,
        mime_type,
        text,
        ..
    } = &contents[0]
    else {
        panic!("text resource must use exact legacy text resource content");
    };
    assert_eq!(uri, "file:///test/sample.txt");
    assert_eq!(mime_type.as_deref(), Some("text/plain"));
    assert!(
        text.contains("Hello, World!"),
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
    let LegacyResourceContent::Text {
        mime_type, text, ..
    } = &contents[0]
    else {
        panic!("JSON resource must use exact legacy text resource content");
    };
    assert_eq!(mime_type.as_deref(), Some("application/json"));

    // Parse the JSON content to verify structure
    let config: serde_json::Value = serde_json::from_str(text).unwrap();
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
        matches!(&first.content, LegacyContent::Text { .. }),
        "expected text content"
    );
    let LegacyContent::Text { text, .. } = &first.content else {
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
        matches!(&first.content, LegacyContent::Text { .. }),
        "expected text content"
    );
    let LegacyContent::Text { text, .. } = &first.content else {
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
        matches!(greeting.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = greeting.first() else {
        return;
    };
    assert_eq!(text, "Hello, E2E!");

    // Step 4: List resources
    let resources = client.list_resources().unwrap();
    assert_eq!(resources.len(), 2);

    // Step 5: Read a resource
    let content = client.read_resource("file:///test/sample.txt").unwrap();
    assert!(matches!(
        content.first(),
        Some(LegacyResourceContent::Text { text, .. }) if text.contains("Hello")
    ));

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
            matches!(result.first(), Some(LegacyContent::Text { .. })),
            "expected text content"
        );
        let Some(LegacyContent::Text { text, .. }) = result.first() else {
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
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
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
        matches!(result.first(), Some(LegacyContent::Text { .. })),
        "expected text content"
    );
    let Some(LegacyContent::Text { text, .. }) = result.first() else {
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

// ============================================================================
// Public facade dual-era stdio negotiation
// ============================================================================

#[cfg(unix)]
fn shipped_echo_server_executable() -> &'static str {
    env!("CARGO_BIN_EXE_echo_server")
}

#[cfg(unix)]
fn connect_auto_stdio_to_shipped_echo_server(server_policy: &str) -> Client {
    let command = shipped_echo_server_executable();
    let builder = auto::client_builder().env("FASTMCP_PROTOCOL_POLICY", server_policy);
    assert_eq!(
        builder.selected_protocol_plan().policy(),
        ProtocolPolicy::Auto
    );

    let cx = Cx::for_request();
    builder
        .connect_stdio_with_cx(command, &[], &cx)
        .expect("the public Auto facade client connects to the shipped stdio example")
}

#[cfg(unix)]
fn connect_modern_stdio_to_shipped_echo_server(server_policy: &str) -> McpResult<modern::Client> {
    let command = shipped_echo_server_executable();
    let builder = modern::client_builder().env("FASTMCP_PROTOCOL_POLICY", server_policy);

    builder.connect_stdio_with_cx(command, &[], &Cx::for_request())
}

#[cfg(unix)]
const STDIO_COMPLETION_IDLE_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(unix)]
const STDIO_COMPLETION_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(4);
#[cfg(unix)]
const STDIO_COMPLETION_CLEANUP_BOUND: Duration = Duration::from_secs(4);

#[cfg(unix)]
fn connect_bounded_modern_stdio_to_shipped_echo_server(
    server_policy: &str,
) -> McpResult<modern::Client> {
    let command = shipped_echo_server_executable();
    modern::client_builder()
        .env("FASTMCP_PROTOCOL_POLICY", server_policy)
        .request_timeout_policy(
            RequestTimeoutPolicy::new(
                STDIO_COMPLETION_IDLE_TIMEOUT,
                STDIO_COMPLETION_ABSOLUTE_TIMEOUT,
            )
            .expect("the public completion timeout policy is valid"),
        )
        .connect_stdio_with_cx(command, &[], &Cx::for_request())
}

#[cfg(unix)]
fn stdio_mrtr_capabilities(
    sampling: bool,
    roots: bool,
    form: bool,
    url: bool,
) -> modern::ClientCapabilities {
    let mut capabilities = modern::ClientCapabilities::default();
    if sampling {
        capabilities.sampling = Some(Default::default());
    }
    if roots {
        capabilities.roots = serde_json::from_value(json!({})).expect("roots capability is valid");
    }
    if form || url {
        let mut elicitation = json!({});
        if form {
            elicitation["form"] = json!({});
        }
        if url {
            elicitation["url"] = json!({});
        }
        capabilities.elicitation =
            serde_json::from_value(elicitation).expect("elicitation capability is valid");
    }
    capabilities
}

#[cfg(unix)]
fn connect_bounded_modern_stdio_with_mrtr(
    server_policy: &str,
    capabilities: modern::ClientCapabilities,
    handlers: modern::ReverseRequestHandlers,
) -> McpResult<modern::Client> {
    let command = shipped_echo_server_executable();
    modern::client_builder()
        .env("FASTMCP_PROTOCOL_POLICY", server_policy)
        .request_timeout_policy(
            RequestTimeoutPolicy::new(
                STDIO_COMPLETION_IDLE_TIMEOUT,
                STDIO_COMPLETION_ABSOLUTE_TIMEOUT,
            )
            .expect("the public completion timeout policy is valid"),
        )
        .capabilities(capabilities)
        .modern_reverse_request_handlers(handlers)
        .connect_stdio_with_cx(command, &[], &Cx::for_request())
}

#[cfg(unix)]
fn assert_stdio_input_required(result: &modern::InputRequiredResult, key: &str, kind: &str) {
    assert!(
        result.request_state().is_some(),
        "{kind} must return framework-issued requestState"
    );
    assert!(
        result
            .input_requests()
            .is_some_and(|requests| requests.get(key).is_some()),
        "{kind} must retain its {key} input request"
    );
}

#[cfg(unix)]
fn assert_stdio_capability_gate(result: &modern::FinalCoreResult, kind: &str) {
    let modern::FinalCoreResult::ToolsCall { result, .. } = result else {
        panic!("{kind} missing capability must fail closed as a tool error: {result:?}");
    };
    assert!(
        result.payload.is_error,
        "{kind} missing capability must fail closed: {result:?}"
    );
    assert!(
        result.payload.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text.contains("not advertised by the client"),
            _ => false,
        }),
        "{kind} missing capability must name the capability gate: {result:?}"
    );
}

#[cfg(unix)]
fn connect_legacy_stdio_to_shipped_echo_server(
    server_policy: &str,
) -> McpResult<legacy_2024::Client> {
    connect_legacy_stdio_to_shipped_echo_server_with_reverse_handlers(
        server_policy,
        legacy_2024::LegacyReverseRequestHandlers::new(),
    )
}

#[cfg(unix)]
fn connect_legacy_stdio_to_shipped_echo_server_with_reverse_handlers(
    server_policy: &str,
    handlers: legacy_2024::LegacyReverseRequestHandlers,
) -> McpResult<legacy_2024::Client> {
    let command = shipped_echo_server_executable();
    let builder = legacy_2024::client_builder()
        .env("FASTMCP_PROTOCOL_POLICY", server_policy)
        .reverse_request_handlers(handlers);
    assert_eq!(
        builder.protocol_policy(),
        legacy_2024::ProtocolPolicy::LegacyOnly
    );

    builder.connect_stdio_with_cx(command, &[], &Cx::for_request())
}

#[cfg(unix)]
fn selected_modern_stdio_raw_result(
    client: &mut Client,
    method: &str,
    parameters: serde_json::Value,
) -> serde_json::Value {
    let cx = Cx::for_request();
    let mut request = client
        .start_multiplexed_request(&cx, method, Some(parameters))
        .expect("the selected modern public facade commits the raw MRTR request");
    let response = client
        .wait_multiplexed_request(&cx, &mut request)
        .expect("the selected modern public facade receives the raw MRTR response");
    assert!(response.error.is_none(), "the raw MRTR request succeeds");
    response
        .result
        .expect("a successful raw MRTR response carries its exact result")
}

#[cfg(unix)]
fn selected_modern_stdio_raw_error(
    client: &mut Client,
    method: &str,
    parameters: serde_json::Value,
) -> String {
    let cx = Cx::for_request();
    let mut request = client
        .start_multiplexed_request(&cx, method, Some(parameters))
        .expect("the selected modern public facade commits the negative MRTR request");
    client
        .wait_multiplexed_request(&cx, &mut request)
        .expect_err("the rejected MRTR retry surfaces as the public wait error")
        .message
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_auto_selects_modern_on_the_shipped_facade_server() {
    let mut client = connect_auto_stdio_to_shipped_echo_server("auto");

    assert_eq!(client.protocol_policy(), ProtocolPolicy::Auto);
    assert_eq!(
        client.selected_protocol_era(),
        Some(ProtocolEra::Modern2026),
        "the real Auto server must retain the successful modern discovery selection"
    );
    assert_eq!(
        client.protocol_version(),
        fastmcp_rust::modern::PROTOCOL_VERSION
    );
    assert_eq!(client.server_info().name, "echo-server");
    assert!(
        client.server_discovery().is_some(),
        "a modern selection retains its public discovery observable"
    );
    let tools = client
        .list_tools()
        .expect("the selected modern stdio client accepts tools/list");
    assert!(
        tools.iter().any(|tool| tool.name == "echo"),
        "the modern tools/list result must expose the shipped echo tool"
    );
    client.close().expect("modern stdio client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_auto_falls_back_to_exact_legacy_on_the_shipped_facade_server() {
    let mut client = connect_auto_stdio_to_shipped_echo_server("legacy-only");

    assert_eq!(client.protocol_policy(), ProtocolPolicy::Auto);
    assert_eq!(
        client.selected_protocol_era(),
        Some(ProtocolEra::Legacy2024),
        "the real legacy-only server must make Auto reopen its fresh exact-legacy stdio session"
    );
    assert_eq!(
        client.protocol_version(),
        fastmcp_rust::legacy_2024::PROTOCOL_VERSION
    );
    assert_eq!(client.server_info().name, "echo-server");
    assert!(
        client.server_discovery().is_none(),
        "an exact legacy session cannot inherit modern discovery state"
    );
    client
        .ping()
        .expect("the selected exact-legacy stdio client remains usable");
    client.close().expect("legacy stdio client cleanup");
}

#[cfg(unix)]
fn assert_public_auto_stdio_multiplexes(server_policy: &str, expected_era: ProtocolEra) {
    let mut client = connect_auto_stdio_to_shipped_echo_server(server_policy);
    assert_eq!(client.protocol_policy(), ProtocolPolicy::Auto);
    assert_eq!(client.selected_protocol_era(), Some(expected_era));

    let executor = client
        .multiplexed_stdio_executor()
        .expect("the selected public stdio session installs its shared executor");
    assert_eq!(executor.selected_protocol_era(), expected_era);
    let cx = Cx::for_request();
    // Both sends occur before either wait. The real subprocess therefore sees
    // two committed request owners on the selected final child, rather than a
    // tautological sequence of one request followed by one response.
    let mut first = client
        .start_multiplexed_request(&cx, "ping", Some(json!({})))
        .expect("first selected-era ping commits");
    let mut second = client
        .start_multiplexed_request(&cx, "ping", Some(json!({})))
        .expect("second selected-era ping commits before the first wait");
    assert_ne!(first.request_id(), second.request_id());

    // The sequential adapter must drive this same ingress/correlation path.
    // Its response wait sees and preserves both earlier multiplexed owners
    // before consuming its own real subprocess response.
    client
        .ping()
        .expect("the sequential adapter cannot consume either multiplexed response");

    let first_response = client
        .wait_multiplexed_request(&cx, &mut first)
        .expect("first committed request receives its own final response");
    let second_response = client
        .wait_multiplexed_request(&cx, &mut second)
        .expect("second committed request receives its own final response");
    assert_eq!(first_response.id.as_ref(), Some(first.request_id()));
    assert_eq!(second_response.id.as_ref(), Some(second.request_id()));
    assert!(first_response.error.is_none());
    assert!(second_response.error.is_none());
    drop(executor);
    client.close().expect("multiplexed stdio client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_auto_modern_selection_multiplexes_two_committed_requests() {
    assert_public_auto_stdio_multiplexes("auto", ProtocolEra::Modern2026);
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_auto_legacy_fallback_multiplexes_two_committed_requests() {
    // The paired positive differs only in the real child's era policy. Auto
    // must tear down its modern probe, establish a fresh exact-2024 child,
    // then install the same shared executor on that final connection.
    assert_public_auto_stdio_multiplexes("legacy-only", ProtocolEra::Legacy2024);
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_only_round_trips_with_the_shipped_facade_server() {
    let mut client = connect_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    assert_eq!(
        client.protocol_version(),
        fastmcp_rust::modern::PROTOCOL_VERSION
    );
    let tools = client
        .list_tools(None)
        .expect("the explicit ModernOnly connection accepts tools/list");
    assert!(
        tools.tools.iter().any(|tool| tool.name == "echo"),
        "the modern tools/list result must expose the shipped echo tool"
    );
    client.close().expect("modern-only stdio client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_composes_nested_tool_and_resource() {
    let mut client = connect_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    let composed = client
        .call_tool("compose_echo", json!({"message": "alpha"}))
        .expect("live modern stdio compose_echo must nest echo and info://server");
    assert!(
        composed.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => {
                text.starts_with("compose:alpha|") && text.contains("echo-server")
            }
            _ => false,
        }),
        "compose_echo must retain the nested echo text and server-info resource: {composed:?}"
    );

    let missing_tool = client.call_tool(
        "compose_echo",
        json!({
            "message": "alpha",
            "tool": "stdio-e2e-missing",
        }),
    );
    let missing_tool = match missing_tool {
        Ok(result) if result.is_error => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
        Ok(result) => panic!(
            "changing only the nested tool name must refuse before the peer resource: {result:?}"
        ),
    };
    assert!(
        missing_tool.contains("stdio-e2e-missing")
            || missing_tool.contains("compose-nested-tool")
            || missing_tool.contains("Unknown tool"),
        "the nested unknown tool must stay a handler-visible refusal: {missing_tool}"
    );

    let missing_resource = client.call_tool(
        "compose_echo",
        json!({
            "message": "beta",
            "resource": "info://stdio-e2e-missing",
        }),
    );
    let missing_resource = match missing_resource {
        Ok(result) if result.is_error => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
        Ok(result) => panic!(
            "changing only the nested resource URI must refuse after the peer tool: {result:?}"
        ),
    };
    assert!(
        missing_resource.contains("info://stdio-e2e-missing")
            || missing_resource.contains("compose-nested-resource")
            || missing_resource.contains("not found"),
        "the nested unknown resource must stay a handler-visible refusal: {missing_resource}"
    );

    client
        .close()
        .expect("modern-only stdio compose client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_prompt_composes_nested_tool_and_resource() {
    let mut client = connect_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    let composed = client
        .get_prompt(
            "compose_greeting",
            HashMap::from([
                ("name".to_owned(), "alpha".to_owned()),
                ("tool".to_owned(), "echo".to_owned()),
                ("resource".to_owned(), "info://server".to_owned()),
            ]),
        )
        .expect("live modern stdio compose_greeting must nest echo and info://server");
    assert!(
        composed
            .messages
            .iter()
            .any(|message| match &message.content {
                ContentBlock::Text { text, .. } => {
                    text.starts_with("compose:alpha|") && text.contains("echo-server")
                }
                _ => false,
            }),
        "compose_greeting must retain the nested echo text and server-info resource: {composed:?}"
    );

    let missing_tool = client
        .get_prompt(
            "compose_greeting",
            HashMap::from([
                ("name".to_owned(), "alpha".to_owned()),
                ("tool".to_owned(), "stdio-e2e-missing".to_owned()),
                ("resource".to_owned(), "info://server".to_owned()),
            ]),
        )
        .expect_err("changing only the nested tool name must refuse before the peer resource");
    let missing_tool = format!("{missing_tool:?}");
    assert!(
        missing_tool.contains("stdio-e2e-missing")
            || missing_tool.contains("compose-nested-tool")
            || missing_tool.contains("Unknown tool"),
        "the nested unknown tool must stay a handler-visible refusal: {missing_tool}"
    );

    client
        .close()
        .expect("modern-only stdio prompt compose client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_resource_composes_nested_tool_and_resource() {
    let mut client = connect_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    let composed = client
        .read_resource("info://compose")
        .expect("live modern stdio info://compose must nest echo and info://server");
    assert!(
        composed.contents.iter().any(|content| match content {
            EmbeddedResourceContents::Text { text, .. } => {
                text.starts_with("compose:alpha|") && text.contains("echo-server")
            }
            _ => false,
        }),
        "info://compose must retain the nested echo text and server-info resource: {composed:?}"
    );

    let missing_tool = client
        .read_resource("info://compose-missing-tool")
        .expect_err("changing only the nested tool name must refuse before the peer resource");
    let missing_tool = format!("{missing_tool:?}");
    assert!(
        missing_tool.contains("stdio-e2e-missing")
            || missing_tool.contains("compose-nested-tool")
            || missing_tool.contains("Unknown tool"),
        "the nested unknown tool must stay a handler-visible refusal: {missing_tool}"
    );

    let missing_resource = client
        .read_resource("info://compose-missing-resource")
        .expect_err("changing only the nested resource URI must refuse after the peer tool");
    let missing_resource = format!("{missing_resource:?}");
    assert!(
        missing_resource.contains("info://stdio-e2e-missing")
            || missing_resource.contains("compose-nested-resource")
            || missing_resource.contains("not found"),
        "the nested unknown resource must stay a handler-visible refusal: {missing_resource}"
    );

    client
        .close()
        .expect("modern-only stdio resource compose client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_handler_timeout_refuses_late_tool_and_admits_fast_peer() {
    let mut client = connect_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    let timed_out = client
        .call_tool("slow_echo", json!({}))
        .expect_err("a handler that outlives its timeout must be refused");
    let timed_out = format!("{timed_out:?}");
    assert!(
        timed_out.contains("Request timeout exceeded") || timed_out.contains("RequestCancelled"),
        "the refused late tools/call must keep the handler-timeout error: {timed_out}"
    );

    let fast = client
        .call_tool("fast_echo", json!({}))
        .expect("changing only the tool must still be admitted after a handler timeout");
    assert!(
        fast.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "fast",
            _ => false,
        }),
        "the fast peer tool must still complete: {fast:?}"
    );

    client
        .close()
        .expect("modern-only stdio handler-timeout client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_default_parameter_is_injected_and_overridable() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    let injected = client
        .call_tool("greet", json!({"name": "World"}))
        .expect("omitting the defaulted argument must still be admitted");
    assert!(
        injected.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "greet:World!",
            _ => false,
        }),
        "the generated default must be injected at call time: {injected:?}"
    );

    let overridden = client
        .call_tool("greet", json!({"name": "World", "suffix": "?"}))
        .expect("supplying the defaulted argument must override the generated default");
    assert!(
        overridden.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "greet:World?",
            _ => false,
        }),
        "changing only the suffix must override the generated default: {overridden:?}"
    );

    let missing_name = client.call_tool("greet", json!({"suffix": "!"}));
    let missing_name = match missing_name {
        Ok(result) if result.is_error => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
        Ok(result) => {
            panic!("a missing required generated argument must stay an error: {result:?}")
        }
    };
    assert!(
        missing_name.contains("name")
            || missing_name.contains("required")
            || missing_name.contains("Invalid")
            || missing_name.contains("input schema")
            || missing_name.contains("inputSchema"),
        "omitting only the required sibling must stay a handler-visible refusal: {missing_name}"
    );

    let listed_prompts = client
        .list_prompts(None)
        .expect("live modern stdio must list the default-parameter prompt");
    let compose = listed_prompts
        .prompts
        .iter()
        .find(|prompt| prompt.name == "compose_greeting")
        .expect("compose_greeting must remain on the live catalog");
    let arguments = compose.arguments.as_deref().unwrap_or(&[]);
    assert!(
        arguments
            .iter()
            .any(|argument| { argument.name == "name" && argument.required == Some(true) }),
        "compose_greeting must still require name: {compose:?}"
    );
    assert!(
        arguments
            .iter()
            .any(|argument| { argument.name == "tool" && argument.required != Some(true) }),
        "the defaulted tool argument must not stay required: {compose:?}"
    );

    let injected_prompt = client
        .get_prompt(
            "compose_greeting",
            HashMap::from([("name".to_owned(), "alpha".to_owned())]),
        )
        .expect("omitting defaulted prompt arguments must still compose echo and info://server");
    assert!(
        injected_prompt
            .messages
            .iter()
            .any(|message| match &message.content {
                ContentBlock::Text { text, .. } => {
                    text.starts_with("compose:alpha|") && text.contains("echo-server")
                }
                _ => false,
            }),
        "prompt defaults must inject echo and info://server: {injected_prompt:?}"
    );

    client
        .close()
        .expect("modern-only stdio default-parameter client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_output_schema_retains_structured_content_and_peer_stays_bare() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    let listed = client
        .list_tools(None)
        .expect("live modern stdio must list the output-schema tools");
    let structured = listed
        .tools
        .iter()
        .find(|tool| tool.name == "structured_echo")
        .expect("structured_echo must remain on the live catalog");
    let echo = listed
        .tools
        .iter()
        .find(|tool| tool.name == "echo")
        .expect("the bare echo peer must remain on the live catalog");
    assert_eq!(
        structured
            .output_schema
            .as_ref()
            .and_then(|schema| schema.get("required")),
        Some(&json!(["value"])),
        "tools/list must retain the advertised output schema: {structured:?}"
    );
    assert_eq!(
        echo.output_schema, None,
        "changing only the missing output schema must keep the echo peer bare: {echo:?}"
    );

    let called = client
        .call_tool("structured_echo", json!({"value": "alpha"}))
        .expect("live modern stdio must admit the structured output tool");
    assert!(
        called.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "tool:alpha",
            _ => false,
        }),
        "the structured tool must still author text content: {called:?}"
    );
    assert_eq!(
        called.structured_content,
        Some(json!({"value": "alpha"})),
        "tools/call must retain structuredContent matching the advertised schema: {called:?}"
    );

    let peer = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("the bare echo peer must still be callable");
    assert_eq!(
        peer.structured_content, None,
        "changing only the missing output schema must not invent structuredContent: {peer:?}"
    );

    client
        .close()
        .expect("modern-only stdio output-schema client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_rich_content_retains_image_and_audio_blocks() {
    let mut client = connect_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    let rich = client
        .call_tool("rich_echo", json!({}))
        .expect("live modern stdio must retain image and audio content blocks");
    assert!(
        rich.content.iter().any(|content| match content {
            ContentBlock::Image {
                data, mime_type, ..
            } => data == "e2eimage" && mime_type == "image/png",
            _ => false,
        }),
        "tools/call must retain the authored image block: {rich:?}"
    );
    assert!(
        rich.content.iter().any(|content| match content {
            ContentBlock::Audio {
                data, mime_type, ..
            } => data == "e2eaudio" && mime_type == "audio/wav",
            _ => false,
        }),
        "tools/call must retain the authored audio block: {rich:?}"
    );

    let peer = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("the text-only echo peer must still be callable");
    assert!(
        peer.content
            .iter()
            .all(|content| matches!(content, ContentBlock::Text { .. })),
        "changing only the missing rich content must keep the echo peer text-only: {peer:?}"
    );

    client
        .close()
        .expect("modern-only stdio rich-content client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_progress_marker_is_retained_from_live_echo() {
    let mut client = connect_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    client
        .call_tool("echo", json!({"message": "no-token"}))
        .expect("echo still completes without a progress token");
    assert!(
        client.take_progress_notifications().is_empty(),
        "without a progressToken the shipped echo tool must not emit request-scoped progress"
    );

    let marker = modern::ProgressMarker::from("stdio-progress");
    client
        .call_tool_with_progress_marker("echo", json!({"message": "token"}), marker.clone())
        .expect("a progressToken must not prevent the shipped echo tool from completing");
    let progress = client.take_progress_notifications();
    assert!(
        progress.iter().any(|notification| {
            notification.progress_token == marker
                && notification.message.as_deref() == Some("echoed")
        }),
        "live stdio must retain notifications/progress after a progressToken: {progress:?}"
    );
    assert!(
        client.take_progress_notifications().is_empty(),
        "take_progress_notifications must drain the retained queue"
    );

    client
        .read_resource("info://server")
        .expect("a resources/read without a progress token still completes");
    assert!(
        client.take_progress_notifications().is_empty(),
        "without a progressToken the shipped server_info resource must not emit request-scoped progress"
    );

    let resource_marker = modern::ProgressMarker::from("stdio-resource-progress");
    client
        .read_resource_with_progress_marker("info://server", resource_marker.clone())
        .expect(
            "a progressToken must not prevent the shipped server_info resource from completing",
        );
    let resource_progress = client.take_progress_notifications();
    assert!(
        resource_progress.iter().any(|notification| {
            notification.progress_token == resource_marker
                && notification.message.as_deref() == Some("info")
        }),
        "live stdio must retain resource notifications/progress after a progressToken: {resource_progress:?}"
    );

    let mut greeting_arguments = std::collections::HashMap::new();
    greeting_arguments.insert("name".to_owned(), "no-token".to_owned());
    client
        .get_prompt("greeting", greeting_arguments)
        .expect("a prompts/get without a progress token still completes");
    assert!(
        client.take_progress_notifications().is_empty(),
        "without a progressToken the shipped greeting prompt must not emit request-scoped progress"
    );

    let prompt_marker = modern::ProgressMarker::from("stdio-prompt-progress");
    let mut greeting_with_token = std::collections::HashMap::new();
    greeting_with_token.insert("name".to_owned(), "token".to_owned());
    client
        .get_prompt_with_progress_marker("greeting", greeting_with_token, prompt_marker.clone())
        .expect("a progressToken must not prevent the shipped greeting prompt from completing");
    let prompt_progress = client.take_progress_notifications();
    assert!(
        prompt_progress.iter().any(|notification| {
            notification.progress_token == prompt_marker
                && notification.message.as_deref() == Some("greeted")
        }),
        "live stdio must retain prompt notifications/progress after a progressToken: {prompt_progress:?}"
    );
    assert!(
        client.take_progress_notifications().is_empty(),
        "take_progress_notifications must drain the retained resource and prompt queues"
    );
    client
        .close()
        .expect("modern-only stdio progress client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_resource_updated_is_retained_on_incremental_listen() {
    let mut client = connect_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    client
        .open_subscriptions_listener(modern::SubscriptionFilter {
            resource_subscriptions: Some(vec!["info://server".to_owned()]),
            ..modern::SubscriptionFilter::default()
        })
        .expect("live stdio must admit an incremental subscriptions/listen");

    let cx = Cx::for_request();
    let cancellation = modern::McpRequestCancellation::new();
    let acknowledgement = client
        .next_subscription_event(&cx, &cancellation)
        .expect("subscriptions/listen must emit its acknowledgement");
    assert!(
        matches!(
            acknowledgement,
            modern::StdioSubscriptionEvent::Acknowledged(ref filter)
                if filter.resource_subscriptions.as_deref() == Some(&["info://server".to_owned()][..])
        ),
        "the first incremental listen record must be the accepted filter: {acknowledgement:?}"
    );

    let touched = client
        .call_tool("touch_server_info", json!({}))
        .expect("touching the watched resource must complete");
    assert!(
        touched.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "notified",
            _ => false,
        }),
        "a matching incremental listener must count as notify_resource_updated delivery: {touched:?}"
    );

    let updated = client
        .next_subscription_event(&cx, &cancellation)
        .expect("subscriptions/listen must retain resources/updated after the handler publish");
    assert!(
        matches!(
            updated,
            modern::StdioSubscriptionEvent::Notification(
                modern::ServerNotification::ResourceUpdated(ref params)
            ) if params.uri.as_str() == "info://server"
        ),
        "live stdio must retain notifications/resources/updated on the incremental listener: {updated:?}"
    );
    client
        .close()
        .expect("modern-only stdio subscription client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_tools_list_changed_is_retained_on_incremental_listen() {
    let mut client = connect_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    client
        .open_subscriptions_listener(modern::SubscriptionFilter {
            tools_list_changed: Some(true),
            ..modern::SubscriptionFilter::default()
        })
        .expect("live stdio must admit an incremental subscriptions/listen");

    let cx = Cx::for_request();
    let cancellation = modern::McpRequestCancellation::new();
    let acknowledgement = client
        .next_subscription_event(&cx, &cancellation)
        .expect("subscriptions/listen must emit its acknowledgement");
    assert!(
        matches!(
            acknowledgement,
            modern::StdioSubscriptionEvent::Acknowledged(ref filter)
                if filter.tools_list_changed == Some(true)
        ),
        "the first incremental listen record must be the accepted filter: {acknowledgement:?}"
    );

    let hidden = client
        .call_tool("hide_echo", json!({}))
        .expect("disabling the shipped echo tool must complete");
    assert!(
        hidden.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "hidden",
            _ => false,
        }),
        "stdio session state must let disable_tool publish list_changed: {hidden:?}"
    );

    let changed = client
        .next_subscription_event(&cx, &cancellation)
        .expect("subscriptions/listen must retain tools/list_changed after the handler mutation");
    assert!(
        matches!(
            changed,
            modern::StdioSubscriptionEvent::Notification(
                modern::ServerNotification::ToolsListChanged(_)
            )
        ),
        "live stdio must retain notifications/tools/list_changed on the incremental listener: {changed:?}"
    );
    client
        .close()
        .expect("modern-only stdio list_changed client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_resource_and_prompt_list_changed_are_retained_on_incremental_listen() {
    let mut client = connect_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    client
        .open_subscriptions_listener(modern::SubscriptionFilter {
            resources_list_changed: Some(true),
            prompts_list_changed: Some(true),
            ..modern::SubscriptionFilter::default()
        })
        .expect("live stdio must admit an incremental subscriptions/listen");

    let cx = Cx::for_request();
    let cancellation = modern::McpRequestCancellation::new();
    let acknowledgement = client
        .next_subscription_event(&cx, &cancellation)
        .expect("subscriptions/listen must emit its acknowledgement");
    assert!(
        matches!(
            acknowledgement,
            modern::StdioSubscriptionEvent::Acknowledged(ref filter)
                if filter.resources_list_changed == Some(true)
                    && filter.prompts_list_changed == Some(true)
        ),
        "the first incremental listen record must be the accepted filter: {acknowledgement:?}"
    );

    let hidden = client
        .call_tool("hide_catalog", json!({}))
        .expect("disabling a shipped resource and prompt must complete");
    assert!(
        hidden.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "hidden",
            _ => false,
        }),
        "stdio session state must let disable_resource and disable_prompt publish: {hidden:?}"
    );

    let first = client
        .next_subscription_event(&cx, &cancellation)
        .expect("subscriptions/listen must retain the first catalog mutation");
    let second = client
        .next_subscription_event(&cx, &cancellation)
        .expect("subscriptions/listen must retain the second catalog mutation");
    let kinds = [first, second];
    assert!(
        kinds.iter().any(|event| matches!(
            event,
            modern::StdioSubscriptionEvent::Notification(
                modern::ServerNotification::ResourcesListChanged(_)
            )
        )),
        "live stdio must retain notifications/resources/list_changed: {kinds:?}"
    );
    assert!(
        kinds.iter().any(|event| matches!(
            event,
            modern::StdioSubscriptionEvent::Notification(
                modern::ServerNotification::PromptsListChanged(_)
            )
        )),
        "live stdio must retain notifications/prompts/list_changed: {kinds:?}"
    );
    client
        .close()
        .expect("modern-only stdio catalog list_changed client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_ctx_info_is_retained_after_set_log_level() {
    let mut client = connect_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    client
        .set_log_level(modern::LoggingLevel::Info)
        .expect("info logLevel is stored as request metadata");
    client
        .call_tool("echo", json!({"message": "log"}))
        .expect("ctx.info must not prevent the shipped echo tool from completing");
    let info_notifications = client.take_server_notifications();
    assert!(
        info_notifications.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.level == modern::LoggingLevel::Info
                    && message.data == json!("echo-handler-info")
        )),
        "live stdio must retain ctx.info after set_log_level(Info): {info_notifications:?}"
    );

    client
        .set_log_level(modern::LoggingLevel::Emergency)
        .expect("emergency logLevel still stores request metadata locally");
    client
        .call_tool("echo", json!({"message": "quiet"}))
        .expect("raising only the logLevel floor cannot break the shipped echo tool");
    let emergency_notifications = client.take_server_notifications();
    assert!(
        !emergency_notifications.iter().any(|notification| matches!(
            notification,
            modern::ServerNotification::Message(message)
                if message.data == json!("echo-handler-info")
        )),
        "raising only the logLevel floor must suppress ctx.info: {emergency_notifications:?}"
    );
    client
        .close()
        .expect("modern-only stdio log client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_completion_returns_typed_result_and_rejects_undeclared_argument() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");
    let params = modern::CompletionParams {
        reference: modern::CompletionReference::PromptWithTitle {
            name: "greeting".to_owned(),
            title: "Greeting".to_owned(),
        },
        argument: modern::FinalCompletionArgument {
            name: "name".to_owned(),
            value: "co".to_owned(),
        },
        context: Some(modern::FinalCompletionContext {
            arguments: Some(std::collections::BTreeMap::from([(
                "locale".to_owned(),
                "en-US".to_owned(),
            )])),
        }),
    };

    let completion_started = Instant::now();
    client
        .complete(params.clone())
        .expect("a completion/complete without a progress token still completes");
    assert!(
        client.take_progress_notifications().is_empty(),
        "without a progressToken the shipped completion handler must not emit request-scoped progress"
    );
    let marker = modern::ProgressMarker::from("stdio-completion-progress");
    let result = client
        .complete_with_progress_marker(params.clone(), marker.clone())
        .expect("the typed ModernOnly client reaches the shipped completion provider");
    assert!(
        completion_started.elapsed() <= STDIO_COMPLETION_ABSOLUTE_TIMEOUT,
        "the positive completion finishes within its explicit public-client absolute bound"
    );
    assert_eq!(
        result.completion.values,
        vec!["stdio-completion-2".to_owned()],
        "the exact FinalCompletionResult retains the provider value and count"
    );
    let progress = client.take_progress_notifications();
    assert!(
        progress.iter().any(|notification| {
            notification.progress_token == marker
                && notification.message.as_deref() == Some("stdio-completion-halfway")
        }),
        "live shipped-echo stdio must retain completion notifications/progress: {progress:?}"
    );
    assert_eq!(
        result.completion.total,
        Some(modern::JsonInteger::from(2_i64)),
        "the exact FinalCompletionResult retains its JSON-integer count"
    );
    assert_eq!(
        result.completion.has_more,
        Some(false),
        "the exact FinalCompletionResult retains the terminal pagination flag"
    );

    // RH-5 near-negative: retain the target, title, prefix, and context,
    // changing only the completion argument name. Router validation must
    // reject before the shipped provider can increment its process-local count.
    let mut undeclared_argument = params.clone();
    undeclared_argument.argument.name = "undeclared".to_owned();
    let error = client
        .complete(undeclared_argument)
        .expect_err("only an undeclared completion argument is rejected");
    assert_eq!(error.code, McpErrorCode::InvalidParams);

    let resumed = client
        .complete(params)
        .expect("the rejected request leaves the live modern client and provider usable");
    assert_eq!(
        resumed.completion.values,
        vec!["stdio-completion-3".to_owned()],
        "the next accepted completion proves the rejected argument did not invoke the provider"
    );
    assert_eq!(
        resumed.completion.total,
        Some(modern::JsonInteger::from(3_i64)),
        "the provider count advances only for the three accepted completions"
    );
    assert_eq!(resumed.completion.has_more, Some(false));
    let cleanup_started = Instant::now();
    client
        .close()
        .expect("modern completion stdio client cleanup and child reap");
    assert!(
        cleanup_started.elapsed() <= STDIO_COMPLETION_CLEANUP_BOUND,
        "the public close confirms bounded stdio child cleanup and reap"
    );
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_result_verbs_keep_live_input_required() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client observes live stdio input_required");
    let pending_resource = client
        .read_resource_result("info://mrtr-resource")
        .expect("live stdio resources/read must keep a typed result");
    let modern::FinalCoreResult::ResourcesReadInputRequired { result, .. } = pending_resource
    else {
        panic!("live stdio resources/read must keep input_required: {pending_resource:?}");
    };
    assert!(
        result.request_state().is_some(),
        "stdio resource MRTR must return framework-issued requestState"
    );
    assert!(
        result
            .input_requests()
            .is_some_and(|requests| requests.get("roots").is_some()),
        "stdio resource MRTR must retain its roots input request"
    );
    let pending_prompt = client
        .get_prompt_result(
            "mrtr_prompt",
            HashMap::from([("mode".to_owned(), "terminal".to_owned())]),
        )
        .expect("live stdio prompts/get must keep a typed result");
    let modern::FinalCoreResult::PromptsGetInputRequired { result, .. } = pending_prompt else {
        panic!("live stdio prompts/get must keep input_required: {pending_prompt:?}");
    };
    assert!(
        result.request_state().is_some(),
        "stdio prompt MRTR must return framework-issued requestState"
    );
    assert!(
        result
            .input_requests()
            .is_some_and(|requests| requests.get("roots").is_some()),
        "stdio prompt MRTR must retain its roots input request"
    );
    client
        .close()
        .expect("stdio result-verb client cleanup reaps the live subprocess");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_read_resource_and_get_prompt_follow_installed_roots_handler() {
    let mut client = modern::client_builder()
        .env("FASTMCP_PROTOCOL_POLICY", "modern-only")
        .request_timeout_policy(
            RequestTimeoutPolicy::new(
                STDIO_COMPLETION_IDLE_TIMEOUT,
                STDIO_COMPLETION_ABSOLUTE_TIMEOUT,
            )
            .expect("the public follow timeout policy is valid"),
        )
        .modern_reverse_request_handlers(
            modern::ReverseRequestHandlers::new().with_modern_roots_list(
                |_cx, _cancellation, _params| {
                    Box::pin(async { Ok(modern::FinalEmbeddedRootsListResult { roots: vec![] }) })
                },
            ),
        )
        .connect_stdio_with_cx(shipped_echo_server_executable(), &[], &Cx::for_request())
        .expect("a ModernOnly facade client installs a roots handler before discovery");

    let resource = client
        .read_resource("info://mrtr-resource")
        .expect("public stdio read_resource follows the installed roots handler");
    assert_eq!(resource.ttl_ms, CacheTtl::milliseconds(7));
    assert_eq!(resource.cache_scope, CacheScope::Private);

    let prompt = client
        .get_prompt(
            "mrtr_prompt",
            HashMap::from([("mode".to_owned(), "terminal".to_owned())]),
        )
        .expect("public stdio get_prompt follows the installed roots handler");
    assert_eq!(
        prompt.description.as_deref(),
        Some("typed MRTR prompt result")
    );
    client
        .close()
        .expect("stdio follow-handler client cleanup reaps the live subprocess");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_sampling_elicitation_keep_input_required_and_fail_closed() {
    let mut client = connect_bounded_modern_stdio_with_mrtr(
        "modern-only",
        stdio_mrtr_capabilities(true, true, true, true),
        modern::ReverseRequestHandlers::new(),
    )
    .expect("a ModernOnly facade client advertises sampling, roots, and elicitation");

    let sampling = client
        .call_tool_result("sample_echo", json!({}))
        .expect("live stdio ctx.final_sampling must return a typed tools/call result");
    let modern::FinalCoreResult::ToolsCallInputRequired { result, .. } = sampling else {
        panic!("live stdio final sampling must keep input_required: {sampling:?}");
    };
    assert_stdio_input_required(&result, "sample", "tools/call sampling");

    let roots = client
        .call_tool_result("roots_echo", json!({}))
        .expect("live stdio ctx.final_roots must return a typed tools/call result");
    let modern::FinalCoreResult::ToolsCallInputRequired { result, .. } = roots else {
        panic!("live stdio final roots must keep input_required: {roots:?}");
    };
    assert_stdio_input_required(&result, "roots", "tools/call roots");

    let url = client
        .call_tool_result("url_elicit_echo", json!({}))
        .expect("live stdio ctx.final_elicitation_url must return a typed tools/call result");
    let modern::FinalCoreResult::ToolsCallInputRequired { result, .. } = url else {
        panic!("live stdio final URL elicitation must keep input_required: {url:?}");
    };
    assert_stdio_input_required(&result, "approval", "tools/call URL elicitation");

    let resource = client
        .read_resource_result("info://elicit-form")
        .expect("live stdio form elicitation resource must return a typed result");
    let modern::FinalCoreResult::ResourcesReadInputRequired { result, .. } = resource else {
        panic!("live stdio resource form elicitation must keep input_required: {resource:?}");
    };
    assert_stdio_input_required(&result, "approval", "resources/read form elicitation");

    let prompt = client
        .get_prompt_result("elicit_form_greeting", HashMap::new())
        .expect("live stdio form elicitation prompt must return a typed result");
    let modern::FinalCoreResult::PromptsGetInputRequired { result, .. } = prompt else {
        panic!("live stdio prompt form elicitation must keep input_required: {prompt:?}");
    };
    assert_stdio_input_required(&result, "approval", "prompts/get form elicitation");
    client
        .close()
        .expect("stdio input_required MRTR client cleanup reaps the live subprocess");

    let mut no_sampling = connect_bounded_modern_stdio_with_mrtr(
        "modern-only",
        stdio_mrtr_capabilities(false, true, true, true),
        modern::ReverseRequestHandlers::new(),
    )
    .expect("a ModernOnly facade client connects without advertising sampling");
    let missing_sampling = no_sampling
        .call_tool_result("sample_echo", json!({}))
        .expect("missing sampling capability must still return a typed tools/call result");
    assert_stdio_capability_gate(&missing_sampling, "sampling");
    no_sampling
        .close()
        .expect("stdio no-sampling client cleanup reaps the live subprocess");

    let mut no_url = connect_bounded_modern_stdio_with_mrtr(
        "modern-only",
        stdio_mrtr_capabilities(true, true, true, false),
        modern::ReverseRequestHandlers::new(),
    )
    .expect("a ModernOnly facade client connects without advertising URL elicitation");
    let missing_url = no_url
        .call_tool_result("url_elicit_echo", json!({}))
        .expect("missing URL elicitation capability must still return a typed tools/call result");
    assert_stdio_capability_gate(&missing_url, "URL elicitation");
    no_url
        .close()
        .expect("stdio no-url-elicitation client cleanup reaps the live subprocess");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_sampling_elicitation_follow_installed_handlers() {
    let handlers = modern::ReverseRequestHandlers::new()
        .with_modern_sampling_create_message(|_cx, _cancellation, _params| {
            Box::pin(async {
                Ok(modern::FinalCreateMessageResult {
                    content: modern::FinalSamplingMessageContent::Block(
                        modern::FinalSamplingMessageContentBlock::Text {
                            text: "sampled".to_owned(),
                            annotations: None,
                            meta: None,
                            additional: std::collections::BTreeMap::new(),
                        },
                    ),
                    model: "stdio-sample-model".to_owned(),
                    role: Role::Assistant,
                    stop_reason: None,
                    meta: None,
                })
            })
        })
        .with_modern_roots_list(|_cx, _cancellation, _params| {
            Box::pin(async { Ok(modern::FinalEmbeddedRootsListResult { roots: vec![] }) })
        })
        .with_modern_elicitation_create(|_cx, _cancellation, params| {
            Box::pin(async move {
                Ok(match params {
                    fastmcp_protocol::ElicitRequestParams::Url(_) => {
                        fastmcp_protocol::ElicitResult::accept_url()
                    }
                    fastmcp_protocol::ElicitRequestParams::Form(_) => {
                        fastmcp_protocol::ElicitResult::accept(HashMap::from([(
                            "approved".to_owned(),
                            fastmcp_protocol::ElicitContentValue::Bool(true),
                        )]))
                    }
                })
            })
        });
    let mut client = connect_bounded_modern_stdio_with_mrtr(
        "modern-only",
        stdio_mrtr_capabilities(true, true, true, true),
        handlers,
    )
    .expect("a ModernOnly facade client installs sampling, roots, and elicitation handlers");

    let sampled = client
        .call_tool("sample_echo", json!({}))
        .expect("public stdio call_tool follows the installed sampling handler");
    assert!(
        sampled.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "sampled:stdio-sample-model",
            _ => false,
        }),
        "the sampling retry must complete from the installed handler: {sampled:?}"
    );

    let roots = client
        .call_tool("roots_echo", json!({}))
        .expect("public stdio call_tool follows the installed roots handler");
    assert!(
        roots.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "roots:0",
            _ => false,
        }),
        "the roots retry must complete from the installed handler: {roots:?}"
    );

    let url = client
        .call_tool("url_elicit_echo", json!({}))
        .expect("public stdio call_tool follows the installed URL elicitation handler");
    assert!(
        url.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "url-elicit:accept",
            _ => false,
        }),
        "the URL elicitation retry must complete from the installed handler: {url:?}"
    );

    let resource = client
        .read_resource("info://elicit-form")
        .expect("public stdio read_resource follows the installed form elicitation handler");
    assert!(
        resource.contents.iter().any(|content| match content {
            EmbeddedResourceContents::Text { text, .. } => text == "form-elicit:true",
            _ => false,
        }),
        "the form elicitation resource retry must complete from the installed handler: {resource:?}"
    );

    let prompt = client
        .get_prompt("elicit_form_greeting", HashMap::new())
        .expect("public stdio get_prompt follows the installed form elicitation handler");
    assert!(
        prompt
            .messages
            .iter()
            .any(|message| match &message.content {
                ContentBlock::Text { text, .. } => text == "form-elicit:true",
                _ => false,
            }),
        "the form elicitation prompt retry must complete from the installed handler: {prompt:?}"
    );

    client
        .close()
        .expect("stdio follow-handler MRTR client cleanup reaps the live subprocess");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_typed_verbs_honor_pre_send_cancellation() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client connects before pre-send cancellation");
    let cx = Cx::for_request();
    let cancellation = fastmcp_rust::McpRequestCancellation::new();
    cancellation.cancel();
    let list = client
        .list_tools_with_cancellation(&cx, &cancellation, None)
        .expect_err("pre-send list_tools cancellation must reject locally");
    assert_eq!(list.code, McpErrorCode::RequestCancelled);
    let resources = client
        .list_resources_with_cancellation(&cx, &cancellation, None)
        .expect_err("pre-send list_resources cancellation must reject locally");
    assert_eq!(resources.code, McpErrorCode::RequestCancelled);
    let templates = client
        .list_resource_templates_with_cancellation(&cx, &cancellation, None)
        .expect_err("pre-send list_resource_templates cancellation must reject locally");
    assert_eq!(templates.code, McpErrorCode::RequestCancelled);
    let prompts = client
        .list_prompts_with_cancellation(&cx, &cancellation, None)
        .expect_err("pre-send list_prompts cancellation must reject locally");
    assert_eq!(prompts.code, McpErrorCode::RequestCancelled);
    let call = client
        .call_tool_with_cancellation(&cx, &cancellation, "echo", json!({"message": "hi"}))
        .expect_err("pre-send call_tool cancellation must reject locally");
    assert_eq!(call.code, McpErrorCode::RequestCancelled);
    let resource = client
        .read_resource_with_cancellation(&cx, &cancellation, "info://mrtr-resource")
        .expect_err("pre-send read_resource cancellation must reject locally");
    assert_eq!(resource.code, McpErrorCode::RequestCancelled);
    let prompt = client
        .get_prompt_with_cancellation(
            &cx,
            &cancellation,
            "mrtr_prompt",
            HashMap::from([("mode".to_owned(), "terminal".to_owned())]),
        )
        .expect_err("pre-send get_prompt cancellation must reject locally");
    assert_eq!(prompt.code, McpErrorCode::RequestCancelled);
    let completion = client
        .complete_with_cancellation(
            &cx,
            &cancellation,
            modern::CompletionParams {
                reference: modern::CompletionReference::PromptWithTitle {
                    name: "greeting".to_owned(),
                    title: "Greeting".to_owned(),
                },
                argument: modern::FinalCompletionArgument {
                    name: "name".to_owned(),
                    value: "co".to_owned(),
                },
                context: None,
            },
        )
        .expect_err("pre-send complete cancellation must reject locally");
    assert_eq!(completion.code, McpErrorCode::RequestCancelled);
    let ping = client
        .ping_with_cancellation(&cx, &cancellation)
        .expect_err("pre-send ping cancellation must reject locally");
    assert_eq!(ping.code, McpErrorCode::RequestCancelled);
    client
        .ping()
        .expect("modern stdio ping remains usable after local cancellation");
    client
        .list_tools(None)
        .expect("the same stdio session remains usable after local cancellation");
    client
        .close()
        .expect("stdio pre-send cancellation client cleanup reaps the live subprocess");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_executor_execute_stamps_modern_meta() {
    let mut client = connect_auto_stdio_to_shipped_echo_server("modern-only");
    assert_eq!(
        client.selected_protocol_era(),
        Some(ProtocolEra::Modern2026)
    );
    let cx = Cx::for_request();
    let executor = client
        .multiplexed_stdio_executor()
        .expect("a negotiated modern stdio session exposes the shared executor");
    let mut listed = executor
        .execute(&cx, "tools/list", Some(json!({})))
        .expect("a cloned executor stamps modern _meta before tools/list");
    let listed = client
        .wait_multiplexed_request(&cx, &mut listed)
        .expect("undecorated tools/list params are admitted after executor stamping");
    assert!(
        listed.error.is_none(),
        "executor-stamped tools/list must not be an era refusal: {listed:?}"
    );
    assert_eq!(
        listed
            .result
            .as_ref()
            .and_then(|result| result.get("resultType")),
        Some(&json!("complete"))
    );

    let refused = executor
        .execute(&cx, "tools/list", Some(json!("not-an-object")))
        .expect_err("modern execute rejects a non-object body before send");
    assert_eq!(refused.code, McpErrorCode::InvalidParams);
    assert!(
        refused.message.contains("object parameters"),
        "only the parameter shape is refused: {refused:?}"
    );
    client
        .list_tools_typed(None)
        .expect("the same stdio session remains usable after the local parameter refusal");
    client
        .close()
        .expect("stdio executor-stamp client cleanup reaps the live subprocess");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_final_resource_keeps_authored_cache_ttl() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");
    let resource = client
        .read_resource_with_mrtr_retry("info://mrtr-resource", |_| {
            Ok(std::collections::BTreeMap::from([(
                "roots".to_owned(),
                json!({"roots": []}),
            )]))
        })
        .expect("the public modern facade resumes the shipped resource with typed roots");
    let modern::FinalCoreResult::ResourcesRead { result, .. } = resource else {
        panic!("the resumed resource returns the exact FinalReadResourceResult branch");
    };
    assert_eq!(result.payload.ttl_ms, CacheTtl::milliseconds(7));
    assert_eq!(result.payload.cache_scope, CacheScope::Private);
    client
        .close()
        .expect("stdio cache-ttl client cleanup reaps the live subprocess");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_resource_and_prompt_mrtr_are_typed_and_bounded() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    let operation_started = Instant::now();
    let resource = client
        .read_resource_with_mrtr_retry("info://mrtr-resource", |_| {
            Ok(std::collections::BTreeMap::from([(
                "roots".to_owned(),
                json!({"roots": []}),
            )]))
        })
        .expect("the public modern facade resumes the shipped resource with typed roots");
    let modern::FinalCoreResult::ResourcesRead { result, .. } = resource else {
        panic!("the resumed resource returns the exact FinalReadResourceResult branch");
    };
    assert_eq!(result.payload.ttl_ms, CacheTtl::milliseconds(7));
    assert_eq!(result.payload.cache_scope, CacheScope::Private);
    let [
        EmbeddedResourceContents::Text {
            uri,
            text,
            mime_type,
            meta,
            additional,
        },
    ] = result.payload.contents.as_slice()
    else {
        panic!("the final resource result contains one exact text resource");
    };
    assert_eq!(uri.as_str(), "info://mrtr-resource/result");
    assert_eq!(text, "typed resource roots=0");
    assert_eq!(mime_type.as_deref(), Some("text/plain"));
    assert!(meta.is_none());
    assert!(additional.is_empty());

    let prompt = client
        .get_prompt_with_mrtr_retry(
            "mrtr_prompt",
            HashMap::from([("mode".to_owned(), "terminal".to_owned())]),
            |_| {
                Ok(std::collections::BTreeMap::from([(
                    "roots".to_owned(),
                    json!({"roots": []}),
                )]))
            },
        )
        .expect("the public modern facade resumes the shipped prompt with typed roots");
    let modern::FinalCoreResult::PromptsGet { result, .. } = prompt else {
        panic!("the resumed prompt returns the exact FinalGetPromptResult branch");
    };
    assert_eq!(
        result.payload.description.as_deref(),
        Some("typed MRTR prompt result")
    );
    let [message] = result.payload.messages.as_slice() else {
        panic!("the final prompt result contains one exact final message");
    };
    assert_eq!(message.role, Role::Assistant);
    assert!(matches!(
        &message.content,
        ContentBlock::Text {
            text,
            annotations: None,
            meta: None,
            additional,
        } if text == "typed prompt roots=0" && additional.is_empty()
    ));
    assert!(
        operation_started.elapsed() <= STDIO_COMPLETION_ABSOLUTE_TIMEOUT,
        "both typed public MRTR completions finish within the explicit absolute bound"
    );

    // RH-5: keep the method, URI, issued state, and typed roots response;
    // changing only requestState must reject without consuming the registry
    // entry, so the originally issued state still completes below.
    let mut raw = connect_auto_stdio_to_shipped_echo_server("modern-only");
    assert_eq!(raw.selected_protocol_era(), Some(ProtocolEra::Modern2026));
    let initial = selected_modern_stdio_raw_result(
        &mut raw,
        "resources/read",
        json!({"uri": "info://mrtr-resource"}),
    );
    assert_eq!(initial["resultType"], "input_required");
    assert_eq!(
        initial["inputRequests"],
        json!({"roots": {"method": "roots/list"}})
    );
    let request_state = initial["requestState"]
        .as_str()
        .expect("the router mints an opaque resource MRTR state")
        .to_owned();
    let bad_request_state = selected_modern_stdio_raw_error(
        &mut raw,
        "resources/read",
        json!({
            "uri": "info://mrtr-resource",
            "inputResponses": {"roots": {"roots": []}},
            "requestState": format!("{request_state}-mutated"),
        }),
    );
    assert_eq!(bad_request_state, "Invalid or expired MRTR request state");

    // RH-5: retain every accepted field and change only the typed response
    // discriminator from roots to elicitation.
    // A subsequent accepted retry with the original state proves neither
    // rejection consumed the server-owned registry entry or reached the handler.
    let bad_input_responses = selected_modern_stdio_raw_error(
        &mut raw,
        "resources/read",
        json!({
            "uri": "info://mrtr-resource",
            "inputResponses": {
                "roots": {"action": "accept", "content": {}},
            },
            "requestState": request_state,
        }),
    );
    assert_eq!(
        bad_input_responses,
        "MRTR input response does not match its request"
    );
    let completed = selected_modern_stdio_raw_result(
        &mut raw,
        "resources/read",
        json!({
            "uri": "info://mrtr-resource",
            "inputResponses": {"roots": {"roots": []}},
            "requestState": initial["requestState"],
        }),
    );
    assert_eq!(completed["resultType"], "complete");
    assert_eq!(completed["ttlMs"], 7);
    assert_eq!(completed["cacheScope"], "private");
    assert_eq!(completed["contents"][0]["text"], "typed resource roots=0");
    let raw_cleanup_started = Instant::now();
    raw.close()
        .expect("the selected-modern raw MRTR public facade cleans up");
    assert!(
        raw_cleanup_started.elapsed() <= STDIO_COMPLETION_CLEANUP_BOUND,
        "the selected-modern raw MRTR facade also bounds child cleanup"
    );

    let cancellation = client
        .get_prompt_with_mrtr_retry(
            "mrtr_prompt",
            HashMap::from([("mode".to_owned(), "terminal".to_owned())]),
            |_| Err(fastmcp_rust::McpError::request_cancelled()),
        )
        .expect_err("a caller cancellation rejects before the MRTR retry is sent");
    assert_eq!(cancellation.code, McpErrorCode::RequestCancelled);

    let mut round_callbacks = 0;
    let round_error = client
        .get_prompt_with_mrtr_retry(
            "mrtr_prompt",
            HashMap::from([("mode".to_owned(), "round-bound".to_owned())]),
            |_| {
                round_callbacks += 1;
                Ok(std::collections::BTreeMap::from([(
                    "roots".to_owned(),
                    json!({"roots": [{"uri": "file:///mrtr/retry"}]}),
                )]))
            },
        )
        .expect_err("one continuation beyond the public round bound is rejected locally");
    assert_eq!(round_error.code, McpErrorCode::InvalidParams);
    assert_eq!(
        round_error.message,
        "MRTR continuation-round limit exceeded"
    );
    assert_eq!(round_callbacks, 4);

    let input_error = client
        .get_prompt_with_mrtr_retry(
            "mrtr_prompt",
            HashMap::from([("mode".to_owned(), "terminal".to_owned())]),
            |_| {
                Ok((0..=128)
                    .map(|index| (format!("oversized-{index}"), json!({"roots": []})))
                    .collect())
            },
        )
        .expect_err("a 129th response differs only by crossing the public input bound");
    assert_eq!(input_error.code, McpErrorCode::InvalidParams);
    assert_eq!(
        input_error.message,
        "MRTR inputResponses must not exceed 128 entries"
    );
    assert!(
        client.list_tools(None).is_ok(),
        "cancellation and local bounds leave the public modern connection usable"
    );

    let cleanup_started = Instant::now();
    client
        .close()
        .expect("modern MRTR stdio client cleanup reaps the shipped server");
    assert!(
        cleanup_started.elapsed() <= STDIO_COMPLETION_CLEANUP_BOUND,
        "the public client bounds the shipped server lifecycle by closing stdio"
    );
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_tasks_create_resume_cancel_and_reject_missing_capability() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client starts the shipped caller-owned Task service");

    // RH-5 near-negative: preserve the modern session, method, tool, and
    // arguments. `call_tool` differs from `call_tool_outcome` only by omitting
    // the official Tasks client capability. The bounded one-task store makes
    // the following successful creation a public proof that this refusal did
    // not persist a Task.
    let missing_capability = client
        .call_tool("durable_task", json!({}))
        .expect_err("a task-capable tool requires the declared Tasks capability");
    assert_eq!(i32::from(missing_capability.code), -32_021);

    let created = client
        .call_tool_outcome("durable_task", json!({}))
        .expect("the typed ModernOnly facade client creates one durable Task");
    let modern::FinalToolCallOutcome::Task(created) = created else {
        panic!("the task-capable tool returns the exact final Task result branch");
    };
    assert!(matches!(created.task, modern::FinalTask::Working(_)));
    assert_eq!(
        created.task.base().status_message.as_deref(),
        Some("durable stdio task call 1"),
        "the created Task proves the missing-capability call reached no durable Task state"
    );
    let task_id = created.task.base().task_id.clone();

    let input_required_deadline = Instant::now() + STDIO_COMPLETION_ABSOLUTE_TIMEOUT;
    let input_required = loop {
        let observed = client
            .get_task(task_id.clone())
            .expect("typed tasks/get observes the live shipped Task");
        if matches!(&observed.task, modern::FinalTask::InputRequired { .. }) {
            break observed;
        }
        assert!(
            Instant::now() < input_required_deadline,
            "the caller-owned supervisor reaches input_required within the public bound"
        );
        std::thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(
        input_required.task.base().status_message.as_deref(),
        Some("awaiting roots from the caller-owned stdio service")
    );

    let responses: modern::FinalTaskInputResponses =
        serde_json::from_value(json!({"roots": {"roots": []}}))
            .expect("the exact public Tasks input response is typed");
    let updated = client
        .update_task(&input_required.task, responses)
        .expect("typed tasks/update accepts the declared input request");
    assert!(
        updated.additional.is_empty(),
        "tasks/update returns the exact empty final acknowledgement"
    );
    let cancelled = client
        .cancel_task(task_id.clone())
        .expect("typed tasks/cancel acknowledges the durable cancellation request");
    assert!(
        cancelled.additional.is_empty(),
        "tasks/cancel returns the exact empty final acknowledgement"
    );

    let cancellation_deadline = Instant::now() + STDIO_COMPLETION_ABSOLUTE_TIMEOUT;
    loop {
        let observed = client
            .get_task(task_id.clone())
            .expect("typed tasks/get remains usable after cancellation");
        if matches!(&observed.task, modern::FinalTask::Cancelled(_)) {
            break;
        }
        assert!(
            Instant::now() < cancellation_deadline,
            "the live caller-owned supervisor honors cancellation within the public bound"
        );
        std::thread::sleep(Duration::from_millis(1));
    }

    let cleanup_started = Instant::now();
    client
        .close()
        .expect("modern Tasks stdio client cleanup reaps the live subprocess");
    assert!(
        cleanup_started.elapsed() <= STDIO_COMPLETION_CLEANUP_BOUND,
        "the caller-owned stdio Task service settles when the client closes"
    );

    let mut legacy = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("the exact-2024 facade retains its separate shipped stdio lifecycle");
    let legacy_result = legacy
        .call_tool("durable_task", json!({}))
        .expect("exact-2024 treats the task-capable tool as an ordinary legacy tool");
    assert!(matches!(
        legacy_result.content.first(),
        Some(LegacyContent::Text { text, .. }) if text == "exact-2024 Tasks are unavailable"
    ));
    let legacy_cleanup_started = Instant::now();
    legacy
        .close()
        .expect("exact-2024 stdio client cleanup reaps its separate subprocess");
    assert!(
        legacy_cleanup_started.elapsed() <= STDIO_COMPLETION_CLEANUP_BOUND,
        "the exact-2024 subprocess also performs bounded cleanup without a Task service"
    );
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_only_rejects_the_exact_legacy_shipped_server() {
    // This differs from the matched ModernOnly positive only in the child
    // server's policy. The public client must not silently downgrade.
    let result = connect_modern_stdio_to_shipped_echo_server("legacy-only");

    assert!(
        result.is_err(),
        "a ModernOnly facade client must reject the exact legacy server instead of downgrading"
    );
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_only_round_trips_with_the_shipped_facade_server() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    assert_eq!(
        client.protocol_version(),
        fastmcp_rust::legacy_2024::PROTOCOL_VERSION
    );
    client
        .ping()
        .expect("the explicit LegacyOnly core connection remains usable");
    let legacy_resource = client
        .read_resource("info://mrtr-resource")
        .expect_err("exact-2024 cannot activate the final MRTR resource handler");
    assert_eq!(legacy_resource.code, McpErrorCode::InternalError);
    assert_eq!(
        legacy_resource.message,
        "final #[resource] handlers must be invoked through ResourceHandler::read_final"
    );
    let legacy_prompt = client
        .get_prompt(
            "mrtr_prompt",
            HashMap::from([("mode".to_owned(), "terminal".to_owned())]),
        )
        .expect_err("exact-2024 cannot activate the final MRTR prompt handler");
    assert_eq!(legacy_prompt.code, McpErrorCode::InternalError);
    assert_eq!(
        legacy_prompt.message,
        "final #[prompt] handlers must be invoked through PromptHandler::get_final"
    );
    client.close().expect("legacy-only stdio client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_composes_nested_tool_and_resource() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    let composed = client
        .call_tool("compose_echo", json!({"message": "alpha"}))
        .expect("live exact-2024 stdio compose_echo must nest echo and info://server");
    assert!(
        composed.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => {
                text.starts_with("compose:alpha|") && text.contains("echo-server")
            }
            _ => false,
        }),
        "compose_echo must retain the nested echo text and server-info resource: {composed:?}"
    );

    let missing_tool = client.call_tool(
        "compose_echo",
        json!({
            "message": "alpha",
            "tool": "stdio-e2e-missing",
        }),
    );
    let missing_tool = match missing_tool {
        Ok(result) if result.is_error => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
        Ok(result) => panic!(
            "changing only the nested tool name must refuse before the peer resource: {result:?}"
        ),
    };
    assert!(
        missing_tool.contains("stdio-e2e-missing")
            || missing_tool.contains("compose-nested-tool")
            || missing_tool.contains("Unknown tool"),
        "the nested unknown tool must stay a handler-visible refusal: {missing_tool}"
    );

    let missing_resource = client.call_tool(
        "compose_echo",
        json!({
            "message": "beta",
            "resource": "info://stdio-e2e-missing",
        }),
    );
    let missing_resource = match missing_resource {
        Ok(result) if result.is_error => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
        Ok(result) => panic!(
            "changing only the nested resource URI must refuse after the peer tool: {result:?}"
        ),
    };
    assert!(
        missing_resource.contains("info://stdio-e2e-missing")
            || missing_resource.contains("compose-nested-resource")
            || missing_resource.contains("not found"),
        "the nested unknown resource must stay a handler-visible refusal: {missing_resource}"
    );

    client
        .close()
        .expect("legacy-only stdio compose client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_prompt_composes_nested_tool_and_resource() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    let composed = client
        .get_prompt(
            "compose_greeting",
            HashMap::from([
                ("name".to_owned(), "alpha".to_owned()),
                ("tool".to_owned(), "echo".to_owned()),
                ("resource".to_owned(), "info://server".to_owned()),
            ]),
        )
        .expect("live exact-2024 stdio compose_greeting must nest echo and info://server");
    assert!(
        composed
            .messages
            .iter()
            .any(|message| match &message.content {
                LegacyContent::Text { text, .. } => {
                    text.starts_with("compose:alpha|") && text.contains("echo-server")
                }
                _ => false,
            }),
        "compose_greeting must retain the nested echo text and server-info resource: {composed:?}"
    );

    let missing_tool = client
        .get_prompt(
            "compose_greeting",
            HashMap::from([
                ("name".to_owned(), "alpha".to_owned()),
                ("tool".to_owned(), "stdio-e2e-missing".to_owned()),
                ("resource".to_owned(), "info://server".to_owned()),
            ]),
        )
        .expect_err("changing only the nested tool name must refuse before the peer resource");
    let missing_tool = format!("{missing_tool:?}");
    assert!(
        missing_tool.contains("stdio-e2e-missing")
            || missing_tool.contains("compose-nested-tool")
            || missing_tool.contains("Unknown tool"),
        "the nested unknown tool must stay a handler-visible refusal: {missing_tool}"
    );

    client
        .close()
        .expect("legacy-only stdio prompt compose client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_resource_composes_nested_tool_and_resource() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    let composed = client
        .read_resource("info://compose")
        .expect("live exact-2024 stdio info://compose must nest echo and info://server");
    assert!(
        composed.contents.iter().any(|content| match content {
            LegacyResourceContent::Text { text, .. } => {
                text.starts_with("compose:alpha|") && text.contains("echo-server")
            }
            _ => false,
        }),
        "info://compose must retain the nested echo text and server-info resource: {composed:?}"
    );

    let missing_tool = client
        .read_resource("info://compose-missing-tool")
        .expect_err("changing only the nested tool name must refuse before the peer resource");
    let missing_tool = format!("{missing_tool:?}");
    assert!(
        missing_tool.contains("stdio-e2e-missing")
            || missing_tool.contains("compose-nested-tool")
            || missing_tool.contains("Unknown tool"),
        "the nested unknown tool must stay a handler-visible refusal: {missing_tool}"
    );

    let missing_resource = client
        .read_resource("info://compose-missing-resource")
        .expect_err("changing only the nested resource URI must refuse after the peer tool");
    let missing_resource = format!("{missing_resource:?}");
    assert!(
        missing_resource.contains("info://stdio-e2e-missing")
            || missing_resource.contains("compose-nested-resource")
            || missing_resource.contains("not found"),
        "the nested unknown resource must stay a handler-visible refusal: {missing_resource}"
    );

    client
        .close()
        .expect("legacy-only stdio resource compose client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_handler_timeout_refuses_late_tool_and_admits_fast_peer() {
    let mut client = legacy_2024::client_builder()
        .env("FASTMCP_PROTOCOL_POLICY", "legacy-only")
        .request_timeout_policy(
            RequestTimeoutPolicy::new(
                STDIO_COMPLETION_IDLE_TIMEOUT,
                STDIO_COMPLETION_ABSOLUTE_TIMEOUT,
            )
            .expect("the public handler-timeout client policy is valid"),
        )
        .connect_stdio_with_cx(shipped_echo_server_executable(), &[], &Cx::for_request())
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    let timed_out = client
        .call_tool("slow_echo", json!({}))
        .expect_err("a handler that outlives its timeout must be refused");
    let timed_out = format!("{timed_out:?}");
    assert!(
        timed_out.contains("Request timeout exceeded") || timed_out.contains("RequestCancelled"),
        "the refused late tools/call must keep the handler-timeout error: {timed_out}"
    );

    let fast = client
        .call_tool("fast_echo", json!({}))
        .expect("changing only the tool must still be admitted after a handler timeout");
    assert!(
        fast.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text == "fast",
            _ => false,
        }),
        "the fast peer tool must still complete: {fast:?}"
    );

    client
        .close()
        .expect("legacy-only stdio handler-timeout client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_default_parameter_is_injected_and_overridable() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    let injected = client
        .call_tool("greet", json!({"name": "World"}))
        .expect("omitting the defaulted argument must still be admitted");
    assert!(
        injected.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text == "greet:World!",
            _ => false,
        }),
        "the generated default must be injected at call time: {injected:?}"
    );

    let overridden = client
        .call_tool("greet", json!({"name": "World", "suffix": "?"}))
        .expect("supplying the defaulted argument must override the generated default");
    assert!(
        overridden.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text == "greet:World?",
            _ => false,
        }),
        "changing only the suffix must override the generated default: {overridden:?}"
    );

    let missing_name = client.call_tool("greet", json!({"suffix": "!"}));
    let missing_name = match missing_name {
        Ok(result) if result.is_error => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
        Ok(result) => {
            panic!("a missing required generated argument must stay an error: {result:?}")
        }
    };
    assert!(
        missing_name.contains("name")
            || missing_name.contains("required")
            || missing_name.contains("Invalid")
            || missing_name.contains("input schema")
            || missing_name.contains("inputSchema"),
        "omitting only the required sibling must stay a handler-visible refusal: {missing_name}"
    );

    let injected_prompt = client
        .get_prompt(
            "compose_greeting",
            HashMap::from([("name".to_owned(), "alpha".to_owned())]),
        )
        .expect("omitting defaulted prompt arguments must still compose echo and info://server");
    assert!(
        injected_prompt
            .messages
            .iter()
            .any(|message| match &message.content {
                LegacyContent::Text { text, .. } => {
                    text.starts_with("compose:alpha|") && text.contains("echo-server")
                }
                _ => false,
            }),
        "prompt defaults must inject echo and info://server: {injected_prompt:?}"
    );

    client
        .close()
        .expect("legacy-only stdio default-parameter client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_legacy_stdio_roots_callback_reaches_context() {
    let callback_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handlers = legacy_2024::LegacyReverseRequestHandlers::new().with_roots_list({
        let callback_calls = Arc::clone(&callback_calls);
        move |_cx, _cancellation, _params| {
            callback_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Box::pin(async {
                Ok(legacy_2024::ListRootsResult::new(vec![
                    legacy_2024::Root::with_name("file:///workspace", "workspace"),
                ]))
            })
        }
    });
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("legacy callback runtime builds");
    runtime.block_on(async move {
        let cx = Cx::current().expect("legacy callback runtime installs its Cx");
        let mut client = connect_legacy_stdio_to_shipped_echo_server_with_reverse_handlers(
            "legacy-only",
            handlers,
        )
        .expect("the roots callback is configured before exact legacy initialization");
        let result = client
            .call_tool_with_cx(&cx, "client_root_uri", json!({}))
            .await
            .expect("the sealed legacy facade services roots/list before its typed tool result");
        assert!(!result.is_error);
        assert!(matches!(
            result.content.first(),
            Some(LegacyContent::Text { text, .. }) if text == "file:///workspace"
        ));
        assert_eq!(
            callback_calls.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the tool's context authority issues exactly one roots/list callback"
        );
        client.close().expect("legacy roots client cleanup");
    });
}

#[cfg(unix)]
#[test]
fn e2e_public_legacy_stdio_roots_without_capability_has_no_callback_authority() {
    // This differs from the positive path only by omitting its roots callback.
    // The builder consequently omits the roots capability before initialization.
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("legacy missing-roots runtime builds");
    runtime.block_on(async move {
        let cx = Cx::current().expect("legacy missing-roots runtime installs its Cx");
        let mut client = connect_legacy_stdio_to_shipped_echo_server_with_reverse_handlers(
            "legacy-only",
            legacy_2024::LegacyReverseRequestHandlers::new(),
        )
        .expect("the exact legacy connection without roots capability initializes");
        let result = client
            .call_tool_with_cx(&cx, "client_root_uri", json!({}))
            .await
            .expect("missing roots authority remains a typed legacy tool result");
        assert!(result.is_error);
        assert!(matches!(
            result.content.first(),
            Some(LegacyContent::Text { text, .. })
                if text == "Roots not available: client does not support roots capability"
        ));
        client.close().expect("legacy roots client cleanup");
    });
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_only_rejects_the_modern_shipped_server() {
    // This differs from the matched LegacyOnly positive only in the child
    // server's policy. The public client must not infer a legacy lifecycle.
    let result = connect_legacy_stdio_to_shipped_echo_server("modern-only");

    assert!(
        result.is_err(),
        "a LegacyOnly facade client must reject the modern server instead of selecting a foreign era"
    );
}
