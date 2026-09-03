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

#[cfg(unix)]
use fastmcp_core::block_on;
use fastmcp_protocol::{LegacyContent, LegacyResourceContent};
use fastmcp_rust::testing::prelude::*;
use fastmcp_rust::{
    AuthContext, CacheScope, CacheTtl, ContentBlock, Cx, EmbeddedResourceContents, McpContext,
    McpErrorCode, McpResult, PromptMessage, Role, StaticTokenVerifier, TokenAuthProvider,
};
#[cfg(unix)]
use fastmcp_rust::{
    Client, ClientCapabilities, ListPromptsParams, ListResourceTemplatesParams,
    ListResourcesParams, ListToolsParams, ProtocolEra, ProtocolPolicy, RequestTimeoutPolicy, auto,
    legacy_2024, modern,
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
        let cx = Cx::for_testing();
        server
            .run_transport_returning_with_cx(&cx, server_transport)
            .expect("server transport loop settles cleanly");
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

    let handle = spawn_thread(move || {
        let cx = Cx::for_testing();
        server
            .run_transport_returning_with_cx(&cx, server_transport)
            .expect("server transport loop settles cleanly");
    });

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
    // Exact 2024-11-05 admission types `cursor?: string`; an explicit null is
    // refused before authentication, so an unauthenticated probe omits it.
    let params = json!({});
    let corr = trace.log_request("tools/list", Some(&params));
    let err = client.send_request_json("tools/list", params).unwrap_err();
    trace.log_response(
        &corr,
        None::<&serde_json::Value>,
        Some(&json!({"error": err.message})),
    );
    assert_eq!(err.code, McpErrorCode::ResourceForbidden);

    // Invalid token should be rejected.
    let params = json!({ "auth": "Bearer bad-token" });
    let corr = trace.log_request("tools/list", Some(&params));
    let err = client.send_request_json("tools/list", params).unwrap_err();
    trace.log_response(
        &corr,
        None::<&serde_json::Value>,
        Some(&json!({"error": err.message})),
    );
    assert_eq!(err.code, McpErrorCode::ResourceForbidden);

    // Authorized tools/list.
    let params = json!({ "auth": "Bearer good-token" });
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
    // RFC 7009: a confidential client must authenticate to revoke its token.
    // Near-identical negative: the same call without the secret is refused.
    assert!(
        matches!(
            oauth.revoke(&access, "test-client", None),
            Err(fastmcp_rust::oauth::OAuthError::InvalidClient { .. })
        ),
        "revocation without the confidential client's secret must be refused"
    );
    oauth
        .revoke(&access, "test-client", Some(CLIENT_SECRET))
        .unwrap();
    let params = json!({ "auth": format!("Bearer {access}") });
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
            // RFC 6749 §6: a confidential client authenticates on the
            // refresh_token grant exactly as it did on the code exchange.
            client_secret: Some(CLIENT_SECRET.to_string()),
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
        let cx = Cx::for_testing();
        server
            .run_transport_returning_with_cx(&cx, server_transport)
            .expect("server transport loop settles cleanly");
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
        let cx = Cx::for_testing();
        server
            .run_transport_returning_with_cx(&cx, server_transport)
            .expect("server transport loop settles cleanly");
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
        let cx = Cx::for_testing();
        server
            .run_transport_returning_with_cx(&cx, server_transport)
            .expect("server transport loop settles cleanly");
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
        let cx = Cx::for_testing();
        server
            .run_transport_returning_with_cx(&cx, server_transport)
            .expect("server transport loop settles cleanly");
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
        let cx = Cx::for_testing();
        server
            .run_transport_returning_with_cx(&cx, server_transport)
            .expect("server transport loop settles cleanly");
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
    block_on(builder.connect_stdio_with_cx(command, &[], &cx))
        .expect("the public Auto facade client connects to the shipped stdio example")
}

#[cfg(unix)]
fn connect_modern_stdio_to_shipped_echo_server(server_policy: &str) -> McpResult<modern::Client> {
    connect_modern_stdio_to_shipped_echo_server_with_env(server_policy, &[])
}

#[cfg(unix)]
fn connect_modern_stdio_to_shipped_echo_server_with_env(
    server_policy: &str,
    extra_env: &[(&str, &str)],
) -> McpResult<modern::Client> {
    let command = shipped_echo_server_executable();
    let mut builder = modern::client_builder().env("FASTMCP_PROTOCOL_POLICY", server_policy);
    for (key, value) in extra_env {
        builder = builder.env(*key, *value);
    }
    block_on(builder.connect_stdio_with_cx(command, &[], &Cx::for_request()))
}

#[cfg(unix)]
const STDIO_COMPLETION_IDLE_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(unix)]
const STDIO_COMPLETION_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(4);
#[cfg(unix)]
const STDIO_COMPLETION_CLEANUP_BOUND: Duration = Duration::from_secs(4);

#[cfg(unix)]
const ECHO_SERVER_INSTRUCTIONS: &str =
    "A simple echo server for testing FastMCP. Try calling the 'echo' tool with a message!";

#[cfg(unix)]
fn connect_bounded_modern_stdio_to_shipped_echo_server(
    server_policy: &str,
) -> McpResult<modern::Client> {
    connect_bounded_modern_stdio_to_shipped_echo_server_with_env(server_policy, &[])
}

#[cfg(unix)]
fn connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
    server_policy: &str,
    extra_env: &[(&str, &str)],
) -> McpResult<modern::Client> {
    let command = shipped_echo_server_executable();
    let mut builder = modern::client_builder()
        .env("FASTMCP_PROTOCOL_POLICY", server_policy)
        .request_timeout_policy(
            RequestTimeoutPolicy::new(
                STDIO_COMPLETION_IDLE_TIMEOUT,
                STDIO_COMPLETION_ABSOLUTE_TIMEOUT,
            )
            .expect("the public completion timeout policy is valid"),
        );
    for (key, value) in extra_env {
        builder = builder.env(*key, *value);
    }
    block_on(builder.connect_stdio_with_cx(command, &[], &Cx::for_request()))
}

#[cfg(unix)]
struct StdioMrtrCapabilities {
    sampling: bool,
    roots: bool,
    form: bool,
    url: bool,
}

#[cfg(unix)]
fn stdio_mrtr_capabilities(requested: StdioMrtrCapabilities) -> modern::ClientCapabilities {
    let mut capabilities = modern::ClientCapabilities::default();
    if requested.sampling {
        capabilities.sampling = Some(fastmcp_protocol::SamplingCapability::default());
    }
    if requested.roots {
        capabilities.roots = serde_json::from_value(json!({})).expect("roots capability is valid");
    }
    if requested.form || requested.url {
        let mut elicitation = json!({});
        if requested.form {
            elicitation["form"] = json!({});
        }
        if requested.url {
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
    block_on(
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
            .connect_stdio_with_cx(command, &[], &Cx::for_request()),
    )
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
    connect_legacy_stdio_to_shipped_echo_server_with_env(server_policy, &[])
}

#[cfg(unix)]
fn connect_legacy_stdio_to_shipped_echo_server_with_env(
    server_policy: &str,
    extra_env: &[(&str, &str)],
) -> McpResult<legacy_2024::Client> {
    connect_legacy_stdio_to_shipped_echo_server_with_reverse_handlers_and_env(
        server_policy,
        legacy_2024::LegacyReverseRequestHandlers::new(),
        extra_env,
    )
}

#[cfg(unix)]
fn connect_legacy_stdio_to_shipped_echo_server_with_reverse_handlers(
    server_policy: &str,
    handlers: legacy_2024::LegacyReverseRequestHandlers,
) -> McpResult<legacy_2024::Client> {
    connect_legacy_stdio_to_shipped_echo_server_with_reverse_handlers_and_env(
        server_policy,
        handlers,
        &[],
    )
}

#[cfg(unix)]
fn connect_legacy_stdio_to_shipped_echo_server_with_reverse_handlers_and_env(
    server_policy: &str,
    handlers: legacy_2024::LegacyReverseRequestHandlers,
    extra_env: &[(&str, &str)],
) -> McpResult<legacy_2024::Client> {
    let command = shipped_echo_server_executable();
    let mut builder = legacy_2024::client_builder()
        .env("FASTMCP_PROTOCOL_POLICY", server_policy)
        .reverse_request_handlers(handlers);
    for (key, value) in extra_env {
        builder = builder.env(*key, *value);
    }
    assert_eq!(
        builder.protocol_policy(),
        legacy_2024::ProtocolPolicy::LegacyOnly
    );

    block_on(builder.connect_stdio_with_cx(command, &[], &Cx::for_request()))
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
    // A modern catalog carries the required `ttlMs`/`cacheScope` directives,
    // which the flattened exact-2024 convenience shape cannot express. The
    // typed verb is the supported modern path and preserves them.
    let listed = client
        .list_tools_typed(None)
        .expect("the selected modern stdio client accepts tools/list");
    let fastmcp_rust::CoreResult::Final(modern::FinalCoreResult::ToolsList { result, .. }) = listed
    else {
        panic!("a modern selection returns the final tools/list result");
    };
    assert!(
        result.payload.tools.iter().any(|tool| tool.name == "echo"),
        "the modern tools/list result must expose the shipped echo tool"
    );
    // Planted negative pinning the projection contract: the exact-2024
    // convenience verb refuses the same modern catalog rather than silently
    // dropping its cache directives.
    let refused = client
        .list_tools()
        .expect_err("the legacy convenience verb cannot represent modern cache fields");
    assert_eq!(refused.code, McpErrorCode::InvalidRequest);
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
fn e2e_public_stdio_modern_discovery_retains_instructions() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");
    assert_eq!(
        client
            .instructions()
            .expect("modern discovery exposes handshake instructions"),
        Some(ECHO_SERVER_INSTRUCTIONS),
        "live stdio modern discovery must retain the shipped echo instructions"
    );
    client
        .close()
        .expect("instructed modern stdio client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_discovery_retains_instructions_peer_stays_bare() {
    let mut bare = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_NO_INSTRUCTIONS", "1")],
    )
    .expect("a ModernOnly facade client connects to the bare echo peer");
    assert_eq!(
        bare.instructions()
            .expect("modern discovery exposes the missing-instructions observable"),
        None,
        "changing only the missing instructions must keep the peer bare"
    );
    bare.close().expect("bare modern stdio client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_discovery_retains_implementation_identity() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");
    let discovery = client
        .server_discovery()
        .expect("modern discovery exposes handshake identity");
    let identified = discovery
        .implementation()
        .expect("configured modern discovery must retain Implementation identity");
    assert_eq!(identified.name, "echo-server");
    assert_eq!(identified.version, "1.0.0");
    assert_eq!(identified.title.as_deref(), Some("FastMCP Echo"));
    assert_eq!(
        identified.description.as_deref(),
        Some("A simple echo server for testing FastMCP.")
    );
    assert_eq!(
        identified.website_url.as_ref().map(|uri| uri.as_str()),
        Some("https://example.test/fastmcp")
    );
    assert_eq!(
        identified.icons.first().map(|icon| icon.src.as_str()),
        Some("https://example.test/echo-icon.png"),
        "live stdio discovery must retain the shipped echo icon: {identified:?}"
    );
    client
        .close()
        .expect("identified modern stdio client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_discovery_retains_implementation_identity_peer_stays_bare() {
    let mut bare = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_NO_IDENTITY", "1")],
    )
    .expect("a ModernOnly facade client connects to the bare-identity echo peer");
    let discovery = bare
        .server_discovery()
        .expect("modern discovery exposes the missing-identity observable");
    assert!(
        discovery.implementation().is_none(),
        "changing only the missing identity extras must keep discovery name/version-only: {:?}",
        discovery.implementation()
    );
    assert_eq!(
        discovery
            .server_info()
            .map(|info| (info.name.as_str(), info.version.as_str())),
        Some(("echo-server", "1.0.0")),
        "the bare peer must still advertise name and version"
    );
    bare.close()
        .expect("bare-identity modern stdio client cleanup");
}

#[cfg(unix)]
fn connect_bounded_modern_stdio_with_client_title(
    server_policy: &str,
    client_name: &str,
    title: Option<&str>,
) -> McpResult<modern::Client> {
    let command = shipped_echo_server_executable();
    let mut builder = modern::client_builder()
        .client_info(client_name, "1.0.0")
        .env("FASTMCP_PROTOCOL_POLICY", server_policy)
        .request_timeout_policy(
            RequestTimeoutPolicy::new(
                STDIO_COMPLETION_IDLE_TIMEOUT,
                STDIO_COMPLETION_ABSOLUTE_TIMEOUT,
            )
            .expect("the public completion timeout policy is valid"),
        );
    if let Some(title) = title {
        builder = builder.title(title);
    }
    block_on(builder.connect_stdio_with_cx(command, &[], &Cx::for_request()))
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_client_implementation_is_visible_to_handler() {
    let mut client = connect_bounded_modern_stdio_with_client_title(
        "modern-only",
        "e2e-stdio-client-identity",
        Some("Client Title"),
    )
    .expect("a titled ModernOnly facade client completes live modern discovery");
    let reported = client
        .call_tool("client_identity", json!({}))
        .expect("live modern stdio client_identity must reach the shipped handler");
    assert!(
        reported.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => {
                text == "name=e2e-stdio-client-identity|title=Client Title"
            }
            _ => false,
        }),
        "live stdio must attach ClientBuilder title onto McpContext: {reported:?}"
    );
    client
        .close()
        .expect("identified modern stdio client-identity cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_client_implementation_peer_stays_bare() {
    let mut bare = connect_bounded_modern_stdio_with_client_title(
        "modern-only",
        "e2e-stdio-client-identity-bare",
        None,
    )
    .expect("a name/version-only ModernOnly facade client connects to the echo peer");
    let reported = bare
        .call_tool("client_identity", json!({}))
        .expect("bare modern stdio client_identity must still reach the shipped handler");
    assert!(
        reported.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => {
                text == "name=e2e-stdio-client-identity-bare|title=none"
            }
            _ => false,
        }),
        "changing only the missing client title must keep handler-visible extras bare: {reported:?}"
    );
    bare.close()
        .expect("bare modern stdio client-identity cleanup");
}

#[cfg(unix)]
fn connect_legacy_stdio_with_client_name(
    server_policy: &str,
    client_name: &str,
) -> McpResult<legacy_2024::Client> {
    let command = shipped_echo_server_executable();
    block_on(
        legacy_2024::client_builder()
            .client_info(client_name, "1.0.0")
            .env("FASTMCP_PROTOCOL_POLICY", server_policy)
            .request_timeout_policy(
                RequestTimeoutPolicy::new(
                    STDIO_COMPLETION_IDLE_TIMEOUT,
                    STDIO_COMPLETION_ABSOLUTE_TIMEOUT,
                )
                .expect("the public completion timeout policy is valid"),
            )
            .connect_stdio_with_cx(command, &[], &Cx::for_request()),
    )
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_client_info_is_visible_to_handler() {
    let mut client =
        connect_legacy_stdio_with_client_name("legacy-only", "e2e-stdio-legacy-client-identity")
            .expect("a named LegacyOnly facade client completes live exact-2024 initialize");
    let reported = client
        .call_tool("client_identity", json!({}))
        .expect("live exact-2024 stdio client_identity must reach the shipped handler");
    assert_eq!(
        stdio_legacy_tool_text(&reported),
        Some("name=e2e-stdio-legacy-client-identity|title=none"),
        "live exact-2024 stdio must attach initialize clientInfo onto McpContext: {reported:?}"
    );
    client
        .close()
        .expect("named exact-2024 stdio client-identity cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_client_info_peer_changes_only_the_name() {
    let mut other = connect_legacy_stdio_with_client_name(
        "legacy-only",
        "e2e-stdio-legacy-client-identity-other",
    )
    .expect("a differently named LegacyOnly facade client connects to the echo peer");
    let reported = other
        .call_tool("client_identity", json!({}))
        .expect("the other exact-2024 stdio client_identity must still reach the shipped handler");
    assert_eq!(
        stdio_legacy_tool_text(&reported),
        Some("name=e2e-stdio-legacy-client-identity-other|title=none"),
        "changing only the initialize client name must change the handler-visible identity: {reported:?}"
    );
    other
        .close()
        .expect("other exact-2024 stdio client-identity cleanup");
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
fn e2e_public_stdio_modern_composes_nested_prompt() {
    let mut client = connect_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    let composed = client
        .call_tool("compose_prompt", json!({"name": "alpha"}))
        .expect("live modern stdio compose_prompt must nest the greeting prompt");
    assert!(
        composed.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => {
                text == "compose-prompt:Please greet alpha in a friendly way."
            }
            _ => false,
        }),
        "compose_prompt must retain the nested greeting text: {composed:?}"
    );

    let missing = client.call_tool(
        "compose_prompt",
        json!({
            "name": "alpha",
            "prompt": "stdio-e2e-missing",
        }),
    );
    let missing = match missing {
        Ok(result) if result.is_error => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
        Ok(result) => panic!("changing only the nested prompt name must refuse: {result:?}"),
    };
    assert!(
        missing.contains("stdio-e2e-missing")
            || missing.contains("compose-nested-prompt")
            || missing.contains("not found"),
        "the nested unknown prompt must stay a handler-visible refusal: {missing}"
    );

    client
        .close()
        .expect("modern-only stdio compose-prompt client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_resource_and_prompt_compose_nested_prompt() {
    let mut client = connect_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");

    let resource = client
        .read_resource("info://compose-prompt")
        .expect("live modern stdio info://compose-prompt must nest greeting");
    assert!(
        resource.contents.iter().any(|content| match content {
            EmbeddedResourceContents::Text { text, .. } => {
                text == "compose-prompt:Please greet alpha in a friendly way."
            }
            _ => false,
        }),
        "info://compose-prompt must retain the nested greeting text: {resource:?}"
    );
    let missing_resource = client
        .read_resource("info://compose-prompt-missing")
        .expect_err("changing only the nested prompt name must refuse the resource compose");
    let missing_resource = format!("{missing_resource:?}");
    assert!(
        missing_resource.contains("stdio-e2e-missing")
            || missing_resource.contains("compose-nested-prompt")
            || missing_resource.contains("not found"),
        "the nested unknown prompt must stay a handler-visible refusal: {missing_resource}"
    );

    let prompt = client
        .get_prompt(
            "compose_from_prompt",
            HashMap::from([("name".to_owned(), "alpha".to_owned())]),
        )
        .expect("live modern stdio compose_from_prompt must nest greeting");
    assert!(
        prompt
            .messages
            .iter()
            .any(|message| match &message.content {
                ContentBlock::Text { text, .. } => {
                    text == "compose-prompt:Please greet alpha in a friendly way."
                }
                _ => false,
            }),
        "compose_from_prompt must retain the nested greeting text: {prompt:?}"
    );
    let missing_prompt = client
        .get_prompt(
            "compose_from_prompt",
            HashMap::from([
                ("name".to_owned(), "alpha".to_owned()),
                ("prompt".to_owned(), "stdio-e2e-missing".to_owned()),
            ]),
        )
        .expect_err("changing only the nested prompt name must refuse the prompt compose");
    let missing_prompt = format!("{missing_prompt:?}");
    assert!(
        missing_prompt.contains("stdio-e2e-missing")
            || missing_prompt.contains("compose-nested-prompt")
            || missing_prompt.contains("not found"),
        "the nested unknown prompt must stay a handler-visible refusal: {missing_prompt}"
    );

    client
        .close()
        .expect("modern-only stdio resource/prompt compose-prompt client cleanup");
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
    assert!(
        client
            .try_next_subscription_event(&cx, &cancellation)
            .expect("the live subscription remains valid after the catalog change")
            .is_none(),
        "one catalog mutation must emit exactly one modern subscription notification"
    );
    client
        .close()
        .expect("modern-only stdio list_changed client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_hide_echo_refuses_later_call_and_show_restores() {
    let mut client = connect_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client connects to the shipped echo server");

    let before = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("the shipped echo tool must be callable before hide_echo");
    assert!(
        before.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text.contains("alpha"),
            _ => false,
        }),
        "the live modern stdio echo must retain the handler text: {before:?}"
    );

    let hidden = client
        .call_tool("hide_echo", json!({}))
        .expect("disabling the shipped echo tool must complete");
    assert!(
        hidden.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "hidden",
            _ => false,
        }),
        "modern stdio session state must retain disable_tool: {hidden:?}"
    );

    let disabled = client.call_tool("echo", json!({"message": "beta"}));
    let disabled = match disabled {
        Ok(result) => {
            assert!(
                result.is_error,
                "hide_echo must turn a later echo call into a tool-level error: {result:?}"
            );
            format!("{result:?}")
        }
        Err(error) => format!("{error:?}"),
    };
    assert!(
        disabled.contains("disabled")
            || disabled.contains("echo")
            || disabled.contains("Method not found")
            || disabled.contains("MethodNotFound"),
        "the refused echo call must name the session-disabled tool: {disabled}"
    );

    let peer = client
        .call_tool("add", json!({"a": 2, "b": 3}))
        .expect("changing only the missing hide must keep an undisabled tool callable");
    assert!(
        peer.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text.contains('5'),
            _ => false,
        }),
        "an undisabled peer tool must still complete after hide_echo: {peer:?}"
    );

    let shown = client
        .call_tool("show_echo", json!({}))
        .expect("re-enabling the shipped echo tool must complete");
    assert!(
        shown.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "shown",
            _ => false,
        }),
        "modern stdio session state must retain enable_tool: {shown:?}"
    );
    let restored = client
        .call_tool("echo", json!({"message": "gamma"}))
        .expect("show_echo must restore a later echo call on the same modern session");
    assert!(
        restored.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text.contains("gamma"),
            _ => false,
        }),
        "the restored modern stdio echo must retain the handler text: {restored:?}"
    );

    client
        .close()
        .expect("modern-only stdio hide_echo client cleanup");
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
fn e2e_public_stdio_modern_resource_template_completion_is_retained_and_unregistered_template_is_refused()
 {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client completes live modern discovery");
    let params = modern::CompletionParams {
        reference: modern::CompletionReference::Resource {
            uri: "note://{name}".to_owned(),
        },
        argument: modern::FinalCompletionArgument {
            name: "name".to_owned(),
            value: "al".to_owned(),
        },
        context: None,
    };

    let result = client
        .complete(params.clone())
        .expect("the typed ModernOnly client reaches the shipped note template provider");
    assert_eq!(
        result.completion.values,
        vec!["alice".to_owned()],
        "the exact FinalCompletionResult retains the note template provider value: {result:?}"
    );
    assert_eq!(
        result.completion.total,
        Some(modern::JsonInteger::from(1_i64))
    );
    assert_eq!(result.completion.has_more, Some(false));

    let mut undeclared_argument = params.clone();
    undeclared_argument.argument.name = "undeclared".to_owned();
    let undeclared = client
        .complete(undeclared_argument)
        .expect_err("only an undeclared template variable is rejected");
    assert_eq!(undeclared.code, McpErrorCode::InvalidParams);

    let mut other_template = params;
    other_template.reference = modern::CompletionReference::Resource {
        uri: "memo://{name}".to_owned(),
    };
    let missing_provider = client
        .complete(other_template)
        .expect_err("changing only the template URI must refuse a missing provider");
    assert_eq!(missing_provider.code, McpErrorCode::InvalidParams);

    let greeting = client
        .complete(modern::CompletionParams {
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
        })
        .expect("the note provider must leave the greeting prompt provider usable");
    assert!(
        greeting
            .completion
            .values
            .first()
            .is_some_and(|value| value.starts_with("stdio-completion-")),
        "the greeting provider must still complete after note template completion: {greeting:?}"
    );

    client
        .close()
        .expect("modern note-completion stdio client cleanup");
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
    let mut client = block_on(
        modern::client_builder()
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
                        Box::pin(async {
                            Ok(modern::FinalEmbeddedRootsListResult { roots: vec![] })
                        })
                    },
                ),
            )
            .connect_stdio_with_cx(shipped_echo_server_executable(), &[], &Cx::for_request()),
    )
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
fn e2e_public_stdio_modern_sampling_elicitation_keep_input_required() {
    let mut client = connect_bounded_modern_stdio_with_mrtr(
        "modern-only",
        stdio_mrtr_capabilities(StdioMrtrCapabilities {
            sampling: true,
            roots: true,
            form: true,
            url: true,
        }),
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
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_sampling_elicitation_fail_closed_without_capability() {
    let mut no_sampling = connect_bounded_modern_stdio_with_mrtr(
        "modern-only",
        stdio_mrtr_capabilities(StdioMrtrCapabilities {
            sampling: false,
            roots: true,
            form: true,
            url: true,
        }),
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
        stdio_mrtr_capabilities(StdioMrtrCapabilities {
            sampling: true,
            roots: true,
            form: true,
            url: false,
        }),
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
        stdio_mrtr_capabilities(StdioMrtrCapabilities {
            sampling: true,
            roots: true,
            form: true,
            url: true,
        }),
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
fn e2e_public_stdio_legacy_typed_verbs_honor_pre_send_cancellation() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client connects before pre-send cancellation");
    let cx = Cx::for_request();
    let cancellation = fastmcp_rust::McpRequestCancellation::new();
    cancellation.cancel();
    let list = client
        .list_tools_with_cancellation(&cx, &cancellation, None)
        .expect_err("pre-send list_tools cancellation must reject locally");
    assert_eq!(list.code, McpErrorCode::RequestCancelled);
    let tagged = client
        .list_tools_with_params_and_cancellation(
            &cx,
            &cancellation,
            ListToolsParams {
                include_tags: Some(vec!["demo".to_owned()]),
                ..ListToolsParams::default()
            },
        )
        .expect_err("pre-send tagged list_tools cancellation must reject locally");
    assert_eq!(tagged.code, McpErrorCode::RequestCancelled);
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
        .read_resource_with_cancellation(&cx, &cancellation, "info://server")
        .expect_err("pre-send read_resource cancellation must reject locally");
    assert_eq!(resource.code, McpErrorCode::RequestCancelled);
    let prompt = client
        .get_prompt_with_cancellation(&cx, &cancellation, "greeting", HashMap::new())
        .expect_err("pre-send get_prompt cancellation must reject locally");
    assert_eq!(prompt.code, McpErrorCode::RequestCancelled);
    let completion = client
        .complete_with_cancellation(
            &cx,
            &cancellation,
            legacy_2024::LegacyCompletionParams {
                reference: legacy_2024::LegacyCompletionReference::Prompt {
                    name: "greeting".to_owned(),
                },
                argument: legacy_2024::LegacyCompletionArgument {
                    name: "name".to_owned(),
                    value: "co".to_owned(),
                },
                meta: None,
            },
        )
        .expect_err("pre-send complete cancellation must reject locally");
    assert_eq!(completion.code, McpErrorCode::RequestCancelled);
    let ping = client
        .ping_with_cancellation(&cx, &cancellation)
        .expect_err("pre-send ping cancellation must reject locally");
    assert_eq!(ping.code, McpErrorCode::RequestCancelled);

    let admitted = fastmcp_rust::McpRequestCancellation::new();
    let echoed = client
        .call_tool_with_cancellation(&cx, &admitted, "echo", json!({"message": "hi"}))
        .expect("an uncancelled exact-2024 tools/call still reaches the handler");
    assert!(matches!(
        echoed.content.first(),
        Some(LegacyContent::Text { text, .. }) if text == "hi"
    ));
    client
        .ping()
        .expect("exact-2024 stdio ping remains usable after local cancellation");
    client
        .list_tools()
        .expect("the same exact-2024 stdio session remains usable after local cancellation");
    client
        .close()
        .expect("exact-2024 stdio pre-send cancellation client cleanup reaps the live subprocess");
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
#[cfg(feature = "tasks")]
#[test]
fn e2e_public_stdio_modern_tasks_listen_retains_status_and_catalog_listen_refuses_task_ids() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client starts the shipped caller-owned Task service");

    let created = client
        .call_tool_outcome("durable_task", json!({}))
        .expect("the typed ModernOnly facade client creates one durable Task");
    let modern::FinalToolCallOutcome::Task(created) = created else {
        panic!("the task-capable tool returns the exact final Task result branch");
    };
    let task_id = created.task.base().task_id.clone();

    let mut catalog_with_tasks = modern::SubscriptionFilter {
        tools_list_changed: Some(true),
        ..modern::SubscriptionFilter::default()
    };
    modern::set_task_subscription_ids(&mut catalog_with_tasks, vec![task_id.clone()])
        .expect("the public Tasks filter composes beside a catalog filter");
    let catalog_refusal = client
        .open_subscriptions_listener(catalog_with_tasks)
        .expect_err("catalog listen must refuse taskIds");
    assert!(
        catalog_refusal
            .to_string()
            .contains("open_final_task_subscription_listener")
            || catalog_refusal.to_string().contains("taskIds"),
        "changing only the added taskIds must keep catalog listen refused: {catalog_refusal:?}"
    );

    let mut filter = modern::SubscriptionFilter::default();
    modern::set_task_subscription_ids(&mut filter, vec![task_id.clone()])
        .expect("the public Tasks filter is valid");
    client
        .open_final_task_subscription_listener(filter)
        .expect("live stdio must admit an incremental official Tasks listener");

    let cx = Cx::for_request();
    let cancellation = modern::McpRequestCancellation::new();
    let acknowledgement = client
        .next_final_task_subscription_event(&cx, &cancellation)
        .expect("official Tasks listen must emit its acknowledgement");
    assert!(
        matches!(
            acknowledgement,
            modern::StdioTaskSubscriptionEvent::Acknowledged(ref accepted)
                if modern::task_subscription_ids(accepted)
                    .expect("acknowledged Tasks filter stays valid")
                    .as_deref()
                    == Some([task_id.clone()].as_slice())
        ),
        "the first incremental Tasks listen record must be the accepted taskIds: {acknowledgement:?}"
    );

    client
        .cancel_task(task_id.clone())
        .expect("typed tasks/cancel acknowledges the durable cancellation request");

    let notification_deadline = Instant::now() + STDIO_COMPLETION_ABSOLUTE_TIMEOUT;
    loop {
        let event = client
            .next_final_task_subscription_event(&cx, &cancellation)
            .expect("official Tasks listen must retain later status updates");
        match event {
            modern::StdioTaskSubscriptionEvent::Notification(notification)
                if matches!(notification.params.task, modern::FinalTask::Cancelled(_)) =>
            {
                assert_eq!(
                    notification.params.task.base().task_id,
                    task_id,
                    "the Tasks notification must keep the created id"
                );
                break;
            }
            modern::StdioTaskSubscriptionEvent::Notification(_)
            | modern::StdioTaskSubscriptionEvent::Acknowledged(_) => {
                assert!(
                    Instant::now() < notification_deadline,
                    "the caller-owned supervisor publishes cancellation within the public bound"
                );
            }
            modern::StdioTaskSubscriptionEvent::Terminal => {
                panic!("the live Tasks listener must retain cancellation before terminal")
            }
        }
    }

    let observed = client
        .get_task(task_id)
        .expect("typed tasks/get remains usable after the listener observed cancellation");
    assert!(
        matches!(observed.task, modern::FinalTask::Cancelled(_)),
        "the same session must still admit tasks/get after listen: {observed:?}"
    );

    client
        .close()
        .expect("modern Tasks listen stdio client cleanup");
}

#[cfg(unix)]
#[cfg(feature = "tasks")]
#[test]
fn e2e_public_stdio_catalog_and_tasks_listen_stay_live_on_the_same_client() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client starts the shipped caller-owned Task service");

    let created = client
        .call_tool_outcome("durable_task", json!({}))
        .expect("the typed ModernOnly facade client creates one durable Task");
    let modern::FinalToolCallOutcome::Task(created) = created else {
        panic!("the task-capable tool returns the exact final Task result branch");
    };
    let task_id = created.task.base().task_id.clone();

    client
        .open_subscriptions_listener(modern::SubscriptionFilter {
            tools_list_changed: Some(true),
            ..modern::SubscriptionFilter::default()
        })
        .expect("live stdio must admit a catalog listener while official Tasks remain unused");

    let cx = Cx::for_request();
    let cancellation = modern::McpRequestCancellation::new();
    let catalog_ack = client
        .next_subscription_event(&cx, &cancellation)
        .expect("catalog listen must emit its acknowledgement");
    assert!(
        matches!(
            catalog_ack,
            modern::StdioSubscriptionEvent::Acknowledged(ref filter)
                if filter.tools_list_changed == Some(true)
        ),
        "the first catalog listen record must be the accepted filter: {catalog_ack:?}"
    );

    let mut task_filter = modern::SubscriptionFilter::default();
    modern::set_task_subscription_ids(&mut task_filter, vec![task_id.clone()])
        .expect("the public Tasks filter is valid");
    client
        .open_final_task_subscription_listener(task_filter)
        .expect(
            "the same stdio Client must admit official Tasks listen while catalog listen is live",
        );

    let task_ack = client
        .next_final_task_subscription_event(&cx, &cancellation)
        .expect("official Tasks listen must emit its acknowledgement");
    assert!(
        matches!(
            task_ack,
            modern::StdioTaskSubscriptionEvent::Acknowledged(ref accepted)
                if modern::task_subscription_ids(accepted)
                    .expect("acknowledged Tasks filter stays valid")
                    .as_deref()
                    == Some([task_id.clone()].as_slice())
        ),
        "the first incremental Tasks listen record must be the accepted taskIds: {task_ack:?}"
    );

    let hidden = client
        .call_tool("hide_echo", json!({}))
        .expect("disabling a peer tool must complete while both listeners are live");
    assert!(
        hidden.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text == "hidden",
            _ => false,
        }),
        "the same stdio Client must still admit tools/call while both listeners are live: {hidden:?}"
    );

    let changed = client
        .next_subscription_event(&cx, &cancellation)
        .expect("catalog listen must retain tools/list_changed while Tasks listen is live");
    assert!(
        matches!(
            changed,
            modern::StdioSubscriptionEvent::Notification(
                modern::ServerNotification::ToolsListChanged(_)
            )
        ),
        "live stdio must retain catalog list_changed on the same client as Tasks listen: {changed:?}"
    );

    client
        .cancel_task(task_id.clone())
        .expect("typed tasks/cancel remains usable while both listeners are live");

    let notification_deadline = Instant::now() + STDIO_COMPLETION_ABSOLUTE_TIMEOUT;
    loop {
        let event = client
            .next_final_task_subscription_event(&cx, &cancellation)
            .expect("official Tasks listen must retain later status updates while catalog listen is live");
        match event {
            modern::StdioTaskSubscriptionEvent::Notification(notification)
                if matches!(notification.params.task, modern::FinalTask::Cancelled(_)) =>
            {
                assert_eq!(
                    notification.params.task.base().task_id,
                    task_id,
                    "the Tasks notification must keep the created id"
                );
                break;
            }
            modern::StdioTaskSubscriptionEvent::Notification(_)
            | modern::StdioTaskSubscriptionEvent::Acknowledged(_) => {
                assert!(
                    Instant::now() < notification_deadline,
                    "the caller-owned supervisor publishes cancellation within the public bound"
                );
            }
            modern::StdioTaskSubscriptionEvent::Terminal => {
                panic!("the live Tasks listener must retain cancellation before terminal")
            }
        }
    }

    let observed = client
        .get_task(task_id)
        .expect("typed tasks/get remains usable after both listeners observed their events");
    assert!(
        matches!(observed.task, modern::FinalTask::Cancelled(_)),
        "the same stdio client must still admit tasks/get after dual listen: {observed:?}"
    );

    client
        .close()
        .expect("modern dual-listen stdio client cleanup");
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
    // The router redacts every handler-returned internal error toward the
    // peer (router `sanitize_handler_error`); the exact macro hint stays in
    // the server incident log, never on the wire.
    assert_eq!(legacy_resource.code, McpErrorCode::InternalError);
    assert_eq!(legacy_resource.message, "Internal server error");
    let legacy_prompt = client
        .get_prompt(
            "mrtr_prompt",
            HashMap::from([("mode".to_owned(), "terminal".to_owned())]),
        )
        .expect_err("exact-2024 cannot activate the final MRTR prompt handler");
    assert_eq!(legacy_prompt.code, McpErrorCode::InternalError);
    assert_eq!(legacy_prompt.message, "Internal server error");
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
fn e2e_public_stdio_legacy_composes_nested_prompt() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    let composed = client
        .call_tool("compose_prompt", json!({"name": "alpha"}))
        .expect("live exact-2024 stdio compose_prompt must nest the greeting prompt");
    assert!(
        composed.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => {
                text == "compose-prompt:Please greet alpha in a friendly way."
            }
            _ => false,
        }),
        "compose_prompt must retain the nested greeting text: {composed:?}"
    );

    let missing = client.call_tool(
        "compose_prompt",
        json!({
            "name": "alpha",
            "prompt": "stdio-e2e-missing",
        }),
    );
    let missing = match missing {
        Ok(result) if result.is_error => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
        Ok(result) => panic!("changing only the nested prompt name must refuse: {result:?}"),
    };
    assert!(
        missing.contains("stdio-e2e-missing")
            || missing.contains("compose-nested-prompt")
            || missing.contains("not found"),
        "the nested unknown prompt must stay a handler-visible refusal: {missing}"
    );

    client
        .close()
        .expect("legacy-only stdio compose-prompt client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_resource_and_prompt_compose_nested_prompt() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    let resource = client
        .read_resource("info://compose-prompt")
        .expect("live exact-2024 stdio info://compose-prompt must nest greeting");
    assert!(
        resource.contents.iter().any(|content| match content {
            LegacyResourceContent::Text { text, .. } => {
                text == "compose-prompt:Please greet alpha in a friendly way."
            }
            _ => false,
        }),
        "info://compose-prompt must retain the nested greeting text: {resource:?}"
    );
    let missing_resource = client
        .read_resource("info://compose-prompt-missing")
        .expect_err("changing only the nested prompt name must refuse the resource compose");
    let missing_resource = format!("{missing_resource:?}");
    assert!(
        missing_resource.contains("stdio-e2e-missing")
            || missing_resource.contains("compose-nested-prompt")
            || missing_resource.contains("not found"),
        "the nested unknown prompt must stay a handler-visible refusal: {missing_resource}"
    );

    let prompt = client
        .get_prompt(
            "compose_from_prompt",
            HashMap::from([("name".to_owned(), "alpha".to_owned())]),
        )
        .expect("live exact-2024 stdio compose_from_prompt must nest greeting");
    assert!(
        prompt
            .messages
            .iter()
            .any(|message| match &message.content {
                LegacyContent::Text { text, .. } => {
                    text == "compose-prompt:Please greet alpha in a friendly way."
                }
                _ => false,
            }),
        "compose_from_prompt must retain the nested greeting text: {prompt:?}"
    );
    let missing_prompt = client
        .get_prompt(
            "compose_from_prompt",
            HashMap::from([
                ("name".to_owned(), "alpha".to_owned()),
                ("prompt".to_owned(), "stdio-e2e-missing".to_owned()),
            ]),
        )
        .expect_err("changing only the nested prompt name must refuse the prompt compose");
    let missing_prompt = format!("{missing_prompt:?}");
    assert!(
        missing_prompt.contains("stdio-e2e-missing")
            || missing_prompt.contains("compose-nested-prompt")
            || missing_prompt.contains("not found"),
        "the nested unknown prompt must stay a handler-visible refusal: {missing_prompt}"
    );

    client
        .close()
        .expect("legacy-only stdio resource/prompt compose-prompt client cleanup");
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
    let mut client = block_on(
        legacy_2024::client_builder()
            .env("FASTMCP_PROTOCOL_POLICY", "legacy-only")
            .request_timeout_policy(
                RequestTimeoutPolicy::new(
                    STDIO_COMPLETION_IDLE_TIMEOUT,
                    STDIO_COMPLETION_ABSOLUTE_TIMEOUT,
                )
                .expect("the public handler-timeout client policy is valid"),
            )
            .connect_stdio_with_cx(shipped_echo_server_executable(), &[], &Cx::for_request()),
    )
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
fn e2e_public_stdio_legacy_output_schema_is_listed_and_call_stays_unstructured() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    let listed = client
        .list_tools()
        .expect("live exact-2024 stdio must list the output-schema tools");
    let structured = listed
        .iter()
        .find(|tool| tool.name == "structured_echo")
        .expect("structured_echo must remain on the live catalog");
    let echo = listed
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
        .expect("live exact-2024 stdio must admit the structured output tool");
    assert!(
        called.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text == "tool:alpha",
            _ => false,
        }),
        "the structured tool must still author text content: {called:?}"
    );

    client
        .close()
        .expect("legacy-only stdio output-schema client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_rich_content_retains_image_and_peer_stays_text() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    let rich = client
        .call_tool("rich_echo", json!({}))
        .expect("live exact-2024 stdio must retain the representable image block");
    assert!(
        rich.content.iter().any(|content| match content {
            LegacyContent::Image {
                data, mime_type, ..
            } => data == "e2eimage" && mime_type == "image/png",
            _ => false,
        }),
        "tools/call must retain the authored image block: {rich:?}"
    );
    assert!(
        rich.content
            .iter()
            .all(|content| !matches!(content, LegacyContent::Text { .. })),
        "exact-2024 must not invent a text projection of the image: {rich:?}"
    );

    let peer = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("the text-only echo peer must still be callable");
    assert!(
        peer.content
            .iter()
            .all(|content| matches!(content, LegacyContent::Text { .. })),
        "changing only the missing rich content must keep the echo peer text-only: {peer:?}"
    );

    client
        .close()
        .expect("legacy-only stdio rich-content client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_initialize_retains_instructions() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");
    assert_eq!(
        client.instructions(),
        Some(ECHO_SERVER_INSTRUCTIONS),
        "live exact-2024 stdio initialize must retain the shipped echo instructions"
    );
    client
        .close()
        .expect("instructed legacy stdio client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_notification_tools_list_changed_is_retained() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    let hidden = client
        .call_tool("hide_echo", json!({}))
        .expect("live exact-2024 stdio must admit hide_echo");
    assert!(
        hidden.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text == "hidden",
            _ => false,
        }),
        "hide_echo must disable the echo tool: {hidden:?}"
    );

    let notifications = client
        .take_server_notifications()
        .expect("exact-2024 stdio notifications must decode");
    assert_eq!(
        notifications
            .iter()
            .filter(|notification| matches!(
                notification,
                legacy_2024::ServerNotification::ToolsListChanged
            ))
            .count(),
        1,
        "one catalog mutation must emit exactly one exact-2024 tools/list_changed notification: {notifications:?}"
    );

    client
        .close()
        .expect("legacy-only stdio list_changed client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_notification_tools_list_changed_peer_stays_silent() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("the text-only echo peer must still be callable");
    let notifications = client
        .take_server_notifications()
        .expect("exact-2024 stdio notifications must decode");
    assert!(
        !notifications.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::ToolsListChanged
        )),
        "changing only the missing catalog mutation must keep tools/list_changed silent: {notifications:?}"
    );

    client
        .close()
        .expect("legacy-only stdio silent list_changed client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_notification_ctx_info_is_retained() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    client
        .set_log_level(legacy_2024::LogLevel::Info)
        .expect("exact-2024 logging/setLevel must be admitted");
    client
        .call_tool("echo", json!({"message": "log"}))
        .expect("ctx.info must not prevent the shipped echo tool from completing");
    let notifications = client
        .take_server_notifications()
        .expect("exact-2024 stdio notifications must decode");
    assert!(
        notifications.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Message(message)
                if message.level == legacy_2024::LogLevel::Info
                    && message.data == json!("echo-handler-info")
        )),
        "live exact-2024 stdio must retain ctx.info after set_log_level(Info): {notifications:?}"
    );

    client
        .close()
        .expect("legacy-only stdio log client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_notification_ctx_info_peer_stays_silent() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    client
        .call_tool("echo", json!({"message": "quiet"}))
        .expect("the echo peer must still be callable without set_log_level");
    let notifications = client
        .take_server_notifications()
        .expect("exact-2024 stdio notifications must decode");
    assert!(
        !notifications.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Message(message)
                if message.data == json!("echo-handler-info")
        )),
        "omitting only logging/setLevel must keep ctx.info silent: {notifications:?}"
    );

    client
        .close()
        .expect("legacy-only stdio silent log client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_progress_marker_is_retained_from_live_echo() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    client
        .call_tool("echo", json!({"message": "no-token"}))
        .expect("echo still completes without a progress token");
    let silent = client
        .take_server_notifications()
        .expect("exact-2024 stdio notifications must decode");
    assert!(
        !silent.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Progress(_)
        )),
        "without a progressToken the shipped echo tool must not emit request-scoped progress: {silent:?}"
    );

    let marker = legacy_2024::ProgressMarker::from("stdio-legacy-progress");
    client
        .call_tool_with_progress_marker("echo", json!({"message": "token"}), marker.clone())
        .expect("a progressToken must not prevent the shipped echo tool from completing");
    let progress = client
        .take_server_notifications()
        .expect("exact-2024 stdio notifications must decode");
    assert!(
        progress.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Progress(params)
                if params.progress_marker == marker
                    && params.message.as_deref() == Some("echoed")
        )),
        "live exact-2024 stdio must retain notifications/progress after a progressToken: {progress:?}"
    );

    client
        .read_resource("info://server")
        .expect("a resources/read without a progress token still completes");
    let silent_resource = client
        .take_server_notifications()
        .expect("exact-2024 stdio notifications must decode");
    assert!(
        !silent_resource.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Progress(_)
        )),
        "without a progressToken the shipped server_info resource must not emit request-scoped progress: {silent_resource:?}"
    );

    let resource_marker = legacy_2024::ProgressMarker::from("stdio-legacy-resource-progress");
    client
        .read_resource_with_progress_marker("info://server", resource_marker.clone())
        .expect(
            "a progressToken must not prevent the shipped server_info resource from completing",
        );
    let resource_progress = client
        .take_server_notifications()
        .expect("exact-2024 stdio notifications must decode");
    assert!(
        resource_progress.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Progress(params)
                if params.progress_marker == resource_marker
                    && params.message.as_deref() == Some("info")
        )),
        "live exact-2024 stdio must retain resource notifications/progress after a progressToken: {resource_progress:?}"
    );

    let mut greeting_arguments = std::collections::HashMap::new();
    greeting_arguments.insert("name".to_owned(), "no-token".to_owned());
    client
        .get_prompt("greeting", greeting_arguments)
        .expect("a prompts/get without a progress token still completes");
    let silent_prompt = client
        .take_server_notifications()
        .expect("exact-2024 stdio notifications must decode");
    assert!(
        !silent_prompt.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Progress(_)
        )),
        "without a progressToken the shipped greeting prompt must not emit request-scoped progress: {silent_prompt:?}"
    );

    let prompt_marker = legacy_2024::ProgressMarker::from("stdio-legacy-prompt-progress");
    let mut greeting_with_token = std::collections::HashMap::new();
    greeting_with_token.insert("name".to_owned(), "token".to_owned());
    client
        .get_prompt_with_progress_marker("greeting", greeting_with_token, prompt_marker.clone())
        .expect("a progressToken must not prevent the shipped greeting prompt from completing");
    let prompt_progress = client
        .take_server_notifications()
        .expect("exact-2024 stdio notifications must decode");
    assert!(
        prompt_progress.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Progress(params)
                if params.progress_marker == prompt_marker
                    && params.message.as_deref() == Some("greeted")
        )),
        "live exact-2024 stdio must retain prompt notifications/progress after a progressToken: {prompt_progress:?}"
    );

    let completion_params = legacy_2024::LegacyCompletionParams {
        reference: legacy_2024::LegacyCompletionReference::Prompt {
            name: "greeting".to_owned(),
        },
        argument: legacy_2024::LegacyCompletionArgument {
            name: "name".to_owned(),
            value: "co".to_owned(),
        },
        meta: None,
    };
    client
        .complete(completion_params.clone())
        .expect("a completion/complete without a progress token still completes");
    let silent_completion = client
        .take_server_notifications()
        .expect("exact-2024 stdio notifications must decode");
    assert!(
        !silent_completion.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Progress(_)
        )),
        "without a progressToken the shipped greeting completion must not emit request-scoped progress: {silent_completion:?}"
    );

    let completion_marker = legacy_2024::ProgressMarker::from("stdio-legacy-completion-progress");
    let completed = client
        .complete_with_progress_marker(completion_params, completion_marker.clone())
        .expect("a progressToken must not prevent the shipped greeting completion from completing");
    assert_eq!(
        completed.completion.values,
        vec!["stdio-completion-legacy".to_owned()],
        "the exact-2024 completion provider must retain its values: {completed:?}"
    );
    let completion_progress = client
        .take_server_notifications()
        .expect("exact-2024 stdio notifications must decode");
    assert!(
        completion_progress.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::Progress(params)
                if params.progress_marker == completion_marker
                    && params.message.as_deref() == Some("stdio-completion-legacy-halfway")
        )),
        "live exact-2024 stdio must retain completion notifications/progress after a progressToken: {completion_progress:?}"
    );

    client
        .close()
        .expect("legacy-only stdio progress client cleanup");
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
const STDIO_FS_PREFIX: &str = "e2e";
#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
const STDIO_FS_TEMPLATE: &str = "file:///e2e/{+path}";
#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
const STDIO_FS_FILE_URI: &str = "file:///e2e/note.txt";
#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
const STDIO_FS_FILE_TEXT: &str = "filesystem:stdio";

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
#[test]
fn e2e_public_stdio_modern_filesystem_provider_lists_and_reads_live_file() {
    let root = std::env::temp_dir().join(format!(
        "fastmcp-public-stdio-fs-e2e-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("the stdio filesystem e2e root is created");
    std::fs::write(root.join("note.txt"), STDIO_FS_FILE_TEXT)
        .expect("the stdio filesystem e2e file is written");
    let root_path = root
        .to_str()
        .expect("the stdio filesystem e2e root is utf-8")
        .to_owned();

    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[
            ("FASTMCP_FS_ROOT", root_path.as_str()),
            ("FASTMCP_FS_PREFIX", STDIO_FS_PREFIX),
        ],
    )
    .expect("a ModernOnly facade client connects to the filesystem echo peer");

    let listed = client
        .list_resource_templates(None)
        .expect("live stdio must list the FilesystemProvider template");
    assert!(
        listed.resource_templates.iter().any(|template| {
            template.uri_template == STDIO_FS_TEMPLATE && template.name == STDIO_FS_PREFIX
        }),
        "FilesystemProvider must advertise its reversible file template: {:?}",
        listed.resource_templates
    );

    let unmatched = client.read_resource("file:///other/note.txt").expect_err(
        "changing only the prefix the template cannot bind must refuse before dispatch",
    );
    assert_eq!(
        unmatched.code,
        McpErrorCode::InvalidParams,
        "an unmatched filesystem URI must stay InvalidParams: {unmatched:?}"
    );

    let file = client
        .read_resource(STDIO_FS_FILE_URI)
        .expect("resources/read must expand the live file URI through the filesystem handler");
    assert!(
        matches!(
            file.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == STDIO_FS_FILE_TEXT
        ),
        "the live filesystem read must retain the file bytes: {:?}",
        file.contents
    );

    client
        .close()
        .expect("modern-only stdio filesystem client cleanup");
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
#[test]
fn e2e_public_stdio_legacy_filesystem_provider_lists_and_reads_live_file() {
    let root = std::env::temp_dir().join(format!(
        "fastmcp-public-stdio-legacy-fs-e2e-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("the exact-2024 stdio filesystem e2e root is created");
    std::fs::write(root.join("note.txt"), STDIO_FS_FILE_TEXT)
        .expect("the exact-2024 stdio filesystem e2e file is written");
    let root_path = root
        .to_str()
        .expect("the exact-2024 stdio filesystem e2e root is utf-8")
        .to_owned();

    let mut client = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[
            ("FASTMCP_FS_ROOT", root_path.as_str()),
            ("FASTMCP_FS_PREFIX", STDIO_FS_PREFIX),
        ],
    )
    .expect("a LegacyOnly facade client connects to the filesystem echo peer");

    let listed = client
        .list_resource_templates()
        .expect("live exact-2024 stdio must list the FilesystemProvider template");
    assert!(
        listed.iter().any(|template| {
            template.uri_template == STDIO_FS_TEMPLATE && template.name == STDIO_FS_PREFIX
        }),
        "FilesystemProvider must advertise its reversible file template: {listed:?}"
    );

    let unmatched = client.read_resource("file:///other/note.txt").expect_err(
        "changing only the prefix the template cannot bind must refuse before dispatch",
    );
    assert_eq!(
        unmatched.code,
        McpErrorCode::ResourceNotFound,
        "an unmatched filesystem URI must stay ResourceNotFound on exact-2024: {unmatched:?}"
    );

    let file = client
        .read_resource(STDIO_FS_FILE_URI)
        .expect("resources/read must expand the live file URI through the filesystem handler");
    assert!(
        file.contents.iter().any(|content| match content {
            LegacyResourceContent::Text { text, .. } => text == STDIO_FS_FILE_TEXT,
            _ => false,
        }),
        "the live exact-2024 filesystem read must retain the file bytes: {:?}",
        file.contents
    );

    client
        .close()
        .expect("legacy-only stdio filesystem client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_hide_catalog_refuses_later_read_and_prompt() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client connects to the shipped echo server");

    let before = client
        .read_resource("info://server")
        .expect("the shipped echo resource must be readable before hide_catalog");
    assert!(
        before.contents.iter().any(|content| match content {
            LegacyResourceContent::Text { text, .. } => text.contains("echo-server"),
            _ => false,
        }),
        "the live exact-2024 stdio resource must retain the echo handler value: {before:?}"
    );

    let hidden = client
        .call_tool("hide_catalog", json!({}))
        .expect("disabling a shipped resource and prompt must complete");
    assert!(
        hidden.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text == "hidden",
            _ => false,
        }),
        "exact-2024 stdio session state must retain disable_resource and disable_prompt: {hidden:?}"
    );

    let disabled_resource = client.read_resource("info://server").expect_err(
        "hide_catalog must refuse a later info://server read on the same exact-2024 session",
    );
    let disabled_resource = format!("{disabled_resource:?}");
    assert!(
        disabled_resource.contains("disabled") && disabled_resource.contains("info://server"),
        "the refused resource read must be the session-disabled URI: {disabled_resource}"
    );
    let disabled_prompt = client
        .get_prompt(
            "greeting",
            HashMap::from([("name".to_owned(), "Bea".to_owned())]),
        )
        .expect_err("hide_catalog must refuse a later greeting get on the same exact-2024 session");
    let disabled_prompt = format!("{disabled_prompt:?}");
    assert!(
        disabled_prompt.contains("disabled") && disabled_prompt.contains("greeting"),
        "the refused prompt get must be the session-disabled prompt: {disabled_prompt}"
    );

    let shown = client
        .call_tool("show_catalog", json!({}))
        .expect("re-enabling a shipped resource and prompt must complete");
    assert!(
        shown.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text == "shown",
            _ => false,
        }),
        "exact-2024 stdio session state must retain enable_resource and enable_prompt: {shown:?}"
    );
    let restored = client.read_resource("info://server").expect(
        "show_catalog must restore a later info://server read on the same exact-2024 session",
    );
    assert!(
        restored.contents.iter().any(|content| match content {
            LegacyResourceContent::Text { text, .. } => text.contains("echo-server"),
            _ => false,
        }),
        "the restored exact-2024 stdio resource must retain the echo handler value: {restored:?}"
    );
    let restored_prompt = client
        .get_prompt(
            "greeting",
            HashMap::from([("name".to_owned(), "Cyd".to_owned())]),
        )
        .expect("show_catalog must restore a later greeting get on the same exact-2024 session");
    assert!(
        restored_prompt
            .messages
            .iter()
            .any(|message| match &message.content {
                LegacyContent::Text { text, .. } => {
                    text == "Please greet Cyd in a friendly way."
                }
                _ => false,
            }),
        "the restored exact-2024 stdio prompt must retain the echo handler value: {restored_prompt:?}"
    );

    client
        .close()
        .expect("legacy-only stdio hide_catalog client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_hide_echo_refuses_later_call_and_show_restores() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client connects to the shipped echo server");

    let before = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("the shipped echo tool must be callable before hide_echo");
    assert!(
        before.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text.contains("alpha"),
            _ => false,
        }),
        "the live exact-2024 stdio echo must retain the handler text: {before:?}"
    );

    let hidden = client
        .call_tool("hide_echo", json!({}))
        .expect("disabling the shipped echo tool must complete");
    assert!(
        hidden.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text == "hidden",
            _ => false,
        }),
        "exact-2024 stdio session state must retain disable_tool: {hidden:?}"
    );

    let disabled = client.call_tool("echo", json!({"message": "beta"}));
    let disabled = match disabled {
        Ok(result) => {
            assert!(
                result.is_error,
                "hide_echo must turn a later echo call into a tool-level error: {result:?}"
            );
            format!("{result:?}")
        }
        Err(error) => format!("{error:?}"),
    };
    assert!(
        disabled.contains("disabled")
            || disabled.contains("echo")
            || disabled.contains("Method not found")
            || disabled.contains("MethodNotFound"),
        "the refused echo call must name the session-disabled tool: {disabled}"
    );

    let peer = client
        .call_tool("add", json!({"a": 2, "b": 3}))
        .expect("changing only the missing hide must keep an undisabled tool callable");
    assert!(
        peer.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text.contains('5'),
            _ => false,
        }),
        "an undisabled peer tool must still complete after hide_echo: {peer:?}"
    );

    let shown = client
        .call_tool("show_echo", json!({}))
        .expect("re-enabling the shipped echo tool must complete");
    assert!(
        shown.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text == "shown",
            _ => false,
        }),
        "exact-2024 stdio session state must retain enable_tool: {shown:?}"
    );
    let restored = client
        .call_tool("echo", json!({"message": "gamma"}))
        .expect("show_echo must restore a later echo call on the same exact-2024 session");
    assert!(
        restored.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text.contains("gamma"),
            _ => false,
        }),
        "the restored exact-2024 stdio echo must retain the handler text: {restored:?}"
    );

    client
        .close()
        .expect("legacy-only stdio hide_echo client cleanup");
}

#[cfg(unix)]
const STDIO_LEAK_RESOURCE_URI: &str = "info://leak";
#[cfg(unix)]
const STDIO_LEAK_SECRET: &str = "secret-db-dsn";

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_mask_error_details_hides_resource_execution_secret() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_MASK_ERROR_DETAILS", "1")],
    )
    .expect("a ModernOnly facade client connects to the masked echo peer");
    let masked = client
        .read_resource(STDIO_LEAK_RESOURCE_URI)
        .expect_err("a leaking resource must stay a resources/read error");
    let masked = format!("{masked:?}");
    assert!(
        masked.contains("Internal server error"),
        "mask_error_details must replace the execution secret: {masked}"
    );
    assert!(
        !masked.contains(STDIO_LEAK_SECRET),
        "mask_error_details must not leak the execution secret: {masked}"
    );
    client
        .close()
        .expect("modern-only stdio masked client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_unmask_error_details_keeps_resource_execution_secret() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client connects to the unmasked echo peer");
    let unmasked = client
        .read_resource(STDIO_LEAK_RESOURCE_URI)
        .expect_err("changing only the missing mask flag must still refuse the leaking resource");
    let unmasked = format!("{unmasked:?}");
    assert!(
        unmasked.contains(STDIO_LEAK_SECRET),
        "disabling mask_error_details must keep the execution secret: {unmasked}"
    );
    client
        .close()
        .expect("modern-only stdio unmasked client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_mask_error_details_hides_resource_execution_secret() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_MASK_ERROR_DETAILS", "1")],
    )
    .expect("a LegacyOnly facade client connects to the masked echo peer");
    let masked = client
        .read_resource(STDIO_LEAK_RESOURCE_URI)
        .expect_err("a leaking resource must stay a resources/read error");
    let masked = format!("{masked:?}");
    assert!(
        masked.contains("Internal server error"),
        "exact-2024 stdio mask_error_details must replace the execution secret: {masked}"
    );
    assert!(
        !masked.contains(STDIO_LEAK_SECRET),
        "exact-2024 stdio mask_error_details must not leak the execution secret: {masked}"
    );
    client
        .close()
        .expect("legacy-only stdio masked client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_unmask_error_details_keeps_resource_execution_secret() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client connects to the unmasked echo peer");
    let unmasked = client
        .read_resource(STDIO_LEAK_RESOURCE_URI)
        .expect_err("changing only the missing mask flag must still refuse the leaking resource");
    let unmasked = format!("{unmasked:?}");
    assert!(
        unmasked.contains(STDIO_LEAK_SECRET),
        "disabling exact-2024 stdio mask_error_details must keep the execution secret: {unmasked}"
    );
    client
        .close()
        .expect("legacy-only stdio unmasked client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_strict_input_validation_refuses_unknown_property() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_STRICT_INPUT", "1")],
    )
    .expect("a ModernOnly facade client connects to the strict echo peer");
    let admitted = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("strict validation must still admit declared arguments");
    assert!(
        !admitted.is_error,
        "declared arguments must not become a tool-level error: {admitted:?}"
    );
    assert!(
        admitted.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text.contains("alpha"),
            _ => false,
        }),
        "declared arguments must reach the handler under strict validation: {admitted:?}"
    );

    let refused = client.call_tool("echo", json!({"message": "alpha", "extra": 1}));
    let refused = match refused {
        Ok(result) => {
            assert!(
                result.is_error,
                "an unknown property must become a tool-level error when strict validation is on: {result:?}"
            );
            format!("{result:?}")
        }
        Err(error) => format!("{error:?}"),
    };
    assert!(
        refused.contains("do not match the declared input schema")
            || refused.contains("unknown")
            || refused.contains("InvalidParams")
            || refused.contains("extra")
            || refused.contains("additional property"),
        "the strict refusal must name the input-schema mismatch: {refused}"
    );
    client
        .close()
        .expect("modern-only stdio strict client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_lenient_input_validation_admits_unknown_property() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client connects to the lenient echo peer");
    let extra = client
        .call_tool("echo", json!({"message": "alpha", "extra": 1}))
        .expect("lenient validation must admit the same extra property");
    assert!(
        !extra.is_error,
        "changing only the missing strict flag must admit the extra property: {extra:?}"
    );
    assert!(
        extra.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text.contains("alpha"),
            _ => false,
        }),
        "the extra property must not change the handler result when strict is off: {extra:?}"
    );
    client
        .close()
        .expect("modern-only stdio lenient client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_strict_input_validation_refuses_unknown_property() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_STRICT_INPUT", "1")],
    )
    .expect("a LegacyOnly facade client connects to the strict echo peer");
    let admitted = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("strict validation must still admit declared arguments");
    assert!(
        !admitted.is_error,
        "declared arguments must not become a tool-level error: {admitted:?}"
    );
    assert!(
        admitted.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text.contains("alpha"),
            _ => false,
        }),
        "declared arguments must reach the handler under strict validation: {admitted:?}"
    );

    let refused = client.call_tool("echo", json!({"message": "alpha", "extra": 1}));
    let refused = match refused {
        Ok(result) => {
            assert!(
                result.is_error,
                "an unknown property must become a tool-level error when strict validation is on: {result:?}"
            );
            format!("{result:?}")
        }
        Err(error) => format!("{error:?}"),
    };
    assert!(
        refused.contains("do not match the declared input schema")
            || refused.contains("unknown")
            || refused.contains("InvalidParams")
            || refused.contains("extra")
            || refused.contains("additional property"),
        "the exact-2024 strict refusal must name the input-schema mismatch: {refused}"
    );
    client
        .close()
        .expect("legacy-only stdio strict client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_lenient_input_validation_admits_unknown_property() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client connects to the lenient echo peer");
    let extra = client
        .call_tool("echo", json!({"message": "alpha", "extra": 1}))
        .expect("lenient validation must admit the same extra property");
    assert!(
        !extra.is_error,
        "changing only the missing strict flag must admit the extra property: {extra:?}"
    );
    assert!(
        extra.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text.contains("alpha"),
            _ => false,
        }),
        "the extra property must not change the handler result when strict is off: {extra:?}"
    );
    client
        .close()
        .expect("legacy-only stdio lenient client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_sliding_window_refuses_second_same_method_and_admits_another() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_SLIDING_WINDOW", "1")],
    )
    .expect("a ModernOnly facade client connects to the sliding-window echo peer");

    let first = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("the first modern stdio tools/call must be admitted by the sliding window");
    assert!(
        !first.is_error,
        "the first sliding-window tools/call must reach the handler: {first:?}"
    );
    assert!(
        first.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text.contains("alpha"),
            _ => false,
        }),
        "the first sliding-window tools/call must retain the handler text: {first:?}"
    );

    let limited = client.call_tool("echo", json!({"message": "beta"}));
    let limited = match limited {
        Ok(result) => {
            assert!(
                result.is_error,
                "a second tools/call must stay an error result: {result:?}"
            );
            format!("{result:?}")
        }
        Err(error) => format!("{error:?}"),
    };
    assert!(
        limited.contains("Rate limit exceeded"),
        "the refused second modern stdio tools/call must keep the sliding-window error: {limited}"
    );

    client
        .ping()
        .expect("changing only the method must still be admitted by the live sliding window");

    client
        .close()
        .expect("modern-only stdio sliding-window client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_sliding_window_refuses_second_same_method_and_admits_another() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_SLIDING_WINDOW", "1")],
    )
    .expect("a LegacyOnly facade client connects to the sliding-window echo peer");

    let first = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("the first exact-2024 stdio tools/call must be admitted by the sliding window");
    assert!(
        !first.is_error,
        "the first sliding-window tools/call must reach the handler: {first:?}"
    );
    assert!(
        first.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text.contains("alpha"),
            _ => false,
        }),
        "the first sliding-window tools/call must retain the handler text: {first:?}"
    );

    let limited = client.call_tool("echo", json!({"message": "beta"}));
    let limited = match limited {
        Ok(result) => {
            assert!(
                result.is_error,
                "a second tools/call must stay an error result: {result:?}"
            );
            format!("{result:?}")
        }
        Err(error) => format!("{error:?}"),
    };
    assert!(
        limited.contains("Rate limit exceeded"),
        "the refused second exact-2024 stdio tools/call must keep the sliding-window error: {limited}"
    );

    let listed = client
        .list_tools()
        .expect("changing only the method must still be admitted by the live sliding window");
    assert!(
        listed.iter().any(|tool| tool.name == "echo"),
        "tools/list must stay callable after tools/call is sliding-window limited: {listed:?}"
    );

    client
        .close()
        .expect("legacy-only stdio sliding-window client cleanup");
}

#[cfg(unix)]
fn stdio_modern_tool_text(result: &fastmcp_rust::FinalCallToolResult) -> Option<&str> {
    result.content.iter().find_map(|content| match content {
        ContentBlock::Text { text, .. } => Some(text.as_str()),
        _ => None,
    })
}

#[cfg(unix)]
fn stdio_legacy_tool_text(result: &fastmcp_protocol::CallToolResult) -> Option<&str> {
    result.content.iter().find_map(|content| match content {
        LegacyContent::Text { text, .. } => Some(text.as_str()),
        _ => None,
    })
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_cache_hits_same_allowlisted_call_and_misses_changed_args() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_CACHE_TOOLS", "1")],
    )
    .expect("a ModernOnly facade client connects to the cached echo peer");

    let first = client
        .call_tool("cache_probe", json!({"token": "alpha"}))
        .expect("the first allowlisted modern stdio tools/call must miss and reach the handler");
    assert!(
        !first.is_error,
        "the first cache_probe call must reach the handler: {first:?}"
    );
    assert_eq!(
        stdio_modern_tool_text(&first),
        Some("alpha:0"),
        "the first cache_probe call must increment the process-local counter: {first:?}"
    );

    let cached = client
        .call_tool("cache_probe", json!({"token": "alpha"}))
        .expect("the second identical allowlisted tools/call must be a cache hit");
    assert!(
        !cached.is_error,
        "the cache hit must stay a complete result: {cached:?}"
    );
    assert_eq!(
        stdio_modern_tool_text(&cached),
        Some("alpha:0"),
        "a cache hit must keep the first complete result without incrementing: {cached:?}"
    );

    let missed = client
        .call_tool("cache_probe", json!({"token": "beta"}))
        .expect("changing only the arguments must miss the cache");
    assert!(
        !missed.is_error,
        "a different-arguments tools/call must reach the handler: {missed:?}"
    );
    assert_eq!(
        stdio_modern_tool_text(&missed),
        Some("beta:1"),
        "a cache miss must increment the process-local counter: {missed:?}"
    );

    client
        .close()
        .expect("modern-only stdio cache client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_cache_off_invokes_handler_twice() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client connects to the uncached echo peer");

    let first = client
        .call_tool("cache_probe", json!({"token": "alpha"}))
        .expect("the first uncached modern stdio tools/call must reach the handler");
    assert_eq!(
        stdio_modern_tool_text(&first),
        Some("alpha:0"),
        "the first uncached cache_probe call must increment: {first:?}"
    );

    let second = client
        .call_tool("cache_probe", json!({"token": "alpha"}))
        .expect("omitting only FASTMCP_CACHE_TOOLS must invoke the handler again");
    assert_eq!(
        stdio_modern_tool_text(&second),
        Some("alpha:1"),
        "changing only the missing cache flag must increment again: {second:?}"
    );

    client
        .close()
        .expect("modern-only stdio uncached client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_cache_hits_same_allowlisted_call_and_misses_changed_args() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_CACHE_TOOLS", "1")],
    )
    .expect("a LegacyOnly facade client connects to the cached echo peer");

    let first = client
        .call_tool("cache_probe", json!({"token": "alpha"}))
        .expect(
            "the first allowlisted exact-2024 stdio tools/call must miss and reach the handler",
        );
    assert!(
        !first.is_error,
        "the first cache_probe call must reach the handler: {first:?}"
    );
    assert_eq!(
        stdio_legacy_tool_text(&first),
        Some("alpha:0"),
        "the first cache_probe call must increment the process-local counter: {first:?}"
    );

    let cached = client
        .call_tool("cache_probe", json!({"token": "alpha"}))
        .expect("the second identical allowlisted tools/call must be a cache hit");
    assert!(
        !cached.is_error,
        "the cache hit must stay a complete result: {cached:?}"
    );
    assert_eq!(
        stdio_legacy_tool_text(&cached),
        Some("alpha:0"),
        "a cache hit must keep the first complete result without incrementing: {cached:?}"
    );

    let missed = client
        .call_tool("cache_probe", json!({"token": "beta"}))
        .expect("changing only the arguments must miss the cache");
    assert!(
        !missed.is_error,
        "a different-arguments tools/call must reach the handler: {missed:?}"
    );
    assert_eq!(
        stdio_legacy_tool_text(&missed),
        Some("beta:1"),
        "a cache miss must increment the process-local counter: {missed:?}"
    );

    client
        .close()
        .expect("legacy-only stdio cache client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_cache_off_invokes_handler_twice() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client connects to the uncached echo peer");

    let first = client
        .call_tool("cache_probe", json!({"token": "alpha"}))
        .expect("the first uncached exact-2024 stdio tools/call must reach the handler");
    assert_eq!(
        stdio_legacy_tool_text(&first),
        Some("alpha:0"),
        "the first uncached cache_probe call must increment: {first:?}"
    );

    let second = client
        .call_tool("cache_probe", json!({"token": "alpha"}))
        .expect("omitting only FASTMCP_CACHE_TOOLS must invoke the handler again");
    assert_eq!(
        stdio_legacy_tool_text(&second),
        Some("alpha:1"),
        "changing only the missing cache flag must increment again: {second:?}"
    );

    client
        .close()
        .expect("legacy-only stdio uncached client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_rate_limit_refuses_second_same_method_and_admits_another() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_RATE_LIMIT", "1")],
    )
    .expect("a ModernOnly facade client connects to the rate-limited echo peer");

    let first = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("the first modern stdio tools/call must be admitted by the token bucket");
    assert!(
        !first.is_error,
        "the first rate-limited tools/call must reach the handler: {first:?}"
    );
    assert!(
        first.content.iter().any(|content| match content {
            ContentBlock::Text { text, .. } => text.contains("alpha"),
            _ => false,
        }),
        "the first rate-limited tools/call must retain the handler text: {first:?}"
    );

    let limited = client.call_tool("echo", json!({"message": "beta"}));
    let limited = match limited {
        Ok(result) => {
            assert!(
                result.is_error,
                "a second tools/call must stay an error result: {result:?}"
            );
            format!("{result:?}")
        }
        Err(error) => format!("{error:?}"),
    };
    assert!(
        limited.contains("Rate limit exceeded"),
        "the refused second modern stdio tools/call must keep the token-bucket error: {limited}"
    );

    client
        .ping()
        .expect("changing only the method must still be admitted by the live token bucket");

    client
        .close()
        .expect("modern-only stdio rate-limit client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_rate_limit_refuses_second_same_method_and_admits_another() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_RATE_LIMIT", "1")],
    )
    .expect("a LegacyOnly facade client connects to the rate-limited echo peer");

    let first = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("the first exact-2024 stdio tools/call must be admitted by the token bucket");
    assert!(
        !first.is_error,
        "the first rate-limited tools/call must reach the handler: {first:?}"
    );
    assert!(
        first.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text.contains("alpha"),
            _ => false,
        }),
        "the first rate-limited tools/call must retain the handler text: {first:?}"
    );

    let limited = client.call_tool("echo", json!({"message": "beta"}));
    let limited = match limited {
        Ok(result) => {
            assert!(
                result.is_error,
                "a second tools/call must stay an error result: {result:?}"
            );
            format!("{result:?}")
        }
        Err(error) => format!("{error:?}"),
    };
    assert!(
        limited.contains("Rate limit exceeded"),
        "the refused second exact-2024 stdio tools/call must keep the token-bucket error: {limited}"
    );

    let listed = client
        .list_tools()
        .expect("changing only the method must still be admitted by the live token bucket");
    assert!(
        listed.iter().any(|tool| tool.name == "echo"),
        "tools/list must stay callable after tools/call is token-bucket limited: {listed:?}"
    );

    client
        .close()
        .expect("legacy-only stdio rate-limit client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_replace_echo_installs_second_handler() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_REPLACE_ECHO", "1")],
    )
    .expect("a ModernOnly facade client connects to the replace-echo peer");

    let replaced = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("Replace must install the second echo registration");
    assert!(
        !replaced.is_error,
        "the replaced echo must stay a complete result: {replaced:?}"
    );
    assert_eq!(
        stdio_modern_tool_text(&replaced),
        Some("replaced:alpha"),
        "changing only on_duplicate to Replace must reach the second handler: {replaced:?}"
    );

    client
        .close()
        .expect("modern-only stdio replace-echo client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_default_echo_keeps_first_handler() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client connects to the default echo peer");

    let kept = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("omitting only FASTMCP_REPLACE_ECHO must keep the first echo");
    assert!(
        !kept.is_error,
        "the default echo must stay a complete result: {kept:?}"
    );
    assert_eq!(
        stdio_modern_tool_text(&kept),
        Some("alpha"),
        "changing only the missing replace flag must keep the first handler: {kept:?}"
    );

    client
        .close()
        .expect("modern-only stdio default-echo client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_replace_echo_installs_second_handler() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_REPLACE_ECHO", "1")],
    )
    .expect("a LegacyOnly facade client connects to the replace-echo peer");

    let replaced = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("Replace must install the second echo registration");
    assert!(
        !replaced.is_error,
        "the replaced echo must stay a complete result: {replaced:?}"
    );
    assert_eq!(
        stdio_legacy_tool_text(&replaced),
        Some("replaced:alpha"),
        "changing only on_duplicate to Replace must reach the second handler: {replaced:?}"
    );

    client
        .close()
        .expect("legacy-only stdio replace-echo client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_default_echo_keeps_first_handler() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client connects to the default echo peer");

    let kept = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("omitting only FASTMCP_REPLACE_ECHO must keep the first echo");
    assert!(
        !kept.is_error,
        "the default echo must stay a complete result: {kept:?}"
    );
    assert_eq!(
        stdio_legacy_tool_text(&kept),
        Some("alpha"),
        "changing only the missing replace flag must keep the first handler: {kept:?}"
    );

    client
        .close()
        .expect("legacy-only stdio default-echo client cleanup");
}

#[cfg(unix)]
const STDIO_LIST_PAGE_LIMITS: fastmcp_rust::ListPageLimits =
    fastmcp_rust::ListPageLimits::new(64, 1_048_576);

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_list_page_continues_and_rejects_wrong_catalog_cursor() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_LIST_PAGE_SIZE", "1")],
    )
    .expect("a ModernOnly facade client connects to the paged echo peer");

    let first = client
        .list_tools(None)
        .expect("the first modern stdio tools/list page must miss and reach the catalog");
    assert_eq!(
        first.tools.len(),
        1,
        "page size 1 must create a real continuation: {first:?}"
    );
    let first_name = first.tools[0].name.clone();
    let cursor = first
        .next_cursor
        .clone()
        .expect("the first page-size-1 tools/list must carry an opaque cursor");

    let second = client
        .list_tools(Some(&cursor))
        .expect("the exact cursor continuation must reach the second live page");
    assert_eq!(
        second.tools.len(),
        1,
        "the continuation must retain one remaining tool: {second:?}"
    );
    assert_ne!(
        second.tools[0].name, first_name,
        "the continuation must advance to a different tool: {second:?}"
    );

    let rejected = client
        .list_resources(Some(&cursor))
        .expect_err("a tools/list cursor must not page resources/list");
    let rejected = format!("{rejected:?}");
    assert!(
        rejected.contains("InvalidParams") || rejected.contains("invalid"),
        "a wrong-catalog cursor must stay InvalidParams: {rejected}"
    );

    client
        .close()
        .expect("modern-only stdio paged client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_default_list_is_not_forced_to_page_size_one() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client connects to the unpaged echo peer");

    let listed = client
        .list_tools(None)
        .expect("omitting only FASTMCP_LIST_PAGE_SIZE must list the full first page");
    assert!(
        listed.tools.len() > 1,
        "changing only the missing page-size flag must keep more than one tool on the first page: {listed:?}"
    );

    client
        .close()
        .expect("modern-only stdio unpaged client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_list_page_continues_and_rejects_wrong_catalog_cursor() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_LIST_PAGE_SIZE", "1")],
    )
    .expect("a LegacyOnly facade client connects to the paged echo peer");

    let first = client
        .list_tools_page(None, STDIO_LIST_PAGE_LIMITS)
        .expect("the first exact-2024 stdio tools/list page must miss and reach the catalog");
    assert_eq!(
        first.items.len(),
        1,
        "page size 1 must create a real continuation: {first:?}"
    );
    let first_name = first.items[0].name.clone();
    let cursor = first
        .next_cursor
        .clone()
        .expect("the first page-size-1 tools/list must carry an opaque cursor");

    let second = client
        .list_tools_page(Some(&cursor), STDIO_LIST_PAGE_LIMITS)
        .expect("the exact cursor continuation must reach the second live page");
    assert_eq!(
        second.items.len(),
        1,
        "the continuation must retain one remaining tool: {second:?}"
    );
    assert_ne!(
        second.items[0].name, first_name,
        "the continuation must advance to a different tool: {second:?}"
    );

    let rejected = client
        .list_resources_page(Some(&cursor), STDIO_LIST_PAGE_LIMITS)
        .expect_err("a tools/list cursor must not page resources/list");
    let rejected = format!("{rejected:?}");
    assert!(
        rejected.contains("InvalidParams") || rejected.contains("invalid"),
        "a wrong-catalog cursor must stay InvalidParams: {rejected}"
    );

    client
        .close()
        .expect("legacy-only stdio paged client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_default_list_is_not_forced_to_page_size_one() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client connects to the unpaged echo peer");

    let listed = client
        .list_tools_page(None, STDIO_LIST_PAGE_LIMITS)
        .expect("omitting only FASTMCP_LIST_PAGE_SIZE must list the full first page");
    assert!(
        listed.items.len() > 1,
        "changing only the missing page-size flag must keep more than one tool on the first page: {listed:?}"
    );

    client
        .close()
        .expect("legacy-only stdio unpaged client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_catalog_list_page_continues_and_rejects_wrong_kind_cursor() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_LIST_PAGE_SIZE", "1")],
    )
    .expect("a ModernOnly facade client connects to the paged echo peer");

    let first_resources = client
        .list_resources(None)
        .expect("the first modern stdio resources/list page must miss and reach the catalog");
    assert_eq!(
        first_resources.resources.len(),
        1,
        "page size 1 must create a real resources continuation: {first_resources:?}"
    );
    let first_resource = first_resources.resources[0].uri.as_str().to_owned();
    let resource_cursor = first_resources
        .next_cursor
        .clone()
        .expect("the first page-size-1 resources/list must carry an opaque cursor");
    let second_resources = client
        .list_resources(Some(&resource_cursor))
        .expect("the exact resources cursor continuation must reach the second live page");
    assert_eq!(
        second_resources.resources.len(),
        1,
        "the resources continuation must retain one remaining resource: {second_resources:?}"
    );
    assert_ne!(
        second_resources.resources[0].uri.as_str(),
        first_resource,
        "the resources continuation must advance to a different URI: {second_resources:?}"
    );
    let rejected_prompts = client
        .list_prompts(Some(&resource_cursor))
        .expect_err("a resources/list cursor must not page prompts/list");
    let rejected_prompts = format!("{rejected_prompts:?}");
    assert!(
        rejected_prompts.contains("InvalidParams") || rejected_prompts.contains("invalid"),
        "a wrong-catalog resources cursor must stay InvalidParams: {rejected_prompts}"
    );

    let first_prompts = client
        .list_prompts(None)
        .expect("the first modern stdio prompts/list page must miss and reach the catalog");
    assert_eq!(
        first_prompts.prompts.len(),
        1,
        "page size 1 must create a real prompts continuation: {first_prompts:?}"
    );
    let first_prompt = first_prompts.prompts[0].name.clone();
    let prompt_cursor = first_prompts
        .next_cursor
        .clone()
        .expect("the first page-size-1 prompts/list must carry an opaque cursor");
    let second_prompts = client
        .list_prompts(Some(&prompt_cursor))
        .expect("the exact prompts cursor continuation must reach the second live page");
    assert_eq!(
        second_prompts.prompts.len(),
        1,
        "the prompts continuation must retain one remaining prompt: {second_prompts:?}"
    );
    assert_ne!(
        second_prompts.prompts[0].name, first_prompt,
        "the prompts continuation must advance to a different name: {second_prompts:?}"
    );
    let rejected_tools = client
        .list_tools(Some(&prompt_cursor))
        .expect_err("a prompts/list cursor must not page tools/list");
    let rejected_tools = format!("{rejected_tools:?}");
    assert!(
        rejected_tools.contains("InvalidParams") || rejected_tools.contains("invalid"),
        "a wrong-catalog prompts cursor must stay InvalidParams: {rejected_tools}"
    );

    let first_templates = client
        .list_resource_templates(None)
        .expect("the first modern stdio templates/list page must miss and reach the catalog");
    assert_eq!(
        first_templates.resource_templates.len(),
        1,
        "page size 1 must create a real templates continuation: {first_templates:?}"
    );
    let first_template = first_templates.resource_templates[0].uri_template.clone();
    let template_cursor = first_templates
        .next_cursor
        .clone()
        .expect("the first page-size-1 templates/list must carry an opaque cursor");
    let second_templates = client
        .list_resource_templates(Some(&template_cursor))
        .expect("the exact templates cursor continuation must reach the second live page");
    assert_eq!(
        second_templates.resource_templates.len(),
        1,
        "the templates continuation must retain one remaining template: {second_templates:?}"
    );
    assert_ne!(
        second_templates.resource_templates[0].uri_template, first_template,
        "the templates continuation must advance to a different URI template: {second_templates:?}"
    );
    let rejected_resources = client
        .list_resources(Some(&template_cursor))
        .expect_err("a templates/list cursor must not page resources/list");
    let rejected_resources = format!("{rejected_resources:?}");
    assert!(
        rejected_resources.contains("InvalidParams") || rejected_resources.contains("invalid"),
        "a wrong-catalog templates cursor must stay InvalidParams: {rejected_resources}"
    );

    client
        .close()
        .expect("modern-only stdio catalog-paged client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_default_catalog_list_is_not_forced_to_page_size_one() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client connects to the unpaged echo peer");

    let resources = client
        .list_resources(None)
        .expect("omitting only FASTMCP_LIST_PAGE_SIZE must list the full first resources page");
    assert!(
        resources.resources.len() > 1,
        "changing only the missing page-size flag must keep more than one resource on the first page: {resources:?}"
    );
    let prompts = client
        .list_prompts(None)
        .expect("omitting only FASTMCP_LIST_PAGE_SIZE must list the full first prompts page");
    assert!(
        prompts.prompts.len() > 1,
        "changing only the missing page-size flag must keep more than one prompt on the first page: {prompts:?}"
    );
    let templates = client
        .list_resource_templates(None)
        .expect("omitting only FASTMCP_LIST_PAGE_SIZE must list the full first templates page");
    assert!(
        templates.resource_templates.len() > 1,
        "changing only the missing page-size flag must keep more than one template on the first page: {templates:?}"
    );

    client
        .close()
        .expect("modern-only stdio unpaged catalog client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_catalog_list_page_continues_and_rejects_wrong_kind_cursor() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_LIST_PAGE_SIZE", "1")],
    )
    .expect("a LegacyOnly facade client connects to the paged echo peer");

    let first_resources = client
        .list_resources_page(None, STDIO_LIST_PAGE_LIMITS)
        .expect("the first exact-2024 stdio resources/list page must miss and reach the catalog");
    assert_eq!(
        first_resources.items.len(),
        1,
        "page size 1 must create a real resources continuation: {first_resources:?}"
    );
    let first_resource = first_resources.items[0].uri.clone();
    let resource_cursor = first_resources
        .next_cursor
        .clone()
        .expect("the first page-size-1 resources/list must carry an opaque cursor");
    let second_resources = client
        .list_resources_page(Some(&resource_cursor), STDIO_LIST_PAGE_LIMITS)
        .expect("the exact resources cursor continuation must reach the second live page");
    assert_eq!(
        second_resources.items.len(),
        1,
        "the resources continuation must retain one remaining resource: {second_resources:?}"
    );
    assert_ne!(
        second_resources.items[0].uri, first_resource,
        "the resources continuation must advance to a different URI: {second_resources:?}"
    );
    let rejected_prompts = client
        .list_prompts_page(Some(&resource_cursor), STDIO_LIST_PAGE_LIMITS)
        .expect_err("a resources/list cursor must not page prompts/list");
    let rejected_prompts = format!("{rejected_prompts:?}");
    assert!(
        rejected_prompts.contains("InvalidParams") || rejected_prompts.contains("invalid"),
        "a wrong-catalog resources cursor must stay InvalidParams: {rejected_prompts}"
    );

    let first_prompts = client
        .list_prompts_page(None, STDIO_LIST_PAGE_LIMITS)
        .expect("the first exact-2024 stdio prompts/list page must miss and reach the catalog");
    assert_eq!(
        first_prompts.items.len(),
        1,
        "page size 1 must create a real prompts continuation: {first_prompts:?}"
    );
    let first_prompt = first_prompts.items[0].name.clone();
    let prompt_cursor = first_prompts
        .next_cursor
        .clone()
        .expect("the first page-size-1 prompts/list must carry an opaque cursor");
    let second_prompts = client
        .list_prompts_page(Some(&prompt_cursor), STDIO_LIST_PAGE_LIMITS)
        .expect("the exact prompts cursor continuation must reach the second live page");
    assert_eq!(
        second_prompts.items.len(),
        1,
        "the prompts continuation must retain one remaining prompt: {second_prompts:?}"
    );
    assert_ne!(
        second_prompts.items[0].name, first_prompt,
        "the prompts continuation must advance to a different name: {second_prompts:?}"
    );
    let rejected_tools = client
        .list_tools_page(Some(&prompt_cursor), STDIO_LIST_PAGE_LIMITS)
        .expect_err("a prompts/list cursor must not page tools/list");
    let rejected_tools = format!("{rejected_tools:?}");
    assert!(
        rejected_tools.contains("InvalidParams") || rejected_tools.contains("invalid"),
        "a wrong-catalog prompts cursor must stay InvalidParams: {rejected_tools}"
    );

    let first_templates = client
        .list_resource_templates_page(None, STDIO_LIST_PAGE_LIMITS)
        .expect("the first exact-2024 stdio templates/list page must miss and reach the catalog");
    assert_eq!(
        first_templates.items.len(),
        1,
        "page size 1 must create a real templates continuation: {first_templates:?}"
    );
    let first_template = first_templates.items[0].uri_template.clone();
    let template_cursor = first_templates
        .next_cursor
        .clone()
        .expect("the first page-size-1 templates/list must carry an opaque cursor");
    let second_templates = client
        .list_resource_templates_page(Some(&template_cursor), STDIO_LIST_PAGE_LIMITS)
        .expect("the exact templates cursor continuation must reach the second live page");
    assert_eq!(
        second_templates.items.len(),
        1,
        "the templates continuation must retain one remaining template: {second_templates:?}"
    );
    assert_ne!(
        second_templates.items[0].uri_template, first_template,
        "the templates continuation must advance to a different URI template: {second_templates:?}"
    );
    let rejected_resources = client
        .list_resources_page(Some(&template_cursor), STDIO_LIST_PAGE_LIMITS)
        .expect_err("a templates/list cursor must not page resources/list");
    let rejected_resources = format!("{rejected_resources:?}");
    assert!(
        rejected_resources.contains("InvalidParams") || rejected_resources.contains("invalid"),
        "a wrong-catalog templates cursor must stay InvalidParams: {rejected_resources}"
    );

    client
        .close()
        .expect("legacy-only stdio catalog-paged client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_default_catalog_list_is_not_forced_to_page_size_one() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client connects to the unpaged echo peer");

    let resources = client
        .list_resources_page(None, STDIO_LIST_PAGE_LIMITS)
        .expect("omitting only FASTMCP_LIST_PAGE_SIZE must list the full first resources page");
    assert!(
        resources.items.len() > 1,
        "changing only the missing page-size flag must keep more than one resource on the first page: {resources:?}"
    );
    let prompts = client
        .list_prompts_page(None, STDIO_LIST_PAGE_LIMITS)
        .expect("omitting only FASTMCP_LIST_PAGE_SIZE must list the full first prompts page");
    assert!(
        prompts.items.len() > 1,
        "changing only the missing page-size flag must keep more than one prompt on the first page: {prompts:?}"
    );
    let templates = client
        .list_resource_templates_page(None, STDIO_LIST_PAGE_LIMITS)
        .expect("omitting only FASTMCP_LIST_PAGE_SIZE must list the full first templates page");
    assert!(
        templates.items.len() > 1,
        "changing only the missing page-size flag must keep more than one template on the first page: {templates:?}"
    );

    client
        .close()
        .expect("legacy-only stdio unpaged catalog client cleanup");
}

#[cfg(unix)]
const STDIO_PANIC_TOOL: &str = "panic_probe";
#[cfg(unix)]
const STDIO_PANIC_PAYLOAD: &str = "planted-handler-panic-payload";

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_handler_panic_is_sanitized_and_admits_fast_peer() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_PANIC_TOOL", "1")],
    )
    .expect("a ModernOnly facade client connects to the panic-probe echo peer");

    let panicked = client
        .call_tool(STDIO_PANIC_TOOL, json!({}))
        .expect_err("a panicking tools/call must stay a protocol error");
    let panicked = format!("{panicked:?}");
    assert!(
        panicked.contains("Internal server error") || panicked.contains("InternalError"),
        "a handler panic must become the sanitized InternalError: {panicked}"
    );
    assert!(
        !panicked.contains(STDIO_PANIC_PAYLOAD),
        "a handler panic must not leak the unwind payload: {panicked}"
    );

    let peer = client
        .call_tool("echo", json!({"message": "after-panic"}))
        .expect("changing only the tool must still be admitted after a sanitized panic");
    assert_eq!(
        stdio_modern_tool_text(&peer),
        Some("after-panic"),
        "the peer echo must still complete after a sanitized panic: {peer:?}"
    );

    client
        .close()
        .expect("modern-only stdio handler-panic client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_handler_panic_is_sanitized_and_admits_fast_peer() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_PANIC_TOOL", "1")],
    )
    .expect("a LegacyOnly facade client connects to the panic-probe echo peer");

    let panicked = client
        .call_tool(STDIO_PANIC_TOOL, json!({}))
        .expect_err("a panicking exact-2024 tools/call must stay a protocol error");
    let panicked = format!("{panicked:?}");
    assert!(
        panicked.contains("Internal server error") || panicked.contains("InternalError"),
        "an exact-2024 handler panic must become the sanitized InternalError: {panicked}"
    );
    assert!(
        !panicked.contains(STDIO_PANIC_PAYLOAD),
        "an exact-2024 handler panic must not leak the unwind payload: {panicked}"
    );

    let peer = client
        .call_tool("echo", json!({"message": "after-panic"}))
        .expect("changing only the tool must still be admitted after a sanitized exact-2024 panic");
    assert_eq!(
        stdio_legacy_tool_text(&peer),
        Some("after-panic"),
        "the exact-2024 peer echo must still complete after a sanitized panic: {peer:?}"
    );

    client
        .close()
        .expect("legacy-only stdio handler-panic client cleanup");
}

#[cfg(unix)]
const STDIO_PANIC_RESOURCE_URI: &str = "info://panic";
#[cfg(unix)]
const STDIO_PANIC_PROMPT_NAME: &str = "panic_greeting";

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_catalog_panic_is_sanitized_and_admits_fast_peer() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_PANIC_CATALOG", "1")],
    )
    .expect("a ModernOnly facade client connects to the panic-catalog echo peer");

    let panicked_resource = client
        .read_resource(STDIO_PANIC_RESOURCE_URI)
        .expect_err("a panicking resources/read must stay a protocol error");
    let panicked_resource = format!("{panicked_resource:?}");
    assert!(
        panicked_resource.contains("Internal server error")
            || panicked_resource.contains("InternalError"),
        "a resource panic must become the sanitized InternalError: {panicked_resource}"
    );
    assert!(
        !panicked_resource.contains(STDIO_PANIC_PAYLOAD),
        "a resource panic must not leak the unwind payload: {panicked_resource}"
    );

    let panicked_prompt = client
        .get_prompt(STDIO_PANIC_PROMPT_NAME, HashMap::new())
        .expect_err("a panicking prompts/get must stay a protocol error");
    let panicked_prompt = format!("{panicked_prompt:?}");
    assert!(
        panicked_prompt.contains("Internal server error")
            || panicked_prompt.contains("InternalError"),
        "a prompt panic must become the sanitized InternalError: {panicked_prompt}"
    );
    assert!(
        !panicked_prompt.contains(STDIO_PANIC_PAYLOAD),
        "a prompt panic must not leak the unwind payload: {panicked_prompt}"
    );

    let peer_resource = client
        .read_resource("info://server")
        .expect("changing only the resource must still be admitted after a sanitized panic");
    let peer_resource = format!("{peer_resource:?}");
    assert!(
        peer_resource.contains("echo-server") || peer_resource.contains("info://server"),
        "the peer resource must still complete after a sanitized catalog panic: {peer_resource}"
    );

    let peer_prompt = client
        .get_prompt(
            "greeting",
            HashMap::from([("name".to_owned(), "World".to_owned())]),
        )
        .expect("changing only the prompt must still be admitted after a sanitized panic");
    let peer_prompt = format!("{peer_prompt:?}");
    assert!(
        peer_prompt.contains("World") || peer_prompt.contains("greet"),
        "the peer prompt must still complete after a sanitized catalog panic: {peer_prompt}"
    );

    client
        .close()
        .expect("modern-only stdio catalog-panic client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_catalog_panic_is_sanitized_and_admits_fast_peer() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_PANIC_CATALOG", "1")],
    )
    .expect("a LegacyOnly facade client connects to the panic-catalog echo peer");

    let panicked_resource = client
        .read_resource(STDIO_PANIC_RESOURCE_URI)
        .expect_err("a panicking exact-2024 resources/read must stay a protocol error");
    let panicked_resource = format!("{panicked_resource:?}");
    assert!(
        panicked_resource.contains("Internal server error")
            || panicked_resource.contains("InternalError"),
        "an exact-2024 resource panic must become the sanitized InternalError: {panicked_resource}"
    );
    assert!(
        !panicked_resource.contains(STDIO_PANIC_PAYLOAD),
        "an exact-2024 resource panic must not leak the unwind payload: {panicked_resource}"
    );

    let panicked_prompt = client
        .get_prompt(STDIO_PANIC_PROMPT_NAME, HashMap::new())
        .expect_err("a panicking exact-2024 prompts/get must stay a protocol error");
    let panicked_prompt = format!("{panicked_prompt:?}");
    assert!(
        panicked_prompt.contains("Internal server error")
            || panicked_prompt.contains("InternalError"),
        "an exact-2024 prompt panic must become the sanitized InternalError: {panicked_prompt}"
    );
    assert!(
        !panicked_prompt.contains(STDIO_PANIC_PAYLOAD),
        "an exact-2024 prompt panic must not leak the unwind payload: {panicked_prompt}"
    );

    let peer_resource = client.read_resource("info://server").expect(
        "changing only the resource must still be admitted after a sanitized exact-2024 panic",
    );
    let peer_resource = format!("{peer_resource:?}");
    assert!(
        peer_resource.contains("echo-server") || peer_resource.contains("info://server"),
        "the exact-2024 peer resource must still complete after a sanitized catalog panic: {peer_resource}"
    );

    let peer_prompt = client
        .get_prompt(
            "greeting",
            HashMap::from([("name".to_owned(), "World".to_owned())]),
        )
        .expect(
            "changing only the prompt must still be admitted after a sanitized exact-2024 panic",
        );
    let peer_prompt = format!("{peer_prompt:?}");
    assert!(
        peer_prompt.contains("World") || peer_prompt.contains("greet"),
        "the exact-2024 peer prompt must still complete after a sanitized catalog panic: {peer_prompt}"
    );

    client
        .close()
        .expect("legacy-only stdio catalog-panic client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_completion_panic_is_sanitized_and_admits_fast_peer() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_PANIC_COMPLETE", "1")],
    )
    .expect("a ModernOnly facade client connects to the panic-complete echo peer");

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
    let panicked = client
        .complete(params)
        .expect_err("a panicking completion/complete must stay a protocol error");
    let panicked = format!("{panicked:?}");
    assert!(
        panicked.contains("Internal server error") || panicked.contains("InternalError"),
        "a completion panic must become the sanitized InternalError: {panicked}"
    );
    assert!(
        !panicked.contains(STDIO_PANIC_PAYLOAD),
        "a completion panic must not leak the unwind payload: {panicked}"
    );

    let peer = client
        .call_tool("echo", json!({"message": "after-complete-panic"}))
        .expect(
            "changing only the method must still be admitted after a sanitized completion panic",
        );
    assert_eq!(
        stdio_modern_tool_text(&peer),
        Some("after-complete-panic"),
        "the peer echo must still complete after a sanitized completion panic: {peer:?}"
    );

    client
        .close()
        .expect("modern-only stdio completion-panic client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_completion_panic_is_sanitized_and_admits_fast_peer() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_PANIC_COMPLETE", "1")],
    )
    .expect("a LegacyOnly facade client connects to the panic-complete echo peer");

    let panicked = client
        .complete(legacy_2024::LegacyCompletionParams {
            reference: legacy_2024::LegacyCompletionReference::Prompt {
                name: "greeting".to_owned(),
            },
            argument: legacy_2024::LegacyCompletionArgument {
                name: "name".to_owned(),
                value: "co".to_owned(),
            },
            meta: None,
        })
        .expect_err("a panicking exact-2024 completion/complete must stay a protocol error");
    let panicked = format!("{panicked:?}");
    assert!(
        panicked.contains("Internal server error") || panicked.contains("InternalError"),
        "an exact-2024 completion panic must become the sanitized InternalError: {panicked}"
    );
    assert!(
        !panicked.contains(STDIO_PANIC_PAYLOAD),
        "an exact-2024 completion panic must not leak the unwind payload: {panicked}"
    );

    let peer = client
        .call_tool("echo", json!({"message": "after-complete-panic"}))
        .expect("changing only the method must still be admitted after a sanitized exact-2024 completion panic");
    assert_eq!(
        stdio_legacy_tool_text(&peer),
        Some("after-complete-panic"),
        "the exact-2024 peer echo must still complete after a sanitized completion panic: {peer:?}"
    );

    client
        .close()
        .expect("legacy-only stdio completion-panic client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_default_catalog_does_not_register_panic_probe() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client connects to the default echo peer");

    let missing = client
        .call_tool(STDIO_PANIC_TOOL, json!({}))
        .expect_err("omitting only FASTMCP_PANIC_TOOL must keep panic_probe unregistered");
    let missing = format!("{missing:?}");
    assert!(
        missing.contains("not found")
            || missing.contains("MethodNotFound")
            || missing.contains("ToolNotFound")
            || missing.contains("Unknown"),
        "changing only the missing panic-tool flag must stay a missing-tool refusal: {missing}"
    );
    assert!(
        !missing.contains(STDIO_PANIC_PAYLOAD),
        "an unregistered panic_probe must not leak the unwind payload: {missing}"
    );

    let peer = client
        .call_tool("echo", json!({"message": "no-panic-tool"}))
        .expect("the default catalog must still admit echo");
    assert_eq!(
        stdio_modern_tool_text(&peer),
        Some("no-panic-tool"),
        "omitting only FASTMCP_PANIC_TOOL must keep echo admitted: {peer:?}"
    );

    client
        .close()
        .expect("modern-only stdio missing panic-probe client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_default_catalog_does_not_register_panic_probe() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client connects to the default echo peer");

    let missing = client.call_tool(STDIO_PANIC_TOOL, json!({})).expect_err(
        "omitting only FASTMCP_PANIC_TOOL must keep exact-2024 panic_probe unregistered",
    );
    let missing = format!("{missing:?}");
    assert!(
        missing.contains("not found")
            || missing.contains("MethodNotFound")
            || missing.contains("ToolNotFound")
            || missing.contains("Unknown"),
        "changing only the missing panic-tool flag must stay a missing-tool refusal: {missing}"
    );
    assert!(
        !missing.contains(STDIO_PANIC_PAYLOAD),
        "an unregistered exact-2024 panic_probe must not leak the unwind payload: {missing}"
    );

    let peer = client
        .call_tool("echo", json!({"message": "no-panic-tool"}))
        .expect("the exact-2024 default catalog must still admit echo");
    assert_eq!(
        stdio_legacy_tool_text(&peer),
        Some("no-panic-tool"),
        "omitting only FASTMCP_PANIC_TOOL must keep exact-2024 echo admitted: {peer:?}"
    );

    client
        .close()
        .expect("legacy-only stdio missing panic-probe client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_transformed_echo_renames_argument() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_TRANSFORM_ECHO", "1")],
    )
    .expect("a ModernOnly facade client connects to the transformed echo peer");

    let renamed = client
        .call_tool("echo_text", json!({"text": "alpha"}))
        .expect("the renamed argument must reach the parent echo handler");
    assert_eq!(
        stdio_modern_tool_text(&renamed),
        Some("alpha"),
        "rename_arg must rewrite text back to message: {renamed:?}"
    );

    let stale = client.call_tool("echo_text", json!({"message": "alpha"}));
    let stale = match stale {
        Ok(result) => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        stale.contains("InvalidParams")
            || stale.contains("required")
            || stale.contains("message")
            || stale.contains("text")
            || stale.contains("is_error")
            || stale.contains("error"),
        "calling the pre-rename argument name must fail: {stale}"
    );

    let parent = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("the parent echo must stay registered beside the transform");
    assert_eq!(
        stdio_modern_tool_text(&parent),
        Some("alpha"),
        "the parent echo must keep the original argument name: {parent:?}"
    );

    client
        .close()
        .expect("modern-only stdio transformed-echo client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_transformed_echo_renames_argument() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_TRANSFORM_ECHO", "1")],
    )
    .expect("a LegacyOnly facade client connects to the transformed echo peer");

    let renamed = client
        .call_tool("echo_text", json!({"text": "alpha"}))
        .expect("the renamed argument must reach the parent echo handler");
    assert_eq!(
        stdio_legacy_tool_text(&renamed),
        Some("alpha"),
        "rename_arg must rewrite text back to message: {renamed:?}"
    );

    let stale = client.call_tool("echo_text", json!({"message": "alpha"}));
    let stale = match stale {
        Ok(result) => format!("{result:?}"),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        stale.contains("InvalidParams")
            || stale.contains("required")
            || stale.contains("message")
            || stale.contains("text")
            || stale.contains("is_error")
            || stale.contains("error"),
        "calling the pre-rename argument name must fail: {stale}"
    );

    let parent = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("the parent echo must stay registered beside the transform");
    assert_eq!(
        stdio_legacy_tool_text(&parent),
        Some("alpha"),
        "the parent echo must keep the original argument name: {parent:?}"
    );

    client
        .close()
        .expect("legacy-only stdio transformed-echo client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_transformed_echo_hides_argument_and_injects_default() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_TRANSFORM_HIDE", "1")],
    )
    .expect("a ModernOnly facade client connects to the hide-arg echo peer");

    let injected = client
        .call_tool("echo_hidden", json!({}))
        .expect("the hide-arg tools/call must inject the configured default");
    assert_eq!(
        stdio_modern_tool_text(&injected),
        Some("hidden-default"),
        "the hidden default must reach the parent echo handler: {injected:?}"
    );

    let parent = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("the parent echo must stay registered beside the hide-arg transform");
    assert_eq!(
        stdio_modern_tool_text(&parent),
        Some("alpha"),
        "the parent echo must keep the original argument: {parent:?}"
    );

    client
        .close()
        .expect("modern-only stdio hide-arg client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_transformed_echo_hides_argument_and_injects_default() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_TRANSFORM_HIDE", "1")],
    )
    .expect("a LegacyOnly facade client connects to the hide-arg echo peer");

    let injected = client
        .call_tool("echo_hidden", json!({}))
        .expect("the hide-arg tools/call must inject the configured default");
    assert_eq!(
        stdio_legacy_tool_text(&injected),
        Some("hidden-default"),
        "the hidden default must reach the parent echo handler: {injected:?}"
    );

    let parent = client
        .call_tool("echo", json!({"message": "alpha"}))
        .expect("the parent echo must stay registered beside the hide-arg transform");
    assert_eq!(
        stdio_legacy_tool_text(&parent),
        Some("alpha"),
        "the parent echo must keep the original argument: {parent:?}"
    );

    client
        .close()
        .expect("legacy-only stdio hide-arg client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_hide_arg_schema_drops_message() {
    let mut client = connect_modern_stdio_to_shipped_echo_server_with_env(
        "modern-only",
        &[("FASTMCP_TRANSFORM_HIDE", "1")],
    )
    .expect("a ModernOnly facade client connects to the hide-arg echo peer");

    let listed = client
        .list_tools(None)
        .expect("hide-arg catalog must list echo_hidden");
    let hidden = listed
        .tools
        .iter()
        .find(|tool| tool.name == "echo_hidden")
        .unwrap_or_else(|| panic!("the hide-arg catalog must advertise echo_hidden: {listed:?}"));
    let schema =
        serde_json::to_string(&hidden.input_schema).expect("the hide-arg schema serializes");
    assert!(
        !schema.contains("\"message\""),
        "the hide-arg schema must drop the hidden argument: {schema}"
    );
    let parent = listed
        .tools
        .iter()
        .find(|tool| tool.name == "echo")
        .unwrap_or_else(|| panic!("the parent echo must stay listed: {listed:?}"));
    let parent_schema =
        serde_json::to_string(&parent.input_schema).expect("the parent schema serializes");
    assert!(
        parent_schema.contains("\"message\""),
        "the parent echo schema must keep message: {parent_schema}"
    );

    client
        .close()
        .expect("modern-only stdio hide-arg schema client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_hide_arg_schema_drops_message() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_TRANSFORM_HIDE", "1")],
    )
    .expect("a LegacyOnly facade client connects to the hide-arg echo peer");

    let listed = client
        .list_tools()
        .expect("hide-arg catalog must list echo_hidden");
    let hidden = listed
        .iter()
        .find(|tool| tool.name == "echo_hidden")
        .unwrap_or_else(|| panic!("the hide-arg catalog must advertise echo_hidden: {listed:?}"));
    let schema =
        serde_json::to_string(&hidden.input_schema).expect("the hide-arg schema serializes");
    assert!(
        !schema.contains("\"message\""),
        "the hide-arg schema must drop the hidden argument: {schema}"
    );
    let parent = listed
        .iter()
        .find(|tool| tool.name == "echo")
        .unwrap_or_else(|| panic!("the parent echo must stay listed: {listed:?}"));
    let parent_schema =
        serde_json::to_string(&parent.input_schema).expect("the parent schema serializes");
    assert!(
        parent_schema.contains("\"message\""),
        "the parent echo schema must keep message: {parent_schema}"
    );

    client
        .close()
        .expect("legacy-only stdio hide-arg schema client cleanup");
}

#[cfg(unix)]
fn stdio_tool_list_params(include: Option<&[&str]>, exclude: Option<&[&str]>) -> ListToolsParams {
    ListToolsParams {
        include_tags: include.map(|tags| tags.iter().map(|tag| (*tag).to_owned()).collect()),
        exclude_tags: exclude.map(|tags| tags.iter().map(|tag| (*tag).to_owned()).collect()),
        ..ListToolsParams::default()
    }
}

#[cfg(unix)]
fn stdio_resource_list_params(
    include: Option<&[&str]>,
    exclude: Option<&[&str]>,
) -> ListResourcesParams {
    ListResourcesParams {
        include_tags: include.map(|tags| tags.iter().map(|tag| (*tag).to_owned()).collect()),
        exclude_tags: exclude.map(|tags| tags.iter().map(|tag| (*tag).to_owned()).collect()),
        ..ListResourcesParams::default()
    }
}

#[cfg(unix)]
fn stdio_prompt_list_params(
    include: Option<&[&str]>,
    exclude: Option<&[&str]>,
) -> ListPromptsParams {
    ListPromptsParams {
        include_tags: include.map(|tags| tags.iter().map(|tag| (*tag).to_owned()).collect()),
        exclude_tags: exclude.map(|tags| tags.iter().map(|tag| (*tag).to_owned()).collect()),
        ..ListPromptsParams::default()
    }
}

#[cfg(unix)]
fn stdio_template_list_params(
    include: Option<&[&str]>,
    exclude: Option<&[&str]>,
) -> ListResourceTemplatesParams {
    ListResourceTemplatesParams {
        include_tags: include.map(|tags| tags.iter().map(|tag| (*tag).to_owned()).collect()),
        exclude_tags: exclude.map(|tags| tags.iter().map(|tag| (*tag).to_owned()).collect()),
        ..ListResourceTemplatesParams::default()
    }
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_list_tools_include_and_exclude_tags() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client connects to the tagged echo peer");

    let demo = client
        .list_tools_with_params(stdio_tool_list_params(Some(&["demo"]), None))
        .expect("includeTags demo must list the tagged echo tool");
    assert!(
        demo.tools.iter().any(|tool| tool.name == "echo"),
        "includeTags demo must retain echo: {demo:?}"
    );
    assert!(
        demo.tools.iter().all(|tool| tool.name != "add"),
        "includeTags demo must omit add: {demo:?}"
    );

    let math = client
        .list_tools_with_params(stdio_tool_list_params(Some(&["math"]), None))
        .expect("changing only includeTags must list the math-tagged add tool");
    assert!(
        math.tools.iter().any(|tool| tool.name == "add"),
        "includeTags math must retain add: {math:?}"
    );
    assert!(
        math.tools.iter().all(|tool| tool.name != "echo"),
        "includeTags math must omit echo: {math:?}"
    );

    let excluded = client
        .list_tools_with_params(stdio_tool_list_params(None, Some(&["demo"])))
        .expect("excludeTags demo must omit only the demo-tagged tool");
    assert!(
        excluded.tools.iter().any(|tool| tool.name == "add"),
        "excludeTags demo must keep add: {excluded:?}"
    );
    assert!(
        excluded.tools.iter().all(|tool| tool.name != "echo"),
        "excludeTags demo must omit echo: {excluded:?}"
    );

    let listed = client
        .list_tools(None)
        .expect("an unfiltered modern tools/list must keep both tagged tools");
    assert!(
        listed.tools.iter().any(|tool| tool.name == "echo")
            && listed.tools.iter().any(|tool| tool.name == "add"),
        "omitting only the tag filters must list echo and add: {listed:?}"
    );

    client
        .close()
        .expect("modern-only stdio tag-filter client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_list_tools_include_and_exclude_tags() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client connects to the tagged echo peer");

    let demo = client
        .list_tools_with_params(stdio_tool_list_params(Some(&["demo"]), None))
        .expect("includeTags demo must list the tagged echo tool");
    assert!(
        demo.iter().any(|tool| tool.name == "echo"),
        "includeTags demo must retain echo: {demo:?}"
    );
    assert!(
        demo.iter().all(|tool| tool.name != "add"),
        "includeTags demo must omit add: {demo:?}"
    );
    assert!(
        demo.iter()
            .any(|tool| tool.name == "echo" && tool.tags.iter().any(|tag| tag == "demo")),
        "exact-2024 includeTags must retain the demo tag on echo: {demo:?}"
    );

    let math = client
        .list_tools_with_params(stdio_tool_list_params(Some(&["math"]), None))
        .expect("changing only includeTags must list the math-tagged add tool");
    assert!(
        math.iter().any(|tool| tool.name == "add"),
        "includeTags math must retain add: {math:?}"
    );
    assert!(
        math.iter().all(|tool| tool.name != "echo"),
        "includeTags math must omit echo: {math:?}"
    );

    let excluded = client
        .list_tools_with_params(stdio_tool_list_params(None, Some(&["demo"])))
        .expect("excludeTags demo must omit only the demo-tagged tool");
    assert!(
        excluded.iter().any(|tool| tool.name == "add"),
        "excludeTags demo must keep add: {excluded:?}"
    );
    assert!(
        excluded.iter().all(|tool| tool.name != "echo"),
        "excludeTags demo must omit echo: {excluded:?}"
    );

    let listed = client
        .list_tools()
        .expect("an unfiltered exact-2024 tools/list must keep both tagged tools");
    assert!(
        listed.iter().any(|tool| tool.name == "echo")
            && listed.iter().any(|tool| tool.name == "add"),
        "omitting only the tag filters must list echo and add: {listed:?}"
    );

    client
        .close()
        .expect("legacy-only stdio tag-filter client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_list_resources_include_and_exclude_tags() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client connects to the tagged echo peer");

    let server = client
        .list_resources_with_params(stdio_resource_list_params(Some(&["server"]), None))
        .expect("includeTags server must list the tagged info://server resource");
    assert!(
        server
            .resources
            .iter()
            .any(|resource| resource.uri.as_str() == "info://server"),
        "includeTags server must retain info://server: {server:?}"
    );
    assert!(
        server
            .resources
            .iter()
            .all(|resource| resource.uri.as_str() != "info://leak"),
        "includeTags server must omit info://leak: {server:?}"
    );

    let secret = client
        .list_resources_with_params(stdio_resource_list_params(Some(&["secret"]), None))
        .expect("changing only includeTags must list the secret-tagged leak resource");
    assert!(
        secret
            .resources
            .iter()
            .any(|resource| resource.uri.as_str() == "info://leak"),
        "includeTags secret must retain info://leak: {secret:?}"
    );
    assert!(
        secret
            .resources
            .iter()
            .all(|resource| resource.uri.as_str() != "info://server"),
        "includeTags secret must omit info://server: {secret:?}"
    );

    let excluded = client
        .list_resources_with_params(stdio_resource_list_params(None, Some(&["server"])))
        .expect("excludeTags server must omit only the server-tagged resource");
    assert!(
        excluded
            .resources
            .iter()
            .any(|resource| resource.uri.as_str() == "info://leak"),
        "excludeTags server must keep info://leak: {excluded:?}"
    );
    assert!(
        excluded
            .resources
            .iter()
            .all(|resource| resource.uri.as_str() != "info://server"),
        "excludeTags server must omit info://server: {excluded:?}"
    );

    let listed = client
        .list_resources(None)
        .expect("an unfiltered modern resources/list must keep both tagged resources");
    assert!(
        listed
            .resources
            .iter()
            .any(|resource| resource.uri.as_str() == "info://server")
            && listed
                .resources
                .iter()
                .any(|resource| resource.uri.as_str() == "info://leak"),
        "omitting only the tag filters must list info://server and info://leak: {listed:?}"
    );

    client
        .close()
        .expect("modern-only stdio resource tag-filter client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_list_resources_include_and_exclude_tags() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client connects to the tagged echo peer");

    let server = client
        .list_resources_with_params(stdio_resource_list_params(Some(&["server"]), None))
        .expect("includeTags server must list the tagged info://server resource");
    assert!(
        server
            .iter()
            .any(|resource| resource.uri == "info://server"),
        "includeTags server must retain info://server: {server:?}"
    );
    assert!(
        server.iter().all(|resource| resource.uri != "info://leak"),
        "includeTags server must omit info://leak: {server:?}"
    );
    assert!(
        server.iter().any(|resource| resource.uri == "info://server"
            && resource.tags.iter().any(|tag| tag == "server")),
        "exact-2024 includeTags must retain the server tag on info://server: {server:?}"
    );

    let secret = client
        .list_resources_with_params(stdio_resource_list_params(Some(&["secret"]), None))
        .expect("changing only includeTags must list the secret-tagged leak resource");
    assert!(
        secret.iter().any(|resource| resource.uri == "info://leak"),
        "includeTags secret must retain info://leak: {secret:?}"
    );
    assert!(
        secret
            .iter()
            .all(|resource| resource.uri != "info://server"),
        "includeTags secret must omit info://server: {secret:?}"
    );

    let excluded = client
        .list_resources_with_params(stdio_resource_list_params(None, Some(&["server"])))
        .expect("excludeTags server must omit only the server-tagged resource");
    assert!(
        excluded
            .iter()
            .any(|resource| resource.uri == "info://leak"),
        "excludeTags server must keep info://leak: {excluded:?}"
    );
    assert!(
        excluded
            .iter()
            .all(|resource| resource.uri != "info://server"),
        "excludeTags server must omit info://server: {excluded:?}"
    );

    let listed = client
        .list_resources()
        .expect("an unfiltered exact-2024 resources/list must keep both tagged resources");
    assert!(
        listed
            .iter()
            .any(|resource| resource.uri == "info://server")
            && listed.iter().any(|resource| resource.uri == "info://leak"),
        "omitting only the tag filters must list info://server and info://leak: {listed:?}"
    );

    client
        .close()
        .expect("legacy-only stdio resource tag-filter client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_list_prompts_include_and_exclude_tags() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client connects to the tagged echo peer");

    let onboarding = client
        .list_prompts_with_params(stdio_prompt_list_params(Some(&["onboarding"]), None))
        .expect("includeTags onboarding must list the tagged greeting prompt");
    assert!(
        onboarding
            .prompts
            .iter()
            .any(|prompt| prompt.name == "greeting"),
        "includeTags onboarding must retain greeting: {onboarding:?}"
    );
    assert!(
        onboarding
            .prompts
            .iter()
            .all(|prompt| prompt.name != "compose_greeting"),
        "includeTags onboarding must omit compose_greeting: {onboarding:?}"
    );

    let compose = client
        .list_prompts_with_params(stdio_prompt_list_params(Some(&["compose"]), None))
        .expect("changing only includeTags must list the compose-tagged prompt");
    assert!(
        compose
            .prompts
            .iter()
            .any(|prompt| prompt.name == "compose_greeting"),
        "includeTags compose must retain compose_greeting: {compose:?}"
    );
    assert!(
        compose
            .prompts
            .iter()
            .all(|prompt| prompt.name != "greeting"),
        "includeTags compose must omit greeting: {compose:?}"
    );

    let excluded = client
        .list_prompts_with_params(stdio_prompt_list_params(None, Some(&["onboarding"])))
        .expect("excludeTags onboarding must omit only the onboarding-tagged prompt");
    assert!(
        excluded
            .prompts
            .iter()
            .any(|prompt| prompt.name == "compose_greeting"),
        "excludeTags onboarding must keep compose_greeting: {excluded:?}"
    );
    assert!(
        excluded
            .prompts
            .iter()
            .all(|prompt| prompt.name != "greeting"),
        "excludeTags onboarding must omit greeting: {excluded:?}"
    );

    let listed = client
        .list_prompts(None)
        .expect("an unfiltered modern prompts/list must keep both tagged prompts");
    assert!(
        listed
            .prompts
            .iter()
            .any(|prompt| prompt.name == "greeting")
            && listed
                .prompts
                .iter()
                .any(|prompt| prompt.name == "compose_greeting"),
        "omitting only the tag filters must list greeting and compose_greeting: {listed:?}"
    );

    client
        .close()
        .expect("modern-only stdio prompt tag-filter client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_list_prompts_include_and_exclude_tags() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client connects to the tagged echo peer");

    let onboarding = client
        .list_prompts_with_params(stdio_prompt_list_params(Some(&["onboarding"]), None))
        .expect("includeTags onboarding must list the tagged greeting prompt");
    assert!(
        onboarding.iter().any(|prompt| prompt.name == "greeting"),
        "includeTags onboarding must retain greeting: {onboarding:?}"
    );
    assert!(
        onboarding
            .iter()
            .all(|prompt| prompt.name != "compose_greeting"),
        "includeTags onboarding must omit compose_greeting: {onboarding:?}"
    );
    assert!(
        onboarding
            .iter()
            .any(|prompt| prompt.name == "greeting"
                && prompt.tags.iter().any(|tag| tag == "onboarding")),
        "exact-2024 includeTags must retain the onboarding tag on greeting: {onboarding:?}"
    );

    let compose = client
        .list_prompts_with_params(stdio_prompt_list_params(Some(&["compose"]), None))
        .expect("changing only includeTags must list the compose-tagged prompt");
    assert!(
        compose
            .iter()
            .any(|prompt| prompt.name == "compose_greeting"),
        "includeTags compose must retain compose_greeting: {compose:?}"
    );
    assert!(
        compose.iter().all(|prompt| prompt.name != "greeting"),
        "includeTags compose must omit greeting: {compose:?}"
    );

    let excluded = client
        .list_prompts_with_params(stdio_prompt_list_params(None, Some(&["onboarding"])))
        .expect("excludeTags onboarding must omit only the onboarding-tagged prompt");
    assert!(
        excluded
            .iter()
            .any(|prompt| prompt.name == "compose_greeting"),
        "excludeTags onboarding must keep compose_greeting: {excluded:?}"
    );
    assert!(
        excluded.iter().all(|prompt| prompt.name != "greeting"),
        "excludeTags onboarding must omit greeting: {excluded:?}"
    );

    let listed = client
        .list_prompts()
        .expect("an unfiltered exact-2024 prompts/list must keep both tagged prompts");
    assert!(
        listed.iter().any(|prompt| prompt.name == "greeting")
            && listed
                .iter()
                .any(|prompt| prompt.name == "compose_greeting"),
        "omitting only the tag filters must list greeting and compose_greeting: {listed:?}"
    );

    client
        .close()
        .expect("legacy-only stdio prompt tag-filter client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_list_resource_templates_include_and_exclude_tags() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client connects to the tagged echo peer");

    let notes = client
        .list_resource_templates_with_params(stdio_template_list_params(Some(&["notes"]), None))
        .expect("includeTags notes must list the note template");
    assert!(
        notes
            .resource_templates
            .iter()
            .any(|template| template.uri_template == "note://{name}"),
        "includeTags notes must retain note://{{name}}: {notes:?}"
    );
    assert!(
        notes
            .resource_templates
            .iter()
            .all(|template| template.uri_template != "memo://{name}"),
        "includeTags notes must omit memo://{{name}}: {notes:?}"
    );

    let memos = client
        .list_resource_templates_with_params(stdio_template_list_params(Some(&["memos"]), None))
        .expect("changing only includeTags must list the memo template");
    assert!(
        memos
            .resource_templates
            .iter()
            .any(|template| template.uri_template == "memo://{name}"),
        "includeTags memos must retain memo://{{name}}: {memos:?}"
    );
    assert!(
        memos
            .resource_templates
            .iter()
            .all(|template| template.uri_template != "note://{name}"),
        "includeTags memos must omit note://{{name}}: {memos:?}"
    );

    let excluded = client
        .list_resource_templates_with_params(stdio_template_list_params(None, Some(&["notes"])))
        .expect("excludeTags notes must omit only the notes template");
    assert!(
        excluded
            .resource_templates
            .iter()
            .any(|template| template.uri_template == "memo://{name}"),
        "excludeTags notes must keep memo://{{name}}: {excluded:?}"
    );
    assert!(
        excluded
            .resource_templates
            .iter()
            .all(|template| template.uri_template != "note://{name}"),
        "excludeTags notes must omit note://{{name}}: {excluded:?}"
    );

    let listed = client
        .list_resource_templates(None)
        .expect("an unfiltered modern templates/list must keep both tagged templates");
    assert!(
        listed
            .resource_templates
            .iter()
            .any(|template| template.uri_template == "note://{name}")
            && listed
                .resource_templates
                .iter()
                .any(|template| template.uri_template == "memo://{name}"),
        "omitting only the tag filters must list note and memo templates: {listed:?}"
    );

    client
        .close()
        .expect("modern-only stdio template tag-filter client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_list_resource_templates_include_and_exclude_tags() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client connects to the tagged echo peer");

    let notes = client
        .list_resource_templates_with_params(stdio_template_list_params(Some(&["notes"]), None))
        .expect("includeTags notes must list the note template");
    assert!(
        notes
            .iter()
            .any(|template| template.uri_template == "note://{name}"),
        "includeTags notes must retain note://{{name}}: {notes:?}"
    );
    assert!(
        notes
            .iter()
            .all(|template| template.uri_template != "memo://{name}"),
        "includeTags notes must omit memo://{{name}}: {notes:?}"
    );
    assert!(
        notes
            .iter()
            .any(|template| template.uri_template == "note://{name}"
                && template.tags.iter().any(|tag| tag == "notes")),
        "exact-2024 includeTags must retain the notes tag on note://{{name}}: {notes:?}"
    );

    let memos = client
        .list_resource_templates_with_params(stdio_template_list_params(Some(&["memos"]), None))
        .expect("changing only includeTags must list the memo template");
    assert!(
        memos
            .iter()
            .any(|template| template.uri_template == "memo://{name}"),
        "includeTags memos must retain memo://{{name}}: {memos:?}"
    );
    assert!(
        memos
            .iter()
            .all(|template| template.uri_template != "note://{name}"),
        "includeTags memos must omit note://{{name}}: {memos:?}"
    );

    let excluded = client
        .list_resource_templates_with_params(stdio_template_list_params(None, Some(&["notes"])))
        .expect("excludeTags notes must omit only the notes template");
    assert!(
        excluded
            .iter()
            .any(|template| template.uri_template == "memo://{name}"),
        "excludeTags notes must keep memo://{{name}}: {excluded:?}"
    );
    assert!(
        excluded
            .iter()
            .all(|template| template.uri_template != "note://{name}"),
        "excludeTags notes must omit note://{{name}}: {excluded:?}"
    );

    let listed = client
        .list_resource_templates()
        .expect("an unfiltered exact-2024 templates/list must keep both tagged templates");
    assert!(
        listed
            .iter()
            .any(|template| template.uri_template == "note://{name}")
            && listed
                .iter()
                .any(|template| template.uri_template == "memo://{name}"),
        "omitting only the tag filters must list note and memo templates: {listed:?}"
    );

    client
        .close()
        .expect("legacy-only stdio template tag-filter client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_list_catalog_include_tags_honor_cancellation_domain() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client connects before tagged catalog cancellation");
    let cx = Cx::for_request();
    let live = fastmcp_rust::McpRequestCancellation::new();

    let server = client
        .list_resources_with_params_and_cancellation(
            &cx,
            &live,
            stdio_resource_list_params(Some(&["server"]), None),
        )
        .expect("an uncancelled domain must still send includeTags on resources/list");
    assert!(
        server
            .resources
            .iter()
            .any(|resource| resource.uri.as_str() == "info://server"),
        "live cancellation domain plus includeTags server must retain info://server: {server:?}"
    );
    assert!(
        server
            .resources
            .iter()
            .all(|resource| resource.uri.as_str() != "info://leak"),
        "live cancellation domain plus includeTags server must omit info://leak: {server:?}"
    );

    let onboarding = client
        .list_prompts_with_params_and_cancellation(
            &cx,
            &live,
            stdio_prompt_list_params(Some(&["onboarding"]), None),
        )
        .expect("an uncancelled domain must still send includeTags on prompts/list");
    assert!(
        onboarding
            .prompts
            .iter()
            .any(|prompt| prompt.name == "greeting"),
        "live cancellation domain plus includeTags onboarding must retain greeting: {onboarding:?}"
    );
    assert!(
        onboarding
            .prompts
            .iter()
            .all(|prompt| prompt.name != "compose_greeting"),
        "live cancellation domain plus includeTags onboarding must omit compose_greeting: {onboarding:?}"
    );

    let notes = client
        .list_resource_templates_with_params_and_cancellation(
            &cx,
            &live,
            stdio_template_list_params(Some(&["notes"]), None),
        )
        .expect("an uncancelled domain must still send includeTags on resources/templates/list");
    assert!(
        notes
            .resource_templates
            .iter()
            .any(|template| template.uri_template == "note://{name}"),
        "live cancellation domain plus includeTags notes must retain note://{{name}}: {notes:?}"
    );
    assert!(
        notes
            .resource_templates
            .iter()
            .all(|template| template.uri_template != "memo://{name}"),
        "live cancellation domain plus includeTags notes must omit memo://{{name}}: {notes:?}"
    );

    let already = fastmcp_rust::McpRequestCancellation::new();
    already.cancel();
    let pre_send_resources = client
        .list_resources_with_params_and_cancellation(
            &cx,
            &already,
            stdio_resource_list_params(Some(&["server"]), None),
        )
        .expect_err("pre-send cancellation must reject a tagged resources/list locally");
    assert_eq!(pre_send_resources.code, McpErrorCode::RequestCancelled);
    let pre_send_prompts = client
        .list_prompts_with_params_and_cancellation(
            &cx,
            &already,
            stdio_prompt_list_params(Some(&["onboarding"]), None),
        )
        .expect_err("pre-send cancellation must reject a tagged prompts/list locally");
    assert_eq!(pre_send_prompts.code, McpErrorCode::RequestCancelled);
    let pre_send_templates = client
        .list_resource_templates_with_params_and_cancellation(
            &cx,
            &already,
            stdio_template_list_params(Some(&["notes"]), None),
        )
        .expect_err("pre-send cancellation must reject a tagged resources/templates/list locally");
    assert_eq!(pre_send_templates.code, McpErrorCode::RequestCancelled);

    client
        .ping()
        .expect("modern stdio ping remains usable after tagged catalog cancellation");
    client
        .close()
        .expect("modern-only stdio tagged catalog cancellation client cleanup");
}

const STDIO_SERVER_INFO_ICON: &str = "https://example.test/echo-server.png";
const STDIO_GREETING_ICON: &str = "https://example.test/echo-greeting.png";

#[cfg(unix)]
#[test]
fn e2e_public_stdio_modern_list_resources_and_prompts_retain_icons() {
    let mut client = connect_bounded_modern_stdio_to_shipped_echo_server("modern-only")
        .expect("a ModernOnly facade client connects to the icon-bearing echo peer");

    let listed = client
        .list_resources(None)
        .expect("modern resources/list must retain shipped icons");
    let server = listed
        .resources
        .iter()
        .find(|resource| resource.uri.as_str() == "info://server")
        .expect("info://server must remain on the live catalog");
    let leak = listed
        .resources
        .iter()
        .find(|resource| resource.uri.as_str() == "info://leak")
        .expect("info://leak must remain the iconless peer");
    let icons = server
        .icons
        .as_ref()
        .expect("info://server must advertise its exact-final icon");
    assert_eq!(icons.len(), 1);
    assert_eq!(icons[0].src.as_str(), STDIO_SERVER_INFO_ICON);
    assert_eq!(
        leak.icons, None,
        "changing only the missing icon must keep info://leak iconless: {leak:?}"
    );

    let listed_prompts = client
        .list_prompts(None)
        .expect("modern prompts/list must retain shipped icons");
    let greeting = listed_prompts
        .prompts
        .iter()
        .find(|prompt| prompt.name == "greeting")
        .expect("greeting must remain on the live catalog");
    let compose = listed_prompts
        .prompts
        .iter()
        .find(|prompt| prompt.name == "compose_greeting")
        .expect("compose_greeting must remain the iconless peer");
    let greeting_icons = greeting
        .icons
        .as_ref()
        .expect("greeting must advertise its exact-final icon");
    assert_eq!(greeting_icons.len(), 1);
    assert_eq!(greeting_icons[0].src.as_str(), STDIO_GREETING_ICON);
    assert_eq!(
        compose.icons, None,
        "changing only the missing icon must keep compose_greeting iconless: {compose:?}"
    );

    client
        .close()
        .expect("modern-only stdio catalog-icon client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_list_resources_and_prompts_retain_icons() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client connects to the icon-bearing echo peer");

    let listed = client
        .list_resources()
        .expect("exact-2024 resources/list must retain shipped icons");
    let server = listed
        .iter()
        .find(|resource| resource.uri == "info://server")
        .expect("info://server must remain on the live catalog");
    let leak = listed
        .iter()
        .find(|resource| resource.uri == "info://leak")
        .expect("info://leak must remain the iconless peer");
    assert_eq!(
        server.icon.as_ref().and_then(|icon| icon.src.as_deref()),
        Some(STDIO_SERVER_INFO_ICON),
        "exact-2024 info://server must retain its icon src: {server:?}"
    );
    assert_eq!(
        leak.icon, None,
        "changing only the missing icon must keep info://leak iconless: {leak:?}"
    );

    let listed_prompts = client
        .list_prompts()
        .expect("exact-2024 prompts/list must retain shipped icons");
    let greeting = listed_prompts
        .iter()
        .find(|prompt| prompt.name == "greeting")
        .expect("greeting must remain on the live catalog");
    let compose = listed_prompts
        .iter()
        .find(|prompt| prompt.name == "compose_greeting")
        .expect("compose_greeting must remain the iconless peer");
    assert_eq!(
        greeting.icon.as_ref().and_then(|icon| icon.src.as_deref()),
        Some(STDIO_GREETING_ICON),
        "exact-2024 greeting must retain its icon src: {greeting:?}"
    );
    assert_eq!(
        compose.icon, None,
        "changing only the missing icon must keep compose_greeting iconless: {compose:?}"
    );

    client
        .close()
        .expect("legacy-only stdio catalog-icon client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_initialize_retains_instructions_peer_stays_bare() {
    let mut bare = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_NO_INSTRUCTIONS", "1")],
    )
    .expect("a LegacyOnly facade client connects to the bare echo peer");
    assert_eq!(
        bare.instructions(),
        None,
        "changing only the missing instructions must keep the peer bare"
    );
    bare.close().expect("bare legacy stdio client cleanup");
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
fn e2e_public_legacy_stdio_sampling_callback_reaches_context() {
    let callback_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handlers = legacy_2024::LegacyReverseRequestHandlers::new().with_sampling_create_message({
        let callback_calls = Arc::clone(&callback_calls);
        move |_cx, _cancellation, _params| {
            callback_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Box::pin(async {
                Ok(legacy_2024::LegacyCreateMessageResult::text(
                    "sampled-legacy",
                    "stdio-legacy-model",
                ))
            })
        }
    });
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("legacy sampling runtime builds");
    runtime.block_on(async move {
        let cx = Cx::current().expect("legacy sampling runtime installs its Cx");
        let mut client = connect_legacy_stdio_to_shipped_echo_server_with_reverse_handlers(
            "legacy-only",
            handlers,
        )
        .expect("the sampling callback is configured before exact legacy initialization");
        let result = client
            .call_tool_with_cx(&cx, "sample_text", json!({}))
            .await
            .expect("the sealed legacy facade services sampling/createMessage before its typed tool result");
        assert!(!result.is_error);
        assert!(matches!(
            result.content.first(),
            Some(LegacyContent::Text { text, .. }) if text == "sampled-legacy"
        ));
        assert_eq!(
            callback_calls.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the tool's context authority issues exactly one sampling/createMessage callback"
        );
        client.close().expect("legacy sampling client cleanup");
    });
}

#[cfg(unix)]
#[test]
fn e2e_public_legacy_stdio_sampling_without_capability_has_no_callback_authority() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("legacy missing-sampling runtime builds");
    runtime.block_on(async move {
        let cx = Cx::current().expect("legacy missing-sampling runtime installs its Cx");
        let mut client = connect_legacy_stdio_to_shipped_echo_server_with_reverse_handlers(
            "legacy-only",
            legacy_2024::LegacyReverseRequestHandlers::new(),
        )
        .expect("the exact legacy connection without sampling capability initializes");
        let result = client
            .call_tool_with_cx(&cx, "sample_text", json!({}))
            .await
            .expect("missing sampling authority remains a typed legacy tool result");
        assert!(result.is_error);
        assert!(matches!(
            result.content.first(),
            Some(LegacyContent::Text { text, .. })
                if text.contains("does not support sampling capability")
        ));
        client.close().expect("legacy sampling client cleanup");
    });
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_ping_is_admitted_and_missing_tool_stays_refused() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    client
        .ping()
        .expect("live exact-2024 stdio must admit ping");

    let missing = client
        .call_tool("stdio-e2e-missing", json!({}))
        .expect_err("changing only the missing tool must keep the session refused");
    let missing = format!("{missing:?}");
    assert!(
        missing.contains("MethodNotFound")
            || missing.contains("InvalidParams")
            || missing.contains("InvalidRequest")
            || missing.contains("not found")
            || missing.contains("Unknown tool"),
        "a missing exact-2024 stdio tool must stay a handler-visible refusal: {missing}"
    );

    client
        .close()
        .expect("legacy-only stdio ping client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_complete_is_retained_and_unknown_prompt_is_refused() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    assert!(
        client.server_capabilities().completions.is_some(),
        "the shipped echo server must advertise completions: {:?}",
        client.server_capabilities()
    );

    let completed = client
        .complete(legacy_2024::LegacyCompletionParams {
            reference: legacy_2024::LegacyCompletionReference::Prompt {
                name: "greeting".to_owned(),
            },
            argument: legacy_2024::LegacyCompletionArgument {
                name: "name".to_owned(),
                value: "co".to_owned(),
            },
            meta: None,
        })
        .expect("live exact-2024 stdio must complete the shipped greeting provider");
    assert_eq!(
        completed.completion.values,
        vec!["stdio-completion-legacy".to_owned()],
        "the exact-2024 completion provider must retain its values: {completed:?}"
    );

    client
        .close()
        .expect("legacy-only stdio complete client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_roots_list_changed_is_admitted_and_unadvertised_peer_is_refused() {
    let command = shipped_echo_server_executable();
    let mut admitted = block_on(
        legacy_2024::client_builder()
            .env("FASTMCP_PROTOCOL_POLICY", "legacy-only")
            .capabilities(ClientCapabilities {
                roots: Some(legacy_2024::RootsCapability { list_changed: true }),
                ..ClientCapabilities::default()
            })
            .reverse_request_handlers(
                legacy_2024::LegacyReverseRequestHandlers::new().with_roots_list(
                    |_cx, _cancel, _params| {
                        Box::pin(async { Ok(legacy_2024::ListRootsResult::new(Vec::new())) })
                    },
                ),
            )
            .connect_stdio_with_cx(command, &[], &Cx::for_request()),
    )
    .expect("an advertised roots.listChanged stdio client completes the exact legacy lifecycle");

    admitted.roots_list_changed().expect(
        "live exact-2024 stdio must admit notifications/roots/list_changed when advertised",
    );
    admitted
        .ping()
        .expect("the same session must still admit ping after roots/list_changed");

    let mut refused = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a bare LegacyOnly facade client completes the exact legacy lifecycle");
    let missing = refused
        .roots_list_changed()
        .expect_err("changing only the missing roots.listChanged advertisement must refuse");
    let missing = format!("{missing:?}");
    assert!(
        missing.contains("roots.listChanged") || missing.contains("InvalidRequest"),
        "the unadvertised refusal must keep the capability gate: {missing}"
    );
    refused
        .ping()
        .expect("changing only the missing advertisement must leave ping admitted");

    admitted
        .close()
        .expect("legacy-only stdio advertised roots-change client cleanup");
    refused
        .close()
        .expect("legacy-only stdio bare roots-change client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_resource_template_completion_is_retained_and_unregistered_template_is_refused()
 {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    let completed = client
        .complete(legacy_2024::LegacyCompletionParams {
            reference: legacy_2024::LegacyCompletionReference::Resource {
                uri: "note://{name}".to_owned(),
            },
            argument: legacy_2024::LegacyCompletionArgument {
                name: "name".to_owned(),
                value: "al".to_owned(),
            },
            meta: None,
        })
        .expect("live exact-2024 stdio must complete the shipped note template provider");
    assert_eq!(
        completed.completion.values,
        vec!["stdio-note-completion-legacy".to_owned()],
        "the exact-2024 note template provider must retain its values: {completed:?}"
    );

    let missing_provider = client
        .complete(legacy_2024::LegacyCompletionParams {
            reference: legacy_2024::LegacyCompletionReference::Resource {
                uri: "memo://{name}".to_owned(),
            },
            argument: legacy_2024::LegacyCompletionArgument {
                name: "name".to_owned(),
                value: "al".to_owned(),
            },
            meta: None,
        })
        .expect_err("changing only the template URI must refuse the greeting catch-all");
    assert_eq!(missing_provider.code, McpErrorCode::InvalidParams);

    let greeting = client
        .complete(legacy_2024::LegacyCompletionParams {
            reference: legacy_2024::LegacyCompletionReference::Prompt {
                name: "greeting".to_owned(),
            },
            argument: legacy_2024::LegacyCompletionArgument {
                name: "name".to_owned(),
                value: "co".to_owned(),
            },
            meta: None,
        })
        .expect("the note provider must leave the greeting prompt provider usable");
    assert_eq!(
        greeting.completion.values,
        vec!["stdio-completion-legacy".to_owned()],
        "the exact-2024 greeting provider must still complete after note template completion: {greeting:?}"
    );

    client
        .close()
        .expect("legacy-only stdio note-completion client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_complete_peer_without_handler_is_refused() {
    let mut omitted = connect_legacy_stdio_to_shipped_echo_server_with_env(
        "legacy-only",
        &[("FASTMCP_NO_COMPLETIONS", "1")],
    )
    .expect("a LegacyOnly facade client connects to the completions-omitted echo peer");

    assert!(
        omitted.server_capabilities().completions.is_none(),
        "changing only the missing completion handler must omit completions: {:?}",
        omitted.server_capabilities()
    );
    omitted
        .complete(legacy_2024::LegacyCompletionParams {
            reference: legacy_2024::LegacyCompletionReference::Prompt {
                name: "greeting".to_owned(),
            },
            argument: legacy_2024::LegacyCompletionArgument {
                name: "name".to_owned(),
                value: "co".to_owned(),
            },
            meta: None,
        })
        .expect_err("changing only the missing completion handler must refuse complete");

    omitted
        .close()
        .expect("legacy-only stdio complete-omitted client cleanup");
}

#[cfg(unix)]
#[test]
fn e2e_public_stdio_legacy_subscribe_then_unsubscribe_gates_resource_updated() {
    let mut client = connect_legacy_stdio_to_shipped_echo_server("legacy-only")
        .expect("a LegacyOnly facade client completes the exact legacy lifecycle");

    let silent = client
        .call_tool("touch_server_info", json!({}))
        .expect("touching an unsubscribed resource must complete");
    assert!(
        silent.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text == "silent",
            _ => false,
        }),
        "without resources/subscribe the handler must not claim updated delivery: {silent:?}"
    );
    let notifications = client
        .take_server_notifications()
        .expect("exact-2024 stdio notifications must decode");
    assert!(
        !notifications.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::ResourceUpdated(_)
        )),
        "omitting only resources/subscribe must keep resources/updated silent: {notifications:?}"
    );

    client
        .subscribe_resource("info://server")
        .expect("exact-2024 stdio resources/subscribe must be admitted");
    let notified = client
        .call_tool("touch_server_info", json!({}))
        .expect("touching a subscribed resource must complete");
    assert!(
        notified.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text == "notified",
            _ => false,
        }),
        "resources/subscribe must count as notify_resource_updated delivery: {notified:?}"
    );
    let notifications = client
        .take_server_notifications()
        .expect("exact-2024 stdio notifications must decode");
    assert!(
        notifications.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::ResourceUpdated(params)
                if params.uri == "info://server"
        )),
        "live exact-2024 stdio must retain notifications/resources/updated: {notifications:?}"
    );

    client
        .unsubscribe_resource("info://server")
        .expect("exact-2024 stdio resources/unsubscribe must be admitted");
    let silent_again = client
        .call_tool("touch_server_info", json!({}))
        .expect("touching an unsubscribed resource must complete");
    assert!(
        silent_again.content.iter().any(|content| match content {
            LegacyContent::Text { text, .. } => text == "silent",
            _ => false,
        }),
        "resources/unsubscribe must stop notify_resource_updated delivery: {silent_again:?}"
    );
    let notifications = client
        .take_server_notifications()
        .expect("exact-2024 stdio notifications must decode");
    assert!(
        !notifications.iter().any(|notification| matches!(
            notification,
            legacy_2024::ServerNotification::ResourceUpdated(_)
        )),
        "changing only resources/unsubscribe must keep later resources/updated silent: {notifications:?}"
    );

    client
        .close()
        .expect("legacy-only stdio subscribe client cleanup");
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
