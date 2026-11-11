//! Exercises secured embedding and configured browser CORS through the public
//! HTTP server, authentication provider, and registered tool. The browser tests
//! also use the default native listener over loopback sockets; they do not prove
//! TLS or browser-engine behavior. No cfg(test) seam replaces production dispatch.

// bd-pf5n7: the default 128 is exceeded resolving this crate's async blocks through
// `handle_secured_async` -> `await_dispatch` in fastmcp-server PRODUCTION source
// (endpoint.rs:164, :297). The compiler suggests this remedy here, and czvvt is the
// precedent. TWO FACTS SUPPORT IT, SEPARATELY, AND NEITHER CORROBORATES THE OTHER:
//   1. The trait-obligation chain is DEEP BUT BOUNDED. The cold check at 256 —
//      a8574340, 455/455 units rebuilt, 0 cached, 0 diagnostics of any code —
//      COMPLETED the proof rather than giving up, so a finite budget suffices and
//      this is a fix, not a suppression. Default feature set only.
//   2. SEPARATELY, by direct call-graph reading: `await_dispatch` has no self-call
//      and no direct call back into `handle_secured_async`. DIRECT CALLS ONLY — an
//      edge through a trait object is invisible to that reading, and this module
//      holds two erasure points (scope_policy.rs:251 `Arc<dyn AuthProvider>`;
//      endpoint/listener.rs:285 a boxed `dyn Future`), one of them on the path
//      `await_dispatch` traverses at endpoint.rs:183.
// Type erasure defeats BOTH instruments in the same direction, so (2) does not
// establish that the call graph is acyclic and (1) does not cover it.
// The depth accumulates inside fastmcp-server, which is why boxing on the test side
// changes nothing: measured, not assumed.
// COST: it removes the early warning that composition depth is growing. It does NOT
// change codegen — `recursion_limit` bounds compile-time trait resolution only — so
// no runtime exposure is created or removed. The mechanism-level repair, boxing the
// three unboxed call sites in endpoint.rs (:180, :199, :217 — the idiom already
// exists at :392), is a production change and is filed apart.
#![recursion_limit = "256"]

use std::future::Future;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use asupersync::Cx;
use fastmcp_core::{AuthContext, McpContext, McpResult};
use fastmcp_protocol::{Content, FINAL_PROTOCOL_VERSION, Tool, protocol_policy::ProtocolPolicy};
use fastmcp_server::http_admission::security::HttpSecurityPolicy;
use fastmcp_server::http_admission::security::endpoint::SecuredHttpEndpointError;
use fastmcp_server::http_admission::{HttpAdmissionLimits, HttpEndpointConfig};
use fastmcp_server::{
    AuthProvider, AuthRequest, HttpServerConfig, HttpServerShutdown, Server, ServerHttpEndpoint,
    ServerHttpEndpointResponse, StaticTokenVerifier, TokenAuthProvider, ToolHandler,
};
use fastmcp_transport::http::{HttpHandlerConfig, HttpMethod, HttpRequest};
use serde_json::json;

#[derive(Clone)]
struct Probe {
    provider: Arc<TokenAuthProvider>,
    authentication: Arc<AtomicUsize>,
    execution: Arc<AtomicUsize>,
}

impl Probe {
    fn new() -> Self {
        let verifier = StaticTokenVerifier::new([(
            "http-security-test-token".to_owned(),
            AuthContext::with_subject("verified-subject".to_owned()),
        )])
        .unwrap();
        Self {
            provider: Arc::new(TokenAuthProvider::new(verifier)),
            authentication: Arc::new(AtomicUsize::new(0)),
            execution: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn counts(&self) -> (usize, usize) {
        (
            self.authentication.load(Ordering::Acquire),
            self.execution.load(Ordering::Acquire),
        )
    }
}

impl AuthProvider for Probe {
    fn authenticate(&self, cx: &McpContext, request: AuthRequest<'_>) -> McpResult<AuthContext> {
        self.authentication.fetch_add(1, Ordering::AcqRel);
        self.provider.authenticate(cx, request)
    }
}

impl ToolHandler for Probe {
    fn definition(&self) -> Tool {
        Tool {
            name: "security_probe".to_owned(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }
    fn call(&self, cx: &McpContext, _: serde_json::Value) -> McpResult<Vec<Content>> {
        self.execution.fetch_add(1, Ordering::AcqRel);
        let subject = cx.auth().and_then(|auth| auth.subject).unwrap_or_default();
        Ok(vec![Content::text(subject)])
    }
}

fn endpoint(probe: &Probe) -> ServerHttpEndpoint {
    let builder = Server::new("secured-http", "1.0.0")
        .protocol_policy(ProtocolPolicy::ModernOnly)
        .unwrap()
        .auth_provider(probe.clone())
        .tool(probe.clone());
    #[cfg(not(feature = "legacy-2024-11-05"))]
    let endpoint = builder.build_http_endpoint();
    #[cfg(feature = "legacy-2024-11-05")]
    let endpoint = builder.build_http_endpoint("http://service.example");
    endpoint.unwrap()
}

fn policy() -> HttpSecurityPolicy {
    HttpSecurityPolicy::new(
        HttpEndpointConfig::new("/mcp", HttpAdmissionLimits::new(32, 8192, 65536).unwrap())
            .unwrap(),
        "https://service.example",
        vec!["https://app.example".to_owned()],
    )
    .unwrap()
}

fn request() -> HttpRequest {
    HttpRequest::new(HttpMethod::Post, "/mcp")
        .with_header("host", "service.example")
        .with_header("authorization", "Bearer http-security-test-token")
        .with_header("content-type", "application/json")
        .with_header("accept", "application/json")
        .with_header("mcp-protocol-version", FINAL_PROTOCOL_VERSION)
        .with_header("mcp-method", "tools/call")
        .with_header("mcp-name", "security_probe")
        .with_body(
            serde_json::to_vec(&json!({
                "jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{
                    "name":"security_probe", "arguments":{}, "_meta":{
                        "io.modelcontextprotocol/protocolVersion":FINAL_PROTOCOL_VERSION,
                        "io.modelcontextprotocol/clientCapabilities":{}
                    }
                }
            }))
            .unwrap(),
        )
}

fn run<F, Fut>(scenario: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(1, 4)
        .build()
        .unwrap()
        .block_on(async move {
            let parent = Cx::current().unwrap();
            let mut task = parent.spawn(scenario).unwrap();
            task.join(&parent).await.unwrap();
        });
}

#[test]
fn secured_http_native_post_reaches_real_authentication_and_tool_once() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let response = Box::pin(endpoint.handle_secured_async(&cx, &policy(), request()))
            .await
            .unwrap();
        assert!(!response.is_streaming());
        let (response, stream) = response.into_parts();
        assert!(stream.is_none());
        assert_eq!(response.status.0, 200);
        let result: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(result.get("error").is_none());
        assert_eq!(result["result"]["content"][0]["text"], "verified-subject");
        assert_eq!(probe.counts(), (1, 1));
        assert!(!response.headers.contains_key("access-control-allow-origin"));
    });
}

#[test]
fn secured_http_browser_preflight_never_invokes_authentication_or_tool() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let preflight = HttpRequest::new(HttpMethod::Options, "/mcp")
            .with_header("host", "service.example")
            .with_header("origin", "https://app.example")
            .with_header("access-control-request-method", "POST")
            .with_header(
                "access-control-request-headers",
                "authorization, mcp-method, mcp-name, mcp-protocol-version, content-type",
            );
        let response = Box::pin(endpoint.handle_secured_async(&cx, &policy(), preflight.clone()))
            .await
            .unwrap();
        assert_eq!(response.response().status.0, 204);
        assert!(response.response().body.is_empty());
        assert_eq!(
            response.response().headers["access-control-allow-origin"],
            "https://app.example"
        );
        assert_eq!(probe.counts(), (0, 0));
        let rejected = preflight.with_header("access-control-request-method", "DELETE");
        let response = Box::pin(endpoint.handle_secured_async(&cx, &policy(), rejected))
            .await
            .unwrap();
        assert_eq!(response.response().status.0, 400);
        assert_eq!(probe.counts(), (0, 0));
    });
}

#[test]
fn secured_http_forbidden_origin_cannot_spend_a_valid_bearer_credential() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let response = Box::pin(endpoint.handle_secured_async(
            &cx,
            &policy(),
            request().with_header("origin", "https://attacker.example"),
        ))
        .await
        .unwrap();
        assert_eq!(response.response().status.0, 403);
        assert!(response.response().body.is_empty());
        assert_eq!(probe.counts(), (0, 0));
        let control = Box::pin(endpoint.handle_secured_async(&cx, &policy(), request()))
            .await
            .unwrap();
        assert_eq!(control.response().status.0, 200);
        assert_eq!(probe.counts(), (1, 1));
    });
}

#[test]
fn secured_http_forwarded_authority_cannot_override_the_public_host() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let response = Box::pin(
            endpoint.handle_secured_async(
                &cx,
                &policy(),
                request()
                    .with_header("host", "attacker.example")
                    .with_header("x-forwarded-host", "service.example")
                    .with_header("forwarded", "host=service.example;proto=https"),
            ),
        )
        .await
        .unwrap();
        assert_eq!(response.response().status.0, 403);
        assert_eq!(probe.counts(), (0, 0));
        let control = Box::pin(endpoint.handle_secured_async(
            &cx,
            &policy(),
            request().with_header("host", "SERVICE.EXAMPLE:443"),
        ))
        .await
        .unwrap();
        assert_eq!(control.response().status.0, 200);
        assert_eq!(probe.counts(), (1, 1));
    });
}

#[test]
fn secured_http_keeps_native_query_credential_refusal_and_challenge() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let response = Box::pin(endpoint.handle_secured_async(
            &cx,
            &policy(),
            request().with_query("access_token", "http-security-test-token"),
        ))
        .await
        .unwrap();
        assert_eq!(response.response().status.0, 401);
        assert_eq!(response.response().headers["www-authenticate"], "Bearer");
        let body: serde_json::Value = serde_json::from_slice(&response.response().body).unwrap();
        assert_eq!(body["error"], "invalid_request");
        assert_eq!(probe.counts(), (0, 0));
        assert!(
            !String::from_utf8_lossy(&response.response().body)
                .contains("http-security-test-token")
        );
    });
}

#[test]
fn secured_http_allowed_authority_is_not_authentication() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let response = Box::pin(endpoint.handle_secured_async(
            &cx,
            &policy(),
            request().with_header("authorization", "Bearer wrong-token"),
        ))
        .await
        .unwrap();
        assert_eq!(response.response().status.0, 401);
        assert!(response.response().headers.contains_key("www-authenticate"));
        assert_eq!(probe.counts(), (1, 0));
    });
}

#[test]
fn secured_http_preserves_the_dispatchers_protocol_error_response() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let malformed = request().with_body(b"not JSON".to_vec());
        let mut session = endpoint.open_session(&cx).unwrap();
        let ServerHttpEndpointResponse::Immediate(expected) =
            session.handle_async(&cx, malformed.clone()).await.unwrap()
        else {
            panic!("native protocol refusal must be immediate")
        };
        session.close(&cx).await;
        let actual = Box::pin(endpoint.handle_secured_async(&cx, &policy(), malformed))
            .await
            .unwrap();
        assert_eq!(actual.response().status, expected.status);
        assert_eq!(actual.response().body, expected.body);
        assert_eq!(probe.counts(), (0, 0));
    });
}

#[test]
fn secured_http_policy_route_mismatch_is_a_configuration_error_before_dispatch() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let wrong = HttpSecurityPolicy::new(
            HttpEndpointConfig::new("/other", HttpAdmissionLimits::new(32, 8192, 65536).unwrap())
                .unwrap(),
            "https://service.example",
            vec![],
        )
        .unwrap();
        assert!(matches!(
            Box::pin(endpoint.handle_secured_async(&cx, &wrong, request())).await,
            Err(SecuredHttpEndpointError::PolicyRouteMismatch)
        ));
        assert_eq!(probe.counts(), (0, 0));
    });
}

#[test]
fn secured_http_returned_sse_retains_its_session_until_explicit_close() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let response = Box::pin(endpoint.handle_secured_async(
            &cx,
            &policy(),
            request().with_header("accept", "text/event-stream"),
        ))
        .await
        .unwrap();
        assert!(response.is_streaming());
        let (head, stream) = response.into_parts();
        assert_eq!(head.status.0, 200);
        let mut stream = stream.expect("SSE owns the native session");
        let cancellation = stream.stream().unwrap().cancellation();
        assert!(
            !cancellation.is_cancelled(),
            "returning the response must not drop its session"
        );
        stream.close(&cx).await;
        assert!(stream.stream().is_none());
        assert!(cancellation.is_cancelled());
        assert!(
            cx.checkpoint().is_ok(),
            "stream close cannot cancel the parent task"
        );
    });
}


fn browser_server(probe: &Probe, protocol: ProtocolPolicy) -> Server {
    Server::new("browser-http", "1.0.0")
        .protocol_policy(protocol)
        .unwrap()
        .http_config(HttpServerConfig::new().handler_config(HttpHandlerConfig {
            base_path: "/browser/mcp".to_owned(),
            allow_cors: true,
            cors_origins: vec!["https://app.example".to_owned()],
            ..HttpHandlerConfig::default()
        }))
        .auth_provider(probe.clone())
        .tool(probe.clone())
        .build()
}

fn browser_preflight() -> HttpRequest {
    HttpRequest::new(HttpMethod::Options, "/browser/mcp")
        .with_header("origin", "https://app.example")
        .with_header("access-control-request-method", "POST")
        .with_header(
            "access-control-request-headers",
            "authorization, content-type, mcp-protocol-version, mcp-method, mcp-name",
        )
}

#[test]
fn native_http_embedding_preflight_does_not_authenticate_or_dispatch() {
    run(|cx| async move {
        let probe = Probe::new();
        let server = browser_server(&probe, ProtocolPolicy::ModernOnly);
        #[cfg(feature = "legacy-2024-11-05")]
        let endpoint = server.into_http_endpoint("http://service.example").unwrap();
        #[cfg(not(feature = "legacy-2024-11-05"))]
        let endpoint = server.into_http_endpoint().unwrap();
        let mut session = endpoint.open_session(&cx).unwrap();
        for (request, status) in [
            (browser_preflight(), 200),
            (
                browser_preflight()
                    .with_header("access-control-request-headers", "x-unreviewed"),
                403,
            ),
            (
                browser_preflight().with_header("origin", "https://untrusted.example"),
                403,
            ),
        ] {
            let ServerHttpEndpointResponse::Immediate(response) =
                session.handle_async(&cx, request).await.unwrap()
            else {
                panic!("preflight must not create an MCP response stream")
            };
            assert_eq!(response.status.0, status);
            assert!(response.body.is_empty());
            assert_eq!(probe.counts(), (0, 0));
            assert_eq!(
                response.headers.contains_key("access-control-allow-origin"),
                status == 200
            );
        }
        session.close(&cx).await;
    });
}

async fn browser_exchange(
    cx: &Cx,
    address: std::net::SocketAddr,
    request: HttpRequest,
) -> Result<Vec<u8>, String> {
    use asupersync::io::{AsyncReadExt, AsyncWriteExt};

    let operation = async {
        let mut stream = asupersync::net::TcpStream::connect(address)
            .await
            .map_err(|error| error.to_string())?;
        let mut wire = format!(
            "{} {} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Length: {}\r\n",
            request.method.as_str(),
            request.path,
            request.body.len(),
        );
        for (name, value) in &request.headers {
            if !name.eq_ignore_ascii_case("host") {
                wire.push_str(&format!("{name}: {value}\r\n"));
            }
        }
        wire.push_str("\r\n");
        stream
            .write_all(wire.as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        stream
            .write_all(&request.body)
            .await
            .map_err(|error| error.to_string())?;
        stream.flush().await.map_err(|error| error.to_string())?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|error| error.to_string())?;
        Ok(response)
    };
    asupersync::time::timeout(cx.now(), std::time::Duration::from_secs(5), operation)
        .await
        .map_err(|_| "browser HTTP exchange timed out".to_owned())?
}

fn browser_response(
    response: &[u8],
) -> (u16, std::collections::HashMap<String, String>, &[u8]) {
    let boundary = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    let head = std::str::from_utf8(&response[..boundary]).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    (status, headers, &response[boundary + 4..])
}

fn native_http_browser_round_trip(protocol: ProtocolPolicy) {
    run(move |cx| async move {
        let probe = Probe::new();
        let bound = browser_server(&probe, protocol)
            .bind_http(&cx, "127.0.0.1:0")
            .await
            .unwrap();
        let address = bound.local_addr().unwrap();
        let observing = probe.clone();
        let shutdown_cx = cx.clone();
        let mut client = cx
            .spawn(move |client_cx| async move {
                let result = async {
                    let mut responses = Vec::new();
                    for preflight in [
                        browser_preflight(),
                        browser_preflight()
                            .with_header("access-control-request-headers", "x-unreviewed"),
                        browser_preflight().with_header("origin", "https://untrusted.example"),
                        browser_preflight().with_body(b"unexpected".to_vec()),
                    ] {
                        responses.push(browser_exchange(&client_cx, address, preflight).await?);
                        if observing.counts() != (0, 0) {
                            return Err("preflight invoked authentication or application code".to_owned());
                        }
                    }
                    for accept in ["application/json", "text/event-stream"] {
                        let mut post = request()
                            .with_header("origin", "https://app.example")
                            .with_header("accept", accept);
                        post.path = "/browser/mcp".to_owned();
                        responses.push(browser_exchange(&client_cx, address, post).await?);
                    }
                    for accept in ["application/json", "text/event-stream"] {
                        for authorization in [None, Some("Bearer rejected-browser-token")] {
                            let mut post = request()
                                .with_header("origin", "https://app.example")
                                .with_header("accept", accept);
                            post.path = "/browser/mcp".to_owned();
                            post.headers.remove("authorization");
                            if let Some(authorization) = authorization {
                                post = post.with_header("authorization", authorization);
                            }
                            responses.push(browser_exchange(&client_cx, address, post).await?);
                            if observing.counts().1 != 2 {
                                return Err("rejected credentials reached application code".to_owned());
                            }
                        }
                    }
                    Ok(responses)
                }
                .await;
                // Always stop the listener, including failed network exchanges.
                shutdown_cx.cancel_with(
                    asupersync::CancelKind::User,
                    Some("browser probes complete"),
                );
                result
            })
            .unwrap();
        let shutdown = bound.serve(&cx).await.unwrap();
        let responses = client.join(&cx).await.unwrap().unwrap();
        match shutdown {
            HttpServerShutdown::Quiescent => {}
            HttpServerShutdown::Nonquiescent(mut pending) => {
                let settled = pending.settle_for(std::time::Duration::from_secs(1)).await;
                panic!("browser HTTP listener did not quiesce: {settled:?}");
            }
        }
        assert_eq!(responses.len(), 10);
        for (index, response) in responses.iter().enumerate() {
            let (status, headers, body) = browser_response(response);
            let allowed = index == 0 || index >= 4;
            assert_eq!(
                status,
                match index {
                    1 | 2 => 403,
                    3 => 400,
                    6..=9 => 401,
                    _ => 200,
                }
            );
            assert_eq!(headers.contains_key("access-control-allow-origin"), allowed);
            if allowed {
                assert_eq!(headers["access-control-allow-origin"], "https://app.example");
                assert!(
                    headers["access-control-expose-headers"]
                        .to_ascii_lowercase()
                        .contains("www-authenticate")
                );
            }
            if index < 4 {
                assert!(body.is_empty());
            } else if index == 4 {
                let result: serde_json::Value = serde_json::from_slice(body).unwrap();
                assert_eq!(result["result"]["content"][0]["text"], "verified-subject");
            } else if index == 5 {
                assert_eq!(headers["content-type"], "text/event-stream");
                assert!(std::str::from_utf8(body).unwrap().contains("verified-subject"));
            } else {
                assert!(body.is_empty());
                assert_eq!(headers["www-authenticate"], "Bearer");
                assert!(!headers.contains_key("access-control-allow-credentials"));
            }
        }
        // Missing credentials fail before the provider. Each rejected bearer
        // reaches authentication once, and neither refusal dispatches the tool.
        assert_eq!(probe.counts(), (4, 2));
    });
}

#[test]
fn native_http_modern_listener_serves_browser_preflight_json_and_sse() {
    native_http_browser_round_trip(ProtocolPolicy::ModernOnly);
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn native_http_auto_listener_serves_browser_preflight_json_and_sse() {
    native_http_browser_round_trip(ProtocolPolicy::Auto);
}
