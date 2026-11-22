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
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use asupersync::Cx;
use fastmcp_core::{
    AuthContext, McpContext, McpResult, OperatorLifecycle, OperatorSnapshot, TraceContext,
    TraceContextRecovery,
};
use fastmcp_protocol::{
    Content, FINAL_PROTOCOL_VERSION, JsonRpcRequest, Tool, protocol_policy::ProtocolPolicy,
};
use fastmcp_server::http_admission::security::HttpSecurityPolicy;
use fastmcp_server::http_admission::security::endpoint::SecuredHttpEndpointError;
use fastmcp_server::http_admission::{HttpAdmissionLimits, HttpEndpointConfig};
use fastmcp_server::{
    AuthProvider, AuthRequest, BoxFuture, FinalToolOutcome, HttpOperatorHandle, HttpServerConfig,
    HttpServerShutdown, Middleware, MiddlewareDecision, Server, ServerHttpEndpoint,
    ServerHttpEndpointResponse, StaticTokenVerifier, TokenAuthProvider, ToolExecutionMode,
    ToolHandler, promote_legacy_tool_content,
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

const TRACE_PARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const TRACE_STATE: &str = "vendor=opaque, other=value";
const TRACE_BAGGAGE: &str = "tenant=example%20tenant;flag, tenant=second";

#[derive(Clone, Debug, PartialEq)]
struct TraceObservation {
    handler: &'static str,
    trace: TraceContext,
    recovery: TraceContextRecovery,
    subject: Option<String>,
    depth: u32,
}

#[derive(Clone)]
struct TraceProbe {
    probe: Probe,
    observations: Arc<Mutex<Vec<TraceObservation>>>,
    auth_metadata: Arc<Mutex<Vec<[Option<serde_json::Value>; 3]>>>,
    middleware_metadata: Arc<Mutex<Vec<[Option<serde_json::Value>; 3]>>>,
    name: &'static str,
    call_inner: bool,
}

fn trace_metadata_fields(params: Option<&serde_json::Value>) -> [Option<serde_json::Value>; 3] {
    ["traceparent", "tracestate", "baggage"].map(|name| {
        params
            .and_then(|params| params.get("_meta")?.get(name))
            .cloned()
    })
}

impl AuthProvider for TraceProbe {
    fn authenticate(&self, ctx: &McpContext, request: AuthRequest<'_>) -> McpResult<AuthContext> {
        self.auth_metadata
            .lock()
            .unwrap()
            .push(trace_metadata_fields(request.params));
        self.probe.authenticate(ctx, request)
    }
}

impl Middleware for TraceProbe {
    fn on_request(
        &self,
        _: &McpContext,
        request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        self.middleware_metadata
            .lock()
            .unwrap()
            .push(trace_metadata_fields(request.params.as_ref()));
        Ok(MiddlewareDecision::Continue)
    }
}

impl ToolHandler for TraceProbe {
    fn definition(&self) -> Tool {
        let mut definition = self.probe.definition();
        definition.name = self.name.to_owned();
        definition
    }

    fn execution_mode(&self) -> ToolExecutionMode {
        ToolExecutionMode::Async
    }

    fn call(&self, _: &McpContext, _: serde_json::Value) -> McpResult<Vec<Content>> {
        panic!("trace probe must use its request-owned async hook")
    }

    fn call_final_outcome_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _: &'a Cx,
        _: serde_json::Value,
    ) -> BoxFuture<'a, fastmcp_core::McpOutcome<FinalToolOutcome>> {
        Box::pin(async move {
            self.probe.execution.fetch_add(1, Ordering::AcqRel);
            let snapshot = |context: &McpContext| TraceObservation {
                handler: self.name,
                trace: context.trace_context().clone(),
                recovery: *context.trace_recovery(),
                subject: context.auth().and_then(|auth| auth.subject),
                depth: context.tool_call_depth(),
            };
            let observed = snapshot(ctx);
            assert_eq!(
                snapshot(&ctx.clone()),
                observed,
                "context clone lost trace or authority"
            );
            self.observations.lock().unwrap().push(observed);
            let text = if self.call_inner {
                match ctx.call_tool("trace_inner", json!({})).await {
                    Ok(result) => {
                        assert!(!result.is_error);
                        result.content[0].as_text().unwrap().to_owned()
                    }
                    Err(error) => return fastmcp_core::Outcome::Err(error),
                }
            } else {
                ctx.auth().and_then(|auth| auth.subject).unwrap_or_default()
            };
            match promote_legacy_tool_content(vec![Content::text(text)]) {
                Ok(result) => fastmcp_core::Outcome::Ok(FinalToolOutcome::Complete(result)),
                Err(error) => fastmcp_core::Outcome::Err(error),
            }
        })
    }
}

fn trace_endpoint(call_inner: bool) -> (ServerHttpEndpoint, TraceProbe) {
    let probe = TraceProbe {
        probe: Probe::new(),
        observations: Arc::new(Mutex::new(Vec::new())),
        auth_metadata: Arc::new(Mutex::new(Vec::new())),
        middleware_metadata: Arc::new(Mutex::new(Vec::new())),
        name: "security_probe",
        call_inner,
    };
    let inner = TraceProbe {
        name: "trace_inner",
        call_inner: false,
        ..probe.clone()
    };
    let builder = Server::new("trace-http", "1.0.0")
        .protocol_policy(ProtocolPolicy::ModernOnly)
        .unwrap()
        .auth_provider(probe.clone())
        .middleware(probe.clone())
        .tool(probe.clone())
        .tool(inner);
    #[cfg(not(feature = "legacy-2024-11-05"))]
    let endpoint = builder.build_http_endpoint();
    #[cfg(feature = "legacy-2024-11-05")]
    let endpoint = builder.build_http_endpoint("http://service.example");
    (endpoint.unwrap(), probe)
}

fn trace_request(fields: serde_json::Value) -> HttpRequest {
    let request = request();
    let mut body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    body["params"]["_meta"]
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    request.with_body(serde_json::to_vec(&body).unwrap())
}

#[test]
fn obs_01_secured_http_preserves_valid_trace_in_handler_clones() {
    run(|cx| async move {
        let (endpoint, probe) = trace_endpoint(true);
        let response = Box::pin(endpoint.handle_secured_async(
            &cx,
            &policy(),
            trace_request(json!({
                "traceparent": TRACE_PARENT, "tracestate": TRACE_STATE, "baggage": TRACE_BAGGAGE,
            })),
        ))
        .await
        .unwrap();
        assert_eq!(response.response().status.0, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.response().body).unwrap();
        assert!(body.get("error").is_none());
        assert_eq!(body["result"]["content"][0]["text"], "verified-subject");
        assert_eq!(probe.probe.counts(), (1, 2));
        let expected_fields =
            [TRACE_PARENT, TRACE_STATE, TRACE_BAGGAGE].map(|field| Some(json!(field)));
        assert_eq!(
            *probe.auth_metadata.lock().unwrap(),
            vec![expected_fields.clone()]
        );
        assert_eq!(
            *probe.middleware_metadata.lock().unwrap(),
            vec![expected_fields]
        );
        let observations = probe.observations.lock().unwrap();
        assert_eq!(
            observations.len(),
            2,
            "outer and actual nested handler must execute"
        );
        assert_eq!(observations[0].handler, "security_probe");
        assert_eq!(observations[0].depth, 0);
        assert_eq!(observations[1].handler, "trace_inner");
        assert_eq!(observations[1].depth, 1);
        for observed in observations.iter() {
            assert_eq!(observed.trace.traceparent(), Some(TRACE_PARENT));
            assert_eq!(observed.trace.tracestate(), Some(TRACE_STATE));
            assert_eq!(observed.trace.baggage(), Some(TRACE_BAGGAGE));
            assert!(observed.recovery.is_empty());
            assert_eq!(observed.subject.as_deref(), Some("verified-subject"));
        }
    });
}

#[test]
fn obs_01_secured_http_recovers_optional_trace_without_application_changes() {
    run(|cx| async move {
        let (endpoint, probe) = trace_endpoint(false);
        let cases = [
            (
                json!({
                    "traceparent": "invalid-parent-secret", "tracestate": TRACE_STATE,
                    "baggage": TRACE_BAGGAGE,
                }),
                [None, None, Some(TRACE_BAGGAGE)],
                [true, true, false],
            ),
            (
                json!({
                    "traceparent": TRACE_PARENT, "tracestate": "vendor=one,vendor=two",
                    "baggage": TRACE_BAGGAGE,
                }),
                [Some(TRACE_PARENT), None, Some(TRACE_BAGGAGE)],
                [false, true, false],
            ),
            (
                json!({
                    "traceparent": TRACE_PARENT, "tracestate": TRACE_STATE,
                    "baggage": "safe=yes,broken-member-secret",
                }),
                [Some(TRACE_PARENT), Some(TRACE_STATE), None],
                [false, false, true],
            ),
            (
                json!({
                    "traceparent": 7, "tracestate": TRACE_STATE,
                    "baggage": {"not": "a W3C string"},
                }),
                [None, None, None],
                [true, true, true],
            ),
            (
                json!({
                    "tracestate": TRACE_STATE, "baggage": TRACE_BAGGAGE,
                }),
                [None, None, Some(TRACE_BAGGAGE)],
                [false, true, false],
            ),
            (
                json!({
                    "traceparent": TRACE_PARENT, "tracestate": TRACE_STATE,
                    "baggage": format!("oversized={}", "x".repeat(fastmcp_core::MAX_BAGGAGE_BYTES)),
                }),
                [Some(TRACE_PARENT), Some(TRACE_STATE), None],
                [false, false, true],
            ),
        ];
        for (index, (fields, expected, rejected)) in cases.into_iter().enumerate() {
            let control = Box::pin(endpoint.handle_secured_async(&cx, &policy(), request()))
                .await
                .unwrap();
            assert_eq!(control.response().status.0, 200);
            let baseline = probe.observations.lock().unwrap().pop().unwrap();
            assert!(baseline.trace.is_empty());
            assert!(baseline.recovery.is_empty());
            assert_eq!(
                probe.auth_metadata.lock().unwrap().pop().unwrap(),
                [None, None, None]
            );
            assert_eq!(
                probe.middleware_metadata.lock().unwrap().pop().unwrap(),
                [None, None, None]
            );

            let recovered =
                Box::pin(endpoint.handle_secured_async(&cx, &policy(), trace_request(fields)))
                    .await
                    .unwrap();
            assert!(!recovered.is_streaming());
            assert_eq!(recovered.response().status, control.response().status);
            assert_eq!(recovered.response().body, control.response().body);
            assert_eq!(probe.probe.counts(), (2 * (index + 1), 2 * (index + 1)));
            let observed = probe.observations.lock().unwrap().pop().unwrap();
            assert_eq!(observed.subject, baseline.subject);
            assert_eq!(observed.trace.traceparent(), expected[0]);
            assert_eq!(observed.trace.tracestate(), expected[1]);
            assert_eq!(observed.trace.baggage(), expected[2]);
            let effective_fields = expected.map(|field| field.map(|field| json!(field)));
            assert_eq!(
                probe.auth_metadata.lock().unwrap().pop().unwrap(),
                effective_fields,
                "invalid optional trace must be removed before the authentication provider",
            );
            assert_eq!(
                probe.middleware_metadata.lock().unwrap().pop().unwrap(),
                effective_fields,
                "committing authentication custody must not restore rejected metadata",
            );
            assert_eq!(observed.recovery.traceparent_rejected(), rejected[0]);
            assert_eq!(observed.recovery.tracestate_rejected(), rejected[1]);
            assert_eq!(observed.recovery.baggage_rejected(), rejected[2]);
            assert_eq!(
                usize::from(observed.recovery.rejected_count()),
                rejected.into_iter().filter(|rejected| *rejected).count(),
            );
        }
        assert!(probe.observations.lock().unwrap().is_empty());
        assert!(probe.auth_metadata.lock().unwrap().is_empty());
        assert!(probe.middleware_metadata.lock().unwrap().is_empty());
    });
}

#[test]
fn obs_01_secured_http_trace_identity_never_authenticates() {
    run(|cx| async move {
        let (endpoint, probe) = trace_endpoint(false);
        let claimed_identity = json!({
            "traceparent": TRACE_PARENT, "tracestate": TRACE_STATE,
            "baggage": "subject=attacker,scope=admin",
        });
        let mut control = None;
        for (index, fields) in [
            json!({}),
            claimed_identity.clone(),
            json!({"traceparent": "invalid", "baggage": "subject=verified-subject,broken"}),
        ]
        .into_iter()
        .enumerate()
        {
            let response = Box::pin(endpoint.handle_secured_async(
                &cx,
                &policy(),
                trace_request(fields).with_header("authorization", "Bearer wrong-token"),
            ))
            .await
            .unwrap();
            assert_eq!(response.response().status.0, 401);
            assert!(response.response().headers.contains_key("www-authenticate"));
            if let Some(expected) = &control {
                assert_eq!(&response.response().body, expected);
            } else {
                control = Some(response.response().body.clone());
            }
            assert_eq!(probe.probe.counts(), (index + 1, 0));
            assert!(probe.observations.lock().unwrap().is_empty());
        }
        let response = Box::pin(endpoint.handle_secured_async(
            &cx,
            &policy(),
            trace_request(claimed_identity),
        ))
        .await
        .unwrap();
        assert_eq!(response.response().status.0, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.response().body).unwrap();
        assert_eq!(body["result"]["content"][0]["text"], "verified-subject");
        assert_eq!(probe.probe.counts(), (4, 1));
        let observed = probe.observations.lock().unwrap().pop().unwrap();
        assert_eq!(observed.subject.as_deref(), Some("verified-subject"));
        assert_eq!(
            observed.trace.baggage(),
            Some("subject=attacker,scope=admin")
        );
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
                browser_preflight().with_header("access-control-request-headers", "x-unreviewed"),
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

fn browser_response(response: &[u8]) -> (u16, std::collections::HashMap<String, String>, &[u8]) {
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
                            return Err(
                                "preflight invoked authentication or application code".to_owned()
                            );
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
                                return Err(
                                    "rejected credentials reached application code".to_owned()
                                );
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
                assert_eq!(
                    headers["access-control-allow-origin"],
                    "https://app.example"
                );
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
                assert!(
                    std::str::from_utf8(body)
                        .unwrap()
                        .contains("verified-subject")
                );
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

struct StopReadinessListener(Cx);

impl Drop for StopReadinessListener {
    fn drop(&mut self) {
        self.0.cancel_with(asupersync::CancelKind::User, None);
    }
}

async fn wait_readiness_snapshot(
    operator: &HttpOperatorHandle,
    predicate: impl Fn(&OperatorSnapshot) -> bool,
) -> OperatorSnapshot {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Ok(snapshot) = OperatorSnapshot::capture(operator)
            && predicate(&snapshot)
        {
            return snapshot;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "listener observation timed out",
        );
        asupersync::runtime::yield_now().await;
    }
}

fn readiness_json(response: &[u8], expected_status: u16) -> serde_json::Value {
    let (status, headers, body) = browser_response(response);
    assert_eq!(status, expected_status);
    assert_eq!(headers["cache-control"], "no-store");
    assert!(
        body.len() < 2048,
        "diagnostic response must have a fixed bound"
    );
    let body: serde_json::Value = serde_json::from_slice(body).unwrap();
    assert_eq!(body["schema"], "fastmcp.http.readiness/v1");
    assert_eq!(body["snapshotSchema"], OperatorSnapshot::SCHEMA_VERSION);
    assert_eq!(body["schemaVersion"], OperatorSnapshot::SCHEMA_VERSION);
    assert!(body["reasons"].is_array());
    assert_eq!(
        body.as_object().unwrap().len(),
        12 + usize::from(cfg!(feature = "tasks"))
    );
    if cfg!(feature = "tasks") {
        let tasks = &body["tasks"];
        assert_eq!(tasks["schema"], "fastmcp.tasks.store/v1");
        assert_eq!(
            tasks["schemaVersion"],
            fastmcp_core::OperatorTaskSnapshot::TASK_SCHEMA_VERSION
        );
        assert_eq!(tasks["scope"], "task_store");
        assert_eq!(tasks["status"], "observed");
        assert_eq!(tasks["storage"]["retainedTasks"], 0);
        assert_eq!(tasks["execution"]["reserved"], 0);
        assert_eq!(
            tasks["pressure"],
            json!({"storage": false, "execution": false, "retention": false})
        );
    } else {
        assert!(body.get("tasks").is_none());
    }
    body
}

async fn readiness_finish_admitted_request(
    cx: &Cx,
    address: std::net::SocketAddr,
    mut admitted: asupersync::net::TcpStream,
) {
    use asupersync::io::{AsyncReadExt, AsyncWriteExt};

    let accepted = request();
    let mut head = format!(
        "POST /mcp HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Length: {}\r\n",
        accepted.body.len(),
    );
    for (name, value) in &accepted.headers {
        if !name.eq_ignore_ascii_case("host") {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    head.push_str("\r\n");
    admitted.write_all(head.as_bytes()).await.unwrap();
    admitted.write_all(&accepted.body).await.unwrap();
    admitted.flush().await.unwrap();
    let mut response = Vec::new();
    asupersync::time::timeout(
        cx.now(),
        std::time::Duration::from_secs(5),
        admitted.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(browser_response(&response).0, 200);
    let body: serde_json::Value = serde_json::from_slice(browser_response(&response).2).unwrap();
    assert_eq!(body["result"]["content"][0]["text"], "verified-subject");
}

async fn readiness_capacity_checks(
    cx: &Cx,
    address: std::net::SocketAddr,
    operator: &HttpOperatorHandle,
    probe: &Probe,
) -> serde_json::Value {
    let diagnostic = || {
        HttpRequest::new(HttpMethod::Get, "/readyz")
            .with_header("authorization", "Bearer private-health-bearer")
            .with_header("cookie", "private-health-cookie")
            .with_header("x-request-id", "private-health-request-id")
    };
    let healthy = browser_exchange(cx, address, diagnostic()).await.unwrap();
    let body = readiness_json(&healthy, 200);
    assert_eq!(
        body["connections"],
        json!({"limit":1,"active":0,"reserved":0})
    );
    assert_eq!(body["saturated"], false);
    let generation = body["generation"].clone();
    assert_eq!(probe.counts(), (0, 0));

    // The same request now sees one real socket retaining the only data
    // permit. The extra control socket must still return an honest 503.
    let occupied = asupersync::net::TcpStream::connect(address).await.unwrap();
    wait_readiness_snapshot(operator, |snapshot| snapshot.connections().active == 1).await;
    let saturated = browser_exchange(cx, address, diagnostic()).await.unwrap();
    let body = readiness_json(&saturated, 503);
    assert_eq!(body["readiness"], "ready");
    assert_eq!(body["saturated"], true);
    assert_eq!(body["connections"]["active"], 1);
    assert_eq!(body["generation"], generation);
    let live = browser_exchange(cx, address, HttpRequest::new(HttpMethod::Get, "/livez"))
        .await
        .unwrap();
    assert_eq!(browser_response(&live).0, 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(browser_response(&live).2).unwrap(),
        json!({"status":"ok"}),
    );
    drop(occupied);
    wait_readiness_snapshot(operator, |snapshot| snapshot.connections().in_use() == 0).await;
    let recovered = browser_exchange(cx, address, diagnostic()).await.unwrap();
    assert_eq!(readiness_json(&recovered, 200)["generation"], generation);

    for response in [&healthy, &saturated, &recovered] {
        let wire = std::str::from_utf8(response).unwrap();
        for canary in [
            "private-health-server-name",
            "private-health-bearer",
            "private-health-cookie",
            "private-health-request-id",
        ] {
            assert!(
                !wire.contains(canary),
                "diagnostics exposed peer or server identity"
            );
        }
    }
    assert_eq!(probe.counts(), (0, 0));
    generation
}

async fn readiness_drain_checks(
    cx: &Cx,
    address: std::net::SocketAddr,
    operator: &HttpOperatorHandle,
    probe: &Probe,
    generation: &serde_json::Value,
) {
    // Drain fences future connections but does not confiscate an already
    // admitted socket or its right to finish one request.
    let admitted = asupersync::net::TcpStream::connect(address).await.unwrap();
    wait_readiness_snapshot(operator, |snapshot| snapshot.connections().active == 1).await;
    operator.begin_drain().unwrap();
    let draining = browser_exchange(cx, address, HttpRequest::new(HttpMethod::Get, "/readyz"))
        .await
        .unwrap();
    assert_eq!(readiness_json(&draining, 503)["lifecycle"], "stopping");
    let refused = browser_exchange(cx, address, request()).await.unwrap();
    assert_eq!(browser_response(&refused).0, 503);
    assert_eq!(
        probe.counts(),
        (0, 0),
        "control capacity must never dispatch MCP"
    );
    readiness_finish_admitted_request(cx, address, admitted).await;
    assert_eq!(probe.counts(), (1, 1));
    let settled =
        wait_readiness_snapshot(operator, |snapshot| snapshot.connections().in_use() == 0).await;
    assert_eq!(settled.counters().accepted, settled.counters().released);
    assert_eq!(
        settled.counters().probes_acquired,
        0,
        "diagnostics never reserve admission"
    );
    let drained = browser_exchange(cx, address, HttpRequest::new(HttpMethod::Get, "/readyz"))
        .await
        .unwrap();
    let body = readiness_json(&drained, 503);
    assert_eq!(&body["generation"], generation);
    assert_eq!(body["lifecycle"], "stopping");
    assert_eq!(
        body["saturated"], false,
        "drain must not reopen when work completes"
    );
}

fn native_http_readiness_lifecycle(protocol: ProtocolPolicy) {
    run(move |cx| async move {
        let probe = Probe::new();
        let bound = Server::new("private-health-server-name", "1.0.0")
            .protocol_policy(protocol)
            .unwrap()
            .http_config(
                HttpServerConfig::new()
                    .health_path("/livez")
                    .readiness_path("/readyz")
                    .max_connections(1)
                    .request_read_timeout(std::time::Duration::from_secs(15)),
            )
            .auth_provider(probe.clone())
            .tool(probe.clone())
            .build()
            .bind_http(&cx, "127.0.0.1:0")
            .await
            .unwrap();
        let address = bound.local_addr().unwrap();
        let operator = bound.operator_handle();
        let observed = operator.clone();
        let shutdown_cx = cx.clone();
        let mut client = cx
            .spawn(move |client_cx| async move {
                let _stop = StopReadinessListener(shutdown_cx);
                wait_readiness_snapshot(&observed, |snapshot| {
                    snapshot.lifecycle() == OperatorLifecycle::Running
                })
                .await;
                let generation =
                    readiness_capacity_checks(&client_cx, address, &observed, &probe).await;
                readiness_drain_checks(&client_cx, address, &observed, &probe, &generation).await;
            })
            .unwrap();
        let shutdown = bound.serve(&cx).await.unwrap();
        client.join(&cx).await.unwrap();
        assert!(matches!(shutdown, HttpServerShutdown::Quiescent));
        let stopped = OperatorSnapshot::capture(&operator).unwrap();
        assert_eq!(stopped.lifecycle(), OperatorLifecycle::Stopped);
        assert_eq!(stopped.connections().in_use(), 0);
        assert_eq!(stopped.counters().accepted, stopped.counters().released);
    });
}

#[test]
fn native_http_readiness_modern_tracks_saturation_recovery_and_drain() {
    native_http_readiness_lifecycle(ProtocolPolicy::ModernOnly);
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn native_http_readiness_auto_tracks_saturation_recovery_and_drain() {
    native_http_readiness_lifecycle(ProtocolPolicy::Auto);
}

#[test]
fn native_http_readiness_control_lane_is_bounded_and_idle_capacity_recovers() {
    run(|cx| async move {
        use asupersync::io::AsyncReadExt;

        let probe = Probe::new();
        let bound = Server::new("control-health", "1.0.0")
            .protocol_policy(ProtocolPolicy::ModernOnly)
            .unwrap()
            .http_config(
                HttpServerConfig::new()
                    .max_connections(0)
                    .request_read_timeout(std::time::Duration::from_secs(30)),
            )
            .auth_provider(probe.clone())
            .tool(probe.clone())
            .build()
            .bind_http(&cx, "127.0.0.1:0")
            .await
            .unwrap();
        let address = bound.local_addr().unwrap();
        let operator = bound.operator_handle();
        let observed = operator.clone();
        let shutdown_cx = cx.clone();
        let mut client = cx
            .spawn(move |client_cx| async move {
                let _stop = StopReadinessListener(shutdown_cx);
                wait_readiness_snapshot(&observed, |snapshot| {
                    snapshot.lifecycle() == OperatorLifecycle::Running
                })
                .await;
                let mut idle = asupersync::net::TcpStream::connect(address).await.unwrap();
                wait_readiness_snapshot(&observed, |snapshot| snapshot.counters().rejected == 1)
                    .await;
                let mut excess = asupersync::net::TcpStream::connect(address).await.unwrap();
                let mut excess_bytes = Vec::new();
                asupersync::time::timeout(
                    client_cx.now(),
                    std::time::Duration::from_secs(3),
                    excess.read_to_end(&mut excess_bytes),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(
                    excess_bytes.is_empty(),
                    "a second control child must not be admitted"
                );
                let mut idle_bytes = Vec::new();
                asupersync::time::timeout(
                    client_cx.now(),
                    std::time::Duration::from_secs(3),
                    idle.read_to_end(&mut idle_bytes),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(
                    idle_bytes.is_empty(),
                    "idle control socket must expire below the 30s data limit"
                );
                let recovered = browser_exchange(
                    &client_cx,
                    address,
                    HttpRequest::new(HttpMethod::Get, "/ready"),
                )
                .await
                .unwrap();
                let body = readiness_json(&recovered, 503);
                assert_eq!(
                    body["connections"],
                    json!({"limit":0,"active":0,"reserved":0})
                );
                assert_eq!(body["readiness"], "not_ready");
                let snapshot = OperatorSnapshot::capture(&observed).unwrap();
                assert_eq!(snapshot.counters().accepted, 0);
                assert_eq!(snapshot.counters().released, 0);
            })
            .unwrap();
        let shutdown = bound.serve(&cx).await.unwrap();
        client.join(&cx).await.unwrap();
        assert!(matches!(shutdown, HttpServerShutdown::Quiescent));
        assert_eq!(probe.counts(), (0, 0));
        assert_eq!(
            OperatorSnapshot::capture(&operator)
                .unwrap()
                .connections()
                .in_use(),
            0
        );
    });
}

#[test]
fn native_http_readiness_routes_reject_collisions_before_listener_binding() {
    run(|cx| async move {
        let invalid = vec![
            HttpServerConfig::new().readiness_path("/mcp"),
            HttpServerConfig::new().health_path("/ready"),
            HttpServerConfig::new().readiness_path("relative"),
            HttpServerConfig::new().readiness_path("//authority/path"),
            HttpServerConfig::new().readiness_path("/ready?secret=value"),
            HttpServerConfig::new().readiness_path("/ready#fragment"),
            HttpServerConfig::new().readiness_path("/ready%2fpath"),
            HttpServerConfig::new().health_path("/ready\r\n"),
        ];
        #[cfg(feature = "legacy-2024-11-05")]
        let invalid = {
            let mut invalid = invalid;
            invalid.push(HttpServerConfig::new().readiness_path("/sse"));
            invalid
        };
        for config in invalid {
            let result = Server::new("invalid-health", "1.0.0")
                .http_config(config)
                .build()
                .bind_http(&cx, "127.0.0.1:0")
                .await;
            assert!(
                result.is_err(),
                "diagnostic path must not shadow an application route"
            );
        }
    });
}

#[test]
fn native_http_readiness_embedding_is_unbound_and_diagnostics_have_no_auth_effects() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let mut session = endpoint.open_session(&cx).unwrap();
        for (request, expected) in [
            (
                HttpRequest::new(HttpMethod::Get, "/ready")
                    .with_header("authorization", "Bearer secret-canary"),
                503,
            ),
            (HttpRequest::new(HttpMethod::Post, "/ready"), 405),
            (
                HttpRequest::new(HttpMethod::Get, "/ready").with_body(b"body-canary".to_vec()),
                400,
            ),
            (
                HttpRequest::new(HttpMethod::Get, "/ready")
                    .with_header("origin", "https://untrusted.example"),
                403,
            ),
            (HttpRequest::new(HttpMethod::Get, "/health"), 200),
        ] {
            let ServerHttpEndpointResponse::Immediate(response) =
                session.handle_async(&cx, request).await.unwrap()
            else {
                panic!("diagnostic routes must never create a protocol stream");
            };
            assert_eq!(response.status.0, expected);
            let body = std::str::from_utf8(&response.body).unwrap();
            assert!(!body.contains("secret-canary"));
            assert!(!body.contains("body-canary"));
            assert!(!body.contains("untrusted.example"));
            assert_eq!(probe.counts(), (0, 0));
        }
        session.close(&cx).await;
    });
}
