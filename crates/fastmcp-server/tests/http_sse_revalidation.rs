//! Public secured SSE ownership and revalidation, including a loopback listener.
//! No test-only server implementation is used. The native test uses plain HTTP
//! behind a configured public authority; it does not verify TLS or a browser.

use std::future::{Future, poll_fn};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asupersync::{Cx, io::{AsyncReadExt, AsyncWriteExt}, types::CancelKind};
use fastmcp_core::{AuthContext, McpContext, McpResult};
use fastmcp_protocol::{Content, FINAL_PROTOCOL_VERSION, Tool, protocol_policy::ProtocolPolicy};
use fastmcp_server::{AuthProvider, AuthRequest, HttpServerShutdown, Server, ServerHttpEndpoint,
    StaticTokenVerifier, TokenAuthProvider, ToolHandler};
use fastmcp_server::http_admission::{HttpAdmissionLimits, HttpEndpointConfig};
use fastmcp_server::http_admission::security::HttpSecurityPolicy;
use fastmcp_server::http_admission::security::endpoint::{SecuredHttpSseResponse, SecuredHttpEndpointError};
use fastmcp_server::http_admission::security::endpoint::revalidation::{SseRevalidationPolicy, SseAuthorizationError};
use fastmcp_server::http_admission::security::scope_policy::{RequiredScopes, ScopeImplicationPolicy};
use fastmcp_server::http_admission::security::scope_policy::request::ScopeRequestPolicy;
use fastmcp_transport::http::{HttpMethod, HttpRequest};
use serde_json::{Value, json};

const TOOL: &str = "revalidation_probe";
const INTERVAL: Duration = Duration::from_millis(100);
const WAIT: Duration = Duration::from_millis(150);

#[derive(Clone)]
struct Probe {
    tokens: [String; 2],
    verifier: StaticTokenVerifier,
    checks: Arc<AtomicUsize>,
    change: Arc<AtomicUsize>,
}
impl Probe {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let tokens = [format!("lease-a-{}-{nonce}", std::process::id()), format!("lease-b-{}-{nonce}", std::process::id())];
        let facts = |index| {
            let mut facts = AuthContext::with_subject(format!("lease-owner-{nonce}-{index}"));
            facts.scopes = vec!["read".to_owned()];
            facts.claims = Some(json!({"tenant":"original"}));
            facts
        };
        let verifier = StaticTokenVerifier::new([
            (tokens[0].clone(), facts(0)), (tokens[1].clone(), facts(1)),
        ]).unwrap();
        Self { tokens, verifier, checks:Arc::new(AtomicUsize::new(0)), change:Arc::new(AtomicUsize::new(0)) }
    }
    fn calls(&self) -> usize { self.checks.load(Ordering::SeqCst) }
}
impl AuthProvider for Probe {
    fn authenticate(&self, ctx: &McpContext, request: AuthRequest<'_>) -> McpResult<AuthContext> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        let mut facts = TokenAuthProvider::new(self.verifier.clone()).authenticate(ctx, request)?;
        match self.change.load(Ordering::SeqCst) {
            1 => facts.scopes.push("write".to_owned()),
            2 => facts.claims = Some(json!({"tenant":"changed"})),
            3 => facts.subject = Some("replacement-principal".to_owned()),
            _ => {},
        }
        Ok(facts)
    }
}
impl ToolHandler for Probe {
    fn definition(&self) -> Tool {
        Tool { name:TOOL.to_owned(), description:None, input_schema:json!({"type":"object"}),
            output_schema:None, icon:None, version:None, tags:vec![], annotations:None }
    }
    fn call(&self, _: &McpContext, _: Value) -> McpResult<Vec<Content>> { Ok(vec![Content::text("unchanged")]) }
}
fn server(probe: &Probe) -> Server {
    Server::new("lease-integration", "1").protocol_policy(ProtocolPolicy::ModernOnly).unwrap()
        .auth_provider(probe.clone()).tool(probe.clone()).build()
}
fn endpoint(probe: &Probe) -> ServerHttpEndpoint {
    #[cfg(not(feature = "legacy-2024-11-05"))]
    let endpoint = server(probe).into_http_endpoint();
    #[cfg(feature = "legacy-2024-11-05")]
    let endpoint = server(probe).into_http_endpoint("https://lease.example");
    endpoint.unwrap()
}
fn policy(checks: usize) -> HttpSecurityPolicy {
    let scopes = ScopeRequestPolicy::new(1, ScopeImplicationPolicy::exact(1).unwrap(),
        ["tools/list", "subscriptions/listen"].into_iter().map(|method| (
            method.to_owned(), RequiredScopes::new(vec!["read".to_owned()]).unwrap(),
        )).collect()).unwrap();
    HttpSecurityPolicy::new(
        HttpEndpointConfig::new("/mcp", HttpAdmissionLimits::new(32,8192,65536).unwrap()).unwrap(),
        "https://lease.example", vec![],
    ).unwrap().with_scope_authorization(scopes).unwrap()
        .with_sse_revalidation(SseRevalidationPolicy::new(INTERVAL,INTERVAL,checks).unwrap()).unwrap()
}
fn request(probe: &Probe, token: usize, listen: bool) -> HttpRequest {
    let method = if listen { "subscriptions/listen" } else { "tools/list" };
    let mut params = if listen { json!({"notifications":{"toolsListChanged":true}}) } else { json!({}) };
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion":FINAL_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities":{},
    });
    HttpRequest::new(HttpMethod::Post,"/mcp")
        .with_header("host","lease.example")
        .with_header("authorization",format!("Bearer {}",probe.tokens[token]))
        .with_header("content-type","application/json").with_header("accept","text/event-stream")
        .with_header("mcp-protocol-version",FINAL_PROTOCOL_VERSION).with_header("mcp-method",method)
        .with_body(serde_json::to_vec(&json!({"jsonrpc":"2.0","id":7,"method":method,"params":params})).unwrap())
}
async fn open(cx: &Cx, endpoint: &ServerHttpEndpoint, policy: &HttpSecurityPolicy, request: HttpRequest) -> SecuredHttpSseResponse {
    let response = Box::pin(endpoint.handle_secured_async(cx,policy,request)).await.unwrap();
    assert_eq!(response.response().status.0,200);
    let (_,stream) = response.into_parts();
    stream.expect("native SSE response")
}
async fn next(cx: &Cx, stream: &mut SecuredHttpSseResponse) -> Result<Option<fastmcp_transport::sse::SseEvent>,SecuredHttpEndpointError> {
    asupersync::time::timeout(cx.now(),Duration::from_secs(3),stream.next_event(cx)).await.expect("bounded event/authorization wait")
}
fn encoded(event: fastmcp_transport::sse::SseEvent) -> String {
    String::from_utf8(event.to_bytes().unwrap()).unwrap()
}
fn run<F,Fut>(scenario: F)
where F: FnOnce(Cx)->Fut+Send+'static, Fut: Future<Output=()>+Send+'static {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(1,4).build().unwrap().block_on(async move {
            let cx = Cx::current().unwrap();
            let mut task = cx.spawn(scenario).unwrap();
            task.join(&cx).await.unwrap();
        });
}

#[test]
fn revalidated_public_sse_delivers_the_real_catalog_without_raw_body_access() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let mut stream = open(&cx,&endpoint,&policy(64),request(&probe,0,false)).await;
        assert!(stream.stream().is_none(),"guarded body cannot be extracted");
        let before = probe.calls();
        asupersync::time::sleep(cx.now(),WAIT).await;
        let event = encoded(next(&cx,&mut stream).await.unwrap().unwrap());
        assert!(event.contains(TOOL));
        assert!(event.contains("\"resultType\":\"complete\""));
        assert!(probe.calls()>before,"a current provider verdict is required");
        assert!(next(&cx,&mut stream).await.unwrap().is_none());
        stream.close(&cx).await;
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn revoked_credential_withholds_an_already_queued_terminal_result() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let mut stream = open(&cx,&endpoint,&policy(64),request(&probe,0,false)).await;
        assert!(probe.verifier.revoke_token(&probe.tokens[0]).unwrap());
        asupersync::time::sleep(cx.now(),WAIT).await;
        assert!(matches!(next(&cx,&mut stream).await,
            Err(SecuredHttpEndpointError::Revalidation(SseAuthorizationError::Rejected))));
        assert!(matches!(next(&cx,&mut stream).await,Err(SecuredHttpEndpointError::BodyClosed)));
        assert!(stream.stream().is_none());
        stream.close(&cx).await;
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn public_sse_refuses_changed_grants_claims_and_identity_without_adopting_them() {
    run(|cx| async move {
        for change in [1,2,3] {
            let probe = Probe::new();
            let endpoint = endpoint(&probe);
            let mut stream = open(&cx,&endpoint,&policy(64),request(&probe,0,false)).await;
            probe.change.store(change,Ordering::SeqCst);
            asupersync::time::sleep(cx.now(),WAIT).await;
            assert!(matches!(next(&cx,&mut stream).await,
                Err(SecuredHttpEndpointError::Revalidation(SseAuthorizationError::FactsChanged))));
            probe.change.store(0,Ordering::SeqCst);
            assert!(matches!(next(&cx,&mut stream).await,Err(SecuredHttpEndpointError::BodyClosed)));
            stream.close(&cx).await;
        }
    });
}

#[test]
fn idle_public_subscription_revalidates_without_an_application_notification() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let mut stream = open(&cx,&endpoint,&policy(64),request(&probe,0,true)).await;
        let ack = encoded(next(&cx,&mut stream).await.unwrap().unwrap());
        assert!(ack.contains("notifications/subscriptions/acknowledged"));
        assert!(probe.verifier.revoke_token(&probe.tokens[0]).unwrap());
        assert!(matches!(next(&cx,&mut stream).await,
            Err(SecuredHttpEndpointError::Revalidation(SseAuthorizationError::Rejected))));
        stream.close(&cx).await;
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn revoking_one_response_does_not_cancel_a_sibling_credential_or_session() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let mut first = open(&cx,&endpoint,&policy(64),request(&probe,0,false)).await;
        let mut second = open(&cx,&endpoint,&policy(64),request(&probe,1,false)).await;
        assert!(probe.verifier.revoke_token(&probe.tokens[0]).unwrap());
        asupersync::time::sleep(cx.now(),WAIT).await;
        assert!(next(&cx,&mut first).await.is_err());
        first.close(&cx).await;
        assert!(encoded(next(&cx,&mut second).await.unwrap().unwrap()).contains(TOOL));
        second.close(&cx).await;
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn exhausted_revalidation_budget_closes_instead_of_leaving_an_unchecked_subscription() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let mut stream = open(&cx,&endpoint,&policy(1),request(&probe,0,true)).await;
        assert!(encoded(next(&cx,&mut stream).await.unwrap().unwrap()).contains("subscriptions/acknowledged"));
        assert!(matches!(next(&cx,&mut stream).await,
            Err(SecuredHttpEndpointError::Revalidation(SseAuthorizationError::CheckLimit))));
        assert_eq!(probe.calls(),2,"one opening verdict and one revalidation only");
        stream.close(&cx).await;
    });
}

#[test]
fn abandoning_a_polled_public_read_retires_its_body_without_reusing_the_lease() {
    run(|cx| async move {
        let probe = Probe::new();
        let endpoint = endpoint(&probe);
        let mut stream = open(&cx,&endpoint,&policy(64),request(&probe,0,true)).await;
        assert!(next(&cx,&mut stream).await.unwrap().is_some());
        {
            let mut pending = std::pin::pin!(stream.next_event(&cx));
            poll_fn(|task| {
                assert!(pending.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
        }
        assert!(matches!(next(&cx,&mut stream).await,Err(SecuredHttpEndpointError::BodyClosed)));
        stream.close(&cx).await;
        assert!(cx.checkpoint().is_ok());
    });
}

fn wire(request: HttpRequest) -> Vec<u8> {
    let mut bytes = format!("{} {} HTTP/1.1\r\n",request.method.as_str(),request.path).into_bytes();
    for (name,value) in request.headers {
        if !name.eq_ignore_ascii_case("content-length") && !name.eq_ignore_ascii_case("connection") {
            bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
    }
    bytes.extend_from_slice(format!("content-length: {}\r\nconnection: close\r\n\r\n",request.body.len()).as_bytes());
    bytes.extend_from_slice(&request.body);
    bytes
}

#[test]
fn idle_native_socket_revocation_closes_only_the_original_stream_without_a_success_terminal() {
    run(|cx| async move {
        let probe = Probe::new();
        let bound = Box::pin(server(&probe).bind_secured_http(&cx,"127.0.0.1:0",policy(64))).await.unwrap();
        let address = bound.local_addr().unwrap();
        let (sender,mut receiver) = asupersync::channel::oneshot::channel();
        let mut serving = cx.spawn(move |server_cx| async move {
            let _ = sender.send_blocking(server_cx.clone());
            Box::pin(bound.serve(&server_cx)).await
        }).unwrap();
        let server_cx = receiver.recv(&cx).await.unwrap();
        // Keep all network waits bounded and always settle the listener before
        // interpreting scenario results, including an I/O or timeout failure.
        let result = asupersync::time::timeout(cx.now(),Duration::from_secs(8),async {
            let mut stream = asupersync::net::TcpStream::connect(address).await.map_err(|_|"connect")?;
            stream.write_all(&wire(request(&probe,0,true))).await.map_err(|_|"write")?;
            stream.flush().await.map_err(|_|"flush")?;
            let mut received = Vec::new();
            let mut chunk = [0_u8;4096];
            loop {
                let count = stream.read(&mut chunk).await.map_err(|_|"ack read")?;
                if count==0 { return Err("stream ended before acknowledgment"); }
                received.extend_from_slice(&chunk[..count]);
                if received.len()>65536 { return Err("response bound"); }
                if String::from_utf8_lossy(&received).contains("notifications/subscriptions/acknowledged") { break; }
            }
            let before = probe.calls();
            while probe.calls()==before { asupersync::time::sleep(cx.now(),Duration::from_millis(5)).await; }
            let successful_check = probe.calls();
            if !probe.verifier.revoke_token(&probe.tokens[0]).map_err(|_|"revoke")? { return Err("token missing"); }
            loop {
                let count = stream.read(&mut chunk).await.map_err(|_|"closure read")?;
                if count==0 { break; }
                received.extend_from_slice(&chunk[..count]);
                if received.len()>65536 { return Err("response bound"); }
            }
            let rejected_check = probe.calls();
            let mut sibling = asupersync::net::TcpStream::connect(address).await.map_err(|_|"sibling connect")?;
            sibling.write_all(&wire(request(&probe,1,false).with_header("accept","application/json")))
                .await.map_err(|_|"sibling write")?;
            sibling.flush().await.map_err(|_|"sibling flush")?;
            let mut surviving = Vec::new();
            loop {
                let count = sibling.read(&mut chunk).await.map_err(|_|"sibling read")?;
                if count==0 { break; }
                surviving.extend_from_slice(&chunk[..count]);
                if surviving.len()>65536 { return Err("sibling response bound"); }
            }
            Ok((received,surviving,successful_check,rejected_check))
        }).await;
        server_cx.cancel_with(CancelKind::User,Some("SSE revalidation test complete"));
        let shutdown = serving.join(&cx).await.unwrap().unwrap();
        if let HttpServerShutdown::Nonquiescent(shutdown) = shutdown { shutdown.settle(&cx).await.unwrap(); }
        let (received,surviving,before,after) = result.expect("bounded socket test").expect("native socket scenario");
        let received = String::from_utf8(received).unwrap();
        assert!(received.starts_with("HTTP/1.1 200"));
        assert!(received.contains("notifications/subscriptions/acknowledged"));
        assert!(!received.contains("\"resultType\""),"revocation must not manufacture a success terminal");
        assert!(!received.ends_with("0\r\n\r\n"),"failed stream cannot claim clean chunked completion");
        assert!(after>before,"credential was actually revalidated after revocation");
        let surviving = String::from_utf8(surviving).unwrap();
        assert!(surviving.starts_with("HTTP/1.1 200"));
        assert!(surviving.contains(TOOL));
        assert!(!surviving.contains("\"error\":"));
        assert!(cx.checkpoint().is_ok());
    });
}
