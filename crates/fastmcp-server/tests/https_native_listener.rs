//! Public native HTTPS listener exercised over real, certificate-verified TLS.
//!
//! No proxy, injected HTTP response, disabled verifier, environment mutation or
//! permanent trust-store change is used. The inlined identity is TEST ONLY and
//! survives RCH's *.pem exclusion. All application calls reach the shipped
//! Server::bind_secured_https and the ordinary authentication/dispatch path.

#![forbid(unsafe_code)]
// bd-pf5n7: applied here although this target did NOT emit in the default-feature
// census — it emitted under run:legneg-verify, which ran with features. Its absence
// from the cold census is an artefact of the feature set, not a property of the
// target, so excluding it would leave a known emitter untouched by construction.
// Cause as in the six: the default 128 is exceeded resolving async blocks through
// `handle_secured_async` -> `await_dispatch` in fastmcp-server PRODUCTION source
// (endpoint.rs:164, :297).
// THIS TARGET IS THE WEAKEST CASE OF THE SEVEN AND IS LABELLED AS SUCH. It did NOT
// emit in the a8574340 cold check, because that check covered the DEFAULT feature
// set; it emitted under run:legneg-verify, which ran WITH features. So the "256 is
// sufficient" evidence that supports the other six DOES NOT COVER THIS FILE — its
// emitting configuration has never been re-checked after the raise. The attribute
// is applied here because excluding a known emitter on the strength of a run that
// could not observe it would be excluding it by construction, not by evidence.
// The direct call-graph reading (`await_dispatch` has no self-call and no direct
// call back into `handle_secured_async`) applies here as it does there, with the
// same blind spot: DIRECT CALLS ONLY, and this module holds two type-erasure points
// (scope_policy.rs:251, endpoint/listener.rs:285), so it does not establish that the
// call graph is acyclic.
// COST: raising removes the early warning that depth is growing; it does NOT change
// codegen, so no runtime exposure is created or removed. The production-side repair
// is filed apart.
#![recursion_limit = "256"]

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::time::Duration;

use asupersync::Cx;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::runtime::TaskHandle;
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsConnector};
use asupersync::types::CancelKind;
use fastmcp_core::{AuthContext, McpContext, McpResult};
use fastmcp_protocol::{Content, FINAL_PROTOCOL_VERSION, Tool, protocol_policy::ProtocolPolicy};
use fastmcp_server::{AuthProvider, AuthRequest, HttpServerShutdown, Server, StaticTokenVerifier, TokenAuthProvider, ToolHandler};
use fastmcp_server::http_admission::{HttpAdmissionLimits, HttpEndpointConfig};
use fastmcp_server::http_admission::security::{HttpSecurityPolicy, resource_metadata::ProtectedResourceMetadata};
use fastmcp_server::http_admission::security::endpoint::listener::SecuredHttpIoLimits;
use fastmcp_transport::http::{HttpMethod, HttpRequest, HttpResponse, HttpStatus};
use serde_json::{Value, json};

const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";
const TOKEN: &str = "test-only-native-https-token";
const SUBJECT: &str = "native-https-principal";
const TOOL: &str = "native_https_probe";
const ORIGIN: &str = "https://browser.example";
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct Probe {
    verifier: StaticTokenVerifier,
    authentications: Arc<AtomicUsize>,
    effects: Arc<AtomicUsize>,
}

impl Probe {
    fn new() -> Self {
        Self {
            verifier: StaticTokenVerifier::new([(TOKEN, AuthContext::with_subject(SUBJECT))]).unwrap(),
            authentications: Arc::new(AtomicUsize::new(0)),
            effects: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn counts(&self) -> (usize, usize) {
        (self.authentications.load(Ordering::SeqCst), self.effects.load(Ordering::SeqCst))
    }
}

impl AuthProvider for Probe {
    fn authenticate(&self, cx: &McpContext, request: AuthRequest<'_>) -> McpResult<AuthContext> {
        self.authentications.fetch_add(1, Ordering::SeqCst);
        TokenAuthProvider::new(self.verifier.clone()).authenticate(cx, request)
    }
}

impl ToolHandler for Probe {
    fn definition(&self) -> Tool {
        Tool {
            name: TOOL.to_owned(), description: None, input_schema: json!({"type":"object"}),
            output_schema: None, icon: None, version: None, tags: Vec::new(), annotations: None,
        }
    }
    fn call(&self, cx: &McpContext, arguments: Value) -> McpResult<Vec<Content>> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        if arguments["progress"] == true { cx.report_progress(1.0, Some("native-https-progress")); }
        let identity = cx.auth().unwrap_or_else(AuthContext::anonymous);
        Ok(vec![Content::text(json!({"subject":identity.subject,"arguments":arguments}).to_string())])
    }
}

fn acceptor() -> TlsAcceptor {
    TlsAcceptor::builder(CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap())
        .alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap()
}

fn connector(trusted: bool, protocols: Vec<Vec<u8>>) -> TlsConnector {
    let builder = TlsConnector::builder().alpn_protocols(protocols);
    let builder = if trusted {
        builder.add_root_certificate(&Certificate::from_pem(ROOT).unwrap().remove(0))
    } else {
        // The ordinary public roots intentionally do not include the test CA.
        // An empty root store is rejected at builder time, not over the wire.
        builder.with_webpki_roots()
    };
    builder.build().unwrap().with_handshake_timeout(EXCHANGE_TIMEOUT)
}

fn policy() -> HttpSecurityPolicy {
    HttpSecurityPolicy::new(
        HttpEndpointConfig::new("/mcp", HttpAdmissionLimits::new(32, 8192, 65536).unwrap()).unwrap(),
        "https://localhost", vec![ORIGIN.to_owned()],
    ).unwrap().with_resource_metadata(ProtectedResourceMetadata::new(
        vec!["https://issuer.example/tenant".to_owned()],
    ).unwrap()).unwrap()
}

fn request(sse: bool) -> HttpRequest {
    let mut meta = json!({
        "io.modelcontextprotocol/protocolVersion":FINAL_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities":{},
    });
    if sse { meta["progressToken"] = json!("tls-progress-owner"); }
    HttpRequest::new(HttpMethod::Post, "/mcp")
        .with_header("host", "localhost")
        .with_header("origin", ORIGIN)
        .with_header("authorization", format!("Bearer {TOKEN}"))
        .with_header("content-type", "application/json")
        .with_header("accept", if sse { "text/event-stream" } else { "application/json" })
        .with_header("mcp-protocol-version", FINAL_PROTOCOL_VERSION)
        .with_header("mcp-method", "tools/call")
        .with_header("mcp-name", TOOL)
        .with_body(serde_json::to_vec(&json!({
            "jsonrpc":"2.0", "id":17, "method":"tools/call", "params":{
                "name":TOOL, "arguments":{"echo":"TLS: 世界 + %2F", "progress":sse}, "_meta":meta,
            },
        })).unwrap())
}

struct Running {
    address: SocketAddr,
    owner: Cx,
    task: Option<TaskHandle<McpResult<HttpServerShutdown>>>,
}

impl Running {
    async fn start(cx: &Cx, probe: &Probe, handshake: Duration) -> Self {
        let server = Server::new("native-https", "1")
            .protocol_policy(ProtocolPolicy::ModernOnly).unwrap()
            .auth_provider(probe.clone()).tool(probe.clone()).build();
        let bound = Box::pin(server.bind_secured_https(cx, "127.0.0.1:0", policy(), acceptor()))
            .await.unwrap().with_io_limits(
                SecuredHttpIoLimits::default().with_handshake_timeout(handshake).unwrap(),
            );
        assert!(bound.is_https());
        let address = bound.local_addr().unwrap();
        let (sender, mut receiver) = asupersync::channel::oneshot::channel();
        let task = cx.spawn(move |server_cx| async move {
            let _ = sender.send_blocking(server_cx.clone());
            Box::pin(bound.serve(&server_cx)).await
        }).unwrap();
        let owner = receiver.recv(cx).await.unwrap();
        Self { address, owner, task: Some(task) }
    }

    async fn stop(mut self, cx: &Cx) {
        self.owner.cancel_with(CancelKind::User, Some("native HTTPS test complete"));
        // Retain the handle in self until join returns. Panic/abandonment still
        // requests cancellation via Drop, and the enclosing test owns the region.
        asupersync::time::timeout(cx.now(), EXCHANGE_TIMEOUT, async {
            let shutdown = self.task.as_mut().unwrap().join(cx).await.unwrap().unwrap();
            self.task = None;
            if let HttpServerShutdown::Nonquiescent(shutdown) = shutdown {
                shutdown.settle(cx).await.unwrap();
            }
        }).await.expect("listener and handshake children must settle within the test bound");
        assert!(cx.checkpoint().is_ok(), "listener shutdown must not cancel its caller");
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.owner.cancel_with(CancelKind::User, Some("native HTTPS test owner dropped"));
    }
}

fn encode(request: HttpRequest) -> Vec<u8> {
    let mut bytes = format!("{} {} HTTP/1.1\r\n", request.method.as_str(), request.path).into_bytes();
    for (name, value) in request.headers {
        if !name.eq_ignore_ascii_case("content-length") && !name.eq_ignore_ascii_case("connection") {
            bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
    }
    bytes.extend_from_slice(format!("content-length: {}\r\nconnection: close\r\n\r\n", request.body.len()).as_bytes());
    bytes.extend_from_slice(&request.body);
    bytes
}

async fn exchange(cx: &Cx, address: SocketAddr, request: HttpRequest) -> Result<Vec<u8>, String> {
    asupersync::time::timeout(cx.now(), EXCHANGE_TIMEOUT, async {
        let tcp = TcpStream::connect(address).await.map_err(|_| "TCP connect failed")?;
        let mut stream = connector(true, vec![b"http/1.1".to_vec()])
            .connect("localhost", tcp).await.map_err(|_| "verified TLS handshake failed")?;
        if stream.alpn_protocol() != Some(b"http/1.1".as_slice()) {
            return Err("HTTP/1.1 was not negotiated".to_owned());
        }
        stream.write_all(&encode(request)).await.map_err(|_| "HTTPS request write failed")?;
        stream.flush().await.map_err(|_| "HTTPS request flush failed")?;
        // Never half-close the request side to unblock the response: the SSE
        // writer must make progress while its own peer-read future is pending.
        let mut response = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let count = stream.read(&mut chunk).await.map_err(|_| "HTTPS response read failed")?;
            if count == 0 { break; }
            if response.len() + count > 256 * 1024 { return Err("HTTPS response exceeds test bound".to_owned()); }
            response.extend_from_slice(&chunk[..count]);
        }
        Ok(response)
    }).await.map_err(|_| "HTTPS exchange exceeded test deadline".to_owned())?
}

fn decode_wire(bytes: &[u8]) -> HttpResponse {
    let end = bytes.windows(4).position(|window| window == b"\r\n\r\n").expect("complete response head");
    let mut lines = std::str::from_utf8(&bytes[..end]).unwrap().split("\r\n");
    let status = lines.next().unwrap().split_whitespace().nth(1).unwrap().parse::<u16>().unwrap();
    let mut response = HttpResponse::new(HttpStatus(status));
    for line in lines {
        let (name, value) = line.split_once(':').unwrap();
        assert!(response.headers.insert(name.to_ascii_lowercase(), value.trim().to_owned()).is_none());
    }
    let mut body = &bytes[end + 4..];
    if response.headers.get("transfer-encoding").is_some_and(|value| value.eq_ignore_ascii_case("chunked")) {
        loop {
            let end = body.windows(2).position(|window| window == b"\r\n").unwrap();
            let size = usize::from_str_radix(std::str::from_utf8(&body[..end]).unwrap(), 16).unwrap();
            body = &body[end + 2..];
            if size == 0 { assert_eq!(body, b"\r\n", "exact terminal chunk, without truncation"); break; }
            assert!(size <= body.len().saturating_sub(2));
            response.body.extend_from_slice(&body[..size]);
            assert_eq!(&body[size..size + 2], b"\r\n");
            body = &body[size + 2..];
        }
    } else {
        response.body = body.to_vec();
        if let Some(length) = response.headers.get("content-length") {
            assert_eq!(length.parse::<usize>().unwrap(), response.body.len());
        }
    }
    response
}

fn success(response: &HttpResponse, sse: bool) {
    assert_eq!(response.status.0, 200);
    assert_eq!(response.headers["access-control-allow-origin"], ORIGIN);
    assert!(!response.headers.contains_key("mcp-session-id"));
    let messages: Vec<Value> = if sse {
        assert!(response.headers["content-type"].starts_with("text/event-stream"));
        String::from_utf8(response.body.clone()).unwrap().replace("\r\n", "\n")
            .split("\n\n").filter_map(|event| {
                let data = event.lines().filter_map(|line| line.strip_prefix("data:"))
                    .map(str::trim_start).collect::<Vec<_>>().join("\n");
                if data.is_empty() { None } else { Some(serde_json::from_str(&data).unwrap()) }
            }).collect()
    } else {
        assert!(response.headers["content-type"].starts_with("application/json"));
        vec![serde_json::from_slice(&response.body).unwrap()]
    };
    let terminals: Vec<_> = messages.iter().filter(|message| message.get("id") == Some(&json!(17))).collect();
    assert_eq!(terminals.len(), 1);
    let terminal = terminals[0];
    assert!(terminal.get("error").is_none());
    let payload: Value = serde_json::from_str(terminal["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(payload, json!({"subject":SUBJECT,"arguments":{"echo":"TLS: 世界 + %2F","progress":sse}}));
    if sse {
        let progress: Vec<_> = messages.iter().enumerate()
            .filter(|(_, message)| message["method"] == "notifications/progress").collect();
        assert_eq!(progress.len(), 1);
        assert_eq!(progress[0].1["params"]["progressToken"], "tls-progress-owner");
        assert!(progress[0].0 < messages.len() - 1, "progress must precede the terminal response");
        assert_eq!(messages.last().unwrap()["id"], 17);
    }
}

fn run<F, Fut>(scenario: F)
where F: FnOnce(Cx) -> Fut + Send + 'static, Fut: Future<Output = ()> + Send + 'static {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(1, 4).build().unwrap().block_on(async move {
            let parent = Cx::current().unwrap();
            let mut task = parent.spawn(scenario).unwrap();
            task.join(&parent).await.unwrap();
        });
}

#[test]
fn https_native_authenticated_json_and_sse_preserve_principal_progress_and_payload() {
    run(|cx| async move {
        let probe = Probe::new();
        let running = Running::start(&cx, &probe, Duration::from_secs(10)).await;
        let json = exchange(&cx, running.address, request(false)).await;
        let sse = exchange(&cx, running.address, request(true)).await;
        running.stop(&cx).await;
        success(&decode_wire(&json.unwrap()), false);
        success(&decode_wire(&sse.unwrap()), true);
        assert_eq!(probe.counts(), (2, 2));
    });
}

#[test]
fn https_native_credential_and_origin_refusals_leave_handler_state_unchanged() {
    run(|cx| async move {
        let probe = Probe::new();
        let running = Running::start(&cx, &probe, Duration::from_secs(10)).await;
        let baseline = exchange(&cx, running.address, request(false)).await;
        let before = probe.counts();
        let mut missing = request(true);
        missing.headers.remove("authorization");
        let wrong = exchange(&cx, running.address, request(false).with_header("authorization", "Bearer wrong")).await;
        let missing = exchange(&cx, running.address, missing).await;
        let after_credentials = probe.counts();
        let forbidden = exchange(&cx, running.address,
            request(true).with_header("origin", "https://attacker.example")).await;
        let after_origin = probe.counts();
        let reaccepted = exchange(&cx, running.address, request(false)).await;
        running.stop(&cx).await;
        success(&decode_wire(&baseline.unwrap()), false);
        for bytes in [wrong.unwrap(), missing.unwrap()] {
            let response = decode_wire(&bytes);
            assert_eq!(response.status.0, 401);
            assert!(response.headers["www-authenticate"].starts_with("Bearer"));
            assert!(!response.headers.contains_key("transfer-encoding"));
        }
        assert_eq!(after_credentials.1, before.1, "invalid credentials must not execute a handler");
        assert_eq!(decode_wire(&forbidden.unwrap()).status.0, 403);
        assert_eq!(after_origin, after_credentials, "untrusted Origin must not invoke authentication");
        success(&decode_wire(&reaccepted.unwrap()), false);
        assert_eq!(probe.effects.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn https_native_resource_metadata_and_preflight_use_the_same_origin_policy() {
    run(|cx| async move {
        let probe = Probe::new();
        let running = Running::start(&cx, &probe, Duration::from_secs(10)).await;
        let metadata = HttpRequest::new(HttpMethod::Get, policy().resource_metadata_path().unwrap())
            .with_header("host", "localhost").with_header("origin", ORIGIN);
        let preflight = HttpRequest::new(HttpMethod::Options, "/mcp")
            .with_header("host", "localhost").with_header("origin", ORIGIN)
            .with_header("access-control-request-method", "POST")
            .with_header("access-control-request-headers", "authorization, content-type, mcp-method, mcp-name, mcp-protocol-version");
        let metadata = exchange(&cx, running.address, metadata).await;
        let preflight = exchange(&cx, running.address, preflight).await;
        running.stop(&cx).await;
        let metadata = decode_wire(&metadata.unwrap());
        let preflight = decode_wire(&preflight.unwrap());
        assert_eq!(metadata.status.0, 200);
        let body: Value = serde_json::from_slice(&metadata.body).unwrap();
        assert_eq!(body["resource"], "https://localhost/mcp");
        assert_eq!(body["authorization_servers"], json!(["https://issuer.example/tenant"]));
        assert_eq!(preflight.status.0, 204);
        for response in [metadata, preflight] { assert_eq!(response.headers["access-control-allow-origin"], ORIGIN); }
        assert_eq!(probe.counts(), (0, 0));
    });
}

#[test]
fn https_native_tls_name_trust_and_alpn_failures_never_dispatch_mcp() {
    run(|cx| async move {
        let probe = Probe::new();
        let running = Running::start(&cx, &probe, Duration::from_secs(10)).await;
        let mut outcomes = Vec::new();
        for (trusted, name, protocol) in [
            (true, "wrong.example", b"http/1.1".as_slice()),
            (false, "localhost", b"http/1.1".as_slice()),
            (true, "localhost", b"h2".as_slice()),
        ] {
            let result = asupersync::time::timeout(cx.now(), EXCHANGE_TIMEOUT, async {
                let stream = TcpStream::connect(running.address).await.unwrap();
                connector(trusted, vec![protocol.to_vec()]).connect(name, stream).await
            }).await;
            outcomes.push(matches!(result, Ok(Err(_))));
        }
        let refused_counts = probe.counts();
        let accepted = exchange(&cx, running.address, request(false)).await;
        running.stop(&cx).await;
        assert_eq!(outcomes, vec![true, true, true], "each real handshake must reject, not merely time out");
        assert_eq!(refused_counts, (0, 0));
        success(&decode_wire(&accepted.unwrap()), false);
    });
}

#[test]
fn https_native_plaintext_never_falls_back_to_http_dispatch() {
    run(|cx| async move {
        let probe = Probe::new();
        let running = Running::start(&cx, &probe, Duration::from_secs(10)).await;
        let plaintext = asupersync::time::timeout(cx.now(), EXCHANGE_TIMEOUT, async {
            let mut stream = TcpStream::connect(running.address).await.unwrap();
            let _ = stream.write_all(&encode(request(false))).await;
            let mut bytes = [0_u8; 4096];
            match stream.read(&mut bytes).await {
                Ok(count) => bytes[..count].to_vec(),
                Err(_) => Vec::new(),
            }
        }).await;
        let refused_counts = probe.counts();
        let accepted = exchange(&cx, running.address, request(false)).await;
        running.stop(&cx).await;
        let bytes = plaintext.expect("plaintext must be refused within the fixed test deadline");
        assert!(!bytes.windows(5).any(|window| window == b"HTTP/"));
        assert_eq!(refused_counts, (0, 0));
        success(&decode_wire(&accepted.unwrap()), false);
    });
}

#[test]
fn https_native_stalled_handshake_does_not_serialize_healthy_clients() {
    run(|cx| async move {
        let probe = Probe::new();
        let running = Running::start(&cx, &probe, Duration::from_secs(30)).await;
        let stalled = TcpStream::connect(running.address).await.unwrap();
        // Give the listener a chance to begin the first handshake. The healthy
        // exchange's five-second bound is shorter than the stalled one's thirty.
        asupersync::time::sleep(cx.now(), Duration::from_millis(30)).await;
        let healthy = exchange(&cx, running.address, request(true)).await;
        drop(stalled);
        running.stop(&cx).await;
        success(&decode_wire(&healthy.unwrap()), true);
        assert_eq!(probe.counts(), (1, 1));
    });
}

#[test]
fn https_native_handshake_deadline_closes_a_stalled_socket_and_preserves_listener() {
    run(|cx| async move {
        let probe = Probe::new();
        let running = Running::start(&cx, &probe, Duration::from_millis(500)).await;
        let mut stalled = TcpStream::connect(running.address).await.unwrap();
        let mut byte = [0_u8; 1];
        let closed = asupersync::time::timeout(cx.now(), EXCHANGE_TIMEOUT, stalled.read(&mut byte)).await;
        let before = probe.counts();
        let healthy = exchange(&cx, running.address, request(false)).await;
        drop(stalled);
        running.stop(&cx).await;
        assert!(matches!(closed, Ok(Ok(0) | Err(_))), "server must close, not leave the read pending");
        assert_eq!(before, (0, 0));
        success(&decode_wire(&healthy.unwrap()), false);
    });
}

#[test]
fn https_native_shutdown_settles_handshakes_without_waiting_for_their_timeout() {
    run(|cx| async move {
        let probe = Probe::new();
        let running = Running::start(&cx, &probe, Duration::from_secs(120)).await;
        let mut stalled = TcpStream::connect(running.address).await.unwrap();
        asupersync::time::sleep(cx.now(), Duration::from_millis(30)).await;
        running.stop(&cx).await;
        let mut byte = [0_u8; 1];
        let closed = asupersync::time::timeout(cx.now(), EXCHANGE_TIMEOUT, stalled.read(&mut byte)).await;
        assert!(matches!(closed, Ok(Ok(0) | Err(_))));
        assert_eq!(probe.counts(), (0, 0));
        assert!(cx.checkpoint().is_ok());
    });
}
