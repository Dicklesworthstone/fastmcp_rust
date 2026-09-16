//! Public OAuth-to-core-MCP integration over real TLS sockets.
//!
//! This target requires `native-tls-roots`: the shipped MCP executor's private-CA
//! path is exercised without replacing TLS, injecting a transport, or disabling
//! certificate verification. Each test runs its fixture in a bounded child of
//! this test binary with an isolated SSL_CERT_FILE. No process-global environment
//! mutation, installed trust-store change, external IdP or browser is involved.
//! Discovery/registration are covered by oauth_discovery; this target starts at
//! the public preregistered login and continues through authenticated MCP use.
#![cfg(feature = "native-tls-roots")]

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::time::Sleep;
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream};
use fastmcp_client::http_auth::managed::{ManagedOAuthSession, OAuthSessionPolicy};
use fastmcp_client::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};
use fastmcp_client::http_auth::rpc::{ManagedCoreError, ManagedCoreEvent, ManagedCoreLimits};
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{ClientCapabilities, CoreRequest, CoreResult, FinalCoreResult, FinalRequestMeta, RequestId, ServerNotification};
use serde_json::{Value, json};

#[path = "oauth_core_rpc/subscriptions.rs"]
mod subscriptions;

const CHILD_CASE: &str = "FASTMCP_TEST_OAUTH_CORE_CASE";
const ROOT: &[u8] = include_bytes!("fixtures/oauth-core-ca.pem");
// TEST ONLY key and certificate, also used by the native OAuth fixture. The
// root is never installed in the developer's or machine's permanent trust store.
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";
const CATALOG: &str = r#"{"resultType":"complete","tools":[],"ttlMs":100,"cacheScope":"private","x-exact":{"z":900719925474099312345,"a":1.20e+4}}"#;
const TOOL_RESULT: &str = r#"{"resultType":"complete","content":[{"type":"text","text":"hello from TLS"}]}"#;
const CHANGED: &str = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
const PROGRESS: &str = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"work","progress":1}}"#;

#[derive(Clone, Copy)]
enum Case { Json, Sse, InvalidResponse, InputRequired, Cancel, Deadline, Preflight, HttpFailure, UntrustedResource }

fn isolated(name: &str, case: Case) {
    if let Ok(selected) = std::env::var(CHILD_CASE) {
        assert_eq!(selected, name, "the child must execute exactly the selected test");
        run(case);
        return;
    }
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let roots = if matches!(case, Case::UntrustedResource) {
        // An existing non-PEM file supplies no roots; native-certs does not fall
        // back to platform trust when SSL_CERT_FILE is explicitly configured.
        manifest.join("Cargo.toml")
    } else {
        manifest.join("tests/fixtures/oauth-core-ca.pem")
    };
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD_CASE, name)
        .env("SSL_CERT_FILE", roots)
        .env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit())
        .spawn().expect("launch isolated public transport test");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "public TLS case {name} failed");
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("public TLS case {name} exceeded its child-process bound");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let mut one = None;
    let mut two = None;
    poll_fn(|task| {
        if one.is_none() {
            if let Poll::Ready(value) = left.as_mut().poll(task) { one = Some(value); }
        }
        if two.is_none() {
            if let Poll::Ready(value) = right.as_mut().poll(task) { two = Some(value); }
        }
        if one.is_some() && two.is_some() {
            Poll::Ready((one.take().unwrap(), two.take().unwrap()))
        } else { Poll::Pending }
    }).await
}

fn url(text: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(text).unwrap() }

fn decode_component(input: &str) -> String {
    let mut output = Vec::new();
    let mut bytes = input.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => output.push(b' '),
            b'%' => {
                let high = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                let low = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                output.push((high * 16 + low) as u8);
            }
            byte => output.push(byte),
        }
    }
    String::from_utf8(output).unwrap()
}

fn form(input: &str) -> BTreeMap<String, String> {
    input.split('&').map(|field| {
        let (key, value) = field.split_once('=').unwrap();
        (decode_component(key), decode_component(value))
    }).collect()
}

async fn browser(authorization: CanonicalHttpUrl) -> Result<(), OAuthError> {
    let params = form(authorization.query().unwrap());
    assert_eq!(params["client_id"], "typed-client");
    assert_eq!(params["code_challenge_method"], "S256");
    let address: SocketAddr = params["redirect_uri"].strip_prefix("http://").unwrap()
        .split('/').next().unwrap().parse().unwrap();
    assert!(address.ip().is_loopback());
    let request = format!(
        "GET /oauth/callback?code=typed-code&iss=https%3A%2F%2Fissuer.example&state={} HTTP/1.1\r\nHost: {address}\r\n\r\n",
        params["state"],
    );
    let mut socket = TcpStream::connect(address).await.map_err(|_| OAuthError::CallbackRejected)?;
    socket.write_all(request.as_bytes()).await.map_err(|_| OAuthError::CallbackRejected)
}

fn core(method: &str, mut params: Value) -> CoreRequest {
    params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    params["_meta"]["progressToken"] = json!("work");
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
}

fn terminal(id: i64, result: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#)
}

struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    token_posts: AtomicUsize,
    mcp_posts: AtomicUsize,
}

impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            acceptor: TlsAcceptorBuilder::new(
                CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap(),
            ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap(),
            token_posts: AtomicUsize::new(0), mcp_posts: AtomicUsize::new(0),
        }
    }

    fn resource(&self) -> String { format!("https://{}/mcp", self.listener.local_addr().unwrap()) }

    fn client(&self) -> OAuthClient {
        OAuthClient::new(OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example", url("https://issuer.example/authorize"),
            url(&format!("https://{}/token", self.listener.local_addr().unwrap())),
            url(&self.resource()), "typed-client", vec!["tools:read".to_owned()],
        ).unwrap().with_extra_root_certificate(Certificate::from_pem(ROOT).unwrap().remove(0)).unwrap())
    }

    async fn request(&self, path: &str) -> (TlsStream<TcpStream>, Vec<u8>) {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut tls = self.acceptor.accept(socket).await.unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0; 2048];
        let end = loop {
            let count = tls.read(&mut buffer).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 16 * 1024);
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") { break index + 4; }
        };
        let head = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
        assert!(head.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
        let headers: BTreeMap<String, String> = head.lines().skip(1).filter_map(|line| {
            line.split_once(':').map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        }).collect();
        let length: usize = headers["content-length"].parse().unwrap();
        assert!(end + length <= 16 * 1024);
        while bytes.len() < end + length {
            let count = tls.read(&mut buffer).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 16 * 1024);
            bytes.extend_from_slice(&buffer[..count]);
        }
        assert_eq!(bytes.len(), end + length);
        let body = bytes[end..].to_vec();
        if path == "/token" {
            assert!(!headers.contains_key("authorization"));
            let fields = form(std::str::from_utf8(&body).unwrap());
            assert_eq!(fields["grant_type"], "authorization_code");
            assert_eq!(fields["client_id"], "typed-client");
            assert_eq!(fields["code"], "typed-code");
            assert_eq!(fields["resource"], self.resource());
            self.token_posts.fetch_add(1, Ordering::SeqCst);
        } else {
            assert_eq!(headers["authorization"], "Bearer typed-access");
            assert_eq!(headers["mcp-protocol-version"], "2026-07-28");
            assert!(!headers.contains_key("mcp-session-id"));
            assert!(!headers.contains_key("last-event-id"));
            assert!(!headers.contains_key("cookie"));
            let envelope: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(headers["mcp-method"], envelope["method"].as_str().unwrap());
            assert_eq!(envelope["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], "2026-07-28");
            if envelope["method"] == "tools/call" { assert_eq!(headers["mcp-name"], "echo"); }
            self.mcp_posts.fetch_add(1, Ordering::SeqCst);
        }
        (tls, body)
    }

    async fn login(&self) {
        let (mut tls, _) = self.request("/token").await;
        json_reply(&mut tls, 200, r#"{"access_token":"typed-access","token_type":"Bearer","expires_in":300,"refresh_token":"typed-refresh"}"#).await;
    }

    async fn catalog(&self, id: i64) {
        let (mut tls, request) = self.request("/mcp").await;
        assert_eq!(serde_json::from_slice::<Value>(&request).unwrap()["id"], id);
        json_reply(&mut tls, 200, &terminal(id, CATALOG)).await;
    }

    fn no_extra_connections(&self) {
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(self.listener.poll_accept(&mut task).is_pending(), "no automatic request/renewal replay");
    }
}

async fn json_reply(tls: &mut TlsStream<TcpStream>, status: u16, body: &str) {
    let wire = format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    tls.write_all(wire.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
}

async fn chunk(tls: &mut TlsStream<TcpStream>, payloads: &[String], terminal: bool) {
    let mut body = String::new();
    for payload in payloads { body.push_str(&format!("data: {payload}\n\n")); }
    let end = if terminal { "0\r\n\r\n" } else { "" };
    let wire = format!("{:X}\r\n{body}\r\n{end}", body.len());
    tls.write_all(wire.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
}

async fn begin_stream(peer: &Peer) -> TlsStream<TcpStream> {
    let (mut tls, _) = peer.request("/mcp").await;
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
    chunk(&mut tls, &[CHANGED.to_owned()], false).await;
    tls
}

async fn first_changed(call: &mut fastmcp_client::http_auth::rpc::ManagedCoreCall, cx: &Cx) {
    let Some(ManagedCoreEvent::Notification(notification)) = call.next_event(cx).await.unwrap() else { panic!("incremental notification expected") };
    assert!(matches!(*notification, ServerNotification::ToolsListChanged(_)));
}

async fn complete_catalog(session: &ManagedOAuthSession, cx: &Cx, id: i64) {
    let mut call = session.request_core(cx, core("tools/list", json!({})), RequestId::Number(id), ManagedCoreLimits::default()).await.unwrap();
    let Some(ManagedCoreEvent::Result(result)) = call.next_event(cx).await.unwrap() else { panic!("typed catalog expected") };
    let encoded = result.encode().unwrap();
    assert!(encoded.contains("900719925474099312345"));
    assert!(encoded.contains("1.20e+4"));
    assert_eq!(call.credential_generation(), 1);
    assert!(call.next_event(cx).await.unwrap().is_none());
}

fn run(case: Case) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let body = async {
            let peer = Peer::new().await;
            let ((), session) = pair(peer.login(), ManagedOAuthSession::authorize(
                &cx, peer.client(), OAuthSessionPolicy::default(), browser,
            )).await;
            let session = session.unwrap();
            match case {
                Case::Json => { pair(peer.catalog(41), complete_catalog(&session, &cx, 41)).await; }
                Case::Sse => {
                    let (release_tx, mut release_rx) = oneshot::channel::<()>();
                    let server = async {
                        let mut tls = begin_stream(&peer).await;
                        release_rx.recv(&cx).await.unwrap();
                        chunk(&mut tls, &[PROGRESS.to_owned(), terminal(41, TOOL_RESULT)], true).await;
                    };
                    let application = async {
                        let mut call = session.request_core(&cx, core("tools/call", json!({"name":"echo","arguments":{"text":"hello"}})), RequestId::Number(41), ManagedCoreLimits::default()).await.unwrap();
                        first_changed(&mut call, &cx).await;
                        release_tx.send(&cx, ()).unwrap();
                        let Some(ManagedCoreEvent::Notification(notification)) = call.next_event(&cx).await.unwrap() else { panic!("progress expected") };
                        assert!(matches!(*notification, ServerNotification::Progress(_)));
                        let Some(ManagedCoreEvent::Result(result)) = call.next_event(&cx).await.unwrap() else { panic!("typed result expected") };
                        assert!(matches!(*result, CoreResult::Final(FinalCoreResult::ToolsCall { .. })));
                        assert!(result.encode().unwrap().contains("hello from TLS"));
                        assert!(call.next_event(&cx).await.unwrap().is_none());
                    };
                    pair(server, application).await;
                }
                Case::InvalidResponse => {
                    for (id, invalid) in [
                        (41, terminal(999, CATALOG)),
                        (43, r#"{"jsonrpc":"2.0","id":43,"id":43,"result":{}}"#.to_owned()),
                        (45, format!("[{}]", terminal(45, CATALOG))),
                    ] {
                        let server = async {
                            let (mut tls, _) = peer.request("/mcp").await;
                            json_reply(&mut tls, 200, &invalid).await;
                            drop(tls);
                            peer.catalog(id + 1).await;
                        };
                        let application = async {
                            let mut call = session.request_core(&cx, core("tools/list", json!({})), RequestId::Number(id), ManagedCoreLimits::default()).await.unwrap();
                            assert!(call.next_event(&cx).await.is_err());
                            assert!(matches!(call.next_event(&cx).await, Err(ManagedCoreError::Closed)));
                            complete_catalog(&session, &cx, id + 1).await;
                        };
                        pair(server, application).await;
                    }
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 6);
                }
                Case::InputRequired => {
                    let server = async {
                        let (mut tls, _) = peer.request("/mcp").await;
                        json_reply(&mut tls, 200, &terminal(41, r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"opaque"}"#)).await;
                    };
                    let application = async {
                        let mut call = session.request_core(&cx, core("resources/read", json!({"uri":"file:///sample"})), RequestId::Number(41), ManagedCoreLimits::default()).await.unwrap();
                        let Some(ManagedCoreEvent::Result(result)) = call.next_event(&cx).await.unwrap() else { panic!("input-required expected") };
                        assert!(matches!(*result, CoreResult::Final(FinalCoreResult::ResourcesReadInputRequired { .. })));
                        assert!(call.next_event(&cx).await.unwrap().is_none());
                    };
                    pair(server, application).await;
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 1);
                }
                Case::Cancel | Case::Deadline => {
                    let server = async {
                        let mut tls = begin_stream(&peer).await;
                        let mut byte = [0];
                        assert!(!matches!(tls.read(&mut byte).await, Ok(count) if count > 0));
                        drop(tls);
                        peer.catalog(42).await;
                    };
                    let application = async {
                        let cancellation = McpRequestCancellation::new();
                        let limits = ManagedCoreLimits::new(4096, 4096, 8192, 4, Duration::from_secs(1)).unwrap();
                        let mut call = session.request_core_with_cancellation(&cx, &cancellation, core("tools/list", json!({})), RequestId::Number(41), limits).await.unwrap();
                        first_changed(&mut call, &cx).await;
                        if matches!(case, Case::Cancel) {
                            let mut reading = Box::pin(call.next_event(&cx));
                            poll_fn(|task| { assert!(reading.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                            cancellation.cancel();
                            assert!(matches!(reading.await, Err(ManagedCoreError::Cancelled)));
                        } else {
                            Sleep::new(cx.now().saturating_add_nanos(1_100_000_000)).await;
                            assert!(matches!(call.next_event(&cx).await, Err(ManagedCoreError::TimedOut)));
                        }
                        assert!(matches!(call.next_event(&cx).await, Err(ManagedCoreError::Closed)));
                        assert!(cx.checkpoint().is_ok());
                        complete_catalog(&session, &cx, 42).await;
                    };
                    pair(server, application).await;
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 2);
                }
                Case::Preflight => {
                    let tiny = ManagedCoreLimits::new(1, 4096, 4096, 1, Duration::from_secs(2)).unwrap();
                    assert!(matches!(session.request_core(&cx, core("tools/list", json!({})), RequestId::Number(41), tiny).await, Err(ManagedCoreError::RequestTooLarge)));
                    peer.no_extra_connections();
                    pair(peer.catalog(42), complete_catalog(&session, &cx, 42)).await;
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 1);
                }
                Case::HttpFailure => {
                    for status in [401, 403, 500] {
                        let server = async {
                            let (mut tls, _) = peer.request("/mcp").await;
                            json_reply(&mut tls, status, "peer-error-canary").await;
                        };
                        let application = session.request_core(&cx, core("tools/list", json!({})), RequestId::Number(41), ManagedCoreLimits::default());
                        let ((), result) = pair(server, application).await;
                        let error = result.err().unwrap();
                        assert!(!format!("{error:?} {error}").contains("peer-error-canary"));
                        peer.no_extra_connections();
                    }
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 3);
                }
                Case::UntrustedResource => {
                    let server = async {
                        let (socket, _) = peer.listener.accept().await.unwrap();
                        assert!(peer.acceptor.accept(socket).await.is_err(), "MCP certificate must be trusted before any bearer POST");
                    };
                    let application = session.request_core(&cx, core("tools/list", json!({})), RequestId::Number(41), ManagedCoreLimits::default());
                    let ((), result) = pair(server, application).await;
                    assert!(result.is_err());
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 0);
                }
            }
            assert_eq!(peer.token_posts.load(Ordering::SeqCst), 1, "MCP failures never trigger a grant replay");
            peer.no_extra_connections();
            session.close();
        };
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), body)
            .await.expect("complete public OAuth/MCP case must settle within its bound");
    });
}

#[test]
fn managed_core_live_json_call_preserves_exact_results() { isolated("managed_core_live_json_call_preserves_exact_results", Case::Json); }
#[test]
fn managed_core_live_sse_delivers_notifications_before_terminal() { isolated("managed_core_live_sse_delivers_notifications_before_terminal", Case::Sse); }
#[test]
fn managed_core_bad_response_does_not_poison_sibling_calls() { isolated("managed_core_bad_response_does_not_poison_sibling_calls", Case::InvalidResponse); }
#[test]
fn managed_core_input_required_does_not_repeat_the_post() { isolated("managed_core_input_required_does_not_repeat_the_post", Case::InputRequired); }
#[test]
fn managed_core_idle_cancellation_closes_only_its_request() { isolated("managed_core_idle_cancellation_closes_only_its_request", Case::Cancel); }
#[test]
fn managed_core_deadline_includes_time_between_event_reads() { isolated("managed_core_deadline_includes_time_between_event_reads", Case::Deadline); }
#[test]
fn managed_core_oversized_request_is_rejected_before_dispatch() { isolated("managed_core_oversized_request_is_rejected_before_dispatch", Case::Preflight); }
#[test]
fn managed_core_http_failures_never_replay_or_renew() { isolated("managed_core_http_failures_never_replay_or_renew", Case::HttpFailure); }
#[test]
fn managed_core_resource_requires_its_own_tls_trust() { isolated("managed_core_resource_requires_its_own_tls_trust", Case::UntrustedResource); }
