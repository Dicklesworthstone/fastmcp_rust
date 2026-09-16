//! Public managed-interaction tests with real OAuth and MCP TLS POSTs.
//! Enable `native-tls-roots` explicitly: default-profile zero tests is not proof.
//! Each case installs its inline TEST ONLY CA into one child process's trust
//! environment. No external fixture asset must be copied to the RCH worker.
#![cfg(feature = "native-tls-roots")]

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::io::Write;
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
use fastmcp_client::http_auth::rpc::interaction::{
    ManagedInteraction, ManagedInteractionError, ManagedInteractionEvent, ManagedInteractionLimits,
};
use fastmcp_client::http_auth::rpc::{ManagedCoreError, ManagedCoreLimits};
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{CoreRequest, FinalInputResponses, RequestId};
use serde_json::{Value, json};

#[path = "oauth_interaction/driver.rs"]
mod driver;

const CHILD: &str = "FASTMCP_TEST_INTERACTION_CASE";
// TEST ONLY certificates and key, never installed in a persistent trust store.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";
const FIRST: &str = r#"{"resultType":"input_required","inputRequests":{"first":{"method":"roots/list"}},"requestState":"  sealed+/%\u0000  "}"#;
const SECOND: &str = r#"{"resultType":"input_required","inputRequests":{"second":{"method":"roots/list"}}}"#;
const CHANGED: &str = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;

#[derive(Clone, Copy)]
enum Case { Tool, Resource, Prompt, HostValidation, StateOnly, RoundLimit, InputLimit, NotificationLimit, ByteLimit, Cancel, Deadline, LostReply, AbandonResume, Capability }

struct RootFile(std::path::PathBuf);
impl RootFile {
    fn create() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        for _ in 0..64 {
            let path = std::env::temp_dir().join(format!("fastmcp-interaction-test-{}-{}.pem", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    let owned = Self(path);
                    file.write_all(ROOT).unwrap();
                    return owned;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(error) => panic!("cannot create isolated test CA: {error}"),
            }
        }
        panic!("test CA name attempts exhausted");
    }
}
impl Drop for RootFile {
    fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); }
}

fn isolated(name: &str, case: Case) {
    if let Ok(selected) = std::env::var(CHILD) {
        assert_eq!(selected, name);
        run(case);
        return;
    }
    let roots = RootFile::create();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit())
        .spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "HTTPS interaction case {name} failed");
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("HTTPS interaction case {name} exceeded its process bound");
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
fn form(input: &str) -> BTreeMap<String, String> {
    fn part(input: &str) -> String {
        let mut result = Vec::new();
        let mut bytes = input.bytes();
        while let Some(byte) = bytes.next() {
            result.push(match byte {
                b'+' => b' ',
                b'%' => (char::from(bytes.next().unwrap()).to_digit(16).unwrap() * 16
                    + char::from(bytes.next().unwrap()).to_digit(16).unwrap()) as u8,
                byte => byte,
            });
        }
        String::from_utf8(result).unwrap()
    }
    input.split('&').map(|field| {
        let (key, value) = field.split_once('=').unwrap();
        (part(key), part(value))
    }).collect()
}

async fn browser(authorization: CanonicalHttpUrl) -> Result<(), OAuthError> {
    let params = form(authorization.query().unwrap());
    assert_eq!(params["code_challenge_method"], "S256");
    let address: SocketAddr = params["redirect_uri"].strip_prefix("http://").unwrap()
        .split('/').next().unwrap().parse().unwrap();
    assert!(address.ip().is_loopback());
    let wire = format!("GET /oauth/callback?code=interaction-code&iss=https%3A%2F%2Fissuer.example&state={} HTTP/1.1\r\nHost: {address}\r\n\r\n", params["state"]);
    let mut socket = TcpStream::connect(address).await.map_err(|_| OAuthError::CallbackRejected)?;
    socket.write_all(wire.as_bytes()).await.map_err(|_| OAuthError::CallbackRejected)
}

fn core(method: &str, advertised: bool) -> CoreRequest {
    let mut params = match method {
        "tools/call" => json!({"name":"echo","arguments":{"payload":"unchanged"}}),
        "resources/read" => json!({"uri":"file:///unchanged"}),
        "prompts/get" => json!({"name":"prompt","arguments":{"subject":"unchanged"}}),
        _ => panic!("unsupported test method"),
    };
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": if advertised { json!({"roots":{}}) } else { json!({}) },
        "com.example/identity":"unchanged",
    });
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
}
fn answers(name: &str) -> FinalInputResponses {
    serde_json::from_value(json!({name:{"roots":[]}})).unwrap()
}
fn terminal(id: i64, result: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#)
}
fn complete(method: &str) -> &'static str {
    match method {
        "tools/call" => r#"{"resultType":"complete","content":[],"x-exact":1.20e+4}"#,
        "resources/read" => r#"{"resultType":"complete","contents":[],"ttlMs":100,"cacheScope":"private","x-exact":1.20e+4}"#,
        "prompts/get" => r#"{"resultType":"complete","messages":[],"x-exact":1.20e+4}"#,
        _ => panic!("unsupported test method"),
    }
}
async fn json_reply(tls: &mut TlsStream<TcpStream>, body: &str) {
    let wire = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    tls.write_all(wire.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
}
async fn sse_head(tls: &mut TlsStream<TcpStream>) {
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
}
async fn event(tls: &mut TlsStream<TcpStream>, payload: &str, last: bool) {
    let data = format!("data: {payload}\n\n");
    let tail = if last { "0\r\n\r\n" } else { "" };
    tls.write_all(format!("{:X}\r\n{data}\r\n{tail}", data.len()).as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
}

struct Peer { listener: TcpListener, acceptor: TlsAcceptor, posts: AtomicUsize, tokens: AtomicUsize }
impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            acceptor: TlsAcceptorBuilder::new(CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap())
                .alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap(),
            posts: AtomicUsize::new(0), tokens: AtomicUsize::new(0),
        }
    }
    fn resource(&self) -> String { format!("https://{}/mcp", self.listener.local_addr().unwrap()) }
    fn client(&self) -> OAuthClient {
        OAuthClient::new(OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example", url("https://issuer.example/authorize"),
            url(&format!("https://{}/token", self.listener.local_addr().unwrap())),
            url(&self.resource()), "interaction-client", vec!["tools:read".to_owned()],
        ).unwrap().with_extra_root_certificate(Certificate::from_pem(ROOT).unwrap().remove(0)).unwrap())
    }
    async fn request(&self, token: bool) -> (TlsStream<TcpStream>, Vec<u8>) {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut tls = self.acceptor.accept(socket).await.unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0; 2048];
        let end = loop {
            let count = tls.read(&mut chunk).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 32 * 1024);
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") { break index + 4; }
        };
        let head = std::str::from_utf8(&bytes[..end]).unwrap();
        assert!(head.starts_with(if token { "POST /token HTTP/1.1\r\n" } else { "POST /mcp HTTP/1.1\r\n" }));
        let headers: BTreeMap<String, String> = head.lines().filter_map(|line| line.split_once(':').map(|(name,value)| (name.to_ascii_lowercase(),value.trim().to_owned()))).collect();
        let size: usize = headers["content-length"].parse().unwrap();
        assert!(end + size <= 32 * 1024);
        while bytes.len() < end + size {
            let count = tls.read(&mut chunk).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 32 * 1024);
            bytes.extend_from_slice(&chunk[..count]);
        }
        assert_eq!(bytes.len(), end + size);
        let body = bytes[end..].to_vec();
        if token {
            assert!(!headers.contains_key("authorization"));
            let fields = form(std::str::from_utf8(&body).unwrap());
            assert_eq!(fields["grant_type"], "authorization_code");
            assert_eq!(fields["code"], "interaction-code");
            assert_eq!(fields["resource"], self.resource());
            self.tokens.fetch_add(1, Ordering::SeqCst);
        } else {
            let request: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(headers["authorization"], "Bearer interaction-access");
            assert_eq!(headers["mcp-method"], request["method"].as_str().unwrap());
            assert_eq!(headers["mcp-protocol-version"], "2026-07-28");
            assert!(!headers.contains_key("mcp-session-id"));
            assert!(!headers.contains_key("last-event-id"));
            self.posts.fetch_add(1, Ordering::SeqCst);
        }
        (tls, body)
    }
    async fn login(&self) {
        let (mut tls, _) = self.request(true).await;
        json_reply(&mut tls, r#"{"access_token":"interaction-access","token_type":"Bearer","expires_in":300,"refresh_token":"interaction-refresh"}"#).await;
    }
    async fn response(&self, id: i64, result: &str) -> Value {
        let (mut tls, body) = self.request(false).await;
        let request: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(request["id"], id);
        json_reply(&mut tls, &terminal(id, result)).await;
        request
    }
    fn quiet(&self) {
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(self.listener.poll_accept(&mut task).is_pending(), "no extra POST or token exchange may be queued");
    }
}

async fn pending(operation: &mut ManagedInteraction, cx: &Cx) {
    assert!(matches!(operation.next_event(cx).await.unwrap(), Some(ManagedInteractionEvent::InputRequired(_))));
    assert!(operation.pending_input().is_some());
}
async fn finished(operation: &mut ManagedInteraction, cx: &Cx) {
    let Some(ManagedInteractionEvent::Complete(result)) = operation.next_event(cx).await.unwrap() else { panic!("complete typed result expected") };
    assert!(result.encode().unwrap().contains("1.20e+4"));
    assert!(operation.pending_input().is_none());
    assert!(operation.next_event(cx).await.unwrap().is_none());
}

fn run(case: Case) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let scenario = async {
            let peer = Peer::new().await;
            let ((), session) = pair(peer.login(), ManagedOAuthSession::authorize(&cx, peer.client(), OAuthSessionPolicy::default(), browser)).await;
            let session = session.unwrap();
            let cancellation = McpRequestCancellation::new();
            let method = match case { Case::Resource => "resources/read", Case::Prompt => "prompts/get", _ => "tools/call" };
            let core_limits = match case {
                Case::Deadline => ManagedCoreLimits::new(4096, 4096, 8192, 8, Duration::from_secs(1)).unwrap(),
                Case::NotificationLimit => ManagedCoreLimits::new(4096, 4096, 8192, 1, Duration::from_secs(15)).unwrap(),
                Case::ByteLimit => ManagedCoreLimits::new(4096, 512, 512, 8, Duration::from_secs(15)).unwrap(),
                _ => ManagedCoreLimits::default(),
            };
            let limits = ManagedInteractionLimits::new(core_limits, if matches!(case, Case::RoundLimit) { 1 } else { 8 }, if matches!(case, Case::InputLimit) { 0 } else { 256 }).unwrap();
            let initial = core(method, !matches!(case, Case::Capability));
            let expected = initial.encode_params().unwrap().unwrap();
            let first_result = if matches!(case, Case::StateOnly) { r#"{"resultType":"input_required","requestState":""}"# } else { FIRST };
            let (first_request, operation) = pair(peer.response(41, first_result), session.start_core_interaction_with_cancellation(&cx, &cancellation, initial, RequestId::Number(41), limits)).await;
            let mut operation = operation.unwrap();
            assert_eq!(first_request["params"], expected);

            if matches!(case, Case::Capability | Case::InputLimit) {
                let error = operation.next_event(&cx).await.err().unwrap();
                assert!(matches!((case, error), (Case::Capability, ManagedInteractionError::CapabilityNotAdvertised) | (Case::InputLimit, ManagedInteractionError::InputLimit)));
                assert!(operation.pending_input().is_none());
                assert_eq!(peer.posts.load(Ordering::SeqCst), 1);
            } else {
                pending(&mut operation, &cx).await;
                assert!(matches!(operation.next_event(&cx).await, Err(ManagedInteractionError::InputPending)));
                peer.quiet();
                match case {
                    Case::Tool | Case::Resource | Case::Prompt | Case::HostValidation => {
                        if matches!(case, Case::HostValidation) {
                            assert!(matches!(operation.resume(&cx, RequestId::Number(41), Some(answers("first"))).await, Err(ManagedInteractionError::RepeatedRequestId)));
                            for invalid in [None, Some(answers("other")), Some(serde_json::from_value(json!({"first":{"action":"decline"}})).unwrap())] {
                                assert!(matches!(operation.resume(&cx, RequestId::Number(42), invalid).await, Err(ManagedInteractionError::InvalidInputResponses)));
                                assert_eq!(operation.continuation_count(), 0);
                                assert_eq!(operation.pending_input().unwrap().request_state(), Some("  sealed+/%\0  "));
                                peer.quiet();
                            }
                        }
                        let (second, resumed) = pair(peer.response(42, SECOND), operation.resume(&cx, RequestId::Number(42), Some(answers("first")))).await;
                        resumed.unwrap();
                        assert_eq!(second["params"]["requestState"], "  sealed+/%\0  ");
                        assert_eq!(second["params"]["inputResponses"], json!({"first":{"roots":[]}}));
                        let mut identity = second["params"].clone();
                        identity.as_object_mut().unwrap().remove("requestState");
                        identity.as_object_mut().unwrap().remove("inputResponses");
                        assert_eq!(identity, expected);
                        pending(&mut operation, &cx).await;
                        let (release_tx, mut release_rx) = oneshot::channel::<()>();
                        let server = async {
                            let (mut tls, body) = peer.request(false).await;
                            let third: Value = serde_json::from_slice(&body).unwrap();
                            assert_eq!(third["id"], 43);
                            assert!(third["params"].get("requestState").is_none());
                            assert_eq!(third["params"]["inputResponses"], json!({"second":{"roots":[]}}));
                            let mut identity = third["params"].clone();
                            identity.as_object_mut().unwrap().remove("inputResponses");
                            assert_eq!(identity, expected);
                            sse_head(&mut tls).await;
                            event(&mut tls, CHANGED, false).await;
                            release_rx.recv(&cx).await.unwrap();
                            event(&mut tls, &terminal(43, complete(method)), true).await;
                        };
                        let client = async {
                            operation.resume(&cx, RequestId::Number(43), Some(answers("second"))).await.unwrap();
                            assert!(matches!(operation.next_event(&cx).await.unwrap(), Some(ManagedInteractionEvent::Notification(_))));
                            release_tx.send(&cx, ()).unwrap();
                            finished(&mut operation, &cx).await;
                        };
                        pair(server, client).await;
                        assert_eq!(operation.continuation_count(), 2);
                        assert_eq!(peer.posts.load(Ordering::SeqCst), 3);
                    }
                    Case::StateOnly => {
                        let empty = serde_json::from_value(json!({})).unwrap();
                        assert!(matches!(operation.resume(&cx, RequestId::Number(42), Some(empty)).await, Err(ManagedInteractionError::InvalidInputResponses)));
                        let (second, result) = pair(peer.response(42, r#"{"resultType":"input_required","inputRequests":{}}"#), operation.resume(&cx, RequestId::Number(42), None)).await;
                        result.unwrap();
                        assert_eq!(second["params"]["requestState"], "");
                        assert!(second["params"].get("inputResponses").is_none());
                        pending(&mut operation, &cx).await;
                        assert!(matches!(operation.resume(&cx, RequestId::Number(43), None).await, Err(ManagedInteractionError::InvalidInputResponses)));
                        let (third, result) = pair(peer.response(43, complete(method)), operation.resume(&cx, RequestId::Number(43), Some(serde_json::from_value(json!({})).unwrap()))).await;
                        result.unwrap();
                        assert_eq!(third["params"]["inputResponses"], json!({}));
                        assert!(third["params"].get("requestState").is_none());
                        finished(&mut operation, &cx).await;
                    }
                    Case::RoundLimit => {
                        let (_, result) = pair(peer.response(42, SECOND), operation.resume(&cx, RequestId::Number(42), Some(answers("first")))).await;
                        result.unwrap();
                        assert!(matches!(operation.next_event(&cx).await, Err(ManagedInteractionError::ContinuationLimit)));
                        assert!(operation.pending_input().is_none());
                        assert!(matches!(operation.resume(&cx, RequestId::Number(43), Some(answers("second"))).await, Err(ManagedInteractionError::Closed)));
                    }
                    Case::NotificationLimit => {
                        // The first resumed round consumes the one allowed
                        // notification; a later round must not reset that count.
                        let server = async {
                            let (mut tls, _) = peer.request(false).await;
                            sse_head(&mut tls).await;
                            event(&mut tls, CHANGED, false).await;
                            event(&mut tls, &terminal(42, SECOND), true).await;
                        };
                        let (_, result) = pair(server, operation.resume(&cx, RequestId::Number(42), Some(answers("first")))).await;
                        result.unwrap();
                        assert!(matches!(operation.next_event(&cx).await.unwrap(), Some(ManagedInteractionEvent::Notification(_))));
                        pending(&mut operation, &cx).await;
                        let server = async {
                            let (mut tls, _) = peer.request(false).await;
                            sse_head(&mut tls).await;
                            event(&mut tls, CHANGED, true).await;
                        };
                        let (_, result) = pair(server, operation.resume(&cx, RequestId::Number(43), Some(answers("second")))).await;
                        result.unwrap();
                        assert!(matches!(operation.next_event(&cx).await, Err(ManagedInteractionError::Core(ManagedCoreError::NotificationLimit))));
                    }
                    Case::ByteLimit => {
                        let large = format!(r#"{{"resultType":"complete","content":[],"padding":"{}"}}"#, "x".repeat(350));
                        assert!(terminal(42, &large).len() < 512);
                        assert!(terminal(41, FIRST).len() + terminal(42, &large).len() > 512);
                        let (_, result) = pair(peer.response(42, &large), operation.resume(&cx, RequestId::Number(42), Some(answers("first")))).await;
                        result.unwrap();
                        assert!(matches!(operation.next_event(&cx).await, Err(ManagedInteractionError::Core(ManagedCoreError::ResponseByteLimit))));
                    }
                    Case::Cancel | Case::Deadline => {
                        if matches!(case, Case::Cancel) { cancellation.cancel(); }
                        else { Sleep::new(cx.now().saturating_add_nanos(1_100_000_000)).await; }
                        let error = operation.resume(&cx, RequestId::Number(42), Some(answers("first"))).await.err().unwrap();
                        assert!(matches!((case, error), (Case::Cancel, ManagedInteractionError::Core(ManagedCoreError::Cancelled)) | (Case::Deadline, ManagedInteractionError::Core(ManagedCoreError::TimedOut))));
                        assert!(operation.pending_input().is_none());
                        peer.quiet();
                        assert_eq!(peer.posts.load(Ordering::SeqCst), 1);
                        assert!(cx.checkpoint().is_ok());
                    }
                    Case::LostReply => {
                        let server = async { let (tls, _) = peer.request(false).await; drop(tls); };
                        let (_, result) = pair(server, operation.resume(&cx, RequestId::Number(42), Some(answers("first")))).await;
                        assert!(result.is_err());
                        assert!(matches!(operation.resume(&cx, RequestId::Number(43), Some(answers("first"))).await, Err(ManagedInteractionError::Closed)));
                        assert!(matches!(operation.next_event(&cx).await, Err(ManagedInteractionError::Closed)));
                        assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                    }
                    Case::AbandonResume => {
                        let (started_tx, mut started_rx) = oneshot::channel::<()>();
                        let server = async {
                            let (mut tls, _) = peer.request(false).await;
                            started_tx.send(&cx, ()).unwrap();
                            let mut byte = [0];
                            assert!(!matches!(tls.read(&mut byte).await, Ok(count) if count > 0));
                        };
                        let client = async {
                            let mut resume = Box::pin(operation.resume(&cx, RequestId::Number(42), Some(answers("first"))));
                            let mut started = std::pin::pin!(started_rx.recv(&cx));
                            poll_fn(|task| {
                                assert!(resume.as_mut().poll(task).is_pending());
                                started.as_mut().poll(task)
                            }).await.unwrap();
                            drop(resume);
                            assert!(matches!(operation.resume(&cx, RequestId::Number(43), Some(answers("first"))).await, Err(ManagedInteractionError::Closed)));
                        };
                        pair(server, client).await;
                        assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                    }
                    Case::Capability | Case::InputLimit => unreachable!(),
                }
            }
            assert_eq!(peer.tokens.load(Ordering::SeqCst), 1, "MRTR does not replay OAuth grants");
            peer.quiet();
            session.close();
        };
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario).await
            .expect("whole interaction fixture must settle within its bound");
    });
}

#[test]
fn tool_interaction_completes_multiple_rounds() { isolated("tool_interaction_completes_multiple_rounds", Case::Tool); }
#[test]
fn resource_interaction_completes_multiple_rounds() { isolated("resource_interaction_completes_multiple_rounds", Case::Resource); }
#[test]
fn prompt_interaction_completes_multiple_rounds() { isolated("prompt_interaction_completes_multiple_rounds", Case::Prompt); }
#[test]
fn invalid_host_answers_preserve_the_pending_challenge() { isolated("invalid_host_answers_preserve_the_pending_challenge", Case::HostValidation); }
#[test]
fn state_only_and_empty_map_rounds_keep_wire_presence() { isolated("state_only_and_empty_map_rounds_keep_wire_presence", Case::StateOnly); }
#[test]
fn continuation_budget_prevents_an_extra_round() { isolated("continuation_budget_prevents_an_extra_round", Case::RoundLimit); }
#[test]
fn input_budget_prevents_host_input_work() { isolated("input_budget_prevents_host_input_work", Case::InputLimit); }
#[test]
fn notification_budget_is_shared_across_rounds() { isolated("notification_budget_is_shared_across_rounds", Case::NotificationLimit); }
#[test]
fn response_byte_budget_is_shared_across_rounds() { isolated("response_byte_budget_is_shared_across_rounds", Case::ByteLimit); }
#[test]
fn cancelling_while_awaiting_input_prevents_resume() { isolated("cancelling_while_awaiting_input_prevents_resume", Case::Cancel); }
#[test]
fn interaction_deadline_includes_host_input_pause() { isolated("interaction_deadline_includes_host_input_pause", Case::Deadline); }
#[test]
fn lost_resume_reply_cannot_replay_the_request() { isolated("lost_resume_reply_cannot_replay_the_request", Case::LostReply); }
#[test]
fn abandoned_resume_closes_the_owned_exchange() { isolated("abandoned_resume_closes_the_owned_exchange", Case::AbandonResume); }
#[test]
fn unadvertised_input_capability_is_rejected() { isolated("unadvertised_input_capability_is_rejected", Case::Capability); }
