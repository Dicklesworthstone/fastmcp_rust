//! Public API tests for resource-bound challenges and native OAuth discovery.
//! Real loopback TLS is used; the browser and authorization server are fixtures.
//! Each test runs with isolated native trust. Enable native-tls-roots explicitly;
//! a feature-filtered zero-test invocation is not validation of this target.
#![cfg(feature = "native-tls-roots")]

use std::future::{Future, poll_fn};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream};
use fastmcp_client::http_auth::discovery::{OAuthDiscoveryError, OAuthDiscoveryPlan, TrustedOAuthIssuer};
use fastmcp_client::http_auth::discovery::challenge::{
    ChallengedOAuthDiscovery, OAuthChallengeError as Error, ResourceMetadataChallenge,
};
use fastmcp_client::http_auth::managed::OAuthSessionPolicy;
use fastmcp_client::http_auth::oauth::{OAuthClientConfiguration, OAuthError};
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::RequestId;
use serde_json::{Value, json};

// TEST ONLY credentials, shared with the existing OAuth TLS fixtures. These
// certificates are not installed in any system trust store (valid 2020-2049).
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";
const CHILD: &str = "FASTMCP_TEST_OAUTH_CHALLENGE_CASE";

#[derive(Clone, Copy)]
enum Case {
    ProbeOnly, Login, NoHint, CrossOrigin, CrossDenied, WrongResource,
    UntrustedIssuer, MissingHintDocument, RedirectHint, InvalidMetadata,
    Ambiguous, BodyOnly, Non401, CancelProbe, DropProbe, TimeoutProbe,
    CancelMetadata, DropMetadata, TimeoutMetadata, UntrustedTls, Preflight,
    OtherScheme, OtherOnly, DuplicateHint, Token68, CancelLogin, DropLogin,
}

struct RootFile(std::path::PathBuf);
impl RootFile {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        for _ in 0..64 {
            let path = std::env::temp_dir().join(format!("fastmcp-challenge-{}-{}.pem",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => { let owner = Self(path); file.write_all(ROOT).unwrap(); return owner; }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(error) => panic!("cannot create test trust file: {error}"),
            }
        }
        panic!("test trust name bound exhausted");
    }
}
impl Drop for RootFile { fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); } }
struct Child(std::process::Child);
impl Drop for Child { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }

fn isolated(name: &str, case: Case) {
    if let Ok(selected) = std::env::var(CHILD) { assert_eq!(selected, name); run(case); return; }
    let root = RootFile::new();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
    if matches!(case, Case::UntrustedTls) { command.env_remove("SSL_CERT_FILE"); }
    else { command.env("SSL_CERT_FILE", &root.0); }
    let mut child = Child(command.spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() { assert!(status.success(), "challenge HTTPS case failed"); return; }
        assert!(Instant::now() < end, "challenge HTTPS child exceeded its deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
}

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = Box::pin(left); let mut right = Box::pin(right);
    let mut one = None; let mut two = None;
    poll_fn(|task| {
        if one.is_none() { if let Poll::Ready(result) = left.as_mut().poll(task) { one = Some(result); } }
        if two.is_none() { if let Poll::Ready(result) = right.as_mut().poll(task) { two = Some(result); } }
        if one.is_some() && two.is_some() { Poll::Ready((one.take().unwrap(), two.take().unwrap())) }
        else { Poll::Pending }
    }).await
}
fn url(text: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(text).unwrap() }
fn root() -> Certificate { Certificate::from_pem(ROOT).unwrap().remove(0) }
fn form(text: &str) -> std::collections::BTreeMap<String, String> {
    fn decode(text: &str) -> String {
        let mut result = Vec::new(); let mut bytes = text.bytes();
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
    text.split('&').map(|field| { let (name, value) = field.split_once('=').unwrap(); (decode(name), decode(value)) }).collect()
}
fn encode(text: &str) -> String {
    let mut result = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') { result.push(char::from(byte)); }
        else { result.push_str(&format!("%{byte:02X}")); }
    }
    result
}
async fn json_reply(tls: &mut TlsStream<TcpStream>, body: &str) {
    tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
}
async fn closed(mut tls: TlsStream<TcpStream>) {
    let mut byte = [0];
    assert!(!matches!(tls.read(&mut byte).await, Ok(count) if count > 0), "owned response must release the connection");
}

struct Peer { listener: TcpListener, acceptor: TlsAcceptor, probes: AtomicUsize, gets: AtomicUsize, tokens: AtomicUsize }
impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            acceptor: TlsAcceptorBuilder::new(CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap())
                .alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap(),
            probes: AtomicUsize::new(0), gets: AtomicUsize::new(0), tokens: AtomicUsize::new(0),
        }
    }
    fn origin(&self) -> String { format!("https://{}", self.listener.local_addr().unwrap()) }
    fn resource(&self) -> CanonicalHttpUrl { url(&format!("{}/mcp", self.origin())) }
    fn issuer(&self) -> String { format!("{}/issuer", self.origin()) }
    fn hint(&self) -> String { format!("{}/metadata?tenant=one,two", self.origin()) }
    fn plan(&self, timeout: Duration) -> OAuthDiscoveryPlan {
        OAuthDiscoveryPlan::new(self.resource(),
            vec![TrustedOAuthIssuer::new(self.issuer()).unwrap().with_root_certificate(root()).unwrap()],
            "native-client", vec!["read".to_owned()]).unwrap()
            .with_resource_root_certificate(root()).unwrap().with_timeout(timeout).unwrap()
    }
    fn expected(&self) -> OAuthClientConfiguration {
        OAuthClientConfiguration::from_trusted_endpoints(self.issuer(), url(&format!("{}/authorize", self.origin())),
            url(&format!("{}/token", self.origin())), self.resource(), "native-client", vec!["read".to_owned()])
            .unwrap().with_extra_root_certificate(root()).unwrap()
    }
    async fn request(&self, expected_start: &str) -> (TlsStream<TcpStream>, Value, Vec<u8>) {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut tls = self.acceptor.accept(socket).await.unwrap();
        let mut wire = Vec::new(); let mut buffer = [0; 2048];
        let end = loop {
            let count = tls.read(&mut buffer).await.unwrap();
            assert!(count > 0 && wire.len() + count <= 32768);
            wire.extend_from_slice(&buffer[..count]);
            if let Some(index) = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n") { break index + 4; }
        };
        let head = std::str::from_utf8(&wire[..end]).unwrap();
        assert_eq!(head.lines().next().unwrap(), expected_start);
        let mut headers = serde_json::Map::new();
        for line in head.lines().skip(1) {
            if let Some((name, value)) = line.split_once(':') {
                assert!(headers.insert(name.to_ascii_lowercase(), json!(value.trim())).is_none());
            }
        }
        assert!(!headers.contains_key("authorization") && !headers.contains_key("cookie"));
        let size = headers.get("content-length").and_then(Value::as_str).map_or(0, |value| value.parse::<usize>().unwrap());
        assert!(end + size <= 32768);
        while wire.len() < end + size {
            let count = tls.read(&mut buffer).await.unwrap();
            assert!(count > 0 && wire.len() + count <= 32768);
            wire.extend_from_slice(&buffer[..count]);
        }
        assert_eq!(wire.len(), end + size);
        (tls, Value::Object(headers), wire[end..].to_vec())
    }
    async fn probe_request(&self) -> TlsStream<TcpStream> {
        let (tls, headers, body) = self.request("POST /mcp HTTP/1.1").await;
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["method"], "server/discover");
        assert_eq!(body["id"], 7);
        assert_eq!(headers["mcp-method"], "server/discover");
        assert_eq!(headers["mcp-protocol-version"], "2026-07-28");
        assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], "2026-07-28");
        assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"], json!({}));
        assert!(!headers.as_object().unwrap().contains_key("mcp-session-id"));
        self.probes.fetch_add(1, Ordering::SeqCst);
        tls
    }
    async fn challenge(&self, case: Case, hint: &str) {
        let mut tls = self.probe_request().await;
        let challenge = match case {
            Case::Ambiguous => "WWW-Authenticate: Bearer scope=read\r\nWWW-Authenticate: Bearer scope=write\r\n".to_owned(),
            Case::DuplicateHint => format!("WWW-Authenticate: Other resource_metadata=\"{hint}\"\r\nWWW-Authenticate: Bearer resource_metadata=\"{hint}\"\r\n"),
            Case::BodyOnly => String::new(),
            Case::NoHint => "WWW-Authenticate: Bearer scope=admin\r\n".to_owned(),
            Case::OtherScheme => format!("WWW-Authenticate: Basic realm=\"not,this\", resource_metadata=\"{hint}\", scope=admin\r\nWWW-Authenticate: Bearer scope=read\r\n"),
            Case::OtherOnly => format!("WWW-Authenticate: Other resource_metadata=\"{hint}\", scope=admin\r\n"),
            Case::Token68 => format!("WWW-Authenticate: Bearer YWJjZA==\r\nWWW-Authenticate: Basic resource_metadata=\"{hint}\"\r\n"),
            _ => format!("WWW-Authenticate: Basic realm=\"not,this\", Bearer realm=primary\r\nwww-authenticate: resource_metadata=\"{hint}\", scope=\"read admin\"\r\n"),
        };
        let (status, other) = if matches!(case, Case::Non401) {
            ("302 Found", format!("Location: {}/must-not-follow\r\n", self.origin()))
        } else { ("401 Unauthorized", String::new()) };
        let forged_body = if matches!(case, Case::BodyOnly) {
            json!({"resource_metadata":hint,"www-authenticate":format!("Bearer resource_metadata=\"{hint}\"")}).to_string()
        } else { String::new() };
        // Deliberately unfinished. Discovery must use the head, close the body
        // and proceed; waiting for EOF would deadlock this real peer exchange.
        // A forged body cannot stand in for the missing header in BodyOnly.
        assert!(forged_body.len() < 1000);
        tls.write_all(format!("HTTP/1.1 {status}\r\n{challenge}{other}Content-Length: 1000\r\nConnection: close\r\n\r\n{forged_body}").as_bytes()).await.unwrap();
        tls.flush().await.unwrap();
        closed(tls).await;
    }
    async fn metadata(&self, case: Case, resource: &CanonicalHttpUrl, issuer: &str) {
        let path = if matches!(case, Case::NoHint) { "/.well-known/oauth-protected-resource/mcp" }
            else { "/metadata?tenant=one,two" };
        let (mut tls, _, body) = self.request(&format!("GET {path} HTTP/1.1")).await;
        assert!(body.is_empty()); self.gets.fetch_add(1, Ordering::SeqCst);
        match case {
            Case::MissingHintDocument => {
                tls.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                tls.flush().await.unwrap();
            }
            Case::RedirectHint => {
                tls.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {}/.well-known/oauth-protected-resource/mcp\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", self.origin()).as_bytes()).await.unwrap();
                tls.flush().await.unwrap();
            }
            Case::InvalidMetadata => json_reply(&mut tls, r#"{"resource":null}"#).await,
            _ => {
                let identity = if matches!(case, Case::WrongResource) { self.hint() } else { resource.as_str().to_owned() };
                let issuer = if matches!(case, Case::UntrustedIssuer) { "https://untrusted.example/issuer" } else { issuer };
                json_reply(&mut tls, &json!({"resource":identity,"authorization_servers":[issuer],"scopes_supported":["read"]}).to_string()).await;
            }
        }
    }
    async fn issuer_metadata(&self) {
        let (mut tls, _, body) = self.request("GET /.well-known/oauth-authorization-server/issuer HTTP/1.1").await;
        assert!(body.is_empty()); self.gets.fetch_add(1, Ordering::SeqCst);
        json_reply(&mut tls, &json!({
            "issuer":self.issuer(),"authorization_endpoint":format!("{}/authorize",self.origin()),
            "token_endpoint":format!("{}/token",self.origin()),"response_types_supported":["code"],
            "token_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"],
            "authorization_response_iss_parameter_supported":true,"scopes_supported":["read"],
        }).to_string()).await;
    }
    async fn token(&self) {
        let (mut tls, headers, body) = self.request("POST /token HTTP/1.1").await;
        assert_eq!(headers["content-type"], "application/x-www-form-urlencoded");
        let fields = form(std::str::from_utf8(&body).unwrap());
        assert_eq!(fields["grant_type"], "authorization_code");
        assert_eq!(fields["code"], "approved-code");
        assert_eq!(fields["client_id"], "native-client");
        assert_eq!(fields["resource"], self.resource().as_str());
        assert!((43..=128).contains(&fields["code_verifier"].len()));
        self.tokens.fetch_add(1, Ordering::SeqCst);
        json_reply(&mut tls, r#"{"access_token":"challenge-access","token_type":"Bearer","expires_in":300,"scope":"read"}"#).await;
    }
    fn quiet(&self) {
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(self.listener.poll_accept(&mut task).is_pending(), "no fallback, login, replay or hidden request");
    }
}

async fn browser(authorization: CanonicalHttpUrl, issuer: String) -> Result<(), OAuthError> {
    let fields = form(authorization.query().unwrap());
    assert_eq!(fields["client_id"], "native-client");
    assert_eq!(fields["scope"], "read", "challenge scope hint cannot widen the grant");
    assert_eq!(fields["code_challenge_method"], "S256");
    let callback = url(&fields["redirect_uri"]);
    let address: std::net::SocketAddr = callback.as_str().strip_prefix("http://").unwrap()
        .split('/').next().unwrap().parse().unwrap();
    assert!(address.ip().is_loopback());
    let mut socket = TcpStream::connect(address).await.map_err(|_| OAuthError::CallbackRejected)?;
    let request = format!("GET /oauth/callback?code=approved-code&state={}&iss={} HTTP/1.1\r\nHost: {address}\r\n\r\n",
        encode(&fields["state"]), encode(&issuer));
    socket.write_all(request.as_bytes()).await.map_err(|_| OAuthError::CallbackRejected)
}

async fn probe(peer: &Peer, cx: &Cx) -> ResourceMetadataChallenge {
    let ((), result) = pair(peer.challenge(Case::ProbeOnly, &peer.hint()),
        ResourceMetadataChallenge::probe(cx, peer.resource(), RequestId::Number(7), Duration::from_secs(10))).await;
    result.unwrap()
}

fn run(case: Case) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let scenario = Box::pin(async {
            let peer = Peer::new().await;
            if matches!(case, Case::UntrustedTls) {
                let server = async {
                    let (socket, _) = peer.listener.accept().await.unwrap();
                    assert!(peer.acceptor.accept(socket).await.is_err(), "untrusted TLS cannot carry the probe");
                };
                let ((), result) = pair(server, ResourceMetadataChallenge::probe(&cx, peer.resource(), RequestId::Number(7), Duration::from_secs(10))).await;
                assert!(matches!(result, Err(Error::Transport))); peer.quiet(); return;
            }
            if matches!(case, Case::Preflight) {
                let cancel = McpRequestCancellation::new(); cancel.cancel();
                assert!(matches!(ResourceMetadataChallenge::probe_with_cancellation(&cx, &cancel, peer.resource(),
                    RequestId::Number(7), Duration::from_secs(1)).await, Err(Error::Discovery(OAuthDiscoveryError::Cancelled))));
                assert!(matches!(ResourceMetadataChallenge::probe(&cx, peer.resource(), RequestId::Number(7), Duration::ZERO).await,
                    Err(Error::InvalidPolicy)));
                peer.quiet(); return;
            }
            if matches!(case, Case::CancelProbe | Case::DropProbe | Case::TimeoutProbe) {
                let cancellation = McpRequestCancellation::new();
                let (sent, mut received) = oneshot::channel::<()>();
                let server = async { let tls = peer.probe_request().await; sent.send(&cx, ()).unwrap(); closed(tls).await; };
                let application = async {
                    let timeout = if matches!(case, Case::TimeoutProbe) { Duration::from_millis(100) } else { Duration::from_secs(10) };
                    let mut pending = Box::pin(ResourceMetadataChallenge::probe_with_cancellation(&cx, &cancellation,
                        peer.resource(), RequestId::Number(7), timeout));
                    let mut ready = std::pin::pin!(received.recv(&cx));
                    poll_fn(|task| { assert!(pending.as_mut().poll(task).is_pending()); ready.as_mut().poll(task) }).await.unwrap();
                    if matches!(case, Case::DropProbe) { drop(pending); }
                    else {
                        if matches!(case, Case::CancelProbe) { cancellation.cancel(); }
                        let error = pending.await.unwrap_err();
                        match case {
                            Case::CancelProbe => assert!(matches!(error, Error::Discovery(OAuthDiscoveryError::Cancelled))),
                            _ => assert!(matches!(error, Error::Discovery(OAuthDiscoveryError::TimedOut))),
                        }
                    }
                };
                pair(server, application).await;
                assert_eq!(peer.probes.load(Ordering::SeqCst), 1); peer.quiet(); return;
            }
            if matches!(case, Case::CrossOrigin | Case::CrossDenied) {
                let metadata = Peer::new().await;
                let ((), result) = pair(peer.challenge(case, &metadata.hint()),
                    ResourceMetadataChallenge::probe(&cx, peer.resource(), RequestId::Number(7), Duration::from_secs(10))).await;
                let mut plan = ChallengedOAuthDiscovery::new(peer.plan(Duration::from_secs(10)), result.unwrap()).unwrap()
                    .with_metadata_root_certificate(root()).unwrap();
                if matches!(case, Case::CrossDenied) {
                    assert!(matches!(plan.discover(&cx).await, Err(Error::MetadataOriginNotTrusted)));
                    assert_eq!(metadata.gets.load(Ordering::SeqCst), 0);
                } else {
                    plan = plan.with_metadata_origin(url(&format!("{}/", metadata.origin()))).unwrap();
                    let server = async {
                        metadata.metadata(case, &peer.resource(), &peer.issuer()).await;
                        peer.issuer_metadata().await;
                    };
                    let ((), result) = pair(server, plan.discover(&cx)).await;
                    assert_eq!(result.unwrap(), peer.expected());
                    assert_eq!(metadata.gets.load(Ordering::SeqCst), 1);
                }
                assert_eq!(peer.tokens.load(Ordering::SeqCst), 0);
                peer.quiet(); metadata.quiet(); return;
            }
            if matches!(case, Case::Ambiguous | Case::BodyOnly | Case::Non401 | Case::DuplicateHint) {
                let ((), result) = pair(peer.challenge(case, &peer.hint()),
                    ResourceMetadataChallenge::probe(&cx, peer.resource(), RequestId::Number(7), Duration::from_secs(10))).await;
                match case {
                    Case::Ambiguous => assert!(matches!(result, Err(Error::AmbiguousBearerChallenge))),
                    Case::DuplicateHint => assert!(matches!(result, Err(Error::AmbiguousMetadataLocation))),
                    Case::BodyOnly => assert!(matches!(result, Err(Error::MissingBearerChallenge))),
                    _ => assert!(matches!(result, Err(Error::UnsupportedStatus { status: 302 }))),
                }
                assert_eq!(peer.gets.load(Ordering::SeqCst), 0); peer.quiet(); return;
            }
            let challenge = if matches!(case, Case::NoHint | Case::OtherScheme | Case::OtherOnly | Case::Token68) {
                let ((), result) = pair(peer.challenge(case, &peer.hint()),
                    ResourceMetadataChallenge::probe(&cx, peer.resource(), RequestId::Number(7), Duration::from_secs(10))).await;
                result.unwrap()
            } else { probe(&peer, &cx).await };
            assert_eq!(challenge.resource(), &peer.resource());
            if matches!(case, Case::ProbeOnly) {
                assert_eq!(challenge.metadata_url().unwrap().as_str(), peer.hint());
                assert_eq!(peer.gets.load(Ordering::SeqCst), 0); peer.quiet(); return;
            }
            if matches!(case, Case::OtherOnly | Case::Token68) { assert!(challenge.scope_hint().is_none()); }
            if matches!(case, Case::OtherScheme) { assert_eq!(challenge.scope_hint(), Some("read")); }
            let timeout = if matches!(case, Case::TimeoutMetadata) { Duration::from_millis(100) } else { Duration::from_secs(10) };
            let plan = ChallengedOAuthDiscovery::new(peer.plan(timeout), challenge).unwrap();
            if matches!(case, Case::CancelMetadata | Case::DropMetadata | Case::TimeoutMetadata) {
                let cancellation = McpRequestCancellation::new();
                let (sent, mut received) = oneshot::channel::<()>();
                let server = async {
                    let (tls, _, body) = peer.request("GET /metadata?tenant=one,two HTTP/1.1").await;
                    assert!(body.is_empty()); peer.gets.fetch_add(1, Ordering::SeqCst);
                    sent.send(&cx, ()).unwrap(); closed(tls).await;
                };
                let application = async {
                    let mut pending = Box::pin(plan.discover_with_cancellation(&cx, &cancellation));
                    let mut ready = std::pin::pin!(received.recv(&cx));
                    poll_fn(|task| { assert!(pending.as_mut().poll(task).is_pending()); ready.as_mut().poll(task) }).await.unwrap();
                    if matches!(case, Case::DropMetadata) { drop(pending); }
                    else {
                        if matches!(case, Case::CancelMetadata) { cancellation.cancel(); }
                        let error = pending.await.unwrap_err();
                        match case {
                            Case::CancelMetadata => assert!(matches!(error, Error::Discovery(OAuthDiscoveryError::Cancelled))),
                            _ => assert!(matches!(error, Error::Discovery(OAuthDiscoveryError::TimedOut))),
                        }
                    }
                };
                pair(server, application).await;
                assert_eq!(peer.gets.load(Ordering::SeqCst), 1); peer.quiet(); return;
            }
            if matches!(case, Case::CancelLogin | Case::DropLogin) {
                let cancellation = McpRequestCancellation::new();
                let bound = std::cell::Cell::new(None::<std::net::SocketAddr>);
                let server = async {
                    peer.metadata(case, &peer.resource(), &peer.issuer()).await;
                    peer.issuer_metadata().await;
                };
                let application = async {
                    let mut pending = Box::pin(plan.authorize_managed_with_cancellation(
                        &cx, &cancellation, OAuthSessionPolicy::default(), |authorization| {
                            let fields = form(authorization.query().unwrap());
                            let address = fields["redirect_uri"].strip_prefix("http://").unwrap()
                                .split('/').next().unwrap().parse().unwrap();
                            bound.set(Some(address));
                            std::future::pending::<Result<(), OAuthError>>()
                        },
                    ));
                    let address = poll_fn(|task| {
                        assert!(pending.as_mut().poll(task).is_pending());
                        match bound.get() { Some(address) => Poll::Ready(address), None => Poll::Pending }
                    }).await;
                    if matches!(case, Case::DropLogin) { drop(pending); }
                    else {
                        cancellation.cancel();
                        assert!(matches!(pending.await, Err(Error::Discovery(OAuthDiscoveryError::Cancelled))));
                    }
                    assert!(TcpStream::connect(address).await.is_err(), "cancelled login releases its bound listener");
                    assert!(cx.checkpoint().is_ok());
                };
                pair(server, application).await;
                assert_eq!(peer.gets.load(Ordering::SeqCst), 2);
                assert_eq!(peer.tokens.load(Ordering::SeqCst), 0);
                assert_eq!(peer.probes.load(Ordering::SeqCst), 1);
                peer.quiet(); return;
            }
            if matches!(case, Case::WrongResource | Case::UntrustedIssuer | Case::MissingHintDocument | Case::RedirectHint | Case::InvalidMetadata) {
                let launched = AtomicUsize::new(0);
                let ((), result) = Box::pin(pair(peer.metadata(case, &peer.resource(), &peer.issuer()),
                    plan.authorize_managed(&cx, OAuthSessionPolicy::default(), |_| async {
                        launched.fetch_add(1, Ordering::SeqCst); Err(OAuthError::BrowserLaunchFailed)
                    }))).await;
                let error = result.unwrap_err();
                match case {
                    Case::WrongResource => assert!(matches!(error, Error::Discovery(OAuthDiscoveryError::ResourceMismatch))),
                    Case::UntrustedIssuer => assert!(matches!(error, Error::Discovery(OAuthDiscoveryError::NoTrustedIssuer))),
                    Case::MissingHintDocument => assert!(matches!(error, Error::Discovery(OAuthDiscoveryError::MetadataNotFound))),
                    Case::RedirectHint => assert!(matches!(error, Error::Discovery(OAuthDiscoveryError::HttpStatus { status: 302 }))),
                    _ => assert!(matches!(error, Error::Discovery(OAuthDiscoveryError::InvalidMetadata))),
                }
                assert_eq!(launched.load(Ordering::SeqCst), 0);
                assert_eq!(peer.gets.load(Ordering::SeqCst), 1, "no alternate-location fallback after a rejected explicit hint");
            } else if matches!(case, Case::Login) {
                let server = async {
                    peer.metadata(case, &peer.resource(), &peer.issuer()).await;
                    peer.issuer_metadata().await; peer.token().await;
                };
                let application = async {
                    let session = plan.authorize_managed(&cx, OAuthSessionPolicy::default(),
                        |authorization| browser(authorization, peer.issuer())).await.unwrap();
                    let credential = session.credential(&cx).await.unwrap();
                    assert_eq!(credential.scopes(), ["read"]);
                    assert_eq!(credential.credential().authorization_for_target(&peer.resource()), Some("Bearer challenge-access".to_owned()));
                    session.close();
                    assert!(credential.credential().authorization_for_target(&peer.resource()).is_none());
                };
                Box::pin(pair(server, application)).await;
                assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
                assert_eq!(peer.probes.load(Ordering::SeqCst), 1, "explicit login never repeats the original resource POST");
            } else {
                assert!(matches!(case, Case::NoHint | Case::OtherScheme | Case::OtherOnly | Case::Token68));
                let server = async { peer.metadata(case, &peer.resource(), &peer.issuer()).await; peer.issuer_metadata().await; };
                let ((), result) = pair(server, plan.discover(&cx)).await;
                assert_eq!(result.unwrap(), peer.expected());
                assert_eq!(peer.gets.load(Ordering::SeqCst), 2);
                assert_eq!(peer.tokens.load(Ordering::SeqCst), 0, "discovery is not authentication-method selection or a grant");
            }
            assert!(cx.checkpoint().is_ok()); peer.quiet();
        });
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario).await
            .expect("the real TLS challenge scenario must settle within its bound");
    }));
}

#[test]
fn probe_returns_at_401_headers_and_drops_an_unfinished_body() { isolated("probe_returns_at_401_headers_and_drops_an_unfinished_body", Case::ProbeOnly); }
#[test]
fn repeated_challenge_headers_drive_relocated_discovery_and_pkce_login() { isolated("repeated_challenge_headers_drive_relocated_discovery_and_pkce_login", Case::Login); }
#[test]
fn bearer_without_a_location_uses_existing_well_known_discovery() { isolated("bearer_without_a_location_uses_existing_well_known_discovery", Case::NoHint); }
#[test]
fn cross_origin_metadata_works_only_after_separate_host_approval() { isolated("cross_origin_metadata_works_only_after_separate_host_approval", Case::CrossOrigin); }
#[test]
fn trusting_a_certificate_does_not_approve_cross_origin_metadata() { isolated("trusting_a_certificate_does_not_approve_cross_origin_metadata", Case::CrossDenied); }
#[test]
fn relocated_document_must_identify_the_original_challenged_resource() { isolated("relocated_document_must_identify_the_original_challenged_resource", Case::WrongResource); }
#[test]
fn challenged_metadata_cannot_select_an_untrusted_issuer() { isolated("challenged_metadata_cannot_select_an_untrusted_issuer", Case::UntrustedIssuer); }
#[test]
fn a_missing_explicit_hint_does_not_fall_back_to_well_known_metadata() { isolated("a_missing_explicit_hint_does_not_fall_back_to_well_known_metadata", Case::MissingHintDocument); }
#[test]
fn a_relocated_metadata_redirect_is_not_followed_or_replaced() { isolated("a_relocated_metadata_redirect_is_not_followed_or_replaced", Case::RedirectHint); }
#[test]
fn malformed_relocated_metadata_never_launches_a_browser() { isolated("malformed_relocated_metadata_never_launches_a_browser", Case::InvalidMetadata); }
#[test]
fn ambiguous_bearer_challenges_prevent_all_discovery_effects() { isolated("ambiguous_bearer_challenges_prevent_all_discovery_effects", Case::Ambiguous); }
#[test]
fn absent_authentication_headers_cannot_be_replaced_by_body_hints() { isolated("absent_authentication_headers_cannot_be_replaced_by_body_hints", Case::BodyOnly); }
#[test]
fn redirected_probe_never_follows_a_metadata_or_login_hint() { isolated("redirected_probe_never_follows_a_metadata_or_login_hint", Case::Non401); }
#[test]
fn cancelling_an_idle_probe_closes_its_socket() { isolated("cancelling_an_idle_probe_closes_its_socket", Case::CancelProbe); }
#[test]
fn dropping_an_idle_probe_closes_its_socket() { isolated("dropping_an_idle_probe_closes_its_socket", Case::DropProbe); }
#[test]
fn probe_timeout_does_not_require_peer_traffic() { isolated("probe_timeout_does_not_require_peer_traffic", Case::TimeoutProbe); }
#[test]
fn cancelling_challenged_metadata_prevents_issuer_fetch_and_login() { isolated("cancelling_challenged_metadata_prevents_issuer_fetch_and_login", Case::CancelMetadata); }
#[test]
fn dropping_challenged_metadata_closes_the_pending_fetch() { isolated("dropping_challenged_metadata_closes_the_pending_fetch", Case::DropMetadata); }
#[test]
fn challenged_metadata_deadline_prevents_later_effects() { isolated("challenged_metadata_deadline_prevents_later_effects", Case::TimeoutMetadata); }
#[test]
fn untrusted_resource_tls_cannot_supply_a_challenge() { isolated("untrusted_resource_tls_cannot_supply_a_challenge", Case::UntrustedTls); }
#[test]
fn invalid_or_precancelled_probes_have_no_network_effect() { isolated("invalid_or_precancelled_probes_have_no_network_effect", Case::Preflight); }
#[test]
fn metadata_on_basic_is_used_without_taking_its_scope_or_authentication() { isolated("metadata_on_basic_is_used_without_taking_its_scope_or_authentication", Case::OtherScheme); }
#[test]
fn metadata_on_another_scheme_preserves_the_host_selected_oauth_flow() { isolated("metadata_on_another_scheme_preserves_the_host_selected_oauth_flow", Case::OtherOnly); }
#[test]
fn identical_hints_on_different_schemes_are_still_ambiguous() { isolated("identical_hints_on_different_schemes_are_still_ambiguous", Case::DuplicateHint); }
#[test]
fn bearer_token68_does_not_hide_another_schemes_metadata_hint() { isolated("bearer_token68_does_not_hide_another_schemes_metadata_hint", Case::Token68); }
#[test]
fn cancellation_spans_challenged_discovery_and_pending_browser_launch() { isolated("cancellation_spans_challenged_discovery_and_pending_browser_launch", Case::CancelLogin); }
#[test]
fn dropping_challenged_login_releases_its_loopback_listener() { isolated("dropping_challenged_login_releases_its_loopback_listener", Case::DropLogin); }
