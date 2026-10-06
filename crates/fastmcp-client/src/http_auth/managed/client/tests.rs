//! The real managed login and native HTTP client, with an in-process TLS peer.
//! Timer mutation below changes only the scheduled renewal instant; token
//! responses, single-flight renewal, discovery and MCP calls use production APIs.

use super::*;
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Instant;

use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder};
use crate::http_auth::managed::OAuthSessionPolicy;
use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};
use crate::{ClientProtocolPlan, ReverseRequestHandlers};
use fastmcp_core::McpError;
use fastmcp_protocol::{FINAL_PROTOCOL_VERSION, FinalCoreResult};
use serde_json::json;

// TEST ONLY: the same private CA as tests/oauth_managed.rs, valid 2020-2049.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";
type TlsStream = asupersync::tls::TlsStream<TcpStream>;

fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }
fn root() -> Certificate { Certificate::from_pem(ROOT).unwrap().remove(0) }

fn builder(resource: CanonicalHttpUrl) -> ClientBuilder {
    ClientBuilder::new().protocol_plan(ClientProtocolPlan::http(
        ProtocolPolicy::ModernOnly, Some(resource), None, None,
        "managed-test-owner".into(), "managed-test-trust".into(), "native-http".into(),
        0, 0, 0,
    ).unwrap())
}

fn run(future: impl Future<Output = ()>) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
        .blocking_threads(0, 8).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            // A fixture runaway guard, not a protocol latency assertion.
            asupersync::time::timeout_at(
                cx.now().saturating_add_nanos(120_000_000_000), future,
            ).await.expect("managed HTTP fixture must settle");
        });
}

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let mut l = None;
    let mut r = None;
    poll_fn(|cx| {
        if l.is_none() {
            if let Poll::Ready(value) = left.as_mut().poll(cx) { l = Some(value); }
        }
        if r.is_none() {
            if let Poll::Ready(value) = right.as_mut().poll(cx) { r = Some(value); }
        }
        if l.is_some() && r.is_some() {
            Poll::Ready((l.take().unwrap(), r.take().unwrap()))
        } else { Poll::Pending }
    }).await
}

fn encode(text: &str) -> String {
    text.bytes().map(|byte| match byte {
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => char::from(byte).to_string(),
        byte => format!("%{byte:02X}"),
    }).collect()
}

fn decode(text: &str) -> String {
    let mut output = Vec::new();
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        output.push(match byte {
            b'+' => b' ',
            b'%' => {
                let a = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                let b = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                u8::try_from(a * 16 + b).unwrap()
            }
            byte => byte,
        });
    }
    String::from_utf8(output).unwrap()
}

fn form(text: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for field in text.split('&') {
        let (name, value) = field.split_once('=').unwrap();
        assert!(fields.insert(decode(name), decode(value)).is_none());
    }
    fields
}

async fn callback(authorization: CanonicalHttpUrl, issuer: String) -> Result<(), OAuthError> {
    let fields = form(authorization.query().unwrap());
    assert_eq!(fields["code_challenge_method"], "S256");
    let redirect = url(&fields["redirect_uri"]);
    // Owned: TcpStream::connect is `A: ToSocketAddrs + Send + 'static`, so a
    // borrow of the local `redirect` cannot satisfy it (E0597).
    let authority = redirect.as_str().strip_prefix("http://").unwrap()
        .split('/').next().unwrap().to_owned();
    let mut stream = TcpStream::connect(authority.clone()).await.map_err(|_| OAuthError::TransportFailed)?;
    stream.write_all(format!(
        "GET /oauth/callback?code=fixture-code&state={}&iss={} HTTP/1.1\r\nHost: {authority}\r\n\r\n",
        encode(&fields["state"]), encode(&issuer),
    ).as_bytes()).await.map_err(|_| OAuthError::TransportFailed)?;
    // Native authorize owns callback receipt; the launcher must return first.
    Ok(())
}

struct Request {
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

async fn read<IO: AsyncRead + Unpin>(stream: &mut IO) -> Request {
    let mut wire = Vec::new();
    let mut buffer = [0_u8; 2048];
    let end = loop {
        let count = stream.read(&mut buffer).await.unwrap();
        assert!(count > 0 && wire.len() + count <= 128 * 1024);
        wire.extend_from_slice(&buffer[..count]);
        if let Some(at) = wire.windows(4).position(|b| b == b"\r\n\r\n") { break at + 4; }
    };
    let head = std::str::from_utf8(&wire[..end]).unwrap();
    let mut lines = head.split("\r\n");
    let request: Vec<_> = lines.next().unwrap().split(' ').collect();
    assert_eq!(request[0], "POST");
    let target = request[1].to_owned();
    assert_eq!(request[2], "HTTP/1.1");
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').unwrap();
        assert!(headers.insert(name.to_ascii_lowercase(), value.trim().to_owned()).is_none());
    }
    let length = headers["content-length"].parse::<usize>().unwrap();
    assert!(end + length <= 128 * 1024);
    while wire.len() < end + length {
        let count = stream.read(&mut buffer).await.unwrap();
        assert!(count > 0 && wire.len() + count <= 128 * 1024);
        wire.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(wire.len(), end + length);
    Request { target, headers, body: wire[end..].to_vec() }
}

async fn reply(stream: &mut TlsStream, status: u16, value: Value) {
    let body = serde_json::to_vec(&value).unwrap();
    stream.write_all(format!(
        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len(),
    ).as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    stream.shutdown().await.unwrap();
}

struct Peer { listener: TcpListener, tls: TlsAcceptor }

impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            tls: TlsAcceptorBuilder::new(
                CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap(),
            ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap(),
        }
    }
    fn origin(&self) -> String { format!("https://{}", self.listener.local_addr().unwrap()) }
    fn resource(&self) -> CanonicalHttpUrl { url(&format!("{}/mcp", self.origin())) }
    fn client_builder(&self) -> ClientBuilder {
        builder(self.resource()).http_resource_root_certificate(self.resource(), root()).unwrap()
    }
    async fn next(&self) -> (TlsStream, Request) {
        let (tcp, _) = self.listener.accept().await.unwrap();
        let mut tls = self.tls.accept(tcp).await.unwrap();
        let request = read(&mut tls).await;
        (tls, request)
    }
    async fn token(&self, grant_type: &str, second: bool) {
        let (mut stream, request) = self.next().await;
        assert_eq!(request.target, "/token");
        for name in ["authorization", "cookie", "referer"] {
            assert!(!request.headers.contains_key(name));
        }
        let fields = form(std::str::from_utf8(&request.body).unwrap());
        assert_eq!(fields["grant_type"], grant_type);
        assert_eq!(fields["resource"], self.resource().as_str());
        assert_eq!(fields["client_id"], "native-client");
        if second {
            assert_eq!(fields["refresh_token"], "refresh-one");
            assert!(!fields.contains_key("code"));
        } else {
            assert_eq!(fields["code"], "fixture-code");
            assert_eq!(fields["code_verifier"].len(), 64);
        }
        reply(&mut stream, 200, token_result(second)).await;
    }
    async fn login(&self, cx: &Cx) -> ManagedOAuthSession {
        let client = OAuthClient::new(OAuthClientConfiguration::from_trusted_endpoints(
            self.origin(), url(&format!("{}/authorize", self.origin())),
            url(&format!("{}/token", self.origin())), self.resource(),
            "native-client", vec!["read".into(), "write".into()],
        ).unwrap().with_extra_root_certificate(root()).unwrap()
            .with_authorization_timeout(Duration::from_secs(90)).unwrap());
        let (session, ()) = pair(
            ManagedOAuthSession::authorize(cx, client, OAuthSessionPolicy::default(),
                |authorization| callback(authorization, self.origin())),
            self.token("authorization_code", false),
        ).await;
        session.unwrap()
    }
    async fn mcp_request(&self, method: &str, token: &str) -> (TlsStream, Value, BTreeMap<String, String>) {
        let (stream, request) = self.next().await;
        assert_eq!(request.target, "/mcp");
        assert_eq!(request.headers["authorization"], format!("Bearer {token}"));
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["method"], method);
        assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], FINAL_PROTOCOL_VERSION);
        (stream, body, request.headers)
    }
    async fn mcp(&self, method: &str, token: &str, result: Value) {
        let (mut stream, body, _) = self.mcp_request(method, token).await;
        reply(&mut stream, 200, json!({"jsonrpc":"2.0","id":body["id"],"result":result})).await;
    }
    async fn discovery(&self, token: &str) { self.mcp("server/discover", token, discovery()).await; }
    async fn catalog(&self, token: &str, name: &str) { self.mcp("tools/list", token, catalog(name)).await; }
    async fn no_more(&self, cx: &Cx) {
        assert!(asupersync::time::timeout_at(
            cx.now().saturating_add_nanos(100_000_000), self.listener.accept(),
        ).await.is_err(), "unexpected discovery, refresh, or replay");
    }
}

fn token_result(second: bool) -> Value {
    json!({"access_token":if second {"access-two"} else {"access-one"},
        "token_type":"Bearer", "expires_in":3600,
        "refresh_token":if second {"refresh-two"} else {"refresh-one"},
        "scope":if second {"read"} else {"read write"}})
}
fn discovery() -> Value {
    json!({"resultType":"complete", "supportedVersions":[FINAL_PROTOCOL_VERSION],
        "capabilities":{"tools":{},"resources":{},"prompts":{}},
        "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"managed-peer","version":"1"}},
        "ttlMs":0,"cacheScope":"private"})
}
fn catalog(name: &str) -> Value {
    json!({"resultType":"complete", "ttlMs":60000,"cacheScope":"private",
        "tools":[{"name":name,"inputSchema":{"type":"object"}}]})
}
fn complete() -> Value {
    json!({"resultType":"complete","content":[{"type":"text","text":"done"}],"isError":false})
}
fn input_required() -> Value {
    json!({"resultType":"input_required","requestState":"bound-state",
        "inputRequests":{"roots":{"method":"roots/list"}}})
}
fn force_renewal(session: &ManagedOAuthSession) {
    let mut state = session.inner.state.try_lock_owned().unwrap();
    state.as_mut().unwrap().renew_after = Instant::now();
}
fn assert_catalog(value: CoreResult, name: &str) {
    let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = value else {
        panic!("expected final catalog");
    };
    assert_eq!(result.payload.tools.len(), 1);
    assert_eq!(result.payload.tools[0].name, name);
}
async fn warmup(cx: &Cx, peer: &Peer, client: &mut ManagedHttpClient) {
    let (listed, ()) = pair(client.list_tools(cx, None), async {
        peer.discovery("access-one").await;
        peer.catalog("access-one", "lookup").await;
    }).await;
    assert_catalog(listed.unwrap(), "lookup");
}

#[test]
fn policy_is_modern_only_exact_resource_and_finite_before_any_io() {
    let resource = url("https://resource.example/mcp");
    assert!(admit_builder(&builder(resource.clone()), &resource, Duration::from_secs(30)).is_ok());
    assert!(admit_builder(&ClientBuilder::new(), &resource, Duration::from_secs(30)).is_err());
    for target in ["https://other.example/mcp", "https://resource.example/other", "https://resource.example/mcp?q=1", "http://127.0.0.1/mcp"] {
        assert!(admit_builder(&builder(url(target)), &resource, Duration::from_secs(30)).is_err());
    }
    for timeout in [Duration::ZERO, Duration::from_secs(901)] {
        assert!(admit_builder(&builder(resource.clone()), &resource, timeout).is_err());
    }
}

#[test]
fn diagnostics_keep_protocol_code_without_peer_messages_or_payloads() {
    let error = request_error(HttpClientError::CoreResult(McpError::invalid_request("secret-canary")));
    assert!(matches!(error, ManagedHttpClientError::Request { code: Some(McpErrorCode::InvalidRequest) }));
    assert!(!format!("{error:?} {error}").contains("secret-canary"));
    let error = ManagedHttpClientError::Session(OAuthSessionError::OAuth(OAuthError::TokenEndpointRejected));
    assert_eq!(format!("{error:?}"), "ManagedHttpClientError::Session(..)");
}

#[test]
fn high_level_calls_reuse_one_grant_then_renew_and_discard_the_old_catalog() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = ManagedHttpClient::new(session.clone(), peer.client_builder(), Duration::from_secs(30)).unwrap();
        warmup(&cx, &peer, &mut client).await;
        assert_eq!(client.cached_credential_generation(), Some(1));
        let (called, ()) = pair(client.call_tool(&cx, "lookup", json!({})),
            peer.mcp("tools/call", "access-one", complete())).await;
        assert!(called.is_ok()); // No second discovery while the grant is unchanged.
        force_renewal(&session);
        let (listed, ()) = pair(client.list_tools(&cx, None), async {
            peer.token("refresh_token", true).await;
            peer.discovery("access-two").await;
            peer.catalog("access-two", "narrowed-catalog").await;
        }).await;
        assert_catalog(listed.unwrap(), "narrowed-catalog");
        assert_eq!(client.cached_credential_generation(), Some(2));
        assert_eq!(session.credential(&cx).await.unwrap().scopes(), &["read".to_owned()]);
        peer.no_more(&cx).await;
    });
}

#[test]
fn stale_catalog_cursor_cannot_cross_a_credential_generation() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = ManagedHttpClient::new(session.clone(), peer.client_builder(), Duration::from_secs(30)).unwrap();
        assert!(matches!(client.list_tools(&cx, Some("unbound-cursor")).await,
            Err(ManagedHttpClientError::CatalogGenerationChanged)));
        let mut page = catalog("lookup"); page["nextCursor"] = json!("generation-one-page");
        let (listed, ()) = pair(client.list_tools(&cx, None), async {
            peer.discovery("access-one").await;
            peer.mcp("tools/list", "access-one", page).await;
        }).await;
        let CoreResult::Final(FinalCoreResult::ToolsList { result: page, .. }) = listed.unwrap() else {
            panic!("expected a tools catalog");
        };
        let cursor = page.payload.next_cursor.unwrap();
        assert_ne!(cursor, "generation-one-page");
        force_renewal(&session);
        let (result, ()) = pair(client.list_tools(&cx, Some(&cursor)),
            peer.token("refresh_token", true)).await;
        assert!(matches!(result, Err(ManagedHttpClientError::CatalogGenerationChanged)));
        assert_eq!(client.cached_credential_generation(), None);
        peer.no_more(&cx).await; // Neither discovery nor the stale cursor is sent.
        let (fresh, ()) = pair(client.list_tools(&cx, None), async {
            peer.discovery("access-two").await;
            peer.catalog("access-two", "fresh").await;
        }).await;
        assert_catalog(fresh.unwrap(), "fresh");
    });
}

#[test]
fn unrelated_renewal_and_reissued_wire_cursors_do_not_revive_old_handles() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = ManagedHttpClient::new(session.clone(), peer.client_builder(), Duration::from_secs(30)).unwrap();
        let first_page = || {
            let mut page = catalog("lookup");
            page["nextCursor"] = json!("same-wire-cursor");
            page
        };
        let (first, ()) = pair(client.list_tools(&cx, None), async {
            peer.discovery("access-one").await;
            peer.mcp("tools/list", "access-one", first_page()).await;
        }).await;
        let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = first.unwrap() else {
            panic!("expected first page");
        };
        let old = result.payload.next_cursor.unwrap();
        force_renewal(&session);
        let (called, ()) = pair(client.call_tool(&cx, "lookup", json!({})), async {
            peer.token("refresh_token", true).await;
            peer.discovery("access-two").await;
            peer.mcp("tools/call", "access-two", complete()).await;
        }).await;
        assert!(called.is_ok());
        assert_eq!(client.cached_credential_generation(), Some(2));
        // This was the bypass: current connection == current token generation,
        // but this cursor came from the connection that renewal discarded.
        assert!(matches!(client.list_tools(&cx, Some(&old)).await,
            Err(ManagedHttpClientError::InvalidCatalogCursor)));
        peer.no_more(&cx).await;

        let (next, ()) = pair(client.list_tools(&cx, None),
            peer.mcp("tools/list", "access-two", first_page())).await;
        let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = next.unwrap() else {
            panic!("expected renewed first page");
        };
        let current = result.payload.next_cursor.unwrap();
        assert_ne!(old, current);
        for rejected in [old.as_str(), "same-wire-cursor"] {
            assert!(matches!(client.list_tools(&cx, Some(rejected)).await,
                Err(ManagedHttpClientError::InvalidCatalogCursor)));
        }
        assert!(matches!(client.list_prompts(&cx, Some(&current)).await,
            Err(ManagedHttpClientError::InvalidCatalogCursor)));
        peer.no_more(&cx).await;
        let (last, ()) = pair(client.list_tools(&cx, Some(&current)), async {
            let (mut stream, body, _) = peer.mcp_request("tools/list", "access-two").await;
            assert_eq!(body["params"]["cursor"], "same-wire-cursor");
            reply(&mut stream, 200, json!({"jsonrpc":"2.0","id":body["id"],"result":catalog("last")})).await;
        }).await;
        assert_catalog(last.unwrap(), "last");
        assert!(matches!(client.list_tools(&cx, Some(&current)).await,
            Err(ManagedHttpClientError::InvalidCatalogCursor)));
        peer.no_more(&cx).await;
    });
}

#[test]
fn request_cancellation_discards_connection_without_cancelling_the_shared_login() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = ManagedHttpClient::new(session.clone(), peer.client_builder(), Duration::from_secs(30)).unwrap();
        warmup(&cx, &peer, &mut client).await;
        let cancellation = McpRequestCancellation::new();
        let (result, held_socket) = pair(
            client.call_tool_with_cancellation(&cx, &cancellation, "lookup", json!({})),
            async {
                let (stream, _, _) = peer.mcp_request("tools/call", "access-one").await;
                cancellation.cancel();
                stream // Retain the silent socket, so EOF cannot cause the failure.
            },
        ).await;
        assert!(matches!(result, Err(ManagedHttpClientError::Session(OAuthSessionError::Cancelled))));
        assert_eq!(client.cached_credential_generation(), None);
        assert!(cx.checkpoint().is_ok());
        assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        drop(held_socket);
        peer.no_more(&cx).await;
        warmup(&cx, &peer, &mut client).await; // An explicit next call rediscovers.
    });
}

#[test]
fn unauthorized_response_never_refreshes_or_replays_the_failed_tool() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = ManagedHttpClient::new(session.clone(), peer.client_builder(), Duration::from_secs(30)).unwrap();
        warmup(&cx, &peer, &mut client).await;
        let (result, ()) = pair(client.call_tool(&cx, "lookup", json!({})), async {
            let (mut stream, _, _) = peer.mcp_request("tools/call", "access-one").await;
            reply(&mut stream, 401, json!({"error":"invalid_token","message":"access-one"})).await;
        }).await;
        assert!(matches!(result, Err(ManagedHttpClientError::Request { .. })));
        assert!(!format!("{result:?}").contains("access-one"));
        assert_eq!(client.cached_credential_generation(), None);
        assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        peer.no_more(&cx).await;
    });
}

#[test]
fn closing_the_shared_session_in_a_reverse_handler_prevents_a_continuation() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let callbacks = Arc::new(AtomicUsize::new(0));
        let called = callbacks.clone(); let owner = session.clone();
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, _, _| {
            called.fetch_add(1, Ordering::SeqCst); owner.close();
            Box::pin(async { Ok(serde_json::from_value(json!({"roots":[]})).unwrap()) })
        });
        let mut client = ManagedHttpClient::new(session.clone(), peer.client_builder().reverse_request_handlers(handlers), Duration::from_secs(30)).unwrap();
        let (result, ()) = pair(client.call_tool(&cx, "lookup", json!({})), async {
            peer.discovery("access-one").await;
            peer.mcp("tools/call", "access-one", input_required()).await;
        }).await;
        assert!(matches!(result, Err(ManagedHttpClientError::Session(OAuthSessionError::Closed))));
        assert_eq!(callbacks.load(Ordering::SeqCst), 1);
        assert_eq!(client.cached_credential_generation(), None);
        peer.no_more(&cx).await;
    });
}

#[test]
fn quiet_response_is_bounded_by_the_whole_operation_deadline() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = ManagedHttpClient::new(session, peer.client_builder(), Duration::from_secs(30)).unwrap();
        warmup(&cx, &peer, &mut client).await;
        client.operation_timeout = Duration::from_secs(2);
        let (result, held_socket) = pair(client.call_tool(&cx, "lookup", json!({})), async {
            let (mut stream, _, _) = peer.mcp_request("tools/call", "access-one").await;
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 500\r\nConnection: close\r\n\r\n{").await.unwrap();
            stream
        }).await;
        assert!(matches!(result, Err(ManagedHttpClientError::Session(OAuthSessionError::TimedOut))));
        assert_eq!(client.cached_credential_generation(), None);
        drop(held_socket);
        peer.no_more(&cx).await;
    });
}

#[test]
fn independent_high_level_clients_share_one_refresh_exchange() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut first = ManagedHttpClient::new(session.clone(), peer.client_builder(), Duration::from_secs(30)).unwrap();
        let mut second = ManagedHttpClient::new(session.clone(), peer.client_builder(), Duration::from_secs(30)).unwrap();
        force_renewal(&session);
        let ((a, b), (refreshes, discoveries, calls)) = pair(
            pair(first.call_tool(&cx, "lookup", json!({"caller":1})), second.call_tool(&cx, "lookup", json!({"caller":2}))),
            async {
                let mut refreshes = 0; let mut discoveries = 0; let mut calls = 0;
                for _ in 0..5 {
                    let (mut stream, request) = peer.next().await;
                    if request.target == "/token" {
                        assert!(!request.headers.contains_key("authorization"));
                        let fields = form(std::str::from_utf8(&request.body).unwrap());
                        assert_eq!(fields["grant_type"], "refresh_token");
                        assert_eq!(fields["refresh_token"], "refresh-one");
                        refreshes += 1;
                        reply(&mut stream, 200, token_result(true)).await;
                    } else {
                        assert_eq!(request.target, "/mcp");
                        assert_eq!(request.headers["authorization"], "Bearer access-two");
                        let body: Value = serde_json::from_slice(&request.body).unwrap();
                        let result = match body["method"].as_str().unwrap() {
                            "server/discover" => { discoveries += 1; discovery() }
                            "tools/call" => { calls += 1; complete() }
                            _ => panic!("unexpected operation"),
                        };
                        reply(&mut stream, 200, json!({"jsonrpc":"2.0","id":body["id"],"result":result})).await;
                    }
                }
                (refreshes, discoveries, calls)
            },
        ).await;
        assert!(a.is_ok() && b.is_ok());
        assert_eq!((refreshes, discoveries, calls), (1, 2, 2));
        assert_eq!(first.cached_credential_generation(), Some(2));
        assert_eq!(second.cached_credential_generation(), Some(2));
        peer.no_more(&cx).await;
    });
}

#[test]
fn reviewed_header_repair_and_mrtr_stay_on_the_original_grant() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let owner = session.clone(); let callbacks = Arc::new(AtomicUsize::new(0));
        let count = callbacks.clone();
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, _, _| {
            count.fetch_add(1, Ordering::SeqCst);
            force_renewal(&owner); // Becoming due must not rotate an active exchange.
            Box::pin(async { Ok(serde_json::from_value(json!({"roots":[]})).unwrap()) })
        });
        let schema = |field: &str| json!({"type":"object","properties":{
            "region":{"type":"string","x-mcp-header":field}}});
        let reviewed = ReviewedToolHeaders::new(peer.resource(), "lookup", schema("Old"), |_| true).unwrap();
        let mut client = ManagedHttpClient::new(session.clone(), peer.client_builder().reverse_request_handlers(handlers), Duration::from_secs(30)).unwrap();
        let (result, ()) = pair(client.call_tool_with_reviewed_headers(&cx, json!({"region":"east"}), &reviewed, &|_| true), async {
            peer.discovery("access-one").await;
            let (mut stream, body, headers) = peer.mcp_request("tools/call", "access-one").await;
            assert_eq!(headers["mcp-param-old"], "east");
            reply(&mut stream, 400, json!({"jsonrpc":"2.0","id":body["id"],"error":{
                "code":fastmcp_protocol::HEADER_MISMATCH_ERROR_CODE,
                "message":fastmcp_protocol::HEADER_MISMATCH_MESSAGE}})).await;
            peer.mcp("tools/list", "access-one", json!({"resultType":"complete","ttlMs":0,"cacheScope":"private",
                "tools":[{"name":"lookup","inputSchema":schema("Region")}]})).await;
            for result in [input_required(), complete()] {
                let (mut stream, body, headers) = peer.mcp_request("tools/call", "access-one").await;
                assert_eq!(headers["mcp-param-region"], "east");
                assert!(!headers.contains_key("mcp-param-old"));
                reply(&mut stream, 200, json!({"jsonrpc":"2.0","id":body["id"],"result":result})).await;
            }
        }).await;
        assert!(result.is_ok()); assert_eq!(callbacks.load(Ordering::SeqCst), 1);
        assert_eq!(client.cached_credential_generation(), Some(1));
        let (next, ()) = pair(client.list_tools(&cx, None), async {
            peer.token("refresh_token", true).await; peer.discovery("access-two").await;
            peer.catalog("access-two", "renewed").await;
        }).await;
        assert_catalog(next.unwrap(), "renewed");
        assert_eq!(client.cached_credential_generation(), Some(2));
    });
}

#[test]
fn local_client_close_does_not_revoke_a_sibling_or_the_shared_login() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut closed = ManagedHttpClient::new(session.clone(), peer.client_builder(), Duration::from_secs(30)).unwrap();
        let mut sibling = ManagedHttpClient::new(session.clone(), peer.client_builder(), Duration::from_secs(30)).unwrap();
        closed.close(); closed.close();
        assert!(matches!(closed.list_tools(&cx, None).await, Err(ManagedHttpClientError::Closed)));
        assert!(!session.credential(&cx).await.unwrap().credential().is_revoked());
        warmup(&cx, &peer, &mut sibling).await;
        let snapshot = session.credential(&cx).await.unwrap(); snapshot.credential().revoke();
        assert!(matches!(sibling.call_tool(&cx, "lookup", json!({})).await,
            Err(ManagedHttpClientError::Session(OAuthSessionError::LoginRequired))));
        assert_eq!(sibling.cached_credential_generation(), None);
        peer.no_more(&cx).await;
    });
}

#[test]
fn abandoned_polled_call_cannot_restore_its_half_consumed_connection() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = ManagedHttpClient::new(session.clone(), peer.client_builder(), Duration::from_secs(30)).unwrap();
        warmup(&cx, &peer, &mut client).await;
        let reached = std::sync::atomic::AtomicBool::new(false);
        let mut call = Box::pin(client.call_tool(&cx, "lookup", json!({})));
        let ((), held_socket) = pair(poll_fn(|task| {
            assert!(call.as_mut().poll(task).is_pending());
            if reached.load(Ordering::SeqCst) { Poll::Ready(()) } else { Poll::Pending }
        }), async {
            let (stream, _, _) = peer.mcp_request("tools/call", "access-one").await;
            reached.store(true, Ordering::SeqCst);
            poll_fn(|task| { task.waker().wake_by_ref(); Poll::Ready(()) }).await;
            stream
        }).await;
        drop(call);
        assert_eq!(client.cached_credential_generation(), None);
        assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        drop(held_socket);
        peer.no_more(&cx).await;
        warmup(&cx, &peer, &mut client).await;
    });
}

#[test]
fn failed_renewal_cannot_fall_back_to_the_old_connection_or_anonymous_traffic() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = ManagedHttpClient::new(session.clone(), peer.client_builder(), Duration::from_secs(30)).unwrap();
        warmup(&cx, &peer, &mut client).await;
        force_renewal(&session);
        let (result, ()) = pair(client.call_tool(&cx, "lookup", json!({})), async {
            let (mut stream, request) = peer.next().await;
            assert_eq!(request.target, "/token");
            let fields = form(std::str::from_utf8(&request.body).unwrap());
            assert_eq!(fields["refresh_token"], "refresh-one");
            reply(&mut stream, 400, json!({"error":"invalid_grant"})).await;
        }).await;
        assert!(matches!(result, Err(ManagedHttpClientError::Session(
            OAuthSessionError::OAuth(OAuthError::TokenEndpointRejected)))));
        assert_eq!(client.cached_credential_generation(), None);
        assert!(matches!(client.list_tools(&cx, None).await,
            Err(ManagedHttpClientError::Session(OAuthSessionError::LoginRequired))));
        peer.no_more(&cx).await;
    });
}

#[test]
fn resource_template_and_prompt_calls_use_the_same_authenticated_client() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = ManagedHttpClient::new(session, peer.client_builder(), Duration::from_secs(30)).unwrap();
        pair(async {
            assert!(matches!(client.list_resources(&cx, None).await.unwrap(),
                CoreResult::Final(FinalCoreResult::ResourcesList { .. })));
            assert!(matches!(client.list_resource_templates(&cx, None).await.unwrap(),
                CoreResult::Final(FinalCoreResult::ResourceTemplatesList { .. })));
            assert!(matches!(client.read_resource(&cx, "note://one").await.unwrap(),
                CoreResult::Final(FinalCoreResult::ResourcesRead { .. })));
            assert!(matches!(client.list_prompts(&cx, None).await.unwrap(),
                CoreResult::Final(FinalCoreResult::PromptsList { .. })));
            assert!(matches!(client.get_prompt(&cx, "greet", HashMap::new()).await.unwrap(),
                CoreResult::Final(FinalCoreResult::PromptsGet { .. })));
        }, async {
            peer.discovery("access-one").await;
            for (method, result) in [
                ("resources/list", json!({"resultType":"complete","resources":[{"uri":"note://one","name":"note"}],"ttlMs":0,"cacheScope":"private"})),
                ("resources/templates/list", json!({"resultType":"complete","resourceTemplates":[{"uriTemplate":"note://{name}","name":"notes"}],"ttlMs":0,"cacheScope":"private"})),
                ("resources/read", json!({"resultType":"complete","contents":[{"uri":"note://one","text":"hello"}],"ttlMs":0,"cacheScope":"private"})),
                ("prompts/list", json!({"resultType":"complete","prompts":[{"name":"greet"}],"ttlMs":0,"cacheScope":"private"})),
                ("prompts/get", json!({"resultType":"complete","messages":[{"role":"user","content":{"type":"text","text":"hello"}}]})),
            ] {
                peer.mcp(method, "access-one", result).await;
            }
        }).await;
        assert_eq!(client.cached_credential_generation(), Some(1));
        peer.no_more(&cx).await;
    });
}
