//! Public high-level OAuth consumer tests over real loopback TLS.
//!
//! The native callback fixture stands in for the browser. Token redemption,
//! renewal, MCP discovery, catalogs and calls all use the production clients.
//! Tests use explicit private roots, not a native-root feature or a TLS bypass.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::time::Sleep;
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder};
use fastmcp_client::http_auth::BoundBearerCredential;
use fastmcp_client::http_auth::http_client::{
    ManagedHttpClient, ManagedHttpClientError, ManagedHttpOperation,
};
use fastmcp_client::http_auth::managed::{
    ManagedOAuthSession, OAuthCredentialSnapshot, OAuthSessionPolicy,
};
use fastmcp_client::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};
use fastmcp_client::http_executor::parameter_headers::ReviewedToolHeaders;
use fastmcp_client::{ClientBuilder, ClientProtocolPlan, ProtocolPolicy};
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::{CoreResult, FINAL_PROTOCOL_VERSION, FinalCoreResult};
use serde_json::{Value, json};

// TEST ONLY. The existing native OAuth fixture's 2020-2049 CA and key are
// inline because remote transfer excludes standalone PEM files.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

type Stream = asupersync::tls::TlsStream<TcpStream>;

fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }
fn root() -> Certificate { Certificate::from_pem(ROOT).unwrap().remove(0) }

fn run(future: impl Future<Output = ()>) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
        .blocking_threads(0, 8).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(60_000_000_000), future)
                .await.expect("complete TLS fixture must settle");
        });
}

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let mut l = None;
    let mut r = None;
    poll_fn(|task| {
        if l.is_none() {
            if let Poll::Ready(value) = left.as_mut().poll(task) { l = Some(value); }
        }
        if r.is_none() {
            if let Poll::Ready(value) = right.as_mut().poll(task) { r = Some(value); }
        }
        if l.is_some() && r.is_some() {
            Poll::Ready((l.take().unwrap(), r.take().unwrap()))
        } else { Poll::Pending }
    }).await
}

fn encode(value: &str) -> String {
    value.bytes().map(|byte| match byte {
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => char::from(byte).to_string(),
        byte => format!("%{byte:02X}"),
    }).collect()
}

fn decode(value: &str) -> String {
    let mut bytes = value.bytes();
    let mut decoded = Vec::new();
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'+' => b' ',
            b'%' => {
                let high = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                let low = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                u8::try_from(high * 16 + low).unwrap()
            }
            byte => byte,
        });
    }
    String::from_utf8(decoded).unwrap()
}

fn form(value: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for field in value.split('&') {
        let (key, value) = field.split_once('=').unwrap();
        assert!(fields.insert(decode(key), decode(value)).is_none());
    }
    fields
}

struct Request {
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

async fn read_request(stream: &mut Stream) -> Request {
    let mut wire = Vec::new();
    let mut chunk = [0_u8; 2048];
    let end = loop {
        let count = stream.read(&mut chunk).await.unwrap();
        assert!(count > 0 && wire.len() + count <= 128 * 1024);
        wire.extend_from_slice(&chunk[..count]);
        if let Some(index) = wire.windows(4).position(|part| part == b"\r\n\r\n") { break index + 4; }
    };
    let head = std::str::from_utf8(&wire[..end]).unwrap();
    let mut lines = head.split("\r\n");
    let line: Vec<_> = lines.next().unwrap().split(' ').collect();
    assert_eq!(line[0], "POST");
    assert_eq!(line[2], "HTTP/1.1");
    let target = line[1].to_owned();
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').unwrap();
        assert!(headers.insert(name.to_ascii_lowercase(), value.trim().to_owned()).is_none());
    }
    assert!(!headers.contains_key("cookie"));
    assert!(!headers.contains_key("referer"));
    let length = headers["content-length"].parse::<usize>().unwrap();
    assert!(end + length <= 128 * 1024);
    while wire.len() < end + length {
        let count = stream.read(&mut chunk).await.unwrap();
        assert!(count > 0 && wire.len() + count <= 128 * 1024);
        wire.extend_from_slice(&chunk[..count]);
    }
    assert_eq!(wire.len(), end + length);
    Request { target, headers, body: wire[end..].to_vec() }
}

async fn reply(stream: &mut Stream, status: u16, value: Value) {
    // Protocol-cache positives must not be defeated by HTTP no-store. Token
    // responses still forbid storage; MCP responses remain private.
    let cache = if value.get("jsonrpc").is_some() { "private" } else { "no-store" };
    let body = serde_json::to_vec(&value).unwrap();
    stream.write_all(format!(
        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: {cache}\r\nConnection: close\r\n\r\n", body.len()
    ).as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    stream.shutdown().await.unwrap();
}

fn token(access: &str, lifetime: u64, refresh: &str, scope: &str) -> Value {
    json!({"access_token":access,"token_type":"Bearer","expires_in":lifetime,"refresh_token":refresh,"scope":scope})
}

fn discovery() -> Value {
    json!({"resultType":"complete","supportedVersions":[FINAL_PROTOCOL_VERSION],
        "capabilities":{"tools":{},"resources":{},"prompts":{}},
        "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"managed-peer","version":"1"}},
        "ttlMs":60000,"cacheScope":"private"})
}

fn catalog(name: &str) -> Value {
    json!({"resultType":"complete","tools":[{"name":name,"inputSchema":{"type":"object"}}],
        "ttlMs":60000,"cacheScope":"private"})
}

fn complete() -> Value {
    json!({"resultType":"complete","content":[{"type":"text","text":"completed"}],"isError":false})
}

fn tool_name(result: CoreResult) -> String {
    let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = result else { panic!("expected tools catalog"); };
    assert_eq!(result.payload.tools.len(), 1);
    result.payload.tools.into_iter().next().unwrap().name
}

async fn expire(cx: &Cx, snapshot: &OAuthCredentialSnapshot) {
    let remaining = snapshot.expires_at().saturating_duration_since(Instant::now());
    let delay = u64::try_from(remaining.as_nanos()).unwrap().saturating_add(1_000_000);
    let sleep = {
        let _caller = Cx::set_current(Some(cx.clone()));
        Sleep::new(cx.now().saturating_add_nanos(delay))
    };
    sleep.await;
    assert!(Instant::now() >= snapshot.expires_at());
}

struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            acceptor: TlsAcceptorBuilder::new(CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap())
                .alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap(),
        }
    }
    fn origin(&self) -> String { format!("https://{}", self.listener.local_addr().unwrap()) }
    fn resource(&self) -> CanonicalHttpUrl { url(&format!("{}/mcp", self.origin())) }
    fn issuer(&self) -> String { format!("{}/issuer", self.origin()) }
    fn builder(&self) -> ClientBuilder {
        let plan = ClientProtocolPlan::http(ProtocolPolicy::ModernOnly, Some(self.resource()), None, None,
            "managed-owner".to_owned(), "explicit-test-ca".to_owned(), "native-http".to_owned(), 0, 0, 0).unwrap();
        // The managed owner must replace this stale setting before ANY request.
        ClientBuilder::new().protocol_plan(plan)
            .http_bearer_credential(BoundBearerCredential::bind(self.resource(), "must-not-be-sent").unwrap())
            .http_resource_root_certificate(self.resource(), root()).unwrap()
    }
    fn client(&self, session: &ManagedOAuthSession) -> ManagedHttpClient {
        ManagedHttpClient::new(session.clone(), self.builder()).unwrap()
    }
    async fn next(&self) -> (Stream, Request) {
        let (stream, _) = self.listener.accept().await.unwrap();
        let mut stream = self.acceptor.accept(stream).await.unwrap();
        let request = read_request(&mut stream).await;
        (stream, request)
    }
    async fn token(&self, grant: &str, response: Option<Value>) {
        let (mut stream, request) = self.next().await;
        assert_eq!(request.target, "/token");
        assert!(!request.headers.contains_key("authorization"));
        let body = form(std::str::from_utf8(&request.body).unwrap());
        assert_eq!(body["grant_type"], grant);
        assert_eq!(body["client_id"], "native-client");
        assert_eq!(body["resource"], self.resource().as_str());
        if grant == "authorization_code" {
            assert_eq!(body["code"], "native-code");
            assert_eq!(body["code_verifier"].len(), 64);
        } else {
            assert_eq!(body["refresh_token"], "refresh-one");
            assert_eq!(body["scope"], "read write");
            assert!(!body.contains_key("code_verifier"));
        }
        match response {
            Some(value) => reply(&mut stream, 200, value).await,
            None => reply(&mut stream, 400, json!({"error":"invalid_grant"})).await,
        }
    }
    async fn login(&self, cx: &Cx, lifetime: u64) -> ManagedOAuthSession {
        let config = OAuthClientConfiguration::from_trusted_endpoints(
            self.issuer(), url(&format!("{}/authorize", self.origin())),
            url(&format!("{}/token", self.origin())), self.resource(), "native-client",
            vec!["read".to_owned(), "write".to_owned()],
        ).unwrap().with_extra_root_certificate(root()).unwrap();
        let policy = OAuthSessionPolicy::new(
            Duration::ZERO, Duration::from_secs(20), Duration::from_secs(20), 64,
        ).unwrap();
        let authorizing = ManagedOAuthSession::authorize(cx, OAuthClient::new(config), policy, |authorization| async move {
            let fields = form(authorization.query().unwrap());
            assert_eq!(fields["code_challenge_method"], "S256");
            let callback = &fields["redirect_uri"];
            let address: SocketAddr = callback.strip_prefix("http://").unwrap().split('/').next().unwrap().parse().unwrap();
            assert!(address.ip().is_loopback());
            let mut stream = TcpStream::connect(address).await.map_err(|_| OAuthError::CallbackRejected)?;
            stream.write_all(format!(
                "GET /oauth/callback?code=native-code&iss={}&state={} HTTP/1.1\r\nHost: {address}\r\n\r\n",
                encode(&self.issuer()), encode(&fields["state"]),
            ).as_bytes()).await.map_err(|_| OAuthError::CallbackRejected)?;
            // Native authorize polls its listener after this launcher returns.
            Ok(())
        });
        let (session, ()) = pair(authorizing, self.token("authorization_code", Some(token("access-one", lifetime, "refresh-one", "read write")))).await;
        session.unwrap()
    }
    async fn expect(&self, method: &str, access: &str) -> (Stream, Request, Value) {
        let (stream, request) = self.next().await;
        assert_eq!(request.target, "/mcp");
        assert_eq!(request.headers["authorization"], format!("Bearer {access}"));
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["method"], method);
        assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], FINAL_PROTOCOL_VERSION);
        (stream, request, body)
    }
    async fn rpc(&self, method: &str, access: &str, result: Value) -> Value {
        let (mut stream, _, body) = self.expect(method, access).await;
        reply(&mut stream, 200, json!({"jsonrpc":"2.0","id":body["id"],"result":result})).await;
        body
    }
    async fn warm(&self, cx: &Cx, client: &mut ManagedHttpClient) {
        let serving = async {
            self.rpc("server/discover", "access-one", discovery()).await;
            self.rpc("tools/list", "access-one", catalog("echo")).await;
        };
        let (result, ()) = pair(client.list_tools(cx, None), serving).await;
        assert_eq!(tool_name(result.unwrap()), "echo");
        assert_eq!(client.connected_generation(), Some(1));
    }
    async fn no_more(&self, cx: &Cx) {
        assert!(asupersync::time::timeout_at(cx.now().saturating_add_nanos(100_000_000), self.listener.accept()).await.is_err(),
            "unexpected refresh, replay, rediscovery or anonymous request");
    }
}

#[test]
fn refresh_replaces_the_high_level_connection_and_its_live_catalog_cache() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx, 4).await; let snapshot = session.credential(&cx).await.unwrap();
        let mut client = peer.client(&session);
        peer.warm(&cx, &mut client).await;
        let (cached, ()) = pair(client.list_tools(&cx, None), peer.no_more(&cx)).await;
        assert_eq!(tool_name(cached.unwrap()), "echo");
        expire(&cx, &snapshot).await;
        let serving = async {
            peer.token("refresh_token", Some(token("access-two", 300, "refresh-two", "read"))).await;
            peer.rpc("server/discover", "access-two", discovery()).await;
            peer.rpc("tools/list", "access-two", catalog("narrowed-catalog")).await;
        };
        let (result, ()) = pair(client.list_tools(&cx, None), serving).await;
        assert_eq!(tool_name(result.unwrap()), "narrowed-catalog");
        assert_eq!(client.connected_generation(), Some(2));
        assert_eq!(session.credential(&cx).await.unwrap().scopes(), &["read".to_owned()]);
        assert!(snapshot.credential().authorization_for_target(&peer.resource()).is_none());
        let (result, request) = pair(client.call_tool(&cx, "narrowed-catalog", json!({"round":2})), peer.rpc("tools/call", "access-two", complete())).await;
        assert!(result.is_ok()); assert_eq!(request["params"]["arguments"]["round"], 2);
        peer.no_more(&cx).await;
    });
}

#[test]
fn two_high_level_clients_share_one_refresh_but_not_connection_caches() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx, 1).await; let snapshot = session.credential(&cx).await.unwrap();
        let mut left = peer.client(&session); let mut right = peer.client(&session);
        expire(&cx, &snapshot).await;
        let serving = async {
            peer.token("refresh_token", Some(token("access-two", 300, "refresh-two", "read"))).await;
            let mut discovers = 0; let mut lists = 0;
            for _ in 0..4 {
                let (mut stream, request) = peer.next().await;
                assert_eq!(request.target, "/mcp");
                assert_eq!(request.headers["authorization"], "Bearer access-two");
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let result = match body["method"].as_str().unwrap() {
                    "server/discover" => { discovers += 1; discovery() }
                    "tools/list" => { lists += 1; catalog("shared-renewal") }
                    _ => panic!("unexpected request or duplicate refresh"),
                };
                reply(&mut stream, 200, json!({"jsonrpc":"2.0","id":body["id"],"result":result})).await;
            }
            assert_eq!((discovers, lists), (2, 2));
        };
        let ((left_result, right_result), ()) = pair(pair(left.list_tools(&cx, None), right.list_tools(&cx, None)), serving).await;
        assert_eq!(tool_name(left_result.unwrap()), "shared-renewal");
        assert_eq!(tool_name(right_result.unwrap()), "shared-renewal");
        assert_eq!(left.connected_generation(), Some(2)); assert_eq!(right.connected_generation(), Some(2));
        left.close();
        assert!(matches!(left.list_tools(&cx, None).await, Err(ManagedHttpClientError::Closed)));
        assert_eq!(tool_name(right.list_tools(&cx, None).await.unwrap()), "shared-renewal");
        assert!(session.credential(&cx).await.is_ok());
        peer.no_more(&cx).await;
    });
}

#[test]
fn failed_refresh_stops_before_mcp_and_is_not_retried_by_another_client() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx, 1).await; let snapshot = session.credential(&cx).await.unwrap();
        let mut left = peer.client(&session); let mut right = peer.client(&session);
        expire(&cx, &snapshot).await;
        let (result, ()) = pair(left.call_tool(&cx, "echo", json!({})), peer.token("refresh_token", None)).await;
        assert!(matches!(result, Err(ManagedHttpClientError::OAuth(_))));
        assert_eq!(left.connected_generation(), None);
        assert!(matches!(right.list_tools(&cx, None).await, Err(ManagedHttpClientError::OAuth(_))));
        peer.no_more(&cx).await;
    });
}

#[test]
fn live_quiet_calls_wake_on_request_cancel_owner_close_and_token_revocation() {
    for kind in 0..3 {
        run(async {
            let cx = Cx::current().unwrap(); let peer = Peer::new().await;
            let session = peer.login(&cx, 300).await; let snapshot = session.credential(&cx).await.unwrap();
            let mut client = peer.client(&session); peer.warm(&cx, &mut client).await;
            let cancellation = McpRequestCancellation::new();
            let serving = async {
                let (stream, _, body) = peer.expect("tools/call", "access-one").await;
                assert_eq!(body["params"]["name"], "echo");
                match kind { 0 => cancellation.cancel(), 1 => session.close(), _ => snapshot.credential().revoke() }
                stream // pair retains the socket: no EOF can cause the terminal.
            };
            let (result, held_socket) = pair(client.execute_with_cancellation(&cx, &cancellation,
                ManagedHttpOperation::CallTool { name:"echo", arguments:json!({}) }), serving).await;
            match kind {
                0 => assert!(matches!(result, Err(ManagedHttpClientError::Cancelled))),
                1 => assert!(matches!(result, Err(ManagedHttpClientError::Closed))),
                _ => assert!(matches!(result, Err(ManagedHttpClientError::CredentialUnavailable))),
            }
            assert_eq!(client.connected_generation(), None); assert!(cx.checkpoint().is_ok());
            drop(held_socket); peer.no_more(&cx).await;
        });
    }
}

#[test]
fn abandoning_a_dispatched_call_discards_the_connection_without_replaying_it() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx, 300).await; let mut client = peer.client(&session);
        peer.warm(&cx, &mut client).await;
        let mut request = Box::pin(client.call_tool(&cx, "echo", json!({"abandon":true})));
        let mut serving = Box::pin(peer.expect("tools/call", "access-one"));
        let (held_socket, _, body) = poll_fn(|task| {
            assert!(request.as_mut().poll(task).is_pending());
            serving.as_mut().poll(task)
        }).await;
        assert_eq!(body["params"]["arguments"]["abandon"], true);
        drop(request);
        assert_eq!(client.connected_generation(), None);
        // Leave the old socket open while the next explicit operation runs.
        let serving = async {
            peer.rpc("server/discover", "access-one", discovery()).await;
            peer.rpc("tools/list", "access-one", catalog("after-abandonment")).await;
        };
        let (result, ()) = pair(client.list_tools(&cx, None), serving).await;
        assert_eq!(tool_name(result.unwrap()), "after-abandonment");
        assert_eq!(client.connected_generation(), Some(1));
        drop(held_socket); peer.no_more(&cx).await;
    });
}

#[test]
fn http_authorization_failure_does_not_refresh_or_replay_the_mutating_call() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx, 300).await; let mut client = peer.client(&session);
        peer.warm(&cx, &mut client).await;
        let serving = async {
            let (mut stream, _, body) = peer.expect("tools/call", "access-one").await;
            assert_eq!(body["params"]["arguments"]["attempt"], 1);
            reply(&mut stream, 401, json!({"error":"invalid_token"})).await;
        };
        let (result, ()) = pair(client.call_tool(&cx, "echo", json!({"attempt":1})), serving).await;
        assert!(matches!(result, Err(ManagedHttpClientError::Http(_))));
        assert_eq!(client.connected_generation(), None); peer.no_more(&cx).await;
        let serving = async {
            peer.rpc("server/discover", "access-one", discovery()).await;
            let body = peer.rpc("tools/call", "access-one", complete()).await;
            assert_eq!(body["params"]["arguments"]["attempt"], 2);
        };
        let (result, ()) = pair(client.call_tool(&cx, "echo", json!({"attempt":2})), serving).await;
        assert!(result.is_ok()); assert_eq!(client.connected_generation(), Some(1));
        peer.no_more(&cx).await;
    });
}

#[test]
fn live_silent_response_is_bounded_by_original_token_expiry_or_request_deadline() {
    for token_expires in [false, true] {
        run(async {
            let cx = Cx::current().unwrap(); let peer = Peer::new().await;
            let session = peer.login(&cx, if token_expires { 4 } else { 300 }).await;
            let mut client = peer.client(&session); peer.warm(&cx, &mut client).await;
            client = client.with_request_timeout(if token_expires { Duration::from_secs(20) } else { Duration::from_millis(100) }).unwrap();
            let serving = async { peer.expect("tools/call", "access-one").await.0 };
            let (result, held_socket) = pair(client.call_tool(&cx, "echo", json!({})), serving).await;
            if token_expires { assert!(matches!(result, Err(ManagedHttpClientError::CredentialUnavailable))); }
            else { assert!(matches!(result, Err(ManagedHttpClientError::TimedOut))); }
            assert_eq!(client.connected_generation(), None);
            drop(held_socket); peer.no_more(&cx).await;
        });
    }
}

#[test]
fn refreshed_reviewed_calls_keep_the_exact_header_plan_and_new_bearer() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx, 1).await; let snapshot = session.credential(&cx).await.unwrap();
        let mut client = peer.client(&session);
        let reviewed = ReviewedToolHeaders::new(peer.resource(), "echo",
            json!({"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}), |_| true).unwrap();
        expire(&cx, &snapshot).await;
        let serving = async {
            peer.token("refresh_token", Some(token("access-two", 300, "refresh-two", "read"))).await;
            peer.rpc("server/discover", "access-two", discovery()).await;
            let (mut stream, request, body) = peer.expect("tools/call", "access-two").await;
            assert_eq!(request.headers["mcp-param-region"], "eu");
            assert_eq!(body["params"]["arguments"]["region"], "eu");
            reply(&mut stream, 200, json!({"jsonrpc":"2.0","id":body["id"],"result":complete()})).await;
        };
        let (result, ()) = pair(client.call_tool_with_reviewed_headers(&cx, &McpRequestCancellation::new(),
            json!({"region":"eu"}), &reviewed, &|_| true), serving).await;
        assert!(result.is_ok()); assert_eq!(client.connected_generation(), Some(2));
        peer.no_more(&cx).await;
    });
}

#[test]
fn all_catalog_operations_forward_owned_cursors_and_prompt_resource_arguments() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let session = peer.login(&cx, 300).await; let mut client = peer.client(&session);
        let operations = vec![
            (ManagedHttpOperation::ListTools { cursor:Some("tools-page".to_owned()) }, "tools/list", "tools-page", catalog("paged")),
            (ManagedHttpOperation::ListResources { cursor:Some("resources-page".to_owned()) }, "resources/list", "resources-page",
                json!({"resultType":"complete","resources":[],"ttlMs":0,"cacheScope":"private"})),
            (ManagedHttpOperation::ListResourceTemplates { cursor:Some("templates-page".to_owned()) }, "resources/templates/list", "templates-page",
                json!({"resultType":"complete","resourceTemplates":[],"ttlMs":0,"cacheScope":"private"})),
            (ManagedHttpOperation::ListPrompts { cursor:Some("prompts-page".to_owned()) }, "prompts/list", "prompts-page",
                json!({"resultType":"complete","prompts":[],"ttlMs":0,"cacheScope":"private"})),
        ];
        for (index, (operation, method, cursor, result)) in operations.into_iter().enumerate() {
            let serving = async {
                if index == 0 { peer.rpc("server/discover", "access-one", discovery()).await; }
                let body = peer.rpc(method, "access-one", result).await;
                assert_eq!(body["params"]["cursor"], cursor);
            };
            let (result, ()) = pair(client.execute(&cx, operation), serving).await;
            assert!(result.is_ok());
        }
        let (result, body) = pair(client.read_resource(&cx, "note://fixture"), peer.rpc("resources/read", "access-one",
            json!({"resultType":"complete","contents":[{"uri":"note://fixture","text":"read"}],"ttlMs":0,"cacheScope":"private"}))).await;
        assert!(result.is_ok()); assert_eq!(body["params"]["uri"], "note://fixture");
        let (result, body) = pair(client.execute(&cx, ManagedHttpOperation::GetPrompt { name:"prompt", arguments:[("topic".to_owned(),"chosen".to_owned())].into_iter().collect() }),
            peer.rpc("prompts/get", "access-one", json!({"resultType":"complete","messages":[{"role":"user","content":{"type":"text","text":"prompt"}}]}))).await;
        assert!(result.is_ok()); assert_eq!(body["params"]["arguments"]["topic"], "chosen");
        peer.no_more(&cx).await;
    });
}
