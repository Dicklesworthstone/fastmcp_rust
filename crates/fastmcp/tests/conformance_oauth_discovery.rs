//! Configured OAuth discovery through the shipped adapter and native TLS/MCP.
//!
//! Include the adapter module itself so these tests cannot validate a parallel
//! reimplementation of its JSON policy. Its unit tests are also discovered in
//! this target. No environment variables, external IdP, native-root feature,
//! production TLS exceptions, or detached async work are used.

#[path = "../examples/conformance_oauth.rs"]
mod conformance_oauth;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::task::Poll;

use asupersync::Cx;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder};
use fastmcp_client::http_auth::discovery::registration::NATIVE_REGISTRATION_REDIRECT_URIS;
use fastmcp_client::http_auth::discovery::registration::metadata_document::NativeClientMetadata;
use fastmcp_client::{ClientBuilder, ClientProtocolPlan, ProtocolPolicy};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::{CoreResult, FINAL_PROTOCOL_VERSION, FinalCoreResult};
use serde_json::{Value, json};

const _: &str = conformance_oauth::ENVIRONMENT;
// TEST ONLY. Same private 2020-2049 CA as the native OAuth integration fixtures.
const ROOT: &str = "-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";
const CLIENT_ID: &str = "HTTPS://CLIENT.EXAMPLE:443/cimd%2Edoc.json";
const PRM: &str = "/.well-known/oauth-protected-resource/mcp";
const ISSUER_LOCATIONS: [&str; 3] = [
    "/.well-known/oauth-authorization-server/tenant",
    "/.well-known/openid-configuration/tenant",
    "/tenant/.well-known/openid-configuration",
];
type Stream = asupersync::tls::TlsStream<TcpStream>;

fn url(value: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(value).unwrap()
}

fn run(future: impl Future<Output = ()>) {
    RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .blocking_threads(0, 8)
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(60_000_000_000), future)
                .await
                .expect("configured OAuth TLS fixture must settle");
        });
}

// Boxed return, not an `async fn`: as an async fn this generator holds both
// input futures inline, so every `pair(..)` await site paid their combined
// size -- the `pair(exercise(..), peer.discovery(..))` sites in this file were
// the largest futures anywhere in the workspace at ~59 KB. Boxing the
// composition helper is the at-source fix for all of them at once, and call
// sites stay `pair(a, b).await`. Same change as the two identical helpers in
// fastmcp-client's integration tests (bd-y2xoc).
fn pair<'a, L: Future + 'a, R: Future + 'a>(
    left: L,
    right: R,
) -> std::pin::Pin<Box<dyn Future<Output = (L::Output, R::Output)> + 'a>> {
    Box::pin(pair_inner(left, right))
}

async fn pair_inner<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let mut left_result = None;
    let mut right_result = None;
    poll_fn(|task| {
        if left_result.is_none() {
            if let Poll::Ready(result) = left.as_mut().poll(task) {
                left_result = Some(result);
            }
        }
        if right_result.is_none() {
            if let Poll::Ready(result) = right.as_mut().poll(task) {
                right_result = Some(result);
            }
        }
        if left_result.is_some() && right_result.is_some() {
            Poll::Ready((left_result.take().unwrap(), right_result.take().unwrap()))
        } else {
            Poll::Pending
        }
    })
    .await
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(byte).to_string()
            }
            byte => format!("%{byte:02X}"),
        })
        .collect()
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
        let (name, value) = field.split_once('=').unwrap();
        assert!(fields.insert(decode(name), decode(value)).is_none());
    }
    fields
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        encoded.push(char::from(ALPHABET[usize::from(first >> 2)]));
        encoded.push(char::from(
            ALPHABET[usize::from((first & 3) << 4 | second >> 4)],
        ));
        if chunk.len() > 1 {
            encoded.push(char::from(
                ALPHABET[usize::from((second & 15) << 2 | third >> 6)],
            ));
        }
        if chunk.len() > 2 {
            encoded.push(char::from(ALPHABET[usize::from(third & 63)]));
        }
    }
    encoded
}

struct Request {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

async fn read_request<IO: AsyncRead + Unpin>(io: &mut IO) -> Request {
    let mut wire = Vec::new();
    let mut buffer = [0_u8; 2048];
    let end = loop {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && wire.len() + count <= 128 * 1024);
        wire.extend_from_slice(&buffer[..count]);
        if let Some(index) = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let head = std::str::from_utf8(&wire[..end]).unwrap();
    let mut lines = head.split("\r\n");
    let line: Vec<_> = lines.next().unwrap().split(' ').collect();
    assert_eq!(line.len(), 3);
    assert_eq!(line[2], "HTTP/1.1");
    let method = line[0].to_owned();
    let target = line[1].to_owned();
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').unwrap();
        assert!(
            headers
                .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                .is_none()
        );
    }
    let length = headers
        .get("content-length")
        .map_or(0, |value| value.parse::<usize>().unwrap());
    assert!(end + length <= 128 * 1024);
    while wire.len() < end + length {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && wire.len() + count <= 128 * 1024);
        wire.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(wire.len(), end + length);
    Request {
        method,
        target,
        headers,
        body: wire[end..].to_vec(),
    }
}

fn public_request(request: &Request) {
    for name in ["authorization", "cookie", "referer"] {
        assert!(
            !request.headers.contains_key(name),
            "credential on an unprotected OAuth route"
        );
    }
}

async fn reply(stream: &mut Stream, status: u16, headers: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n{headers}\r\n",
        body.len(),
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    // The complete length-delimited response was sent. A rejecting client may
    // close before the test peer can write TLS close_notify.
    if let Err(error) = stream.shutdown().await {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ),
            "unexpected fixture shutdown failure: {error}"
        );
    }
}

struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    routes: RefCell<Vec<String>>,
}

impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            acceptor: TlsAcceptorBuilder::new(
                CertificateChain::from_pem(LEAF).unwrap(),
                PrivateKey::from_pem(KEY).unwrap(),
            )
            .alpn_protocols(vec![b"http/1.1".to_vec()])
            .build()
            .unwrap(),
            routes: RefCell::new(Vec::new()),
        }
    }

    fn origin(&self) -> String {
        format!("https://{}", self.listener.local_addr().unwrap())
    }
    fn resource(&self) -> CanonicalHttpUrl {
        url(&format!("{}/mcp", self.origin()))
    }
    fn issuer(&self) -> String {
        format!("{}/tenant", self.origin())
    }

    fn config(&self, client_id: Option<&str>, cimd: bool, dcr: bool) -> Value {
        let mut discovery = json!({"issuer_root_pem": ROOT});
        if cimd {
            let metadata = NativeClientMetadata::new(CLIENT_ID, "Configured fixture").unwrap();
            discovery["client_metadata"] = json!({
                "url": CLIENT_ID,
                "document_json": std::str::from_utf8(metadata.document_json()).unwrap(),
            });
        }
        if dcr {
            discovery["allow_dynamic_registration"] = json!(true);
            discovery["client_name"] = json!("Configured fixture");
        }
        let mut config = json!({
            "preauthorized_redirect": true,
            "issuer": self.issuer(),
            "authorization_endpoint": format!("{}/authorize", self.origin()),
            "resource": self.resource().as_str(),
            "scopes": ["read"],
            "timeout_seconds": 30,
            "authorization_root_pem": ROOT,
            "resource_root_pem": ROOT,
            "discovery": discovery,
        });
        if let Some(client_id) = client_id {
            config["client_id"] = json!(client_id);
        }
        config
    }

    fn builder(&self) -> ClientBuilder {
        let plan = ClientProtocolPlan::http(
            ProtocolPolicy::ModernOnly,
            Some(self.resource()),
            None,
            None,
            "fixture-oauth".to_owned(),
            "fixture".to_owned(),
            "native-http".to_owned(),
            0,
            0,
            0,
        )
        .unwrap();
        ClientBuilder::new().protocol_plan(plan)
    }

    fn metadata(&self, support: Value) -> Value {
        json!({
            "issuer": self.issuer(),
            "authorization_endpoint": format!("{}/authorize", self.origin()),
            "token_endpoint": format!("{}/token", self.origin()),
            "registration_endpoint": format!("{}/register", self.origin()),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": true,
            "client_id_metadata_document_supported": support,
            "scopes_supported": ["read"],
        })
    }

    async fn next(&self, method: &str, path: &str) -> (Stream, Request) {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut stream = self.acceptor.accept(socket).await.unwrap();
        let request = read_request(&mut stream).await;
        assert_eq!(request.method, method);
        let actual_path = request.target.split('?').next().unwrap();
        assert_eq!(actual_path, path);
        self.routes.borrow_mut().push(format!("{method} {path}"));
        (stream, request)
    }

    async fn discovery(&self, documents: &[Value]) {
        let (mut stream, request) = self.next("GET", PRM).await;
        public_request(&request);
        assert!(request.body.is_empty());
        let body = json!({"resource":self.resource().as_str(), "authorization_servers":[self.issuer()], "scopes_supported":["read"]});
        reply(&mut stream, 200, "", &serde_json::to_vec(&body).unwrap()).await;
        for (document, path) in documents.iter().zip(ISSUER_LOCATIONS) {
            let (mut stream, request) = self.next("GET", path).await;
            public_request(&request);
            assert!(request.body.is_empty());
            reply(&mut stream, 200, "", &serde_json::to_vec(document).unwrap()).await;
        }
    }

    async fn register(&self, status: u16, bad_redirect: bool) {
        let (mut stream, request) = self.next("POST", "/register").await;
        public_request(&request);
        let mut body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["client_name"], "Configured fixture");
        assert_eq!(
            body["redirect_uris"],
            json!(NATIVE_REGISTRATION_REDIRECT_URIS)
        );
        assert_eq!(body["token_endpoint_auth_method"], "none");
        assert_eq!(body["scope"], "read");
        body["client_id"] = json!("registered-client");
        if bad_redirect {
            body["redirect_uris"] = json!(["https://untrusted.example/callback"]);
        }
        reply(&mut stream, status, "", &serde_json::to_vec(&body).unwrap()).await;
    }

    /// Sends the front-channel redirect and validates the actual token POST.
    /// Return its still-open socket so a caller can deliberately stall it.
    async fn token_request(&self, client_id: &str) -> Stream {
        let (mut stream, request) = self.next("GET", "/authorize").await;
        public_request(&request);
        let fields = form(request.target.split_once('?').unwrap().1);
        assert_eq!(fields["client_id"], client_id);
        assert_eq!(fields["resource"], self.resource().as_str());
        assert_eq!(fields["response_type"], "code");
        assert_eq!(fields["code_challenge_method"], "S256");
        assert_eq!(fields["scope"], "read");
        let location = format!(
            "{}?code=fixture-code&state={}&iss={}",
            fields["redirect_uri"],
            encode(&fields["state"]),
            encode(&self.issuer()),
        );
        reply(
            &mut stream,
            302,
            &format!("Location: {location}\r\nSet-Cookie: forbidden=canary\r\n"),
            b"",
        )
        .await;
        let (stream, request) = self.next("POST", "/token").await;
        public_request(&request);
        let token = form(std::str::from_utf8(&request.body).unwrap());
        assert_eq!(token["client_id"], client_id);
        assert_eq!(token["grant_type"], "authorization_code");
        assert_eq!(token["code"], "fixture-code");
        assert_eq!(token["redirect_uri"], fields["redirect_uri"]);
        assert_eq!(token["resource"], fields["resource"]);
        let hash = fastmcp_core::sha256_bounded(token["code_verifier"].as_bytes(), 128).unwrap();
        assert_eq!(base64url(hash.as_bytes()), fields["code_challenge"]);
        stream
    }

    async fn login(&self, client_id: &str, status: u16) {
        let mut stream = self.token_request(client_id).await;
        let body = if status == 200 {
            br#"{"access_token":"fixture-access","token_type":"Bearer","expires_in":300,"scope":"read"}"#.as_slice()
        } else {
            br#"{"error":"invalid_grant","error_description":"secret-canary"}"#.as_slice()
        };
        reply(&mut stream, status, "", body).await;
    }

    async fn mcp(&self) {
        for method in ["server/discover", "tools/list", "tools/call"] {
            let (mut stream, request) = self.next("POST", "/mcp").await;
            assert_eq!(
                request.headers.get("authorization").map(String::as_str),
                Some("Bearer fixture-access")
            );
            assert!(!request.headers.contains_key("cookie"));
            assert!(!request.headers.contains_key("referer"));
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body["method"], method);
            assert_eq!(
                body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
                FINAL_PROTOCOL_VERSION
            );
            assert_eq!(
                request.headers.get("mcp-method").map(String::as_str),
                Some(method)
            );
            let result = match method {
                "server/discover" => json!({
                    "resultType":"complete", "supportedVersions":[FINAL_PROTOCOL_VERSION],
                    "capabilities":{"tools":{}}, "ttlMs":0, "cacheScope":"private",
                    "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"fixture","version":"1"}},
                }),
                "tools/list" => json!({
                    "resultType":"complete", "ttlMs":0, "cacheScope":"private",
                    "tools":[{"name":"echo","inputSchema":{"type":"object","properties":{"text":{"type":"string"}}}}],
                }),
                _ => {
                    assert_eq!(body["params"]["name"], "echo");
                    assert_eq!(body["params"]["arguments"], json!({"text":"configured"}));
                    json!({"resultType":"complete","content":[{"type":"text","text":"configured"}]})
                }
            };
            let response = json!({"jsonrpc":"2.0","id":body["id"],"result":result});
            reply(
                &mut stream,
                200,
                "",
                &serde_json::to_vec(&response).unwrap(),
            )
            .await;
        }
    }

    fn count(&self, route: &str) -> usize {
        self.routes
            .borrow()
            .iter()
            .filter(|observed| observed.as_str() == route)
            .count()
    }

    async fn no_more(&self, cx: &Cx) {
        assert!(
            asupersync::time::timeout_at(
                cx.now().saturating_add_nanos(100_000_000),
                self.listener.accept(),
            )
            .await
            .is_err(),
            "an extra connection followed a terminal configured operation"
        );
    }
}

async fn exercise(cx: &Cx, peer: &Peer, configuration: &Value) -> Result<(), String> {
    let endpoint = peer.resource();
    let source = configuration.to_string();
    let (builder, lease) =
        conformance_oauth::configure(cx, &endpoint, peer.builder(), Some(&source)).await?;
    let lease = lease.ok_or_else(|| "configured authorization returned no grant".to_owned())?;
    lease
        .run(cx, async {
            let mut client = builder
                .connect_http_client_with_cx(cx)
                .await
                .map_err(|_| "MCP discovery failed".to_owned())?;
            let listed = client
                .list_tools(cx, None)
                .await
                .map_err(|_| "MCP catalog failed".to_owned())?;
            let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = listed else {
                return Err("unexpected catalog result".to_owned());
            };
            assert_eq!(result.payload.tools.len(), 1);
            assert_eq!(result.payload.tools[0].name, "echo");
            let result = client
                .call_tool(cx, "echo", json!({"text":"configured"}))
                .await
                .map_err(|_| "MCP tool failed".to_owned())?;
            assert!(matches!(result, CoreResult::Final(_)));
            Ok(())
        })
        .await
}

#[test]
fn configured_preregistration_and_cimd_discover_redeem_and_call_protected_tools() {
    for cimd in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let id = if cimd {
                CLIENT_ID
            } else {
                "preregistered-client"
            };
            let config = peer.config((!cimd).then_some(id), cimd, false);
            let (result, ()) = pair(exercise(&cx, &peer, &config), async {
                peer.discovery(&[peer.metadata(json!(cimd))]).await;
                peer.login(id, 200).await;
                peer.mcp().await;
            })
            .await;
            result.unwrap();
            assert_eq!(peer.count("POST /register"), 0);
            assert_eq!(peer.count("POST /token"), 1);
            assert_eq!(peer.count("POST /mcp"), 3);
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn configured_selection_writes_only_when_no_preferred_identity_wins() {
    for (preregistered, cimd, supports, expected_id, registrations) in [
        (
            Some("preregistered-client"),
            true,
            true,
            "preregistered-client",
            0,
        ),
        (None, true, true, CLIENT_ID, 0),
        (None, true, false, "registered-client", 1),
        (None, false, true, "registered-client", 1),
    ] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let config = peer.config(preregistered, cimd, true);
            let (result, ()) = pair(exercise(&cx, &peer, &config), async {
                peer.discovery(&[peer.metadata(json!(supports))]).await;
                if registrations != 0 {
                    peer.register(201, false).await;
                }
                peer.login(expected_id, 200).await;
                peer.mcp().await;
            })
            .await;
            result.unwrap();
            assert_eq!(peer.count("POST /register"), registrations);
            assert_eq!(peer.count("POST /token"), 1);
            assert_eq!(peer.count("POST /mcp"), 3);
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn configured_cimd_refusal_or_malformed_support_never_falls_back_to_dcr() {
    for (supports, permission) in [
        (json!(false), false),
        (Value::Null, true),
        (json!("true"), true),
    ] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let config = peer.config(None, true, permission);
            let body = peer.metadata(supports);
            let (result, ()) = pair(
                exercise(&cx, &peer, &config),
                peer.discovery(&[body.clone(), body.clone(), body]),
            )
            .await;
            assert_eq!(result.unwrap_err(), "explicit OAuth authorization failed");
            assert_eq!(peer.routes.borrow().len(), 4);
            assert_eq!(peer.count("POST /register"), 0);
            assert_eq!(peer.count("GET /authorize"), 0);
            assert_eq!(peer.count("POST /mcp"), 0);
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn configured_registration_or_redemption_failure_does_not_replay_or_send_anonymous_mcp() {
    for (registration_status, bad_redirect, token_status) in [
        (400, false, None),
        (201, true, None),
        (201, false, Some(400)),
    ] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let config = peer.config(None, false, true);
            let (result, ()) = pair(exercise(&cx, &peer, &config), async {
                peer.discovery(&[peer.metadata(json!(false))]).await;
                peer.register(registration_status, bad_redirect).await;
                if let Some(status) = token_status {
                    peer.login("registered-client", status).await;
                }
            })
            .await;
            let error = result.unwrap_err();
            assert_eq!(error, "explicit OAuth authorization failed");
            assert!(!error.contains("secret-canary"));
            assert_eq!(peer.count("POST /register"), 1);
            assert_eq!(
                peer.count("POST /token"),
                usize::from(token_status.is_some())
            );
            assert_eq!(peer.count("POST /mcp"), 0);
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn discovered_authorization_endpoint_cannot_replace_the_local_front_channel_pin() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let config = peer.config(None, true, false);
        let mut metadata = peer.metadata(json!(true));
        metadata["authorization_endpoint"] = json!(format!("{}/changed-authorize", peer.origin()));
        let (result, ()) = pair(exercise(&cx, &peer, &config), peer.discovery(&[metadata])).await;
        assert_eq!(result.unwrap_err(), "explicit OAuth authorization failed");
        assert_eq!(peer.routes.borrow().len(), 2);
        peer.no_more(&cx).await;
    });
}

#[test]
fn configured_authorization_deadline_bounds_a_live_silent_token_socket() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let mut config = peer.config(Some("preregistered-client"), false, false);
        config["timeout_seconds"] = json!(1);
        let (result, held_token_socket) = pair(exercise(&cx, &peer, &config), async {
            peer.discovery(&[peer.metadata(json!(false))]).await;
            // pair retains this result while the other future is pending. Do
            // not drop the socket: EOF would test a different failure path.
            peer.token_request("preregistered-client").await
        })
        .await;
        assert_eq!(result.unwrap_err(), "explicit OAuth authorization failed");
        assert_eq!(peer.count("POST /token"), 1);
        assert_eq!(peer.count("POST /mcp"), 0);
        assert_eq!(peer.count("POST /register"), 0);
        peer.no_more(&cx).await;
        drop(held_token_socket);
    });
}
