//! Native CIMD and registration selection through public APIs over loopback TLS.
//!
//! These fixtures model a trusted authorization server; they do not prove that
//! an external server fetched or authenticated the operator-published document.
//! No native-root feature is needed: each endpoint receives its explicit test CA.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder};
use fastmcp_client::http_auth::discovery::TrustedOAuthIssuer;
use fastmcp_client::http_auth::discovery::registration::{
    NATIVE_REGISTRATION_REDIRECT_URIS, NativeClientRegistration,
};
use fastmcp_client::http_auth::discovery::registration::metadata_document::{
    MetadataDocumentDiscovery, MetadataDocumentError, NativeClientMetadata,
};
use fastmcp_client::http_auth::discovery::registration::selection::{
    NativeClientRegistrationChoice, NativeClientRegistrationMethod, NativeClientSelectionError,
};
use fastmcp_client::http_auth::driver::redirect::RedirectAuthorizationDriver;
use fastmcp_client::http_auth::managed::{OAuthSessionError, OAuthSessionPolicy};
use fastmcp_client::http_auth::oauth::OAuthError;
use fastmcp_client::{ClientBuilder, ClientProtocolPlan, ProtocolPolicy};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::{CoreResult, FINAL_PROTOCOL_VERSION, FinalCoreResult};
use serde_json::{Value, json};

// TEST ONLY. Inline copies of the native OAuth fixture's 2020-2049 CA and key;
// remote transfer excludes standalone PEM files. No production trust is added.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";
const EXACT_CLIENT_ID: &str = "HTTPS://CLIENT.EXAMPLE:443/cimd%2Edoc.json";
const PRM: &str = "/.well-known/oauth-protected-resource/mcp";
const AS_LOCATIONS: [&str; 3] = [
    "/.well-known/oauth-authorization-server/tenant",
    "/.well-known/openid-configuration/tenant",
    "/tenant/.well-known/openid-configuration",
];

type Stream = asupersync::tls::TlsStream<TcpStream>;

fn url(text: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(text).unwrap()
}

fn root() -> Certificate {
    Certificate::from_pem(ROOT).unwrap().remove(0)
}

fn run(future: impl Future<Output = ()>) {
    RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .blocking_threads(0, 8)
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), future)
                .await.expect("the complete public-API TLS exchange must settle");
        });
}

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let mut left_result = None;
    let mut right_result = None;
    poll_fn(|task| {
        if left_result.is_none() {
            if let Poll::Ready(result) = left.as_mut().poll(task) { left_result = Some(result); }
        }
        if right_result.is_none() {
            if let Poll::Ready(result) = right.as_mut().poll(task) { right_result = Some(result); }
        }
        if left_result.is_some() && right_result.is_some() {
            Poll::Ready((left_result.take().unwrap(), right_result.take().unwrap()))
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
    let mut map = BTreeMap::new();
    for field in value.split('&') {
        let (key, value) = field.split_once('=').unwrap();
        assert!(map.insert(decode(key), decode(value)).is_none());
    }
    map
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        encoded.push(char::from(ALPHABET[usize::from(first >> 2)]));
        encoded.push(char::from(ALPHABET[usize::from((first & 3) << 4 | second >> 4)]));
        if chunk.len() > 1 { encoded.push(char::from(ALPHABET[usize::from((second & 15) << 2 | third >> 6)])); }
        if chunk.len() > 2 { encoded.push(char::from(ALPHABET[usize::from(third & 63)])); }
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
        if let Some(index) = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n") { break index + 4; }
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
        let (key, value) = line.split_once(':').unwrap();
        assert!(headers.insert(key.to_ascii_lowercase(), value.trim().to_owned()).is_none());
    }
    let length = headers.get("content-length").map_or(0, |value| value.parse::<usize>().unwrap());
    assert!(end + length <= 128 * 1024);
    while wire.len() < end + length {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && wire.len() + count <= 128 * 1024);
        wire.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(wire.len(), end + length);
    Request { method, target, headers, body: wire[end..].to_vec() }
}

fn public_request(request: &Request) {
    for forbidden in ["authorization", "cookie", "referer"] {
        assert!(!request.headers.contains_key(forbidden), "unexpected front-channel credential");
    }
}

async fn reply(stream: &mut Stream, status: u16, extra_headers: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n{extra_headers}\r\n",
        body.len(),
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.shutdown().await.unwrap();
}

struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            acceptor: TlsAcceptorBuilder::new(
                CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap(),
            ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap(),
        }
    }

    fn origin(&self) -> String { format!("https://{}", self.listener.local_addr().unwrap()) }
    fn resource(&self) -> CanonicalHttpUrl { url(&format!("{}/mcp", self.origin())) }
    fn issuer(&self) -> String { format!("{}/tenant", self.origin()) }
    fn trusted(&self) -> TrustedOAuthIssuer {
        TrustedOAuthIssuer::new(self.issuer()).unwrap().with_root_certificate(root()).unwrap()
    }
    fn metadata() -> NativeClientMetadata {
        NativeClientMetadata::new(EXACT_CLIENT_ID, "Native CIMD test").unwrap()
    }
    fn cimd(&self) -> MetadataDocumentDiscovery {
        MetadataDocumentDiscovery::new(self.resource(), vec![self.trusted()], Self::metadata(), vec!["read".to_owned()])
            .unwrap().with_resource_root_certificate(root()).unwrap()
    }
    fn registration(&self) -> NativeClientRegistration {
        NativeClientRegistration::new(self.resource(), vec![self.trusted()], "Native CIMD test", vec!["read".to_owned()])
            .unwrap().with_resource_root_certificate(root()).unwrap()
    }
    fn driver(&self) -> RedirectAuthorizationDriver {
        RedirectAuthorizationDriver::new(url(&format!("{}/authorize", self.origin())))
            .unwrap().with_extra_root_certificate(root()).unwrap()
    }
    fn issuer_document(&self, supports: Value) -> Value {
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
            "client_id_metadata_document_supported": supports,
            "scopes_supported": ["read"]
        })
    }
    async fn next(&self) -> (Stream, Request) {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut stream = self.acceptor.accept(socket).await.unwrap();
        let request = read_request(&mut stream).await;
        (stream, request)
    }
    async fn discovery(&self, issuer_documents: Vec<Value>) {
        let (mut stream, request) = self.next().await;
        assert_eq!(request.method, "GET"); assert_eq!(request.target, PRM);
        assert!(request.body.is_empty()); public_request(&request);
        let body = json!({"resource":self.resource().as_str(), "authorization_servers":[self.issuer()], "scopes_supported":["read"], "bearer_methods_supported":["header"]});
        reply(&mut stream, 200, "", &serde_json::to_vec(&body).unwrap()).await;
        for (index, body) in issuer_documents.into_iter().enumerate() {
            let (mut stream, request) = self.next().await;
            assert_eq!(request.method, "GET"); assert_eq!(request.target, AS_LOCATIONS[index]);
            assert!(request.body.is_empty()); public_request(&request);
            reply(&mut stream, 200, "", &serde_json::to_vec(&body).unwrap()).await;
        }
    }
    async fn register(&self, status: u16, corrupt: bool) {
        let (mut stream, request) = self.next().await;
        assert_eq!(request.method, "POST"); assert_eq!(request.target, "/register");
        public_request(&request);
        let mut body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["application_type"], "native");
        assert_eq!(body["token_endpoint_auth_method"], "none");
        assert_eq!(body["redirect_uris"], json!(NATIVE_REGISTRATION_REDIRECT_URIS));
        assert_eq!(body["scope"], "read");
        assert!(body.get("client_id").is_none()); assert!(body.get("client_secret").is_none());
        body["client_id"] = json!("created-client");
        if corrupt { body["redirect_uris"] = json!(["https://wrong.example/callback"]); }
        reply(&mut stream, status, "", &serde_json::to_vec(&body).unwrap()).await;
    }
    async fn login(&self, expected_id: &str, accepted: bool) {
        let (mut stream, request) = self.next().await;
        assert_eq!(request.method, "GET"); public_request(&request);
        let fields = form(request.target.strip_prefix("/authorize?").unwrap());
        assert_eq!(fields["client_id"], expected_id);
        assert_eq!(fields["resource"], self.resource().as_str());
        assert_eq!(fields["scope"], "read");
        assert_eq!(fields["code_challenge_method"], "S256");
        assert!(!fields.contains_key("code_verifier"));
        let callback = format!("{}?code=issued-code&state={}&iss={}", fields["redirect_uri"], encode(&fields["state"]), encode(&self.issuer()));
        reply(&mut stream, 302, &format!("Location: {callback}\r\n"), b"").await;
        let (mut stream, request) = self.next().await;
        assert_eq!(request.method, "POST"); assert_eq!(request.target, "/token");
        public_request(&request);
        let token = form(std::str::from_utf8(&request.body).unwrap());
        assert_eq!(token["client_id"], expected_id);
        assert_eq!(token["grant_type"], "authorization_code");
        assert_eq!(token["code"], "issued-code");
        assert_eq!(token["resource"], fields["resource"]);
        assert_eq!(token["redirect_uri"], fields["redirect_uri"]);
        let digest = fastmcp_core::sha256_bounded(token["code_verifier"].as_bytes(), 128).unwrap();
        assert_eq!(base64url(digest.as_bytes()), fields["code_challenge"]);
        if accepted {
            reply(&mut stream, 200, "", br#"{"access_token":"cimd-access","token_type":"Bearer","expires_in":300,"refresh_token":"cimd-refresh","scope":"read"}"#).await;
        } else {
            reply(&mut stream, 400, "", br#"{"error":"invalid_client"}"#).await;
        }
    }
    async fn protected_catalog(&self) {
        for method in ["server/discover", "tools/list"] {
            let (mut stream, request) = self.next().await;
            assert_eq!(request.method, "POST"); assert_eq!(request.target, "/mcp");
            assert_eq!(request.headers["authorization"], "Bearer cimd-access");
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body["method"], method);
            assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], FINAL_PROTOCOL_VERSION);
            let result = if method == "server/discover" {
                json!({"resultType":"complete", "supportedVersions":[FINAL_PROTOCOL_VERSION], "capabilities":{"tools":{}}, "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"cimd-peer","version":"1"}}, "ttlMs":0, "cacheScope":"private"})
            } else {
                json!({"resultType":"complete", "tools":[{"name":"listed-through-oauth","inputSchema":{"type":"object"}}], "ttlMs":0, "cacheScope":"private"})
            };
            let response = json!({"jsonrpc":"2.0", "id":body["id"], "result":result});
            reply(&mut stream, 200, "", &serde_json::to_vec(&response).unwrap()).await;
        }
    }
    async fn no_more_requests(&self, cx: &Cx) {
        let result = asupersync::time::timeout_at(cx.now().saturating_add_nanos(100_000_000), self.listener.accept()).await;
        assert!(result.is_err(), "unexpected retry, registration, metadata fetch, or login");
    }
}

#[test]
fn cimd_candidate_admission_then_pkce_login_reaches_authenticated_public_mcp_client() {
    assert_eq!(base64url(b"foo"), "Zm9v");
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let plan = peer.cimd(); let driver = peer.driver();
        let serving = async {
            // A generic first-200 selector would stop at this non-CIMD document.
            peer.discovery(vec![peer.issuer_document(json!(false)), peer.issuer_document(json!(true))]).await;
            peer.login(EXACT_CLIENT_ID, true).await;
        };
        let (session, ()) = pair(plan.authorize_managed_with_browser_driver(
            &cx, OAuthSessionPolicy::default(), Duration::from_secs(10), |url| driver.drive(&cx, url),
        ), serving).await;
        let session = session.unwrap(); let snapshot = session.credential(&cx).await.unwrap();
        assert_eq!(snapshot.generation(), 1); assert_eq!(snapshot.scopes(), &["read".to_owned()]);
        let protocol = ClientProtocolPlan::http(ProtocolPolicy::ModernOnly, Some(peer.resource()), None, None,
            "cimd-principal".to_owned(), "private-test-ca".to_owned(), "native-http".to_owned(), 0, 0, 0).unwrap();
        let exercise = async {
            let mut client = ClientBuilder::new().protocol_plan(protocol)
                .http_bearer_credential(snapshot.credential().clone())
                .http_resource_root_certificate(peer.resource(), root()).unwrap()
                .connect_http_client_with_cx(&cx).await.unwrap();
            let result = client.list_tools(&cx, None).await.unwrap();
            let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = result else { panic!("expected final tools catalog"); };
            assert_eq!(result.payload.tools.len(), 1);
            assert_eq!(result.payload.tools[0].name, "listed-through-oauth");
        };
        pair(exercise, peer.protected_catalog()).await;
        session.close(); assert!(snapshot.credential().is_revoked());
        peer.no_more_requests(&cx).await;
    });
}

#[test]
fn selection_priority_changes_only_whether_the_single_registration_post_occurs() {
    for method in [NativeClientRegistrationMethod::Preregistered, NativeClientRegistrationMethod::MetadataDocument, NativeClientRegistrationMethod::DynamicRegistration] {
        run(async {
            let cx = Cx::current().unwrap(); let peer = Peer::new().await;
            let mut choice = NativeClientRegistrationChoice::new(peer.registration()).with_metadata_document(Peer::metadata()).unwrap();
            if method == NativeClientRegistrationMethod::Preregistered {
                choice = choice.with_preregistered_client_id("configured-client").unwrap();
            }
            let dcr = method == NativeClientRegistrationMethod::DynamicRegistration;
            let serving = async {
                peer.discovery(vec![peer.issuer_document(json!(!dcr))]).await;
                if dcr { peer.register(201, false).await; }
            };
            let (identity, ()) = pair(choice.resolve(&cx), serving).await;
            let identity = identity.unwrap(); assert_eq!(identity.registration_method(), method);
            let expected_id = match method {
                NativeClientRegistrationMethod::Preregistered => "configured-client",
                NativeClientRegistrationMethod::MetadataDocument => EXACT_CLIENT_ID,
                NativeClientRegistrationMethod::DynamicRegistration => "created-client",
            };
            assert_eq!(identity.client().client_id(), expected_id);
            let driver = peer.driver();
            let (session, ()) = pair(identity.authorize_managed_with_browser_driver(
                &cx, OAuthSessionPolicy::default(), Duration::from_secs(5), |url| driver.drive(&cx, url),
            ), peer.login(expected_id, true)).await;
            let session = session.unwrap(); assert!(session.credential(&cx).await.is_ok()); session.close();
            peer.no_more_requests(&cx).await;
        });
    }
}

#[test]
fn standalone_registration_uses_the_same_single_post_and_response_admission() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let serving = async {
            peer.discovery(vec![peer.issuer_document(json!(false))]).await;
            peer.register(201, false).await;
        };
        let (registered, ()) = pair(peer.registration().register(&cx), serving).await;
        assert_eq!(registered.unwrap().client_id(), "created-client");
        peer.no_more_requests(&cx).await;
    });
}

#[test]
fn cimd_only_refuses_unsupported_malformed_and_wrong_issuer_metadata_without_dcr() {
    for variant in [json!(false), Value::Null, json!("true"), json!(true)] {
        run(async {
            let cx = Cx::current().unwrap(); let peer = Peer::new().await;
            let mut body = peer.issuer_document(variant.clone());
            if variant == json!(true) { body["issuer"] = json!("https://wrong.example/tenant"); }
            let plan = peer.cimd();
            let (result, ()) = pair(plan.discover(&cx), peer.discovery(vec![body.clone(), body.clone(), body])).await;
            assert!(matches!(result, Err(MetadataDocumentError::Discovery(_))));
            peer.no_more_requests(&cx).await;
        });
    }
}

#[test]
fn dcr_rejection_and_changed_redirects_do_not_repeat_registration_or_start_login() {
    for (status, corrupt) in [(400, false), (201, true)] {
        run(async {
            let cx = Cx::current().unwrap(); let peer = Peer::new().await;
            let choice = NativeClientRegistrationChoice::new(peer.registration()).with_metadata_document(Peer::metadata()).unwrap();
            let serving = async {
                peer.discovery(vec![peer.issuer_document(json!(false))]).await;
                peer.register(status, corrupt).await;
            };
            let (result, ()) = pair(choice.resolve(&cx), serving).await;
            assert!(matches!(result, Err(NativeClientSelectionError::Registration(_))));
            peer.no_more_requests(&cx).await;
        });
    }
}

#[test]
fn login_refusal_keeps_the_selected_identity_without_fallback_registration() {
    run(async {
        let cx = Cx::current().unwrap(); let peer = Peer::new().await;
        let choice = NativeClientRegistrationChoice::new(peer.registration()).with_metadata_document(Peer::metadata()).unwrap();
        let (identity, ()) = pair(choice.resolve(&cx), peer.discovery(vec![peer.issuer_document(json!(true))])).await;
        let identity = identity.unwrap(); let driver = peer.driver();
        let (result, ()) = pair(identity.authorize_managed_with_browser_driver(
            &cx, OAuthSessionPolicy::default(), Duration::from_secs(5), |url| driver.drive(&cx, url),
        ), peer.login(EXACT_CLIENT_ID, false)).await;
        assert!(matches!(result, Err(OAuthSessionError::OAuth(OAuthError::TokenEndpointRejected))));
        assert_eq!(identity.registration_method(), NativeClientRegistrationMethod::MetadataDocument);
        assert_eq!(identity.client().client_id(), EXACT_CLIENT_ID);
        peer.no_more_requests(&cx).await;
    });
}
