//! Public managed catalog traversal over real TLS and a real native OAuth login.
//!
//! The browser substitute returns the native loopback callback. Token redemption,
//! discovery, pagination, credential lifetime and connection disposal use shipped
//! APIs. No session internals, fixture credentials or disabled TLS checks are used.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder};
use fastmcp_client::http_auth::managed::client::{
    CatalogError, CatalogLimits, ManagedHttpClient, ManagedHttpClientError,
};
use fastmcp_client::http_auth::managed::{
    ManagedOAuthSession, OAuthSessionError, OAuthSessionPolicy,
};
use fastmcp_client::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};
use fastmcp_client::{ClientBuilder, ClientProtocolPlan, ProtocolPolicy};
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::FINAL_PROTOCOL_VERSION;
use serde_json::{Value, json};

// TEST ONLY: the existing OAuth fixture CA, valid 2020-2049. Inline because
// remote source transfer excludes PEM/key files. Trust is scoped to this peer.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";
type Stream = asupersync::tls::TlsStream<TcpStream>;

fn url(value: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(value).unwrap()
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
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(60_000_000_000), future)
                .await
                .expect("catalog TLS fixture must settle");
        });
}

fn pair<'a, L: Future + 'a, R: Future + 'a>(
    left: L,
    right: R,
) -> Pin<Box<dyn Future<Output = (L::Output, R::Output)> + 'a>> {
    Box::pin(async move {
        let mut left = std::pin::pin!(left);
        let mut right = std::pin::pin!(right);
        let (mut one, mut two) = (None, None);
        poll_fn(|task| {
            if one.is_none() {
                if let Poll::Ready(value) = left.as_mut().poll(task) {
                    one = Some(value);
                }
            }
            if two.is_none() {
                if let Poll::Ready(value) = right.as_mut().poll(task) {
                    two = Some(value);
                }
            }
            if one.is_some() && two.is_some() {
                Poll::Ready((one.take().unwrap(), two.take().unwrap()))
            } else {
                Poll::Pending
            }
        })
        .await
    })
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
    let mut output = Vec::new();
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
fn form(value: &str) -> BTreeMap<String, String> {
    let mut output = BTreeMap::new();
    for field in value.split('&') {
        let (key, value) = field.split_once('=').unwrap();
        assert!(output.insert(decode(key), decode(value)).is_none());
    }
    output
}
async fn callback(authorization: CanonicalHttpUrl, issuer: String) -> Result<(), OAuthError> {
    let fields = form(authorization.query().unwrap());
    assert_eq!(fields["code_challenge_method"], "S256");
    let redirect = url(&fields["redirect_uri"]);
    let authority = redirect
        .as_str()
        .strip_prefix("http://")
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .to_owned();
    let mut stream = TcpStream::connect(authority.clone())
        .await
        .map_err(|_| OAuthError::TransportFailed)?;
    stream.write_all(format!(
        "GET /oauth/callback?code=catalog-code&state={}&iss={} HTTP/1.1\r\nHost: {authority}\r\n\r\n",
        encode(&fields["state"]), encode(&issuer),
    ).as_bytes()).await.map_err(|_| OAuthError::TransportFailed)
}

async fn read(stream: &mut Stream) -> (String, BTreeMap<String, String>, Vec<u8>) {
    let mut wire = Vec::new();
    let mut buffer = [0; 2048];
    let end = loop {
        let count = stream.read(&mut buffer).await.unwrap();
        assert!(count > 0 && wire.len() + count <= 128 * 1024);
        wire.extend_from_slice(&buffer[..count]);
        if let Some(at) = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = std::str::from_utf8(&wire[..end]).unwrap();
    let mut lines = head.split("\r\n");
    let request: Vec<_> = lines.next().unwrap().split(' ').collect();
    assert_eq!(request[0], "POST");
    assert_eq!(request[2], "HTTP/1.1");
    let target = request[1].to_owned();
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').unwrap();
        assert!(
            headers
                .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                .is_none()
        );
    }
    for name in ["cookie", "referer"] {
        assert!(!headers.contains_key(name));
    }
    let length = headers["content-length"].parse::<usize>().unwrap();
    assert!(end + length <= 128 * 1024);
    while wire.len() < end + length {
        let count = stream.read(&mut buffer).await.unwrap();
        assert!(count > 0 && wire.len() + count <= 128 * 1024);
        wire.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(wire.len(), end + length);
    (target, headers, wire[end..].to_vec())
}
async fn reply(stream: &mut Stream, status: u16, body: Value) {
    let body = serde_json::to_vec(&body).unwrap();
    stream.write_all(format!(
        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len(),
    ).as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    stream.shutdown().await.unwrap();
}
async fn closed(stream: &mut Stream) {
    let mut byte = [0];
    assert!(
        !matches!(stream.read(&mut byte).await, Ok(count) if count > 0),
        "retired pagination must close its response socket, not send more bytes"
    );
}

struct Peer {
    listener: TcpListener,
    tls: TlsAcceptor,
}
impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            tls: TlsAcceptorBuilder::new(
                CertificateChain::from_pem(LEAF).unwrap(),
                PrivateKey::from_pem(KEY).unwrap(),
            )
            .alpn_protocols(vec![b"http/1.1".to_vec()])
            .build()
            .unwrap(),
        }
    }
    fn origin(&self) -> String {
        format!("https://{}", self.listener.local_addr().unwrap())
    }
    fn resource(&self) -> CanonicalHttpUrl {
        url(&format!("{}/mcp", self.origin()))
    }
    fn client(&self, session: ManagedOAuthSession, timeout: Duration) -> ManagedHttpClient {
        let builder = ClientBuilder::new()
            .protocol_plan(
                ClientProtocolPlan::http(
                    ProtocolPolicy::ModernOnly,
                    Some(self.resource()),
                    None,
                    None,
                    "catalog-owner".into(),
                    "catalog-trust".into(),
                    "native-http".into(),
                    0,
                    0,
                    0,
                )
                .unwrap(),
            )
            .http_resource_root_certificate(self.resource(), root())
            .unwrap();
        ManagedHttpClient::new(session, builder, timeout).unwrap()
    }
    async fn next(&self) -> (Stream, String, BTreeMap<String, String>, Vec<u8>) {
        let (tcp, _) = self.listener.accept().await.unwrap();
        let mut stream = self.tls.accept(tcp).await.unwrap();
        let (target, headers, body) = read(&mut stream).await;
        (stream, target, headers, body)
    }
    async fn login(&self, cx: &Cx) -> ManagedOAuthSession {
        let oauth = OAuthClient::new(
            OAuthClientConfiguration::from_trusted_endpoints(
                self.origin(),
                url(&format!("{}/authorize", self.origin())),
                url(&format!("{}/token", self.origin())),
                self.resource(),
                "native-client",
                vec!["read".to_owned()],
            )
            .unwrap()
            .with_extra_root_certificate(root())
            .unwrap(),
        );
        let (session, ()) = pair(
            ManagedOAuthSession::authorize(
                cx,
                oauth,
                OAuthSessionPolicy::default(),
                |authorization| callback(authorization, self.origin()),
            ),
            async {
                let (mut stream, target, headers, body) = self.next().await;
                assert_eq!(target, "/token");
                assert!(!headers.contains_key("authorization"));
                let fields = form(std::str::from_utf8(&body).unwrap());
                assert_eq!(fields["grant_type"], "authorization_code");
                assert_eq!(fields["code"], "catalog-code");
                assert_eq!(fields["code_verifier"].len(), 64);
                assert_eq!(fields["resource"], self.resource().as_str());
                assert_eq!(fields["client_id"], "native-client");
                reply(
                    &mut stream,
                    200,
                    json!({"access_token":"catalog-access", "token_type":"Bearer",
                    "expires_in":3600, "refresh_token":"catalog-refresh", "scope":"read"}),
                )
                .await;
            },
        )
        .await;
        session.unwrap()
    }
    async fn request(&self, method: &str) -> (Stream, Value) {
        let (stream, target, headers, body) = self.next().await;
        assert_eq!(target, "/mcp");
        assert_eq!(headers["authorization"], "Bearer catalog-access");
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["method"], method);
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            FINAL_PROTOCOL_VERSION
        );
        assert!(body.get("id").is_some());
        (stream, body)
    }
    async fn discovery(&self) {
        let (mut stream, body) = self.request("server/discover").await;
        reply(&mut stream, 200, json!({"jsonrpc":"2.0", "id":body["id"], "result":{
            "resultType":"complete", "supportedVersions":[FINAL_PROTOCOL_VERSION],
            "capabilities":{"tools":{}, "resources":{}, "prompts":{}},
            "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"catalog-peer","version":"1"}},
            "ttlMs":0, "cacheScope":"private"
        }})).await;
    }
    async fn page(
        &self,
        kind: Kind,
        cursor: Option<&str>,
        names: &[&str],
        next: Option<&str>,
    ) -> Value {
        let (mut stream, body) = self.request(kind.method()).await;
        assert_eq!(
            body["params"].get("cursor"),
            cursor.map(|value| json!(value)).as_ref()
        );
        reply(
            &mut stream,
            200,
            json!({"jsonrpc":"2.0", "id":body["id"],
            "result":kind.page(names, next)}),
        )
        .await;
        body["id"].clone()
    }
    async fn no_more(&self, cx: &Cx) {
        assert!(
            asupersync::time::timeout_at(
                cx.now().saturating_add_nanos(100_000_000),
                self.listener.accept(),
            )
            .await
            .is_err(),
            "unexpected refresh, discovery or page replay"
        );
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Tools,
    Resources,
    Templates,
    Prompts,
}
impl Kind {
    fn method(self) -> &'static str {
        match self {
            Self::Tools => "tools/list",
            Self::Resources => "resources/list",
            Self::Templates => "resources/templates/list",
            Self::Prompts => "prompts/list",
        }
    }
    fn page(self, names: &[&str], next: Option<&str>) -> Value {
        let mut value = json!({"resultType":"complete", "ttlMs":0, "cacheScope":"private"});
        let field = match self {
            Self::Tools => "tools",
            Self::Resources => "resources",
            Self::Templates => "resourceTemplates",
            Self::Prompts => "prompts",
        };
        value[field] = Value::Array(
            names
                .iter()
                .map(|name| match self {
                    Self::Tools => json!({"name":name, "inputSchema":{"type":"object"}}),
                    Self::Resources => json!({"name":name, "uri":format!("note:///{name}")}),
                    Self::Templates => {
                        json!({"name":name, "uriTemplate":format!("note:///{name}/{{id}}")})
                    }
                    Self::Prompts => json!({"name":name}),
                })
                .collect(),
        );
        if let Some(next) = next {
            value["nextCursor"] = json!(next);
        }
        value
    }
    async fn all(
        self,
        client: &mut ManagedHttpClient,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        limits: CatalogLimits,
    ) -> Result<(Vec<String>, usize), ManagedHttpClientError> {
        match self {
            Self::Tools => {
                let result = client
                    .list_all_tools_with_cancellation(cx, cancellation, limits)
                    .await?;
                Ok((
                    result
                        .entries()
                        .iter()
                        .map(|entry| entry.name.clone())
                        .collect(),
                    result.page_count(),
                ))
            }
            Self::Resources => {
                let result = client
                    .list_all_resources_with_cancellation(cx, cancellation, limits)
                    .await?;
                Ok((
                    result
                        .entries()
                        .iter()
                        .map(|entry| entry.name.clone())
                        .collect(),
                    result.page_count(),
                ))
            }
            Self::Templates => {
                let result = client
                    .list_all_resource_templates_with_cancellation(cx, cancellation, limits)
                    .await?;
                Ok((
                    result
                        .entries()
                        .iter()
                        .map(|entry| entry.name.clone())
                        .collect(),
                    result.page_count(),
                ))
            }
            Self::Prompts => {
                let result = client
                    .list_all_prompts_with_cancellation(cx, cancellation, limits)
                    .await?;
                Ok((
                    result
                        .entries()
                        .iter()
                        .map(|entry| entry.name.clone())
                        .collect(),
                    result.page_count(),
                ))
            }
        }
    }
}

#[test]
fn all_four_catalogs_follow_opaque_cursors_and_preserve_page_order() {
    for kind in [Kind::Tools, Kind::Resources, Kind::Templates, Kind::Prompts] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session.clone(), Duration::from_secs(30));
            let cancellation = McpRequestCancellation::new();
            let (result, ()) = pair(
                kind.all(&mut client, &cx, &cancellation, CatalogLimits::default()),
                async {
                    peer.discovery().await;
                    let first = peer.page(kind, None, &["first"], Some("")).await;
                    let second = peer.page(kind, Some(""), &[], Some("")).await;
                    let third = peer
                        .page(kind, Some(""), &["first"], Some("opaque-雪%2F"))
                        .await;
                    let fourth = peer
                        .page(kind, Some("opaque-雪%2F"), &[], Some("opaque-雪%2F"))
                        .await;
                    let fifth = peer
                        .page(kind, Some("opaque-雪%2F"), &["second"], None)
                        .await;
                    let ids = [first, second, third, fourth, fifth];
                    for (index, id) in ids.iter().enumerate() {
                        assert!(ids[..index].iter().all(|previous| previous != id));
                    }
                },
            )
            .await;
            assert_eq!(
                result.unwrap(),
                (vec!["first".into(), "first".into(), "second".into()], 5)
            );
            assert_eq!(client.cached_credential_generation(), Some(1));
            assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
            assert!(!cancellation.is_cancel_requested());
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn limits_never_publish_or_replay_a_partial_catalog() {
    for failure in [
        CatalogError::PageLimit,
        CatalogError::EntryLimit,
        CatalogError::ByteLimit,
    ] {
        for reject in [false, true] {
            run(async {
                let cx = Cx::current().unwrap();
                let peer = Peer::new().await;
                let session = peer.login(&cx).await;
                let mut client = peer.client(session.clone(), Duration::from_secs(30));
                let limits = CatalogLimits::new(
                    if reject && failure == CatalogError::PageLimit {
                        1
                    } else {
                        3
                    },
                    if reject && failure == CatalogError::EntryLimit {
                        1
                    } else {
                        2
                    },
                    if reject && failure == CatalogError::ByteLimit {
                        1
                    } else {
                        4096
                    },
                )
                .unwrap();
                let (result, ()) = pair(client.list_all_tools(&cx, limits), async {
                    peer.discovery().await;
                    peer.page(Kind::Tools, None, &["first"], Some("next")).await;
                    if !(reject
                        && matches!(failure, CatalogError::PageLimit | CatalogError::ByteLimit))
                    {
                        peer.page(Kind::Tools, Some("next"), &["second"], None)
                            .await;
                    }
                })
                .await;
                if reject {
                    assert!(
                        matches!(result, Err(ManagedHttpClientError::Catalog(error)) if error == failure)
                    );
                    assert_eq!(client.cached_credential_generation(), None);
                } else {
                    let result = result.unwrap();
                    assert_eq!(result.entries().len(), 2);
                    assert_eq!(result.page_count(), 2);
                    assert_eq!(client.cached_credential_generation(), Some(1));
                }
                assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
                peer.no_more(&cx).await;
            });
        }
    }
}

#[test]
fn repeated_tokens_terminate_only_on_absence_or_the_unchanged_page_budget() {
    for kind in [Kind::Tools, Kind::Resources, Kind::Templates, Kind::Prompts] {
        for cursor in ["", "opaque-雪%2F", " \t\"\\\n "] {
            for terminal in [false, true] {
                run(async {
                    let cx = Cx::current().unwrap();
                    let peer = Peer::new().await;
                    let session = peer.login(&cx).await;
                    let mut client = peer.client(session.clone(), Duration::from_secs(30));
                    let cancellation = McpRequestCancellation::new();
                    let limits = CatalogLimits::new(3, 4, 4096).unwrap();
                    let (outcome, ()) = pair(
                        kind.all(&mut client, &cx, &cancellation, limits),
                        async {
                            peer.discovery().await;
                            let first = peer.page(kind, None, &["first"], Some(cursor)).await;
                            let second = peer.page(kind, Some(cursor), &[], Some(cursor)).await;
                            let third = peer
                                .page(
                                    kind,
                                    Some(cursor),
                                    &["second"],
                                    if terminal { None } else { Some(cursor) },
                                )
                                .await;
                            assert_ne!(first, second);
                            assert_ne!(first, third);
                            assert_ne!(second, third);
                        },
                    )
                    .await;
                    if terminal {
                        assert_eq!(outcome.unwrap(), (vec!["first".into(), "second".into()], 3));
                        assert_eq!(client.cached_credential_generation(), Some(1));
                    } else {
                        assert!(matches!(
                            outcome,
                            Err(ManagedHttpClientError::Catalog(CatalogError::PageLimit))
                        ));
                        assert_eq!(client.cached_credential_generation(), None);
                    }
                    // A repeated token is neither a request to refresh nor
                    // permission to exceed the cap or leak a partial result.
                    assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
                    assert!(!cancellation.is_cancel_requested());
                    peer.no_more(&cx).await;
                });
            }
        }
    }
}

#[test]
fn stalled_page_observes_cancellation_logout_and_token_revocation() {
    for transition in 0..4 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let snapshot = session.credential(&cx).await.unwrap();
            let mut client = peer.client(session.clone(), Duration::from_secs(30));
            let cancellation = McpRequestCancellation::new();
            let (result, ()) = pair(
                client.list_all_tools_with_cancellation(
                    &cx,
                    &cancellation,
                    CatalogLimits::default(),
                ),
                async {
                    peer.discovery().await;
                    peer.page(Kind::Tools, None, &["first"], Some("next")).await;
                    let (mut stream, request) = peer.request("tools/list").await;
                    assert_eq!(request["params"]["cursor"], "next");
                    match transition {
                        0 => {
                            reply(
                                &mut stream,
                                200,
                                json!({"jsonrpc":"2.0", "id":request["id"],
                            "result":Kind::Tools.page(&["second"], None)}),
                            )
                            .await;
                        }
                        1 => {
                            cancellation.cancel();
                        }
                        2 => session.close(),
                        _ => snapshot.credential().revoke(),
                    }
                    if transition != 0 {
                        closed(&mut stream).await;
                    }
                },
            )
            .await;
            match (transition, result) {
                (0, Ok(result)) => assert_eq!(result.entries().len(), 2),
                (1, Err(ManagedHttpClientError::Session(OAuthSessionError::Cancelled)))
                | (2, Err(ManagedHttpClientError::Session(OAuthSessionError::Closed)))
                | (3, Err(ManagedHttpClientError::Session(OAuthSessionError::LoginRequired))) => {
                    assert_eq!(client.cached_credential_generation(), None);
                }
                (_, result) => panic!("unexpected lifetime disposition: {result:?}"),
            }
            assert!(cx.checkpoint().is_ok());
            if transition <= 1 {
                assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
            }
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn abandoning_a_partial_traversal_releases_the_socket_without_logging_out() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session.clone(), Duration::from_secs(30));
        let reached = McpRequestCancellation::new();
        let ((), ()) = pair(
            async {
                let mut operation = Box::pin(client.list_all_tools(&cx, CatalogLimits::default()));
                let mut reached = std::pin::pin!(reached.cancelled());
                poll_fn(|task| {
                    assert!(operation.as_mut().poll(task).is_pending());
                    reached.as_mut().poll(task)
                })
                .await;
                drop(operation);
            },
            async {
                peer.discovery().await;
                peer.page(Kind::Tools, None, &["first"], Some("next")).await;
                let (mut stream, request) = peer.request("tools/list").await;
                assert_eq!(request["params"]["cursor"], "next");
                reached.cancel();
                closed(&mut stream).await;
            },
        )
        .await;
        assert_eq!(client.cached_credential_generation(), None);
        assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        peer.no_more(&cx).await;
        let (result, ()) = pair(
            client.list_all_tools(&cx, CatalogLimits::default()),
            async {
                peer.discovery().await;
                peer.page(Kind::Tools, None, &["fresh"], None).await;
            },
        )
        .await;
        assert_eq!(result.unwrap().entries()[0].name, "fresh");
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn quiet_second_page_is_bounded_by_the_managed_operation_deadline() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session.clone(), Duration::from_secs(2));
        let (result, ()) = pair(
            client.list_all_tools(&cx, CatalogLimits::default()),
            async {
                peer.discovery().await;
                peer.page(Kind::Tools, None, &["first"], Some("next")).await;
                let (mut stream, request) = peer.request("tools/list").await;
                assert_eq!(request["params"]["cursor"], "next");
                closed(&mut stream).await;
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(ManagedHttpClientError::Session(OAuthSessionError::TimedOut))
        ));
        assert_eq!(client.cached_credential_generation(), None);
        assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        assert!(cx.checkpoint().is_ok());
        peer.no_more(&cx).await;
    });
}

#[test]
fn a_failed_second_page_is_not_success_or_permission_to_retry() {
    for http_error in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session.clone(), Duration::from_secs(30));
            let (result, ()) =
                pair(
                    client.list_all_tools(&cx, CatalogLimits::default()),
                    async {
                        peer.discovery().await;
                        peer.page(Kind::Tools, None, &["first"], Some("private-next"))
                            .await;
                        let (mut stream, request) = peer.request("tools/list").await;
                        assert_eq!(request["params"]["cursor"], "private-next");
                        reply(&mut stream, if http_error { 401 } else { 200 }, json!({
                    "jsonrpc":"2.0", "id":request["id"], "error":{
                        "code":-32603, "message":"private-diagnostic", "data":"private-next"
                    }
                })).await;
                    },
                )
                .await;
            let error = result.unwrap_err();
            assert!(matches!(error, ManagedHttpClientError::Request { .. }));
            assert!(!format!("{error:?} {error}").contains("private-"));
            assert_eq!(client.cached_credential_generation(), None);
            peer.no_more(&cx).await;
            // An explicit new operation is permitted, but must discover again.
            let (result, ()) = pair(
                client.list_all_tools(&cx, CatalogLimits::default()),
                async {
                    peer.discovery().await;
                    peer.page(Kind::Tools, None, &["fresh"], None).await;
                },
            )
            .await;
            assert_eq!(result.unwrap().entries()[0].name, "fresh");
            assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        });
    }
}
