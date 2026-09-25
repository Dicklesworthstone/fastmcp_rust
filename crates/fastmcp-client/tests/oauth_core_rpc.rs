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
use asupersync::tls::{
    Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream,
};
use fastmcp_client::http_auth::managed::{ManagedOAuthSession, OAuthSessionPolicy};
use fastmcp_client::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};
use fastmcp_client::http_auth::rpc::catalog::{
    CollectedCatalog, ManagedCatalogClient, ManagedCatalogError, ManagedCatalogLimits,
};
use fastmcp_client::http_auth::rpc::{ManagedCoreError, ManagedCoreEvent, ManagedCoreLimits};
use fastmcp_client::http_auth::tool::ManagedToolClient;
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    ClientCapabilities, CoreRequest, CoreResult, FinalCoreResult, FinalRequestMeta, FinalTool,
    RequestId, ServerNotification,
};
use serde_json::{Value, json};

#[path = "oauth_core_rpc/subscriptions.rs"]
mod subscriptions;

const CHILD_CASE: &str = "FASTMCP_TEST_OAUTH_CORE_CASE";
// TEST ONLY root, leaf, and key, also used by the native OAuth fixture. The
// root is never installed in the developer's or machine's permanent trust store.
// All three are inlined rather than read from `tests/fixtures/`: the remote
// build worker never receives `*.pem`, so `include_bytes!` made this whole
// target unbuildable there and it reported `0 passed` instead of failing.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";
const CATALOG: &str = r#"{"resultType":"complete","tools":[],"ttlMs":100,"cacheScope":"private","x-exact":{"z":900719925474099312345,"a":1.20e+4}}"#;
const TOOL_RESULT: &str =
    r#"{"resultType":"complete","content":[{"type":"text","text":"hello from TLS"}]}"#;
const CHANGED: &str = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
const PROGRESS: &str = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"work","progress":1}}"#;

// Two catalog pages for the collector cases. Every page carries `ttlMs` and
// `cacheScope` because `page_facts` requires cache hints on each page and
// rejects a page without them as InvalidPage -- a page omitting them would
// fail these tests for a reason unrelated to pagination.
const CATALOG_PAGE_ONE: &str = r#"{"resultType":"complete","ttlMs":60000,"cacheScope":"private","tools":[{"name":"alpha","inputSchema":{"type":"object"}}],"nextCursor":"opaque-cursor-1"}"#;
// The positive's second page ends the traversal. The negative's differs from
// it in EXACTLY ONE TOKEN -- the trailing `nextCursor` repeating page one's --
// which is the single planted variable and the only difference between the
// two cases anywhere in this file.
const CATALOG_PAGE_TWO_FINAL: &str = r#"{"resultType":"complete","ttlMs":60000,"cacheScope":"private","tools":[{"name":"beta","inputSchema":{"type":"object"}}]}"#;
const CATALOG_PAGE_TWO_REPEATS_CURSOR: &str = r#"{"resultType":"complete","ttlMs":60000,"cacheScope":"private","tools":[{"name":"beta","inputSchema":{"type":"object"}}],"nextCursor":"opaque-cursor-1"}"#;

#[derive(Clone, Copy)]
enum Case {
    Json,
    Sse,
    InvalidResponse,
    InputRequired,
    Cancel,
    Deadline,
    Preflight,
    HttpFailure,
    UntrustedResource,
    CatalogPages,
    CatalogRepeatedCursor,
    ToolHeadersReviewed,
    ToolHeadersUnreviewed,
}

fn isolated(name: &str, case: Case) {
    if let Ok(selected) = std::env::var(CHILD_CASE) {
        assert_eq!(
            selected, name,
            "the child must execute exactly the selected test"
        );
        run(case);
        return;
    }
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let roots = if matches!(case, Case::UntrustedResource) {
        // An existing non-PEM file supplies no roots; native-certs does not fall
        // back to platform trust when SSL_CERT_FILE is explicitly configured.
        manifest.join("Cargo.toml")
    } else {
        // Materialized from the inlined TEST ONLY root rather than read from
        // `tests/fixtures/`: the remote build worker never receives `*.pem`, so
        // pointing the child's trust store at a repository file made every
        // case here fail with "public TLS case ... failed" on that worker.
        let path = std::env::temp_dir().join(format!(
            "fastmcp-oauth-core-ca-{}.pem",
            name.replace("::", "_")
        ));
        std::fs::write(&path, ROOT)
            .expect("materialize the TEST ONLY root for the child trust store");
        path
    };
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD_CASE, name)
        .env("SSL_CERT_FILE", roots)
        .env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("launch isolated public transport test");
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
}

fn url(text: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(text).unwrap()
}

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
    input
        .split('&')
        .map(|field| {
            let (key, value) = field.split_once('=').unwrap();
            (decode_component(key), decode_component(value))
        })
        .collect()
}

async fn browser(authorization: CanonicalHttpUrl) -> Result<(), OAuthError> {
    let params = form(authorization.query().unwrap());
    assert_eq!(params["client_id"], "typed-client");
    assert_eq!(params["code_challenge_method"], "S256");
    let address: SocketAddr = params["redirect_uri"]
        .strip_prefix("http://")
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(address.ip().is_loopback());
    let request = format!(
        "GET /oauth/callback?code=typed-code&iss=https%3A%2F%2Fissuer.example&state={} HTTP/1.1\r\nHost: {address}\r\n\r\n",
        params["state"],
    );
    let mut socket = TcpStream::connect(address)
        .await
        .map_err(|_| OAuthError::CallbackRejected)?;
    socket
        .write_all(request.as_bytes())
        .await
        .map_err(|_| OAuthError::CallbackRejected)
}

fn core(method: &str, mut params: Value) -> CoreRequest {
    params["_meta"] =
        serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
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
                CertificateChain::from_pem(LEAF).unwrap(),
                PrivateKey::from_pem(KEY).unwrap(),
            )
            .alpn_protocols(vec![b"http/1.1".to_vec()])
            .build()
            .unwrap(),
            token_posts: AtomicUsize::new(0),
            mcp_posts: AtomicUsize::new(0),
        }
    }

    fn resource(&self) -> String {
        format!("https://{}/mcp", self.listener.local_addr().unwrap())
    }

    fn client(&self) -> OAuthClient {
        OAuthClient::new(
            OAuthClientConfiguration::from_trusted_endpoints(
                "https://issuer.example",
                url("https://issuer.example/authorize"),
                url(&format!(
                    "https://{}/token",
                    self.listener.local_addr().unwrap()
                )),
                url(&self.resource()),
                "typed-client",
                vec!["tools:read".to_owned()],
            )
            .unwrap()
            .with_extra_root_certificate(Certificate::from_pem(ROOT).unwrap().remove(0))
            .unwrap(),
        )
    }

    async fn request(&self, path: &str) -> (TlsStream<TcpStream>, Vec<u8>) {
        let (tls, body, _) = self.request_with_headers(path).await;
        (tls, body)
    }

    /// Also returns the received header block, names lowercased.
    async fn request_with_headers(
        &self,
        path: &str,
    ) -> (TlsStream<TcpStream>, Vec<u8>, BTreeMap<String, String>) {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut tls = self.acceptor.accept(socket).await.unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0; 2048];
        let end = loop {
            let count = tls.read(&mut buffer).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 16 * 1024);
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let head = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
        assert!(head.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
        let headers: BTreeMap<String, String> = head
            .lines()
            .skip(1)
            .filter_map(|line| {
                line.split_once(':')
                    .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
            })
            .collect();
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
            assert_eq!(
                envelope["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
                "2026-07-28"
            );
            if envelope["method"] == "tools/call" {
                assert_eq!(headers["mcp-name"], "echo");
            }
            self.mcp_posts.fetch_add(1, Ordering::SeqCst);
        }
        (tls, body, headers)
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
        assert!(
            self.listener.poll_accept(&mut task).is_pending(),
            "no automatic request/renewal replay"
        );
    }
}

async fn json_reply(tls: &mut TlsStream<TcpStream>, status: u16, body: &str) {
    let wire = format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(wire.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
}

async fn chunk(tls: &mut TlsStream<TcpStream>, payloads: &[String], terminal: bool) {
    let mut body = String::new();
    for payload in payloads {
        body.push_str(&format!("data: {payload}\n\n"));
    }
    let end = if terminal { "0\r\n\r\n" } else { "" };
    let wire = format!("{:X}\r\n{body}\r\n{end}", body.len());
    tls.write_all(wire.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
}

async fn begin_stream(peer: &Peer) -> TlsStream<TcpStream> {
    let (mut tls, _) = peer.request("/mcp").await;
    tls.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
    )
    .await
    .unwrap();
    chunk(&mut tls, &[CHANGED.to_owned()], false).await;
    tls
}

async fn first_changed(call: &mut fastmcp_client::http_auth::rpc::ManagedCoreCall, cx: &Cx) {
    let Some(ManagedCoreEvent::Notification(notification)) = call.next_event(cx).await.unwrap()
    else {
        panic!("incremental notification expected")
    };
    assert!(matches!(
        *notification,
        ServerNotification::ToolsListChanged(_)
    ));
}

/// Serves page one, then `second` for the cursor-bearing follow-up.
///
/// Both collector cases share this server verbatim; only `second` differs, so
/// the two tests are near-identical by construction rather than by review.
/// The follow-up assertions are the point of the positive: the second POST has
/// to carry the EXACT opaque cursor page one emitted, under a FRESH request id.
async fn two_page_catalog_peer(peer: &Peer, second: &'static str) {
    let (mut tls, first) = peer.request("/mcp").await;
    let first: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(first["method"], "tools/list");
    assert!(
        first["params"].get("cursor").is_none(),
        "the first page must be requested without a cursor"
    );
    let first_id = first["id"].as_i64().expect("numeric request id");
    json_reply(&mut tls, 200, &terminal(first_id, CATALOG_PAGE_ONE)).await;
    drop(tls);

    let (mut tls, follow) = peer.request("/mcp").await;
    let follow: Value = serde_json::from_slice(&follow).unwrap();
    assert_eq!(follow["method"], "tools/list");
    assert_eq!(
        follow["params"]["cursor"], "opaque-cursor-1",
        "the follow-up POST must carry the exact opaque cursor the peer emitted"
    );
    let follow_id = follow["id"].as_i64().expect("numeric request id");
    assert_ne!(
        follow_id, first_id,
        "the follow-up POST must use a fresh request id"
    );
    json_reply(&mut tls, 200, &terminal(follow_id, second)).await;
}

/// A cached collector over one login. `new` disables caching, so the cache
/// limits are what make the reuse half of the positive observable at all.
fn catalog_client(session: &ManagedOAuthSession) -> ManagedCatalogClient {
    let limits = ManagedCatalogLimits::new(ManagedCoreLimits::default(), 2, 100_000, 1024 * 1024)
        .expect("bounded two-page traversal limits are valid");
    ManagedCatalogClient::new(session.clone(), limits)
        .with_cache_limits(4, 64 * 1024)
        .expect("bounded cache limits are valid")
}

/// Monotonic request ids for a collection, so each page gets a fresh one.
fn fresh_ids(start: i64) -> impl FnMut() -> Result<RequestId, ManagedCatalogError> {
    let mut next = start;
    move || {
        let id = RequestId::Number(next);
        next += 1;
        Ok(id)
    }
}

fn catalog_tool_names(collected: &CollectedCatalog) -> String {
    collected
        .pages()
        .iter()
        .map(|page| page.encode().unwrap())
        .collect()
}

async fn complete_catalog(session: &ManagedOAuthSession, cx: &Cx, id: i64) {
    let mut call = session
        .request_core(
            cx,
            core("tools/list", json!({})),
            RequestId::Number(id),
            ManagedCoreLimits::default(),
        )
        .await
        .unwrap();
    let Some(ManagedCoreEvent::Result(result)) = call.next_event(cx).await.unwrap() else {
        panic!("typed catalog expected")
    };
    let encoded = result.encode().unwrap();
    assert!(encoded.contains("900719925474099312345"));
    assert!(encoded.contains("1.20e+4"));
    assert_eq!(call.credential_generation(), 1);
    assert!(call.next_event(cx).await.unwrap().is_none());
}

const HEADER_ARGUMENTS: &str = r#"{"text":"hello","region":"eu-west"}"#;

/// `region` carries an `x-mcp-header` annotation; `text` is body-only.
fn header_tool(session: &ManagedOAuthSession) -> ManagedToolClient {
    ManagedToolClient::new(
        session.clone(),
        FinalTool {
            name: "echo".to_owned(),
            title: None,
            description: None,
            icons: None,
            input_schema: json!({"type":"object", "properties":{
                "text":{"type":"string"},
                "region":{"type":"string","x-mcp-header":"Region"}
            }, "required":["text"]}),
            output_schema: None,
            annotations: None,
            meta: None,
        },
    )
    .expect("the annotated tool definition is admissible")
}

/// Runs one public tools/call through `client` against a peer that records
/// the received header block and JSON-RPC params. Both header cases call this
/// verbatim; only how `client` was built differs between them.
async fn header_tool_call(
    peer: &Peer,
    client: &ManagedToolClient,
    cx: &Cx,
) -> (BTreeMap<String, String>, Value) {
    let server = async {
        let (mut tls, body, headers) = peer.request_with_headers("/mcp").await;
        let envelope: Value = serde_json::from_slice(&body).unwrap();
        json_reply(&mut tls, 200, &terminal(51, TOOL_RESULT)).await;
        (headers, envelope["params"].clone())
    };
    let application = async {
        let arguments: Value = serde_json::from_str(HEADER_ARGUMENTS).unwrap();
        let request = core("tools/call", json!({"name":"echo","arguments":arguments}));
        let mut call = client
            .request(
                cx,
                request,
                RequestId::Number(51),
                ManagedCoreLimits::default(),
            )
            .await
            .expect("an admitted tool call dispatches");
        let Some(ManagedCoreEvent::Result(result)) = call.next_event(cx).await.unwrap() else {
            panic!("typed tool result expected")
        };
        assert!(result.encode().unwrap().contains("hello from TLS"));
        assert!(call.next_event(cx).await.unwrap().is_none());
    };
    let (observed, ()) = Box::pin(pair(server, application)).await;
    observed
}

fn parameter_header_names(headers: &BTreeMap<String, String>) -> Vec<&str> {
    headers
        .keys()
        .map(String::as_str)
        .filter(|name| name.starts_with("mcp-param-"))
        .collect()
}

fn run(case: Case) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let body = async {
            let peer = Peer::new().await;
            let ((), session) = Box::pin(pair(peer.login(), ManagedOAuthSession::authorize(
                &cx, peer.client(), OAuthSessionPolicy::default(), browser,
            ))).await;
            let session = session.unwrap();
            match case {
                Case::Json => { Box::pin(pair(peer.catalog(41), complete_catalog(&session, &cx, 41))).await; }
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
                    Box::pin(pair(server, application)).await;
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
                        Box::pin(pair(server, application)).await;
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
                    Box::pin(pair(server, application)).await;
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
                    Box::pin(pair(server, application)).await;
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 2);
                }
                Case::Preflight => {
                    let tiny = ManagedCoreLimits::new(1, 4096, 4096, 1, Duration::from_secs(2)).unwrap();
                    assert!(matches!(session.request_core(&cx, core("tools/list", json!({})), RequestId::Number(41), tiny).await, Err(ManagedCoreError::RequestTooLarge)));
                    peer.no_extra_connections();
                    Box::pin(pair(peer.catalog(42), complete_catalog(&session, &cx, 42))).await;
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 1);
                }
                Case::HttpFailure => {
                    for status in [401, 403, 500] {
                        let server = async {
                            let (mut tls, _) = peer.request("/mcp").await;
                            json_reply(&mut tls, status, "peer-error-canary").await;
                        };
                        let application = session.request_core(&cx, core("tools/list", json!({})), RequestId::Number(41), ManagedCoreLimits::default());
                        let ((), result) = Box::pin(pair(server, application)).await;
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
                    let ((), result) = Box::pin(pair(server, application)).await;
                    assert!(result.is_err());
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 0);
                }
                Case::CatalogPages => {
                    let client = catalog_client(&session);
                    let ((), collected) = Box::pin(pair(
                        two_page_catalog_peer(&peer, CATALOG_PAGE_TWO_FINAL),
                        client.collect(&cx, core("tools/list", json!({})), fresh_ids(61), |_| Ok(())),
                    )).await;
                    let collected = collected.expect("a complete two-page traversal must succeed");

                    // Complete output: BOTH pages, and both actual tools.
                    assert_eq!(collected.pages().len(), 2, "both pages must be retained, unmerged");
                    assert_eq!(collected.item_count(), 2);
                    let tools = catalog_tool_names(&collected);
                    assert!(tools.contains("alpha"), "page one's tool must survive the traversal");
                    assert!(tools.contains("beta"), "page two's tool must survive the traversal");
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 2, "exactly two authenticated POSTs");

                    // Cached repeat: identical tools and NOT ONE further POST.
                    // `fresh_ids` deliberately starts elsewhere -- a cache hit
                    // must not consume an id, and must not reach the peer even
                    // though the peer has nothing left to serve.
                    let again = Box::pin(client
                        .collect(&cx, core("tools/list", json!({})), fresh_ids(91), |_| Ok(())))
                        .await
                        .expect("the cached repeat must succeed without the peer");
                    assert_eq!(
                        catalog_tool_names(&again), tools,
                        "the cached repeat must return identical tools"
                    );
                    assert_eq!(
                        peer.mcp_posts.load(Ordering::SeqCst), 2,
                        "a cache hit must not issue a POST"
                    );
                }
                Case::ToolHeadersReviewed | Case::ToolHeadersUnreviewed => {
                    let client = if matches!(case, Case::ToolHeadersReviewed) {
                        header_tool(&session)
                            .review_headers(|binding| binding.header_name() == "Mcp-Param-Region")
                            .expect("the host approves the single annotated binding")
                    } else {
                        header_tool(&session)
                    };
                    let (headers, params) = header_tool_call(&peer, &client, &cx).await;
                    // The body is identical either way: disclosure mirrors a
                    // value into a header, it never moves or rewrites it.
                    assert_eq!(params["arguments"], serde_json::from_str::<Value>(HEADER_ARGUMENTS).unwrap());
                    assert!(!headers.values().any(|value| value.contains("hello")), "body-only text must never reach a header");
                    if matches!(case, Case::ToolHeadersReviewed) {
                        assert_eq!(parameter_header_names(&headers), vec!["mcp-param-region"]);
                        assert_eq!(headers["mcp-param-region"], "eu-west");
                    } else {
                        assert!(parameter_header_names(&headers).is_empty(), "unreviewed call disclosed {headers:?}");
                        assert!(!headers.values().any(|value| value.contains("eu-west")), "an annotation alone must not disclose");
                    }
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 1);
                }
                Case::CatalogRepeatedCursor => {
                    // Identical to Case::CatalogPages up to ONE token in the
                    // second page: its nextCursor repeats page one's instead
                    // of being absent.
                    let client = catalog_client(&session);
                    let ((), collected) = Box::pin(pair(
                        two_page_catalog_peer(&peer, CATALOG_PAGE_TWO_REPEATS_CURSOR),
                        client.collect(&cx, core("tools/list", json!({})), fresh_ids(61), |_| Ok(())),
                    )).await;

                    // Destructured rather than `expect_err`: CollectedCatalog
                    // does not implement Debug, so the Err-extracting helpers
                    // are unavailable here.
                    let Err(error) = collected else {
                        panic!("a present cursor cannot complete a two-page-bounded catalog");
                    };
                    assert!(
                        matches!(error, ManagedCatalogError::PageLimit),
                        "the refusal must be the typed PageLimit, got {error:?}"
                    );
                    // Cursor contents never decide termination. The configured
                    // page bound prevents preparing any third request.
                    assert_eq!(
                        peer.mcp_posts.load(Ordering::SeqCst), 2,
                        "exhausting the page budget must not issue a third POST"
                    );
                }
            }
            assert_eq!(peer.token_posts.load(Ordering::SeqCst), 1, "MCP failures never trigger a grant replay");
            peer.no_extra_connections();
            session.close();
        };
        Box::pin(asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), body))
            .await.expect("complete public OAuth/MCP case must settle within its bound");
    });
}

#[test]
fn managed_core_live_json_call_preserves_exact_results() {
    isolated(
        "managed_core_live_json_call_preserves_exact_results",
        Case::Json,
    );
}
#[test]
fn managed_core_live_sse_delivers_notifications_before_terminal() {
    isolated(
        "managed_core_live_sse_delivers_notifications_before_terminal",
        Case::Sse,
    );
}
#[test]
fn managed_core_bad_response_does_not_poison_sibling_calls() {
    isolated(
        "managed_core_bad_response_does_not_poison_sibling_calls",
        Case::InvalidResponse,
    );
}
#[test]
fn managed_core_input_required_does_not_repeat_the_post() {
    isolated(
        "managed_core_input_required_does_not_repeat_the_post",
        Case::InputRequired,
    );
}
#[test]
fn managed_core_idle_cancellation_closes_only_its_request() {
    isolated(
        "managed_core_idle_cancellation_closes_only_its_request",
        Case::Cancel,
    );
}
#[test]
fn managed_core_deadline_includes_time_between_event_reads() {
    isolated(
        "managed_core_deadline_includes_time_between_event_reads",
        Case::Deadline,
    );
}
#[test]
fn managed_core_oversized_request_is_rejected_before_dispatch() {
    isolated(
        "managed_core_oversized_request_is_rejected_before_dispatch",
        Case::Preflight,
    );
}
#[test]
fn managed_core_http_failures_never_replay_or_renew() {
    isolated(
        "managed_core_http_failures_never_replay_or_renew",
        Case::HttpFailure,
    );
}
#[test]
fn managed_core_resource_requires_its_own_tls_trust() {
    isolated(
        "managed_core_resource_requires_its_own_tls_trust",
        Case::UntrustedResource,
    );
}
#[test]
fn managed_catalog_collects_all_pages_and_reuses_cache() {
    isolated(
        "managed_catalog_collects_all_pages_and_reuses_cache",
        Case::CatalogPages,
    );
}
#[test]
fn managed_catalog_bounds_repeated_cursor_without_extra_post() {
    isolated(
        "managed_catalog_bounds_repeated_cursor_without_extra_post",
        Case::CatalogRepeatedCursor,
    );
}
#[test]
fn managed_tool_reviewed_parameter_header_reaches_the_wire() {
    isolated(
        "managed_tool_reviewed_parameter_header_reaches_the_wire",
        Case::ToolHeadersReviewed,
    );
}
#[test]
fn managed_tool_unreviewed_annotation_sends_no_parameter_header() {
    isolated(
        "managed_tool_unreviewed_annotation_sends_no_parameter_header",
        Case::ToolHeadersUnreviewed,
    );
}
