//! Actual managed OAuth and verified TLS for explicit, one-shot header repair.
//! The peer scripts a configured pre-dispatch rejection contract; these tests
//! exercise client wire/ownership behavior, not server-side contract enforcement.
//! Run the complete target with native-tls-roots through the project batch lane.
#![cfg(feature = "native-tls-roots")]

use std::collections::{BTreeMap, VecDeque};
use std::future::{Future, poll_fn};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Mutex, atomic::{AtomicUsize, Ordering}};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream};
use fastmcp_client::http_auth::managed::{ManagedOAuthSession, OAuthSessionPolicy};
use fastmcp_client::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};
use fastmcp_client::http_auth::rpc::{ManagedCoreError, ManagedCoreEvent, ManagedCoreLimits};
use fastmcp_client::http_auth::rpc::catalog::ManagedCatalogError;
use fastmcp_client::http_auth::rpc::tool_headers::repair::{
    ToolHeaderRepairContract, ToolHeaderRepairError, ToolHeaderRepairLimits, ToolHeaderRepairOutcome,
};
use fastmcp_client::http_executor::parameter_headers::{ReviewedToolHeaders, ToolHeaderDispatchError};
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::{ClientCapabilities, CoreRequest, FinalRequestMeta, FinalTool, RequestId};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use serde_json::{Value, json};

const CHILD: &str = "FASTMCP_TEST_TOOL_HEADER_REPAIR";
// TEST ONLY: the existing OAuth fixture's localhost identity. Trust is isolated
// in each child process; no machine root store or insecure verifier is changed.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

#[derive(Clone, Copy, Debug)]
enum Case {
    Repair, Fresh, DropRejection, CancelBeforeRefresh, DefinitionDenied, HeaderDenied,
    CancelDefinition, ReusedListId, ReusedRetryId, DuplicateTool, MissingTool,
    WrongProjection, SecondRejection, WrongId, WrongCode, Opaque, Status200, Truncated, LostHead,
}

fn isolated(name: &str, case: Case) {
    if let Ok(selected) = std::env::var(CHILD) {
        assert_eq!(selected, name);
        run(case);
        return;
    }
    struct Root(std::path::PathBuf);
    impl Drop for Root { fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); } }
    struct Child(std::process::Child);
    impl Drop for Child { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    let root = Root(std::env::temp_dir().join(format!("fastmcp-header-repair-{}-{name}.pem", std::process::id())));
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&root.0).unwrap();
    file.write_all(ROOT).unwrap();
    drop(file);
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name).env("SSL_CERT_FILE", &root.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() { assert!(status.success(), "{case:?}"); return; }
        assert!(Instant::now() < deadline, "header repair child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn run(case: Case) {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(20), Box::pin(scenario(&cx, case)))
                .await.expect("bounded header repair exchange");
        });
}

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = Box::pin(left);
    let mut right = Box::pin(right);
    let (mut one, mut two) = (None, None);
    poll_fn(|cx| {
        if one.is_none() && let Poll::Ready(value) = left.as_mut().poll(cx) { one = Some(value); }
        if two.is_none() && let Poll::Ready(value) = right.as_mut().poll(cx) { two = Some(value); }
        if one.is_some() && two.is_some() { Poll::Ready((one.take().unwrap(), two.take().unwrap())) }
        else { Poll::Pending }
    }).await
}

fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }
fn form(value: &str) -> BTreeMap<String, String> {
    fn decode(value: &str) -> String {
        let mut out = Vec::new();
        let mut bytes = value.bytes();
        while let Some(byte) = bytes.next() {
            out.push(match byte {
                b'+' => b' ',
                b'%' => {
                    let high = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                    let low = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                    (high * 16 + low) as u8
                }
                byte => byte,
            });
        }
        String::from_utf8(out).unwrap()
    }
    value.split('&').map(|part| {
        let (key, value) = part.split_once('=').unwrap();
        (decode(key), decode(value))
    }).collect()
}

async fn browser(authorization: CanonicalHttpUrl) -> Result<(), OAuthError> {
    let fields = form(authorization.query().unwrap());
    assert_eq!(fields["client_id"], "header-repair-client");
    assert_eq!(fields["code_challenge_method"], "S256");
    let address: std::net::SocketAddr = fields["redirect_uri"].strip_prefix("http://").unwrap()
        .split('/').next().unwrap().parse().unwrap();
    assert!(address.ip().is_loopback());
    let mut socket = TcpStream::connect(address).await.map_err(|_| OAuthError::CallbackRejected)?;
    socket.write_all(format!("GET /oauth/callback?code=repair-code&iss=https%3A%2F%2Fissuer.example&state={} HTTP/1.1\r\nHost: {address}\r\n\r\n", fields["state"]).as_bytes())
        .await.map_err(|_| OAuthError::CallbackRejected)
}

struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    grants: AtomicUsize,
    requests: Mutex<Vec<Value>>,
}

impl Peer {
    async fn new() -> Self {
        Self { listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            acceptor: TlsAcceptorBuilder::new(CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap())
                .alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap(),
            grants: AtomicUsize::new(0), requests: Mutex::new(Vec::new()) }
    }
    fn resource(&self) -> CanonicalHttpUrl { url(&format!("https://{}/mcp", self.listener.local_addr().unwrap())) }
    fn client(&self) -> OAuthClient {
        OAuthClient::new(OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example", url("https://issuer.example/authorize"),
            url(&format!("https://{}/token", self.listener.local_addr().unwrap())),
            self.resource(), "header-repair-client", vec!["tools:call".to_owned()],
        ).unwrap().with_extra_root_certificate(Certificate::from_pem(ROOT).unwrap().remove(0)).unwrap())
    }
    async fn receive(&self, path: &str) -> (TlsStream<TcpStream>, BTreeMap<String, String>, Vec<u8>) {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut socket = self.acceptor.accept(socket).await.unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0; 2048];
        let end = loop {
            let count = socket.read(&mut buffer).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 16 * 1024);
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(at) = bytes.windows(4).position(|part| part == b"\r\n\r\n") { break at + 4; }
        };
        let head = std::str::from_utf8(&bytes[..end]).unwrap();
        assert_eq!(head.lines().next().unwrap(), format!("POST {path} HTTP/1.1"));
        let mut headers = BTreeMap::new();
        for line in head.lines().skip(1).filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').unwrap();
            assert!(headers.insert(name.to_ascii_lowercase(), value.trim().to_owned()).is_none());
        }
        assert!(!headers.contains_key("transfer-encoding"));
        let length: usize = headers["content-length"].parse().unwrap();
        assert!(end + length <= 16 * 1024);
        while bytes.len() < end + length {
            let count = socket.read(&mut buffer).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 16 * 1024);
            bytes.extend_from_slice(&buffer[..count]);
        }
        assert_eq!(bytes.len(), end + length);
        (socket, headers, bytes[end..].to_vec())
    }
    async fn login(&self) {
        let (mut socket, headers, body) = self.receive("/token").await;
        assert!(!headers.contains_key("authorization"));
        let fields = form(std::str::from_utf8(&body).unwrap());
        assert_eq!(fields["resource"], self.resource().as_str());
        assert_eq!(fields["grant_type"], "authorization_code");
        assert_eq!(fields["client_id"], "header-repair-client");
        assert_eq!(fields["code"], "repair-code");
        self.grants.fetch_add(1, Ordering::SeqCst);
        reply(&mut socket, 200, "application/json",
            r#"{"access_token":"repair-access","token_type":"Bearer","expires_in":300}"#, false).await;
    }
    async fn rpc(&self, method: &str, id: i64, parameter: Option<&str>) -> (TlsStream<TcpStream>, Value) {
        let (socket, headers, body) = self.receive("/mcp").await;
        assert_eq!(headers["authorization"], "Bearer repair-access");
        assert_eq!(headers["mcp-protocol-version"], "2026-07-28");
        assert_eq!(headers["mcp-method"], method);
        for forbidden in ["mcp-session-id", "last-event-id", "cookie"] { assert!(!headers.contains_key(forbidden)); }
        let fields: Vec<_> = headers.iter().filter(|(key, _)| key.starts_with("mcp-param-")).collect();
        match parameter {
            Some(parameter) => {
                assert_eq!(headers["mcp-name"], "lookup");
                assert_eq!(fields.len(), 1, "null and private values must not acquire mirrors");
                assert_eq!(fields[0].0, parameter);
                assert_eq!(fastmcp_protocol::http_headers::decode_mcp_header_value(fields[0].1.as_bytes()).unwrap(), "雪");
            }
            None => assert!(fields.is_empty()),
        }
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["id"], id);
        assert_eq!(value["method"], method);
        let mut requests = self.requests.lock().unwrap();
        assert!(requests.iter().all(|previous| previous["id"] != value["id"]));
        requests.push(value.clone());
        (socket, value)
    }
    fn quiet(&self) {
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(self.listener.poll_accept(&mut task).is_pending(), "no implicit retry or refresh");
    }
    async fn first(&self, case: Case) {
        let (mut socket, _) = self.rpc("tools/call", 10, Some("mcp-param-old")).await;
        if matches!(case, Case::LostHead) { let _ = socket.shutdown().await; return; }
        let body = if matches!(case, Case::Fresh) { complete(10) }
            else { error(if matches!(case, Case::WrongId) { 999 } else { 10 },
                if matches!(case, Case::WrongCode) { -32602 } else { -32020 }) };
        let status = if matches!(case, Case::Fresh | Case::Status200) { 200 } else { 400 };
        let content_type = if matches!(case, Case::Opaque) { "text/plain" } else { "application/json" };
        reply(&mut socket, status, content_type, &body, matches!(case, Case::Truncated)).await;
    }
    async fn refresh(&self, case: Case) {
        for index in 0..2 {
            let (mut socket, request) = self.rpc("tools/list", 11 + index, None).await;
            assert_eq!(request["params"]["_meta"], json!({
                "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientCapabilities":{}
            }));
            assert!(request["params"].get("arguments").is_none());
            if index == 0 { assert!(request["params"].get("cursor").is_none()); }
            else { assert_eq!(request["params"]["cursor"], "page-two"); }
            let name = if matches!(case, Case::MissingTool) {
                if index == 0 { "other-one" } else { "other-two" }
            } else if index == 0 || matches!(case, Case::DuplicateTool) { "lookup" } else { "other" };
            let mut definition = definition(name, "Fresh");
            if matches!(case, Case::WrongProjection) { definition.input_schema["properties"]["region"]["type"] = json!("integer"); }
            let mut result = json!({"resultType":"complete","tools":[definition],"ttlMs":0,"cacheScope":"private"});
            if index == 0 { result["nextCursor"] = json!("page-two"); }
            reply(&mut socket, 200, "application/json", &json!({"jsonrpc":"2.0","id":11+index,"result":result}).to_string(), false).await;
        }
        if matches!(case, Case::Repair | Case::SecondRejection) {
            let (mut socket, _) = self.rpc("tools/call", 13, Some("mcp-param-fresh")).await;
            let (status, body) = if matches!(case, Case::SecondRejection) { (400, error(13, -32020)) }
                else { (200, complete(13)) };
            reply(&mut socket, status, "application/json", &body, false).await;
        }
    }
    async fn sibling(&self) {
        let (mut socket, _) = self.rpc("tools/list", 900, None).await;
        reply(&mut socket, 200, "application/json", &json!({"jsonrpc":"2.0","id":900,"result":{
            "resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"
        }}).to_string(), false).await;
    }
}

async fn reply(socket: &mut TlsStream<TcpStream>, status: u16, kind: &str, body: &str, truncate: bool) {
    let head = format!("HTTP/1.1 {status} Reply\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    // Send the tiny head/body in one TLS write. Head-only refusal may otherwise
    // close the socket between our two fixture writes rather than fail a test
    // for any defect in the client. Truncation still advertises the full size.
    let payload = if truncate { &body.as_bytes()[..1] } else { body.as_bytes() };
    let wire = [head.as_bytes(), payload].concat();
    socket.write_all(&wire).await.unwrap();
    socket.flush().await.unwrap();
    let _ = socket.shutdown().await;
}
fn definition(name: &str, field: &str) -> FinalTool {
    serde_json::from_value(json!({"name":name,"inputSchema":{"type":"object","properties":{
        "region":{"type":"string","x-mcp-header":field},
        "verbose":{"type":"boolean","x-mcp-header":"Verbose"}
    }}})).unwrap()
}
fn core(method: &str, mut params: Value) -> CoreRequest {
    params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    params["_meta"]["com.example/private-observation"] = json!({"source":"original-call-only"});
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
}
fn complete(id: i64) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{"resultType":"complete","content":[],"x-exact":1.20e+4}}}}"#)
}
fn error(id: i64, code: i64) -> String {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":"private-peer-canary"}}).to_string()
}

async fn scenario(cx: &Cx, case: Case) {
    let peer = Peer::new().await;
    let ((), session) = pair(peer.login(), ManagedOAuthSession::authorize(cx, peer.client(), OAuthSessionPolicy::default(), browser)).await;
    let session = session.unwrap();
    let cancelled = McpRequestCancellation::new();
    let request = core("tools/call", json!({"name":"lookup","arguments":{"region":"雪","verbose":null,"private":"body-only"}}));
    let original = request.encode_params().unwrap().unwrap();
    let reviewed = ReviewedToolHeaders::new(peer.resource(), "lookup", definition("lookup", "Old").input_schema, |_| true).unwrap();
    let limits = ToolHeaderRepairLimits::new(
        ManagedCoreLimits::new(4096, 4096, 65536, 0, Duration::from_secs(10)).unwrap(), 16384, 4, 8,
    ).unwrap();
    let ((), outcome) = pair(peer.first(case), session.request_tool_with_header_repair_and_cancellation(
        cx, &cancelled, request, RequestId::Number(10), &reviewed,
        ToolHeaderRepairContract::for_configured_endpoint(peer.resource()).unwrap(), limits,
    )).await;
    peer.quiet();
    assert_eq!(peer.requests.lock().unwrap().len(), 1, "repair must wait for an explicit host decision");
    let mut expected_posts = 1;
    match outcome {
        Ok(ToolHeaderRepairOutcome::Call(mut call)) => {
            match case {
                Case::Fresh => {
                    let Some(ManagedCoreEvent::Result(result)) = call.next_event(cx).await.unwrap() else { panic!("complete result"); };
                    assert!(result.encode().unwrap().contains("1.20e+4"));
                }
                Case::Status200 => assert!(matches!(call.next_event(cx).await, Err(ManagedCoreError::Remote { .. }))),
                _ => panic!("unexpected successful HTTP head: {case:?}"),
            }
        }
        Err(error) => {
            assert!(matches!(case, Case::WrongId | Case::WrongCode | Case::Opaque | Case::Truncated | Case::LostHead));
            assert!(!format!("{error:?} {error}").contains("private-peer-canary"));
        }
        Ok(ToolHeaderRepairOutcome::Rejected(rejected)) => {
            if matches!(case, Case::DropRejection) { drop(rejected); }
            else {
                if matches!(case, Case::CancelBeforeRefresh) { cancelled.cancel(); }
                let no_catalog = matches!(case, Case::CancelBeforeRefresh | Case::ReusedListId);
                let mut ids = VecDeque::from(if matches!(case, Case::ReusedListId) { vec![10] }
                    else if matches!(case, Case::ReusedRetryId) { vec![11, 12, 10] } else { vec![11, 12, 13] });
                let approvals = AtomicUsize::new(0);
                let headers = AtomicUsize::new(0);
                let server = async { if !no_catalog { peer.refresh(case).await; } };
                let retry = rejected.refresh_and_retry(cx,
                    || Ok(RequestId::Number(ids.pop_front().expect("no third attempt or extra page"))),
                    |definition| {
                        assert_eq!(peer.requests.lock().unwrap().len(), 3, "approve only a fully traversed catalog");
                        assert_eq!(definition.name, "lookup");
                        approvals.fetch_add(1, Ordering::SeqCst);
                        if matches!(case, Case::CancelDefinition) { cancelled.cancel(); }
                        !matches!(case, Case::DefinitionDenied)
                    },
                    |binding| {
                        assert!(matches!(binding.header_name(), "Mcp-Param-Fresh" | "Mcp-Param-Verbose"));
                        headers.fetch_add(1, Ordering::SeqCst);
                        !matches!(case, Case::HeaderDenied)
                    },
                );
                let ((), result) = pair(server, retry).await;
                expected_posts += if no_catalog { 0 } else { 2 };
                match case {
                    Case::Repair => {
                        expected_posts += 1;
                        let mut call = result.unwrap();
                        let Some(ManagedCoreEvent::Result(result)) = call.next_event(cx).await.unwrap() else { panic!("repaired result"); };
                        assert!(result.encode().unwrap().contains("1.20e+4"));
                        assert!(call.next_event(cx).await.unwrap().is_none());
                        assert_eq!(approvals.load(Ordering::SeqCst), 1);
                        assert_eq!(headers.load(Ordering::SeqCst), 2);
                    }
                    Case::SecondRejection => {
                        expected_posts += 1;
                        assert!(matches!(result, Err(ToolHeaderRepairError::Core(ManagedCoreError::HttpStatus { status: 400 }))));
                    }
                    Case::DefinitionDenied => {
                        assert!(matches!(result, Err(ToolHeaderRepairError::DefinitionDeclined)));
                        assert_eq!(headers.load(Ordering::SeqCst), 0);
                    }
                    Case::HeaderDenied => {
                        assert!(matches!(result, Err(ToolHeaderRepairError::Headers(ToolHeaderDispatchError::DisclosureDenied))));
                        assert_eq!(headers.load(Ordering::SeqCst), 1);
                    }
                    Case::CancelDefinition | Case::CancelBeforeRefresh => {
                        assert!(matches!(result, Err(ToolHeaderRepairError::Core(ManagedCoreError::Cancelled))));
                        assert_eq!(headers.load(Ordering::SeqCst), 0);
                    }
                    Case::ReusedListId | Case::ReusedRetryId => assert!(matches!(result,
                        Err(ToolHeaderRepairError::Catalog(ManagedCatalogError::RepeatedRequestId)))),
                    Case::DuplicateTool => assert!(matches!(result, Err(ToolHeaderRepairError::DuplicateTool))),
                    Case::MissingTool => assert!(matches!(result, Err(ToolHeaderRepairError::ToolUnavailable))),
                    Case::WrongProjection => assert!(matches!(result, Err(ToolHeaderRepairError::Headers(_)))),
                    _ => panic!("unexpected repair eligibility: {case:?}"),
                }
                if matches!(case, Case::CancelBeforeRefresh | Case::ReusedListId | Case::DuplicateTool | Case::MissingTool) {
                    assert_eq!(approvals.load(Ordering::SeqCst), 0);
                    assert_eq!(headers.load(Ordering::SeqCst), 0);
                }
            }
        }
    }
    peer.quiet();
    {
        let requests = peer.requests.lock().unwrap();
        assert_eq!(requests.len(), expected_posts);
        for request in requests.iter().filter(|request| request["method"] == "tools/call") {
            assert_eq!(request["params"], original, "neither refresh nor approval may replace invocation data");
        }
    }
    assert!(cx.checkpoint().is_ok());
    // Repair failure/cancellation retires only its owned operation, not login.
    let sibling = async {
        let mut call = session.request_core(cx, core("tools/list", json!({})), RequestId::Number(900), ManagedCoreLimits::default()).await.unwrap();
        assert!(matches!(call.next_event(cx).await.unwrap(), Some(ManagedCoreEvent::Result(_))));
    };
    pair(peer.sibling(), sibling).await;
    assert_eq!(peer.requests.lock().unwrap().len(), expected_posts + 1);
    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
    peer.quiet();
    session.close();
}

macro_rules! cases {
    ($($name:ident => $case:ident),+ $(,)?) => { $(
        #[test] fn $name() { isolated(stringify!($name), Case::$case); }
    )+ };
}
cases! {
    repair_traverses_every_page_and_reprojects_once => Repair,
    repair_fresh_success_never_lists_or_retries => Fresh,
    repair_dropped_rejection_never_lists_or_retries => DropRejection,
    repair_cancelled_rejection_never_lists => CancelBeforeRefresh,
    repair_definition_denial_sends_no_tool_retry => DefinitionDenied,
    repair_disclosure_denial_sends_no_tool_retry => HeaderDenied,
    repair_callback_cancellation_sends_no_tool_retry => CancelDefinition,
    repair_catalog_id_cannot_reuse_initial_id => ReusedListId,
    repair_retry_id_cannot_reuse_initial_id => ReusedRetryId,
    repair_later_duplicate_tool_refuses_replacement => DuplicateTool,
    repair_missing_tool_refuses_replacement => MissingTool,
    repair_incompatible_projection_sends_no_tool_retry => WrongProjection,
    repair_second_rejection_cannot_create_a_third_attempt => SecondRejection,
    repair_foreign_error_id_never_grants_custody => WrongId,
    repair_other_error_code_never_grants_custody => WrongCode,
    repair_opaque_error_never_grants_custody => Opaque,
    repair_200_error_never_grants_custody => Status200,
    repair_truncated_error_never_grants_custody => Truncated,
    repair_lost_response_head_never_grants_custody => LostHead,
}

#[path = "oauth_tool_header_repair/schema.rs"]
mod schema;
