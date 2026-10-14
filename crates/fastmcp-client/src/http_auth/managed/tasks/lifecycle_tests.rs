//! Native HTTPS coverage of managed Task routing and streamed lifecycle replies.
//!
//! Starts with an admitted credential snapshot, then uses production discovery,
//! dispatch and response ownership. This does not claim interactive OAuth login
//! coverage. The private CA is explicitly resource-bound; no process trust store,
//! environment variable, transport substitute or certificate bypass is used.

use super::*;
use std::future::{Future, poll_fn};
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize}};
use std::task::{Context, Poll, Waker};

use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::net::TcpListener;
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::sync::Mutex;
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder};
use crate::http_auth::{BoundBearerCredential, CanonicalHttpUrl};
use crate::http_auth::managed::{OAuthSessionPolicy, SessionInner};
use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration};
use fastmcp_protocol::{
    ClientCapabilities, FinalHttpRequestMetadata, RequestVersionMetadata, admit_final_http_request,
};
use serde_json::json;

// Existing public TEST ONLY identity, inlined because remote workers exclude
// PEM/key files. This root grants trust only to this loopback fixture resource.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";
const PROGRESS: &str = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"owned","progress":1}}"#;

#[derive(Clone, Copy, Debug)]
enum Case {
    Json,
    Sse,
    ForeignId,
    TrailingRecord,
    MissingTerminal,
    Cancelled,
    Revoked,
}

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let (mut one, mut two) = (None, None);
    poll_fn(|task| {
        if one.is_none() {
            if let Poll::Ready(value) = left.as_mut().poll(task) { one = Some(value); }
        }
        if two.is_none() {
            if let Poll::Ready(value) = right.as_mut().poll(task) { two = Some(value); }
        }
        if one.is_some() && two.is_some() {
            Poll::Ready((one.take().unwrap(), two.take().unwrap()))
        } else {
            Poll::Pending
        }
    }).await
}

async fn read_request<IO: AsyncRead + Unpin>(io: &mut IO) -> (Vec<(String, String)>, Value) {
    let mut bytes = Vec::new();
    let mut buffer = [0; 2048];
    let end = loop {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let head = std::str::from_utf8(&bytes[..end]).unwrap();
    assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
    let fields: Vec<_> = head.lines().skip(1).filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_owned(), value.trim().to_owned())).collect();
    let length = header(&fields, "content-length").unwrap().parse::<usize>().unwrap();
    assert!(end + length <= 32 * 1024);
    while bytes.len() < end + length {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(bytes.len(), end + length);
    (fields, serde_json::from_slice(&bytes[end..]).unwrap())
}

fn header<'a>(fields: &'a [(String, String)], key: &str) -> Option<&'a str> {
    fields.iter().find(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.as_str())
}

fn admit(fields: &[(String, String)], body: &Value, mirror: Option<&str>) -> bool {
    admit_final_http_request(FinalHttpRequestMetadata {
        version: RequestVersionMetadata {
            header_version: header(fields, "mcp-protocol-version"),
            body_version: body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"].as_str(),
        },
        header_method: header(fields, "mcp-method"),
        body_method: body["method"].as_str(),
        header_name: mirror,
        body_name: body["params"]["taskId"].as_str(),
    }).is_ok()
}

async fn json_reply<IO: AsyncWrite + Unpin>(io: &mut IO, body: &Value) {
    let body = serde_json::to_vec(body).unwrap();
    io.write_all(format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    ).as_bytes()).await.unwrap();
    io.write_all(&body).await.unwrap();
    io.flush().await.unwrap();
}

async fn chunk<IO: AsyncWrite + Unpin>(io: &mut IO, body: &str) {
    io.write_all(format!("{:X}\r\n{body}\r\n", body.len()).as_bytes()).await.unwrap();
    io.flush().await.unwrap();
}

fn operation(method: &str) -> ManagedTaskRequest {
    match method {
        TASK_GET => ManagedTaskRequest::Get(TaskId::parse("task-one").unwrap()),
        TASK_CANCEL => ManagedTaskRequest::Cancel(TaskId::parse("task-one").unwrap()),
        TASK_UPDATE => ManagedTaskRequest::Update {
            task: Box::new(serde_json::from_value(json!({
                "taskId":"task-one", "status":"input_required",
                "createdAt":"2026-09-16T00:00:00Z", "lastUpdatedAt":"2026-09-16T00:00:00Z",
                "ttlMs":60000, "inputRequests":{"roots":{"method":"roots/list"}}
            })).unwrap()),
            input_responses: serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap(),
        },
        _ => panic!("unexpected fixture operation"),
    }
}

#[test]
fn native_https_lifecycle_preserves_routing_incremental_delivery_and_terminal_ownership() {
    for method in [TASK_GET, TASK_UPDATE, TASK_CANCEL] {
        for case in [Case::Json, Case::Sse, Case::ForeignId, Case::TrailingRecord,
            Case::MissingTerminal, Case::Cancelled, Case::Revoked] {
            RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
                .build().unwrap().block_on(async {
                    let cx = Cx::current().unwrap();
                    asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), async {
                        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                        let url = |text: &str| CanonicalHttpUrl::parse(text).unwrap();
                        let resource = url(&format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap()));
                        let config = OAuthClientConfiguration::from_trusted_endpoints(
                            "https://issuer.example", url("https://issuer.example/authorize"),
                            url("https://issuer.example/token"), resource.clone(), "native-client", vec![],
                        ).unwrap().with_resource_root_certificate(
                            Certificate::from_pem(ROOT).unwrap().remove(0),
                        ).unwrap();
                        let session = ManagedOAuthSession {
                            inner: Arc::new(SessionInner {
                                client: OAuthClient::new(config), resource: resource.clone(),
                                policy: OAuthSessionPolicy::default(), state: Arc::new(Mutex::new(None)),
                                closed: McpRequestCancellation::new(), logout_handoff: AtomicBool::new(false),
                                pending: AtomicUsize::new(0),
                            }),
                        };
                        let expires = Instant::now() + Duration::from_secs(60);
                        let bearer = BoundBearerCredential::bind_with_expiry(
                            resource.clone(), "lifecycle-test-token", expires,
                        ).unwrap();
                        let credential = OAuthCredentialSnapshot::new(
                            &bearer, &[], 1, expires, &session.inner.closed,
                        ).unwrap();
                        let mut metadata = serde_json::to_value(
                            FinalRequestMeta::new(ClientCapabilities::default()),
                        ).unwrap();
                        metadata["progressToken"] = json!("owned");
                        let limits = ManagedTasksLimits::new(8192, 8192, 8, Duration::from_secs(10)).unwrap();
                        let client = ManagedTasksClient::new(
                            session, serde_json::from_value(metadata).unwrap(), limits,
                        ).unwrap();
                        let ids = ManagedTaskRequestIds::new(RequestId::Number(1), RequestId::Number(2)).unwrap();
                        let prepared = prepare(resource.as_str(), &client.metadata, &ids.operation,
                            operation(method), limits).unwrap();
                        let round = client.prepare_round(ids, prepared).unwrap();
                        let cancellation = McpRequestCancellation::new();
                        let observed = McpRequestCancellation::new();
                        let deadline = deadline_after(&cx, limits.timeout).unwrap();
                        let acceptor = TlsAcceptorBuilder::new(
                            CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap(),
                        ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();
                        let application = async {
                            let mut call = client.execute_round(&cx, &cancellation, round,
                                &credential, deadline, limits.records).await.unwrap();
                            assert_eq!(call.credential_generation(), 1);
                            if !matches!(case, Case::Json) {
                                let first = call.next_event(&cx).await.unwrap().unwrap();
                                assert!(matches!(first, ManagedTaskEvent::Notification(notification)
                                    if matches!(*notification, ServerNotification::Progress(_))));
                                // The peer has not sent terminal bytes yet. A
                                // buffered-only implementation cannot pass this handshake.
                                observed.cancel();
                                if matches!(case, Case::Cancelled) { cancellation.cancel(); }
                                if matches!(case, Case::Revoked) { bearer.revoke(); }
                            }
                            let outcome = call.next_event(&cx).await;
                            match case {
                                Case::Json | Case::Sse => {
                                    let event = outcome.unwrap().unwrap();
                                    match (method, event) {
                                        (TASK_GET, ManagedTaskEvent::Snapshot(snapshot)) => {
                                            assert_eq!(snapshot.task.base().task_id, TaskId::parse("task-one").unwrap());
                                        }
                                        (TASK_UPDATE, ManagedTaskEvent::Updated(_))
                                        | (TASK_CANCEL, ManagedTaskEvent::Cancelled(_)) => {}
                                        _ => panic!("wrong method-owned terminal result"),
                                    }
                                    assert!(call.next_event(&cx).await.unwrap().is_none());
                                }
                                Case::ForeignId => assert!(matches!(outcome, Err(ManagedTasksError::ResponseIdMismatch))),
                                Case::TrailingRecord => assert!(matches!(outcome, Err(ManagedTasksError::InvalidResponse))),
                                Case::MissingTerminal => assert!(matches!(outcome, Err(ManagedTasksError::MissingTerminal))),
                                Case::Cancelled => assert!(matches!(outcome, Err(ManagedTasksError::Session(OAuthSessionError::Cancelled)))),
                                Case::Revoked => assert!(matches!(outcome, Err(ManagedTasksError::Session(OAuthSessionError::LoginRequired)))),
                            }
                            if !matches!(case, Case::Json | Case::Sse) {
                                assert!(matches!(call.next_event(&cx).await, Err(ManagedTasksError::Closed)));
                            }
                        };
                        let server = async {
                            let (socket, _) = listener.accept().await.unwrap();
                            let mut socket = acceptor.accept(socket).await.unwrap();
                            let (fields, body) = read_request(&mut socket).await;
                            assert_eq!(body["id"], 1);
                            assert_eq!(body["method"], "server/discover");
                            assert!(header(&fields, "mcp-name").is_none());
                            assert_eq!(header(&fields, "authorization"), Some("Bearer lifecycle-test-token"));
                            assert_eq!(body["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],
                                json!({TASKS_EXTENSION:{}}));
                            json_reply(&mut socket, &json!({"jsonrpc":"2.0","id":1,"result":{
                                "resultType":"complete","supportedVersions":[FINAL_PROTOCOL_VERSION],
                                "capabilities":{"tools":{},"extensions":{TASKS_EXTENSION:{}}},
                                "ttlMs":0,"cacheScope":"private",
                                "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"task-peer","version":"1"}}
                            }})).await;
                            drop(socket);
                            let (socket, _) = listener.accept().await.unwrap();
                            let mut socket = acceptor.accept(socket).await.unwrap();
                            let (fields, body) = read_request(&mut socket).await;
                            assert_eq!(body["id"], 2);
                            assert_eq!(body["method"], method);
                            assert_eq!(body["params"]["taskId"], "task-one");
                            assert_eq!(header(&fields, "authorization"), Some("Bearer lifecycle-test-token"));
                            assert_eq!(fields.iter().filter(|(key, _)| key.eq_ignore_ascii_case("mcp-name")).count(), 1);
                            assert!(admit(&fields, &body, header(&fields, "mcp-name")));
                            assert!(!admit(&fields, &body, None));
                            assert!(!admit(&fields, &body, Some("task-two")));
                            if method == TASK_UPDATE {
                                assert_eq!(body["params"]["inputResponses"], json!({"roots":{"roots":[]}}));
                            }
                            let result = if method == TASK_GET {
                                json!({"resultType":"complete","taskId":"task-one","status":"working",
                                    "createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z","ttlMs":60000})
                            } else { json!({"resultType":"complete"}) };
                            let reply = json!({"jsonrpc":"2.0", "id":if matches!(case, Case::ForeignId) { 3 } else { 2 }, "result":result});
                            if matches!(case, Case::Json) {
                                json_reply(&mut socket, &reply).await;
                                return;
                            }
                            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
                            chunk(&mut socket, &format!("data: {PROGRESS}\r\n\r\n")).await;
                            observed.cancelled().await;
                            if matches!(case, Case::Cancelled | Case::Revoked) {
                                let mut one = [0];
                                assert!(!matches!(socket.read(&mut one).await, Ok(n) if n > 0));
                                return;
                            }
                            if !matches!(case, Case::MissingTerminal) {
                                let mut data = format!("data: {reply}\r\n\r\n");
                                if matches!(case, Case::TrailingRecord) {
                                    data.push_str(&format!("data: {PROGRESS}\r\n\r\n"));
                                }
                                // Publish the data and final chunk together:
                                // rejection may close before a second write.
                                socket.write_all(format!("{:X}\r\n{data}\r\n0\r\n\r\n", data.len()).as_bytes()).await.unwrap();
                            } else {
                                socket.write_all(b"0\r\n\r\n").await.unwrap();
                            }
                            socket.flush().await.unwrap();
                        };
                        pair(application, server).await;
                        assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending(),
                            "{method} {case:?} must not replay or reconnect");
                        assert!(cx.checkpoint().is_ok());
                        assert!(!client.session.inner.closed.is_cancel_requested());
                    }).await.expect("bounded managed Task HTTPS fixture");
                });
        }
    }
}

// This second fixture enters through native OAuth authorization and the public
// Task APIs, rather than constructing a ManagedTaskCall or a prepared round.
// Only the browser/issuer peer is simulated. Token admission, retained grant,
// HTTPS discovery, continuation ownership and header projection are production.
fn form_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").unwrap();
        }
    }
    encoded
}

fn form_fields(value: &str) -> std::collections::BTreeMap<String, String> {
    fn decode(value: &str) -> String {
        let source = value.as_bytes();
        let mut decoded = Vec::new();
        let mut index = 0;
        while index < source.len() {
            match source[index] {
                b'%' => {
                    assert!(index + 2 < source.len());
                    let hex = std::str::from_utf8(&source[index + 1..index + 3]).unwrap();
                    decoded.push(u8::from_str_radix(hex, 16).unwrap());
                    index += 3;
                }
                b'+' => {
                    decoded.push(b' ');
                    index += 1;
                }
                byte => {
                    decoded.push(byte);
                    index += 1;
                }
            }
        }
        String::from_utf8(decoded).unwrap()
    }
    let mut fields = std::collections::BTreeMap::new();
    for field in value.split('&') {
        let (name, value) = field.split_once('=').unwrap();
        assert!(fields.insert(decode(name), decode(value)).is_none());
    }
    fields
}

async fn read_token_form<IO: AsyncRead + Unpin>(io: &mut IO) -> std::collections::BTreeMap<String, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 2048];
    let end = loop {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let head = std::str::from_utf8(&bytes[..end]).unwrap();
    assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
    let fields: Vec<_> = head.lines().skip(1).filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_owned(), value.trim().to_owned())).collect();
    assert_eq!(header(&fields, "content-type"), Some("application/x-www-form-urlencoded"));
    assert!(projected_fields(&fields).is_empty());
    let length = header(&fields, "content-length").unwrap().parse::<usize>().unwrap();
    assert!(end + length <= 32 * 1024);
    while bytes.len() < end + length {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(bytes.len(), end + length);
    form_fields(std::str::from_utf8(&bytes[end..]).unwrap())
}

fn projected_fields(fields: &[(String, String)]) -> std::collections::BTreeMap<String, String> {
    let mut projected = std::collections::BTreeMap::new();
    for (name, value) in fields {
        let name = name.to_ascii_lowercase();
        if name.starts_with("mcp-param-") {
            let value = fastmcp_protocol::http_headers::decode_mcp_header_value(value.as_bytes()).unwrap();
            assert!(projected.insert(name, value).is_none(), "duplicate parameter header");
        }
    }
    projected
}

fn reviewed_tool_arguments() -> Value {
    json!({"region":"north/λ%", "count":42, "enabled":false, "secret":"body-only-canary"})
}

fn tool_reply(kind: &str) -> Value {
    match kind {
        "complete" => json!({"resultType":"complete","content":[{"type":"text","text":"done"}]}),
        "task" => json!({
            "resultType":"task", "taskId":"task-one", "status":"working",
            "createdAt":"2026-09-16T00:00:00Z", "lastUpdatedAt":"2026-09-16T00:00:00Z", "ttlMs":60000
        }),
        "input_required" => json!({
            "resultType":"input_required", "requestState":"sealed-state-canary",
            "inputRequests":{"roots":{"method":"roots/list"}}
        }),
        _ => panic!("unknown tool fixture result"),
    }
}

fn assert_tool_kind(kind: &str, result: &FinalCoreResult) {
    assert!(matches!((kind, result),
        ("complete", FinalCoreResult::ToolsCall { .. })
        | ("task", FinalCoreResult::ToolsCallTask { .. })
        | ("input_required", FinalCoreResult::ToolsCallInputRequired { .. })
    ));
}

fn sequential_ids(discovery: i64) -> ManagedTaskRequestIds {
    ManagedTaskRequestIds::new(RequestId::Number(discovery), RequestId::Number(discovery + 1)).unwrap()
}

async fn reviewed_discovery<IO: AsyncRead + AsyncWrite + Unpin>(io: &mut IO, id: i64) {
    let (fields, body) = read_request(io).await;
    assert_eq!(body["id"], id);
    assert_eq!(body["method"], "server/discover");
    assert_eq!(header(&fields, "authorization"), Some("Bearer reviewed-task-token"));
    assert!(header(&fields, "mcp-name").is_none());
    assert!(projected_fields(&fields).is_empty());
    for member in ["name", "arguments", "requestState", "inputResponses"] {
        assert!(body["params"].get(member).is_none(), "discovery leaked {member}");
    }
    assert_eq!(body["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],
        json!({TASKS_EXTENSION:{}}));
    json_reply(io, &json!({"jsonrpc":"2.0", "id":id, "result":{
        "resultType":"complete", "supportedVersions":[FINAL_PROTOCOL_VERSION],
        "capabilities":{"tools":{}, "extensions":{TASKS_EXTENSION:{}}},
        "ttlMs":0, "cacheScope":"private",
        "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"reviewed-task-peer","version":"1"}}
    }})).await;
}

fn assert_reviewed_tool_post(fields: &[(String, String)], body: &Value, resumed: bool, reviewed: bool) {
    assert_eq!(body["method"], "tools/call");
    assert_eq!(body["params"]["name"], "echo");
    assert_eq!(body["params"]["arguments"], reviewed_tool_arguments());
    assert_eq!(header(fields, "authorization"), Some("Bearer reviewed-task-token"));
    let routing = |mirror| admit_final_http_request(FinalHttpRequestMetadata {
        version: RequestVersionMetadata {
            header_version: header(fields, "mcp-protocol-version"),
            body_version: body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"].as_str(),
        },
        header_method: header(fields, "mcp-method"), body_method: body["method"].as_str(),
        header_name: mirror, body_name: body["params"]["name"].as_str(),
    }).is_ok();
    assert!(routing(header(fields, "mcp-name")));
    assert!(!routing(None));
    assert!(!routing(Some("other-tool")));
    if reviewed {
        assert_eq!(projected_fields(fields), std::collections::BTreeMap::from([
            ("mcp-param-region".to_owned(), "north/λ%".to_owned()),
            ("mcp-param-count".to_owned(), "42".to_owned()),
            ("mcp-param-enabled".to_owned(), "false".to_owned()),
        ]));
    } else {
        assert!(projected_fields(fields).is_empty());
    }
    assert!(!fields.iter().any(|(_, value)|
        value.contains("body-only-canary") || value.contains("sealed-state-canary")));
    if resumed {
        assert_eq!(body["params"]["requestState"], "sealed-state-canary");
        assert_eq!(body["params"]["inputResponses"], json!({"roots":{"roots":[]}}));
    } else {
        assert!(body["params"].get("requestState").is_none());
        assert!(body["params"].get("inputResponses").is_none());
    }
}

#[test]
fn native_oauth_reviewed_task_calls_keep_headers_through_public_continuation_and_lifecycle() {
    use super::interaction::{ManagedTaskInteractionEvent, ManagedTaskInteractionPolicy};
    use crate::http_auth::oauth::OAuthError;

    // Six ordinary calls and four actual multi-round interactions. Every case
    // has public-API negative preflight controls and an unreviewed sibling call.
    for continued in [false, true] {
        for sse in [false, true] {
            for kind in ["complete", "task", "input_required"] {
                if continued && kind == "input_required" {
                    continue;
                }
                RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
                    .build().unwrap().block_on(async {
                        let cx = Cx::current().unwrap();
                        asupersync::time::timeout_at(cx.now().saturating_add_nanos(30_000_000_000), async {
                            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                            let issuer = format!("https://{}", listener.local_addr().unwrap());
                            let url = |text: &str| CanonicalHttpUrl::parse(text).unwrap();
                            let resource = url(&format!("{issuer}/mcp?tenant=one"));
                            let config = OAuthClientConfiguration::from_trusted_endpoints(
                                issuer.clone(), url(&format!("{issuer}/authorize")),
                                url(&format!("{issuer}/token")), resource.clone(), "native-client", vec![],
                            ).unwrap()
                                .with_extra_root_certificate(Certificate::from_pem(ROOT).unwrap().remove(0)).unwrap()
                                .with_resource_root_certificate(Certificate::from_pem(ROOT).unwrap().remove(0)).unwrap()
                                .with_authorization_timeout(Duration::from_secs(10)).unwrap();
                            let acceptor = TlsAcceptorBuilder::new(
                                CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap(),
                            ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();
                            let observed = [McpRequestCancellation::new(), McpRequestCancellation::new()];
                            let application = async {
                                let callback_issuer = issuer.clone();
                                let session = ManagedOAuthSession::authorize(
                                    &cx, OAuthClient::new(config), OAuthSessionPolicy::default(),
                                    move |authorization| {
                                        let fields = form_fields(authorization.query().unwrap());
                                        assert_eq!(fields["code_challenge_method"], "S256");
                                        let redirect = fields["redirect_uri"].clone();
                                        let state = fields["state"].clone();
                                        async move {
                                            let (address, path) = redirect.strip_prefix("http://").unwrap()
                                                .split_once('/').unwrap();
                                            let mut callback = asupersync::net::TcpStream::connect(address).await
                                                .map_err(|_| OAuthError::BrowserLaunchFailed)?;
                                            let request = format!(
                                                "GET /{path}?code=fixture-code&state={}&iss={} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n",
                                                form_component(&state), form_component(&callback_issuer),
                                            );
                                            callback.write_all(request.as_bytes()).await
                                                .map_err(|_| OAuthError::BrowserLaunchFailed)?;
                                            // Do not wait for receipt here: authorize starts
                                            // consuming its callback AFTER the launcher returns.
                                            Ok(())
                                        }
                                    },
                                ).await.unwrap();
                                let capabilities: ClientCapabilities = serde_json::from_value(json!({"roots":{}})).unwrap();
                                let mut metadata = serde_json::to_value(FinalRequestMeta::new(capabilities)).unwrap();
                                metadata["progressToken"] = json!("owned");
                                let limits = ManagedTasksLimits::new(8192, 8192, 8, Duration::from_secs(15)).unwrap();
                                let plain = ManagedTasksClient::new(
                                    session.clone(), serde_json::from_value(metadata).unwrap(), limits,
                                ).unwrap();
                                let review = Arc::new(ReviewedToolHeaders::new(resource.clone(), "echo", json!({
                                    "type":"object", "properties":{
                                        "region":{"type":"string","x-mcp-header":"Region"},
                                        "count":{"type":"number","x-mcp-header":"Count"},
                                        "enabled":{"type":"boolean","x-mcp-header":"Enabled"},
                                        "secret":{"type":"string","writeOnly":true}
                                    }
                                }), |_| true).unwrap());
                                let client = plain.clone().with_reviewed_tool_headers(Arc::clone(&review)).unwrap();
                                assert!(matches!(client.clone().with_reviewed_tool_headers(Arc::clone(&review)),
                                    Err(ManagedTasksError::ParameterHeaders(ToolHeaderDispatchError::AlreadyProjected))));
                                for (name, arguments) in [
                                    ("other-tool", reviewed_tool_arguments()),
                                    ("echo", json!({"count":"invalid-number-canary"})),
                                ] {
                                    let mut refused = Box::pin(client.request(&cx, sequential_ids(1),
                                        ManagedTaskRequest::CallTool { name: name.to_owned(), arguments: Some(arguments) }));
                                    poll_fn(|task| match refused.as_mut().poll(task) {
                                        Poll::Ready(Err(ManagedTasksError::ParameterHeaders(_))) => Poll::Ready(()),
                                        _ => panic!("invalid review must fail before discovery on its first poll"),
                                    }).await;
                                }
                                let pre_cancelled = McpRequestCancellation::new();
                                pre_cancelled.cancel();
                                assert!(matches!(client.request_with_cancellation(&cx, &pre_cancelled, sequential_ids(1),
                                    ManagedTaskRequest::CallTool { name: "echo".to_owned(), arguments: Some(reviewed_tool_arguments()) }
                                ).await, Err(ManagedTasksError::Session(OAuthSessionError::Cancelled))));

                                if continued {
                                    let mut interaction = client.start_tool_interaction(
                                        &cx, sequential_ids(1), "echo".to_owned(), Some(reviewed_tool_arguments()),
                                        ManagedTaskInteractionPolicy::new(1, 8, 8).unwrap(),
                                    ).await.unwrap();
                                    if sse {
                                        assert!(matches!(interaction.next_event(&cx).await.unwrap(),
                                            Some(ManagedTaskInteractionEvent::Notification(notification))
                                            if matches!(*notification, ServerNotification::Progress(_))));
                                        observed[0].cancel();
                                    }
                                    assert!(matches!(interaction.next_event(&cx).await.unwrap(),
                                        Some(ManagedTaskInteractionEvent::InputRequired(_))));
                                    let answers = || serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap();
                                    // Reusing the opening identities cannot consume this
                                    // challenge or emit discovery. The corrected resume works.
                                    assert!(interaction.resume(&cx, sequential_ids(1), Some(answers())).await.is_err());
                                    assert!(interaction.pending_input().is_some());
                                    assert_eq!(interaction.continuation_count(), 0);
                                    interaction.resume(&cx, sequential_ids(3), Some(answers())).await.unwrap();
                                    if sse {
                                        assert!(matches!(interaction.next_event(&cx).await.unwrap(),
                                            Some(ManagedTaskInteractionEvent::Notification(notification))
                                            if matches!(*notification, ServerNotification::Progress(_))));
                                        observed[1].cancel();
                                    }
                                    let Some(ManagedTaskInteractionEvent::Result(result)) =
                                        interaction.next_event(&cx).await.unwrap()
                                    else { panic!("expected resumed tool result") };
                                    assert_tool_kind(kind, &result);
                                    assert_eq!(interaction.continuation_count(), 1);
                                    assert!(interaction.is_finished());
                                    assert!(interaction.next_event(&cx).await.unwrap().is_none());
                                } else {
                                    let mut call = client.request(&cx, sequential_ids(1), ManagedTaskRequest::CallTool {
                                        name: "echo".to_owned(), arguments: Some(reviewed_tool_arguments()),
                                    }).await.unwrap();
                                    assert_eq!(call.credential_generation(), 1);
                                    if sse {
                                        assert!(matches!(call.next_event(&cx).await.unwrap(),
                                            Some(ManagedTaskEvent::Notification(notification))
                                            if matches!(*notification, ServerNotification::Progress(_))));
                                        observed[0].cancel();
                                    }
                                    let Some(ManagedTaskEvent::ToolResult(result)) = call.next_event(&cx).await.unwrap()
                                    else { panic!("expected standalone tool result") };
                                    assert_tool_kind(kind, &result);
                                    assert!(call.next_event(&cx).await.unwrap().is_none());
                                }

                                if kind == "task" {
                                    let mut get = client.request(&cx, sequential_ids(11),
                                        ManagedTaskRequest::Get(TaskId::parse("task-one").unwrap())).await.unwrap();
                                    let Some(ManagedTaskEvent::Snapshot(snapshot)) = get.next_event(&cx).await.unwrap()
                                    else { panic!("expected Task snapshot") };
                                    assert!(get.next_event(&cx).await.unwrap().is_none());
                                    let mut update = client.request(&cx, sequential_ids(13), ManagedTaskRequest::Update {
                                        task: Box::new(snapshot.task),
                                        input_responses: serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap(),
                                    }).await.unwrap();
                                    assert!(matches!(update.next_event(&cx).await.unwrap(), Some(ManagedTaskEvent::Updated(_))));
                                    assert!(update.next_event(&cx).await.unwrap().is_none());
                                    let mut cancel = client.request(&cx, sequential_ids(15),
                                        ManagedTaskRequest::Cancel(TaskId::parse("task-one").unwrap())).await.unwrap();
                                    assert!(matches!(cancel.next_event(&cx).await.unwrap(), Some(ManagedTaskEvent::Cancelled(_))));
                                    assert!(cancel.next_event(&cx).await.unwrap().is_none());
                                }
                                // Attaching a review to a clone did not mutate the
                                // original client or the shared OAuth grant's headers.
                                let mut sibling = plain.request(&cx, sequential_ids(41), ManagedTaskRequest::CallTool {
                                    name: "echo".to_owned(), arguments: Some(reviewed_tool_arguments()),
                                }).await.unwrap();
                                let Some(ManagedTaskEvent::ToolResult(result)) = sibling.next_event(&cx).await.unwrap()
                                else { panic!("explicit sibling request must complete") };
                                assert_tool_kind("complete", &result);
                                assert!(sibling.next_event(&cx).await.unwrap().is_none());
                                assert!(cx.checkpoint().is_ok());
                                assert!(!session.inner.closed.is_cancel_requested());
                            };
                            let server = async {
                                let (socket, _) = listener.accept().await.unwrap();
                                let mut socket = acceptor.accept(socket).await.unwrap();
                                let form = read_token_form(&mut socket).await;
                                assert_eq!(form["grant_type"], "authorization_code");
                                assert_eq!(form["code"], "fixture-code");
                                assert_eq!(form["client_id"], "native-client");
                                assert_eq!(form["resource"], resource.as_str());
                                assert_eq!(form["code_verifier"].len(), 64);
                                assert!(form["redirect_uri"].starts_with("http://127.0.0.1:")
                                    || form["redirect_uri"].starts_with("http://[::1]:"));
                                json_reply(&mut socket, &json!({
                                    "access_token":"reviewed-task-token", "token_type":"Bearer", "expires_in":120
                                })).await;
                                drop(socket);

                                let rounds = if continued { 2 } else { 1 };
                                for round in 0..rounds {
                                    let discovery_id = 1 + (round as i64) * 2;
                                    let (socket, _) = listener.accept().await.unwrap();
                                    let mut socket = acceptor.accept(socket).await.unwrap();
                                    reviewed_discovery(&mut socket, discovery_id).await;
                                    drop(socket);
                                    let (socket, _) = listener.accept().await.unwrap();
                                    let mut socket = acceptor.accept(socket).await.unwrap();
                                    let (fields, body) = read_request(&mut socket).await;
                                    assert_eq!(body["id"], discovery_id + 1);
                                    assert_reviewed_tool_post(&fields, &body, round > 0, true);
                                    let result = tool_reply(if continued && round == 0 { "input_required" } else { kind });
                                    let reply = json!({"jsonrpc":"2.0","id":discovery_id + 1,"result":result});
                                    if sse {
                                        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
                                        chunk(&mut socket, &format!("data: {PROGRESS}\r\n\r\n")).await;
                                        // A terminal-only collector cannot satisfy this:
                                        // no result bytes exist until progress is delivered.
                                        observed[round].cancelled().await;
                                        let data = format!("data: {reply}\r\n\r\n");
                                        socket.write_all(format!("{:X}\r\n{data}\r\n0\r\n\r\n", data.len()).as_bytes()).await.unwrap();
                                        socket.flush().await.unwrap();
                                    } else {
                                        json_reply(&mut socket, &reply).await;
                                    }
                                }
                                if kind == "task" {
                                    for (id, method) in [(11, TASK_GET), (13, TASK_UPDATE), (15, TASK_CANCEL)] {
                                        let (socket, _) = listener.accept().await.unwrap();
                                        let mut socket = acceptor.accept(socket).await.unwrap();
                                        reviewed_discovery(&mut socket, id).await;
                                        drop(socket);
                                        let (socket, _) = listener.accept().await.unwrap();
                                        let mut socket = acceptor.accept(socket).await.unwrap();
                                        let (fields, body) = read_request(&mut socket).await;
                                        assert_eq!(body["id"], id + 1);
                                        assert_eq!(body["method"], method);
                                        assert_eq!(body["params"]["taskId"], "task-one");
                                        assert_eq!(header(&fields, "authorization"), Some("Bearer reviewed-task-token"));
                                        assert!(projected_fields(&fields).is_empty());
                                        assert!(admit(&fields, &body, header(&fields, "mcp-name")));
                                        assert!(!admit(&fields, &body, None));
                                        if method == TASK_UPDATE {
                                            assert_eq!(body["params"]["inputResponses"], json!({"roots":{"roots":[]}}));
                                        }
                                        let result = if method == TASK_GET {
                                            json!({"resultType":"complete","taskId":"task-one","status":"input_required",
                                                "createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z",
                                                "ttlMs":60000,"inputRequests":{"roots":{"method":"roots/list"}}})
                                        } else { json!({"resultType":"complete"}) };
                                        json_reply(&mut socket, &json!({"jsonrpc":"2.0","id":id + 1,"result":result})).await;
                                    }
                                }
                                let (socket, _) = listener.accept().await.unwrap();
                                let mut socket = acceptor.accept(socket).await.unwrap();
                                reviewed_discovery(&mut socket, 41).await;
                                drop(socket);
                                let (socket, _) = listener.accept().await.unwrap();
                                let mut socket = acceptor.accept(socket).await.unwrap();
                                let (fields, body) = read_request(&mut socket).await;
                                assert_eq!(body["id"], 42);
                                assert_reviewed_tool_post(&fields, &body, false, false);
                                json_reply(&mut socket, &json!({"jsonrpc":"2.0","id":42,"result":tool_reply("complete")})).await;
                            };
                            pair(application, server).await;
                            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending(),
                                "reviewed tool fixture must not replay, renew, or reconnect after completion");
                        }).await.expect("bounded public OAuth/Task/header fixture");
                    });
            }
        }
    }
}
