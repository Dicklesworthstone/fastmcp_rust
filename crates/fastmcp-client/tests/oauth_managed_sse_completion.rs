//! Public managed core/Tasks finite-response admission over native TLS.
//!
//! Login uses the public native authorization driver and a fixture loopback
//! callback. Issuer and resource trust are configured explicitly; no ambient
//! trust mutation, browser process, transport replacement or injected grant.
//! The peer scripts responses, not native server dispatch or issuer policy.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream};
use fastmcp_client::http_auth::managed::{ManagedOAuthSession, OAuthSessionError, OAuthSessionPolicy};
use fastmcp_client::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};
use fastmcp_client::http_auth::rpc::{ManagedCoreError, ManagedCoreEvent, ManagedCoreLimits};
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{ClientCapabilities, CoreRequest, FinalRequestMeta, RequestId};
use serde_json::{Value, json};

// TEST ONLY: the existing oauth_core_rpc fixture, inlined so remote workers
// need no transfer-excluded PEM/key files. Never installed in system trust.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

const COMPLETE: &str = r#"{"resultType":"complete","content":[{"type":"text","text":"complete"}],"x-exact":{"large":900719925474099312345,"decimal":1.20e+4}}"#;
const INPUT: &str = r#"{"resultType":"input_required","requestState":"private-state"}"#;
const PROGRESS: &str = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"work","progress":1}}"#;

#[derive(Clone, Copy)]
enum Tail { Clean, PartialLine, PendingEvent, ShortHttp, Duplicate, Notification, Stall }

fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }
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
    input.split('&').map(|field| {
        let (key, value) = field.split_once('=').unwrap();
        (decode_component(key), decode_component(value))
    }).collect()
}
async fn browser(authorization: CanonicalHttpUrl) -> Result<(), OAuthError> {
    let params = form(authorization.query().unwrap());
    assert_eq!(params["client_id"], "completion-client");
    assert_eq!(params["code_challenge_method"], "S256");
    let address: SocketAddr = params["redirect_uri"].strip_prefix("http://").unwrap()
        .split('/').next().unwrap().parse().unwrap();
    assert!(address.ip().is_loopback());
    let request = format!("GET /oauth/callback?code=completion-code&iss=https%3A%2F%2Fissuer.example&state={} HTTP/1.1\r\nHost: {address}\r\n\r\n", params["state"]);
    let mut socket = TcpStream::connect(address).await.map_err(|_| OAuthError::CallbackRejected)?;
    socket.write_all(request.as_bytes()).await.map_err(|_| OAuthError::CallbackRejected)
}
async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let (mut one, mut two) = (None, None);
    poll_fn(|task| {
        if one.is_none() { if let Poll::Ready(value) = left.as_mut().poll(task) { one = Some(value); } }
        if two.is_none() { if let Poll::Ready(value) = right.as_mut().poll(task) { two = Some(value); } }
        if one.is_some() && two.is_some() { Poll::Ready((one.take().unwrap(), two.take().unwrap())) }
        else { Poll::Pending }
    }).await
}
fn run<F: Future<Output = ()>>(scenario: impl FnOnce(Cx) -> F) {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), Box::pin(scenario(cx))).await.unwrap();
        });
}
async fn read_request(socket: &mut TlsStream<TcpStream>) -> (String, Vec<u8>) {
    let mut bytes = Vec::new();
    let mut chunk = [0; 2048];
    let end = loop {
        let count = socket.read(&mut chunk).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 64 * 1024);
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") { break index + 4; }
    };
    let head = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
    let size = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
    }).unwrap();
    assert!(size <= (64 * 1024) - end);
    while bytes.len() < end + size {
        let count = socket.read(&mut chunk).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 64 * 1024);
        bytes.extend_from_slice(&chunk[..count]);
    }
    assert_eq!(bytes.len(), end + size);
    (head, bytes[end..].to_vec())
}
async fn json_reply(socket: &mut TlsStream<TcpStream>, body: &str) {
    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    socket.shutdown().await.unwrap();
}
struct Peer { listener: TcpListener, tls: TlsAcceptor, calls: AtomicUsize }
impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            tls: TlsAcceptorBuilder::new(CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap())
                .alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap(),
            calls: AtomicUsize::new(0),
        }
    }
    async fn login(&self, cx: &Cx) -> ManagedOAuthSession {
        let target = format!("https://{}", self.listener.local_addr().unwrap());
        let root = Certificate::from_pem(ROOT).unwrap();
        let configuration = OAuthClientConfiguration::from_trusted_endpoints("https://issuer.example",
            url("https://issuer.example/authorize"), url(&format!("{target}/token")),
            url(&format!("{target}/mcp")), "completion-client", vec!["tools:read".to_owned()]).unwrap()
            .with_extra_root_certificate(root.clone()).unwrap().with_resource_root_certificate(root).unwrap();
        let server = async {
            let (socket, _) = self.listener.accept().await.unwrap();
            let mut socket = self.tls.accept(socket).await.unwrap();
            let (head, body) = read_request(&mut socket).await;
            assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
            let fields = form(std::str::from_utf8(&body).unwrap());
            assert_eq!(fields["grant_type"], "authorization_code");
            assert_eq!(fields["code"], "completion-code");
            assert_eq!(fields["client_id"], "completion-client");
            assert_eq!(fields["resource"], format!("{target}/mcp"));
            assert!(!fields["code_verifier"].is_empty());
            json_reply(&mut socket, r#"{"access_token":"completion-access","token_type":"Bearer","expires_in":3600,"scope":"tools:read"}"#).await;
        };
        let (_, session) = pair(server, ManagedOAuthSession::authorize(cx, OAuthClient::new(configuration),
            OAuthSessionPolicy::default(), browser)).await;
        session.unwrap()
    }
    async fn rpc(&self, method: &str, id: i64) -> (TlsStream<TcpStream>, Value) {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut socket = self.tls.accept(socket).await.unwrap();
        let (head, bytes) = read_request(&mut socket).await;
        assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
        let head = head.to_ascii_lowercase();
        assert!(head.contains("authorization: bearer completion-access\r\n"));
        assert!(!head.contains("mcp-session-id:") && !head.contains("last-event-id:"));
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["id"], id);
        assert_eq!(body["method"], method);
        self.calls.fetch_add(1, Ordering::SeqCst);
        (socket, body)
    }
    async fn reply(&self, method: &str, result: &str, tail: Tail, progress: bool) {
        let (mut socket, body) = self.rpc(method, 41).await;
        if progress { assert_eq!(body["params"]["_meta"]["progressToken"], "work"); }
        let terminal = format!(r#"{{"jsonrpc":"2.0","id":41,"result":{result}}}"#);
        let mut body = if progress { format!("data: {PROGRESS}\n\n") } else { String::new() };
        body.push_str(&format!("data: {terminal}\n\n"));
        body.push_str(&match tail {
            Tail::Clean => ": complete comment\n\n".to_owned(),
            Tail::PartialLine => "data: private-unfinished".to_owned(),
            Tail::PendingEvent => "data: private-unfinished\n".to_owned(),
            Tail::Duplicate => format!("data: {terminal}\n\n"),
            Tail::Notification => format!("data: {PROGRESS}\n\n"),
            Tail::ShortHttp | Tail::Stall => String::new(),
        });
        if matches!(tail, Tail::Stall) {
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{body}\r\n", body.len()).as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
            let mut byte = [0];
            assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0));
        } else {
            let length = body.len() + usize::from(matches!(tail, Tail::ShortHttp));
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{body}").as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        }
    }
    async fn follow_up(&self) {
        let (mut socket, _) = self.rpc("tools/call", 42).await;
        json_reply(&mut socket, &format!(r#"{{"jsonrpc":"2.0","id":42,"result":{COMPLETE}}}"#)).await;
    }
    fn quiet(&self, expected: usize) {
        assert_eq!(self.calls.load(Ordering::SeqCst), expected);
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(self.listener.poll_accept(&mut task).is_pending(), "no retry or extra token exchange");
    }
}
fn core(method: &str) -> CoreRequest {
    let mut params = match method {
        "tools/call" | "prompts/get" => json!({"name":"fixture"}),
        "resources/read" => json!({"uri":"file:///fixture"}),
        _ => panic!("unrecognized fixture method"),
    };
    params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    params["_meta"]["progressToken"] = json!("work");
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
}
fn result_for(method: &str) -> &'static str {
    match method {
        "tools/call" => COMPLETE,
        "resources/read" => r#"{"resultType":"complete","contents":[],"ttlMs":0,"cacheScope":"private"}"#,
        "prompts/get" => r#"{"resultType":"complete","messages":[]}"#,
        _ => unreachable!(),
    }
}
async fn follow_up(cx: &Cx, session: &ManagedOAuthSession) {
    let mut call = session.request_core(cx, core("tools/call"), RequestId::Number(42), ManagedCoreLimits::default()).await.unwrap();
    assert!(matches!(call.next_event(cx).await.unwrap(), Some(ManagedCoreEvent::Result(_))));
    assert!(call.next_event(cx).await.unwrap().is_none());
}
fn core_case(method: &str, result: &str, tail: Tail, progress: bool) {
    run(|cx| async move {
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let server = async { peer.reply(method, result, tail, progress).await; peer.follow_up().await; };
        let application = async {
            let mut call = session.request_core(&cx, core(method), RequestId::Number(41), ManagedCoreLimits::default()).await.unwrap();
            if progress { assert!(matches!(call.next_event(&cx).await.unwrap(), Some(ManagedCoreEvent::Notification(_)))); }
            let event = call.next_event(&cx).await;
            match tail {
                Tail::Clean => {
                    let Some(ManagedCoreEvent::Result(delivered)) = event.unwrap() else { panic!("terminal result"); };
                    let encoded = delivered.encode().unwrap();
                    if result == COMPLETE { assert!(encoded.contains("900719925474099312345")); }
                    if result == INPUT { assert!(encoded.contains("private-state")); }
                    assert!(call.next_event(&cx).await.unwrap().is_none());
                }
                Tail::PartialLine | Tail::PendingEvent => {
                    assert!(matches!(event, Err(ManagedCoreError::Session(OAuthSessionError::IncompleteSseResponse))));
                    assert!(matches!(call.next_event(&cx).await, Err(ManagedCoreError::Closed)));
                }
                Tail::Duplicate | Tail::Notification | Tail::ShortHttp => {
                    assert!(event.is_err());
                    assert!(matches!(call.next_event(&cx).await, Err(ManagedCoreError::Closed)));
                }
                Tail::Stall => unreachable!(),
            }
            follow_up(&cx, &session).await;
        };
        pair(server, application).await;
        peer.quiet(2);
        session.close();
    });
}

#[test]
fn managed_public_core_publishes_clean_results_with_exact_payloads() {
    for method in ["tools/call", "resources/read", "prompts/get"] { core_case(method, result_for(method), Tail::Clean, false); }
    core_case("tools/call", INPUT, Tail::Clean, false);
}
#[test]
fn managed_public_core_refuses_partial_sse_endings_for_all_interactive_methods() {
    for method in ["tools/call", "resources/read", "prompts/get"] {
        for tail in [Tail::PartialLine, Tail::PendingEvent] { core_case(method, result_for(method), tail, false); }
    }
}
#[test]
fn managed_public_core_never_publishes_an_input_challenge_from_incomplete_framing() {
    for tail in [Tail::PartialLine, Tail::PendingEvent] { core_case("tools/call", INPUT, tail, false); }
}
#[test]
fn managed_public_core_keeps_prior_progress_but_withholds_the_terminal() {
    core_case("tools/call", COMPLETE, Tail::Clean, true);
    for tail in [Tail::PartialLine, Tail::PendingEvent] { core_case("tools/call", COMPLETE, tail, true); }
}
#[test]
fn managed_public_core_rejects_duplicate_trailing_and_truncated_responses() {
    for tail in [Tail::Duplicate, Tail::Notification, Tail::ShortHttp] { core_case("tools/call", COMPLETE, tail, false); }
}
#[test]
fn managed_public_completion_wait_is_cancel_correct_and_does_not_poison_the_session() {
    for abandon in [false, true] {
        run(|cx| async move {
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let cancel = McpRequestCancellation::new();
            let server = async { peer.reply("tools/call", COMPLETE, Tail::Stall, true).await; peer.follow_up().await; };
            let application = async {
                let mut call = session.request_core_with_cancellation(&cx, &cancel, core("tools/call"), RequestId::Number(41), ManagedCoreLimits::default()).await.unwrap();
                assert!(matches!(call.next_event(&cx).await.unwrap(), Some(ManagedCoreEvent::Notification(_))));
                let mut finishing = Box::pin(call.next_event(&cx));
                poll_fn(|task| { assert!(finishing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                if abandon { drop(finishing); } else {
                    cancel.cancel();
                    assert!(finishing.await.is_err());
                }
                assert!(matches!(call.next_event(&cx).await, Err(ManagedCoreError::Closed) | Err(ManagedCoreError::Cancelled)));
                follow_up(&cx, &session).await;
            };
            pair(server, application).await;
            peer.quiet(2);
            session.close();
        });
    }
}

#[cfg(feature = "tasks")]
mod tasks {
    use super::*;
    use fastmcp_client::http_auth::managed::tasks::{ManagedTaskEvent, ManagedTaskRequest, ManagedTaskRequestIds, ManagedTasksClient, ManagedTasksError, ManagedTasksLimits};
    use fastmcp_protocol::tasks_extension::{TASKS_EXTENSION, TaskId};

    const TASK: &str = r#"{"resultType":"task","taskId":"task-one","status":"working","createdAt":"2026-09-26T00:00:00Z","lastUpdatedAt":"2026-09-26T00:00:00Z","ttlMs":60000}"#;
    const SNAPSHOT: &str = r#"{"resultType":"complete","taskId":"task-one","status":"working","createdAt":"2026-09-26T00:00:00Z","lastUpdatedAt":"2026-09-26T00:00:00Z","ttlMs":60000}"#;
    fn scenario(result: &str, tail: Tail, get: bool) {
        run(|cx| async move {
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let client = ManagedTasksClient::new(session.clone(), FinalRequestMeta::new(ClientCapabilities::default()),
                ManagedTasksLimits::new(65536, 65536, 1, Duration::from_secs(5)).unwrap()).unwrap();
            let server = async {
                let (mut socket, request) = peer.rpc("server/discover", 40).await;
                assert_eq!(request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"], json!({TASKS_EXTENSION:{}}));
                let reply = json!({"jsonrpc":"2.0","id":40,"result":{"resultType":"complete",
                    "supportedVersions":["2026-07-28"],"capabilities":{"extensions":{TASKS_EXTENSION:{}}},"ttlMs":0,"cacheScope":"private"}});
                json_reply(&mut socket, &reply.to_string()).await;
                peer.reply(if get {"tasks/get"} else {"tools/call"}, result, tail, false).await;
                peer.follow_up().await;
            };
            let application = async {
                let request = if get { ManagedTaskRequest::Get(TaskId::parse("task-one").unwrap()) }
                    else { ManagedTaskRequest::CallTool { name:"fixture".to_owned(), arguments:None } };
                let ids = ManagedTaskRequestIds::new(RequestId::Number(40), RequestId::Number(41)).unwrap();
                let mut call = client.request(&cx, ids, request).await.unwrap();
                let event = call.next_event(&cx).await;
                match tail {
                    Tail::Clean => {
                        assert!(matches!(event.unwrap(), Some(ManagedTaskEvent::ToolResult(_)) | Some(ManagedTaskEvent::Snapshot(_))));
                        assert!(call.next_event(&cx).await.unwrap().is_none(), "EOF consumes no extra record budget");
                    }
                    Tail::PartialLine | Tail::PendingEvent => {
                        assert!(matches!(event, Err(ManagedTasksError::Session(OAuthSessionError::IncompleteSseResponse))));
                        assert!(matches!(call.next_event(&cx).await, Err(ManagedTasksError::Closed)));
                    }
                    _ => unreachable!(),
                }
                follow_up(&cx, &session).await;
            };
            pair(server, application).await;
            peer.quiet(3);
            session.close();
        });
    }
    #[test]
    fn managed_tasks_clean_completion_preserves_one_record_limit() {
        for result in [COMPLETE, INPUT, TASK] { scenario(result, Tail::Clean, false); }
        scenario(SNAPSHOT, Tail::Clean, true);
    }
    #[test]
    fn managed_tasks_withhold_complete_input_and_task_results_on_incomplete_sse() {
        for result in [COMPLETE, INPUT, TASK] {
            for tail in [Tail::PartialLine, Tail::PendingEvent] { scenario(result, tail, false); }
        }
    }
    #[test]
    fn managed_tasks_withhold_get_snapshots_on_incomplete_sse() {
        for tail in [Tail::PartialLine, Tail::PendingEvent] { scenario(SNAPSHOT, tail, true); }
    }
}
