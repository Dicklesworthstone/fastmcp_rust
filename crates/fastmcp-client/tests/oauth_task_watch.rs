//! Public notification-driven Tasks watches over real loopback TLS.
//! The peer is an in-process MCP/authorization-server fixture, not an external
//! IdP or a conformance oracle. No production transport or watch is mocked.
#![cfg(feature = "tasks")]

use std::collections::{BTreeMap, BTreeSet};
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream};
use fastmcp_client::http_auth::managed::{ManagedOAuthSession, OAuthSessionError, OAuthSessionPolicy};
use fastmcp_client::http_auth::managed::tasks::{ManagedTasksClient, ManagedTasksError, ManagedTasksLimits};
use fastmcp_client::http_auth::managed::tasks::watch::{
    ManagedTaskSnapshotCause, ManagedTaskWatchError, ManagedTaskWatchPolicy,
};
use fastmcp_client::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_SUBSCRIPTION_ID_META_KEY};
use fastmcp_protocol::tasks_extension::{Task, TaskId, TASKS_EXTENSION};
use serde_json::{Value, json};

const CHILD_CASE: &str = "FASTMCP_TEST_OAUTH_TASK_WATCH_CASE";
// TEST ONLY, matching the existing public native OAuth fixtures. Trust is
// installed only in the isolated child, never the host's permanent store.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

#[derive(Clone, Copy)]
enum Case { Multi, CompletionRace, PartialAck, Interrupted, Cancel, SessionClose, Abandon, SnapshotLimit, WrongResponse, WrongTask, Precancel }

fn isolated(name: &str, case: Case) {
    if let Ok(selected) = std::env::var(CHILD_CASE) {
        assert_eq!(selected, name);
        run_case(case);
        return;
    }
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
    }
    let root = std::env::temp_dir().join(format!("fastmcp-task-watch-ca-{}-{name}.pem", std::process::id()));
    std::fs::write(&root, ROOT).unwrap();
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD_CASE, name).env("SSL_CERT_FILE", root).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "public Task watch case failed");
            return;
        }
        assert!(Instant::now() < deadline, "public Task watch exceeded its process bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let mut one = None;
    let mut two = None;
    poll_fn(|cx| {
        if one.is_none() { if let Poll::Ready(value) = left.as_mut().poll(cx) { one = Some(value); } }
        if two.is_none() { if let Poll::Ready(value) = right.as_mut().poll(cx) { two = Some(value); } }
        if one.is_some() && two.is_some() { Poll::Ready((one.take().unwrap(), two.take().unwrap())) }
        else { Poll::Pending }
    }).await
}

fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }
fn component(value: &str) -> String {
    let mut bytes = value.bytes();
    let mut result = Vec::new();
    while let Some(byte) = bytes.next() {
        result.push(match byte {
            b'+' => b' ',
            b'%' => {
                let high = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                let low = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                (high * 16 + low) as u8
            }
            byte => byte,
        });
    }
    String::from_utf8(result).unwrap()
}
fn form(value: &str) -> BTreeMap<String, String> {
    value.split('&').map(|field| {
        let (name, value) = field.split_once('=').unwrap();
        (component(name), component(value))
    }).collect()
}
async fn browser(authorization: CanonicalHttpUrl) -> Result<(), OAuthError> {
    let fields = form(authorization.query().unwrap());
    let address: SocketAddr = fields["redirect_uri"].strip_prefix("http://").unwrap()
        .split('/').next().unwrap().parse().unwrap();
    assert!(address.ip().is_loopback());
    assert_eq!(fields["code_challenge_method"], "S256");
    let mut socket = TcpStream::connect(address).await.map_err(|_| OAuthError::CallbackRejected)?;
    socket.write_all(format!(
        "GET /oauth/callback?code=watch-code&iss=https%3A%2F%2Fissuer.example&state={} HTTP/1.1\r\nHost: {address}\r\n\r\n",
        fields["state"],
    ).as_bytes()).await.map_err(|_| OAuthError::CallbackRejected)?;
    Ok(())
}

async fn read_request<IO: AsyncRead + Unpin>(socket: &mut IO) -> (String, Vec<u8>) {
    let mut bytes = Vec::new();
    let mut chunk = [0; 2048];
    let end = loop {
        let count = socket.read(&mut chunk).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 64 * 1024);
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(offset) = bytes.windows(4).position(|value| value == b"\r\n\r\n") { break offset + 4; }
    };
    let head = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
    let length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
    }).unwrap();
    assert!(end + length <= 64 * 1024);
    while bytes.len() < end + length {
        let count = socket.read(&mut chunk).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 64 * 1024);
        bytes.extend_from_slice(&chunk[..count]);
    }
    assert_eq!(bytes.len(), end + length);
    (head, bytes[end..].to_vec())
}
async fn reply(socket: &mut TlsStream<TcpStream>, value: Value) {
    let body = value.to_string();
    socket.write_all(format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len(),
    ).as_bytes()).await.unwrap();
    socket.shutdown().await.unwrap();
}
async fn event(socket: &mut TlsStream<TcpStream>, value: Value) {
    let body = format!("data: {value}\n\n");
    socket.write_all(format!("{:X}\r\n{body}\r\n", body.len()).as_bytes()).await.unwrap();
    socket.flush().await.unwrap();
}
async fn assert_closed(socket: &mut TlsStream<TcpStream>) {
    let mut byte = [0];
    assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0), "watch must release its owned subscription socket");
}
fn task(id: &str, status: &str) -> Value {
    json!({"taskId":id, "status":status, "createdAt":"2026-09-17T00:00:00Z",
        "lastUpdatedAt":"2026-09-17T00:00:00Z", "ttlMs":60000})
}
fn notification(id: &str, status: &str, subscription: &Value) -> Value {
    let mut params = task(id, status);
    params["_meta"] = json!({(FINAL_SUBSCRIPTION_ID_META_KEY):subscription});
    json!({"jsonrpc":"2.0", "method":"notifications/tasks", "params":params})
}

struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    gets: AtomicUsize,
    discoveries: AtomicUsize,
    listens: AtomicUsize,
    seen: Mutex<BTreeSet<String>>,
}
impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            acceptor: TlsAcceptorBuilder::new(CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap())
                .alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap(),
            gets: AtomicUsize::new(0), discoveries: AtomicUsize::new(0), listens: AtomicUsize::new(0),
            seen: Mutex::new(BTreeSet::new()),
        }
    }
    fn resource(&self) -> String { format!("https://{}/mcp", self.listener.local_addr().unwrap()) }
    fn client(&self) -> OAuthClient {
        OAuthClient::new(OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example", url("https://issuer.example/authorize"),
            url(&format!("https://{}/token", self.listener.local_addr().unwrap())),
            url(&self.resource()), "watch-client", vec!["tools:read".to_owned()],
        ).unwrap().with_extra_root_certificate(Certificate::from_pem(ROOT).unwrap().remove(0)).unwrap())
    }
    async fn receive(&self) -> (TlsStream<TcpStream>, String, Vec<u8>) {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut socket = self.acceptor.accept(socket).await.unwrap();
        let (head, bytes) = read_request(&mut socket).await;
        (socket, head, bytes)
    }
    async fn login(&self) {
        let (mut socket, head, bytes) = self.receive().await;
        assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
        assert!(!head.to_ascii_lowercase().contains("authorization:"));
        let fields = form(std::str::from_utf8(&bytes).unwrap());
        assert_eq!(fields["grant_type"], "authorization_code");
        assert_eq!(fields["client_id"], "watch-client");
        assert_eq!(fields["code"], "watch-code");
        assert_eq!(fields["resource"], self.resource());
        assert!((43..=128).contains(&fields["code_verifier"].len()));
        reply(&mut socket, json!({"access_token":"watch-access", "token_type":"Bearer", "expires_in":300})).await;
    }
    async fn request(&self, expected: &str) -> (TlsStream<TcpStream>, Value) {
        let (socket, head, bytes) = self.receive().await;
        assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
        let headers = head.to_ascii_lowercase();
        assert!(headers.contains("authorization: bearer watch-access\r\n"));
        assert!(!headers.contains("mcp-session-id:") && !headers.contains("last-event-id:"));
        let request: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(request["method"], expected, "watch must not poll, replay or mutate tasks");
        assert_eq!(request["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"], json!({TASKS_EXTENSION:{}}));
        assert!(self.seen.lock().unwrap().insert(request["id"].as_str().unwrap().to_owned()), "all requests in one watch need fresh IDs");
        (socket, request)
    }
    async fn discover(&self) {
        let (mut socket, request) = self.request("server/discover").await;
        self.discoveries.fetch_add(1, Ordering::SeqCst);
        reply(&mut socket, json!({"jsonrpc":"2.0", "id":request["id"], "result":{
            "resultType":"complete", "supportedVersions":["2026-07-28"], "ttlMs":0,
            "cacheScope":"private", "capabilities":{"extensions":{TASKS_EXTENSION:{}}},
        }})).await;
    }
    async fn listen(&self, selected: Value, partial: bool) -> (TlsStream<TcpStream>, Value) {
        self.discover().await;
        let (mut socket, request) = self.request("subscriptions/listen").await;
        self.listens.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request["params"]["notifications"], json!({"taskIds":selected}));
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
        let accepted = if partial { json!(["one"]) } else { selected };
        event(&mut socket, json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged", "params":{
            "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):request["id"]}, "notifications":{"taskIds":accepted},
        }})).await;
        (socket, request["id"].clone())
    }
    async fn get(&self, expected: &str, status: &str, case: Case) {
        self.discover().await;
        let (mut socket, request) = self.request("tasks/get").await;
        self.gets.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request["params"]["taskId"], expected);
        let mut result = task(if matches!(case, Case::WrongTask) { "other" } else { expected }, status);
        result["resultType"] = json!("complete");
        let id = if matches!(case, Case::WrongResponse) { json!("foreign-response") } else { request["id"].clone() };
        reply(&mut socket, json!({"jsonrpc":"2.0", "id":id, "result":result})).await;
    }
    fn no_extra_request(&self) {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(self.listener.poll_accept(&mut cx).is_pending(), "no hidden polling, replay or cancellation POST");
    }
}

fn run_case(case: Case) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let test = Box::pin(async {
            let peer = Peer::new().await;
            let ((), session) = pair(peer.login(), ManagedOAuthSession::authorize(
                &cx, peer.client(), OAuthSessionPolicy::default(), browser,
            )).await;
            let session = session.unwrap();
            let client = ManagedTasksClient::new(session.clone(), FinalRequestMeta::new(ClientCapabilities::default()), ManagedTasksLimits::default()).unwrap();
            let cancellation = McpRequestCancellation::new();
            let policy = ManagedTaskWatchPolicy::new(Duration::from_secs(10), if matches!(case, Case::SnapshotLimit) { 1 } else { 16 }, 32).unwrap();
            let selected = if matches!(case, Case::Multi | Case::PartialAck) { json!(["one", "two"]) } else { json!(["one"]) };
            let ids: Vec<TaskId> = serde_json::from_value(selected.clone()).unwrap();
            if matches!(case, Case::Precancel) {
                cancellation.cancel();
                assert!(matches!(Box::pin(client.watch_tasks_with_cancellation(&cx, &cancellation, ids, "watch".to_owned(), policy)).await,
                    Err(ManagedTaskWatchError::Session(OAuthSessionError::Cancelled))));
                peer.no_extra_request();
                assert_eq!(peer.discoveries.load(Ordering::SeqCst), 0);
                return;
            }
            let (release_tx, mut release_rx) = oneshot::channel::<()>();
            let server = Box::pin(async {
                let (mut stream, listen_id) = peer.listen(selected, matches!(case, Case::PartialAck)).await;
                if matches!(case, Case::PartialAck) { assert_closed(&mut stream).await; return; }
                let terminal = matches!(case, Case::CompletionRace | Case::WrongResponse | Case::WrongTask);
                peer.get("one", if terminal { "cancelled" } else { "working" }, case).await;
                if terminal { assert_closed(&mut stream).await; return; }
                if matches!(case, Case::Multi) { peer.get("two", "cancelled", case).await; }
                release_rx.recv(&cx).await.unwrap();
                peer.no_extra_request();
                match case {
                    Case::Multi => {
                        // An obsolete event for an already retired task must not
                        // cause a get or regress its delivered terminal state.
                        event(&mut stream, notification("two", "working", &listen_id)).await;
                        event(&mut stream, notification("one", "working", &listen_id)).await;
                        // The notification still said working. Only this newly
                        // authorized snapshot is allowed to complete task one.
                        peer.get("one", "cancelled", case).await;
                    }
                    Case::SnapshotLimit => { event(&mut stream, notification("one", "working", &listen_id)).await; }
                    Case::Interrupted => {
                        event(&mut stream, json!({"jsonrpc":"2.0", "id":listen_id, "result":{
                            "resultType":"complete", "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):listen_id},
                        }})).await;
                    }
                    _ => {},
                }
                assert_closed(&mut stream).await;
            });
            let application = Box::pin(async {
                let result = Box::pin(client.watch_tasks_with_cancellation(&cx, &cancellation, ids, "watch".to_owned(), policy)).await;
                if matches!(case, Case::PartialAck) {
                    assert!(matches!(result, Err(ManagedTaskWatchError::IncompleteAcknowledgement)));
                    return;
                }
                let mut watch = result.unwrap();
                let first = Box::pin(watch.next_snapshot(&cx)).await;
                if matches!(case, Case::WrongResponse | Case::WrongTask) {
                    match case {
                        Case::WrongResponse => assert!(matches!(first, Err(ManagedTaskWatchError::Task(ManagedTasksError::ResponseIdMismatch)))),
                        _ => assert!(matches!(first, Err(ManagedTaskWatchError::Task(ManagedTasksError::TaskIdMismatch)))),
                    }
                    assert_eq!(watch.remaining_tasks(), 1);
                    assert!(matches!(Box::pin(watch.next_snapshot(&cx)).await, Err(ManagedTaskWatchError::Closed)));
                    return;
                }
                let first = first.unwrap().unwrap();
                assert_eq!(first.cause, ManagedTaskSnapshotCause::Initial);
                assert_eq!(first.task.base().task_id, TaskId::parse("one").unwrap());
                if matches!(case, Case::CompletionRace) {
                    assert!(matches!(*first.task, Task::Cancelled(_)));
                    assert_eq!(watch.remaining_tasks(), 0);
                    assert!(Box::pin(watch.next_snapshot(&cx)).await.unwrap().is_none());
                    return;
                }
                assert!(matches!(*first.task, Task::Working(_)));
                if matches!(case, Case::Multi) {
                    let second = Box::pin(watch.next_snapshot(&cx)).await.unwrap().unwrap();
                    assert_eq!(second.cause, ManagedTaskSnapshotCause::Initial);
                    assert_eq!(second.task.base().task_id, TaskId::parse("two").unwrap());
                    assert!(matches!(*second.task, Task::Cancelled(_)));
                }
                assert_eq!(watch.remaining_tasks(), 1);
                let mut reading = Box::pin(watch.next_snapshot(&cx));
                poll_fn(|cx| {
                    assert!(reading.as_mut().poll(cx).is_pending(), "a quiet watch waits instead of polling");
                    Poll::Ready(())
                }).await;
                release_tx.send(&cx, ()).unwrap();
                match case {
                    Case::Cancel => { cancellation.cancel(); }
                    Case::SessionClose => session.close(),
                    _ => {},
                }
                if matches!(case, Case::Abandon) { drop(reading); }
                else {
                    let result = reading.await;
                    match case {
                        Case::Multi => {
                            let last = result.unwrap().unwrap();
                            assert_eq!(last.cause, ManagedTaskSnapshotCause::ChangeNotification);
                            assert_eq!(last.task.base().task_id, TaskId::parse("one").unwrap());
                            assert!(matches!(*last.task, Task::Cancelled(_)));
                            assert_eq!(watch.remaining_tasks(), 0);
                            assert!(Box::pin(watch.next_snapshot(&cx)).await.unwrap().is_none());
                        }
                        Case::SnapshotLimit => assert!(matches!(result, Err(ManagedTaskWatchError::SnapshotLimit))),
                        Case::Interrupted => assert!(matches!(result, Err(ManagedTaskWatchError::Interrupted))),
                        Case::Cancel => assert!(matches!(result, Err(ManagedTaskWatchError::Session(OAuthSessionError::Cancelled)))),
                        Case::SessionClose => assert!(matches!(result, Err(ManagedTaskWatchError::Session(OAuthSessionError::Closed)))),
                        _ => panic!("unexpected fixture branch"),
                    }
                }
                if !matches!(case, Case::Multi) {
                    assert_eq!(watch.remaining_tasks(), 1);
                    assert!(matches!(Box::pin(watch.next_snapshot(&cx)).await, Err(ManagedTaskWatchError::Closed)));
                }
                assert!(cx.checkpoint().is_ok(), "the watch cannot cancel its caller's context");
                if !matches!(case, Case::SessionClose) {
                    assert!(session.credential(&cx).await.is_ok(), "stopping a watch leaves its login usable");
                }
            });
            pair(server, application).await;
            let expected = if matches!(case, Case::PartialAck) { 0 } else if matches!(case, Case::Multi) { 3 } else { 1 };
            assert_eq!(peer.gets.load(Ordering::SeqCst), expected);
            assert_eq!(peer.discoveries.load(Ordering::SeqCst), expected + 1);
            assert_eq!(peer.listens.load(Ordering::SeqCst), 1);
            peer.no_extra_request();
        });
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), test)
            .await.expect("the complete public TLS watch must settle within its bound");
    });
}

#[test]
fn watch_reconciles_multiple_tasks_without_polling_or_stale_terminal_regression() {
    isolated("watch_reconciles_multiple_tasks_without_polling_or_stale_terminal_regression", Case::Multi);
}
#[test]
fn watch_observes_completion_between_acknowledgement_and_initial_snapshot() {
    isolated("watch_observes_completion_between_acknowledgement_and_initial_snapshot", Case::CompletionRace);
}
#[test]
fn watch_refuses_partial_acknowledgement_before_any_task_get() {
    isolated("watch_refuses_partial_acknowledgement_before_any_task_get", Case::PartialAck);
}
#[test]
fn subscription_terminal_is_not_success_for_unfinished_tasks() {
    isolated("subscription_terminal_is_not_success_for_unfinished_tasks", Case::Interrupted);
}
#[test]
fn cancelling_an_idle_watch_closes_only_observation_without_remote_cancel() {
    isolated("cancelling_an_idle_watch_closes_only_observation_without_remote_cancel", Case::Cancel);
}
#[test]
fn session_close_wakes_an_idle_watch_without_cancelling_the_caller() {
    isolated("session_close_wakes_an_idle_watch_without_cancelling_the_caller", Case::SessionClose);
}
#[test]
fn abandoning_a_polled_watch_read_drops_both_custody_and_reusability() {
    isolated("abandoning_a_polled_watch_read_drops_both_custody_and_reusability", Case::Abandon);
}
#[test]
fn watch_snapshot_limit_prevents_an_extra_discovery_or_get() {
    isolated("watch_snapshot_limit_prevents_an_extra_discovery_or_get", Case::SnapshotLimit);
}
#[test]
fn watch_rejects_a_foreign_response_identity_without_publishing_state() {
    isolated("watch_rejects_a_foreign_response_identity_without_publishing_state", Case::WrongResponse);
}
#[test]
fn watch_rejects_a_foreign_task_identity_without_publishing_state() {
    isolated("watch_rejects_a_foreign_task_identity_without_publishing_state", Case::WrongTask);
}
#[test]
fn precancelled_watch_never_discovers_or_subscribes() {
    isolated("precancelled_watch_never_discovers_or_subscribes", Case::Precancel);
}
