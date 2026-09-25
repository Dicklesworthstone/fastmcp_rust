//! Public OAuth watch/input composition over real loopback TLS. The issuer and
//! MCP peer are fixtures; the production login, HTTP, watch and driver are not
//! mocked. These tests are not external-IdP or aggregate conformance evidence.
// The MCP peer is trusted only through SSL_CERT_FILE in the isolated child,
// which the executor reads only with OS roots enabled (bd-poz5k).
#![cfg(all(feature = "tasks", feature = "native-tls-roots"))]

use std::collections::{BTreeMap, BTreeSet};
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream};
use fastmcp_client::http_auth::managed::{ManagedOAuthSession, OAuthSessionError, OAuthSessionPolicy};
use fastmcp_client::http_auth::managed::tasks::{ManagedTasksClient, ManagedTasksLimits};
use fastmcp_client::http_auth::managed::tasks::watch::{ManagedTaskWatchError, ManagedTaskWatchPolicy};
use fastmcp_client::http_auth::managed::tasks::watch::drive::{
    ManagedTaskDriverError, ManagedTaskInputAction, ManagedTaskRunOutcome,
    ManagedTaskWatchDriveError, ManagedTaskWatchDrivePolicy,
};
use fastmcp_client::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_SUBSCRIPTION_ID_META_KEY};
use fastmcp_protocol::tasks_extension::{Task, TaskId, TASKS_EXTENSION};
use serde_json::{Value, json};

const CHILD_CASE: &str = "FASTMCP_TEST_OAUTH_WATCH_DRIVE_CASE";
// TEST ONLY: the same isolated-child trust fixtures as oauth_task_watch.rs.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

#[derive(Clone, Copy)]
enum Case { Partial, SnapshotLimit, InvalidAnswer, CancelResolver, Observation, MissingCapability, LostAck, ChangedKey }

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
    let root = std::env::temp_dir().join(format!("fastmcp-watch-drive-ca-{}-{name}.pem", std::process::id()));
    std::fs::write(&root, ROOT).unwrap();
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD_CASE, name).env("SSL_CERT_FILE", root).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "public OAuth watch driver case failed");
            return;
        }
        assert!(Instant::now() < deadline, "public OAuth watch driver exceeded its process bound");
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
    assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0), "driver must release its subscription socket");
}
fn task(status: &str) -> Value {
    let mut task = json!({"taskId":"one", "status":status, "createdAt":"2026-09-17T00:00:00Z",
        "lastUpdatedAt":"2026-09-17T00:00:00Z", "ttlMs":60000, "resultType":"complete"});
    if status == "input_required" {
        task["inputRequests"] = json!({"first":{"method":"roots/list"},"second":{"method":"roots/list"}});
    } else if status == "completed" {
        task["result"] = json!({"content":[]});
    }
    task
}

struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    gets: AtomicUsize,
    updates: AtomicUsize,
    discoveries: AtomicUsize,
    seen: Mutex<BTreeSet<String>>,
}
impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            acceptor: TlsAcceptorBuilder::new(CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap())
                .alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap(),
            gets: AtomicUsize::new(0), updates: AtomicUsize::new(0), discoveries: AtomicUsize::new(0),
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
        assert_eq!(request["method"], expected, "no hidden polling, replay or remote cancellation");
        assert_eq!(request["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"], json!({TASKS_EXTENSION:{}}));
        assert!(self.seen.lock().unwrap().insert(request["id"].as_str().unwrap().to_owned()), "IDs must be unique across listen/get/update");
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
    async fn listen(&self) -> TlsStream<TcpStream> {
        self.discover().await;
        let (mut socket, request) = self.request("subscriptions/listen").await;
        assert_eq!(request["params"]["notifications"], json!({"taskIds":["one"]}));
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
        event(&mut socket, json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged", "params":{
            "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):request["id"]}, "notifications":{"taskIds":["one"]},
        }})).await;
        socket
    }
    async fn get(&self, result: Value) {
        self.discover().await;
        let (mut socket, request) = self.request("tasks/get").await;
        self.gets.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request["params"]["taskId"], "one");
        reply(&mut socket, json!({"jsonrpc":"2.0", "id":request["id"], "result":result})).await;
    }
    async fn update(&self, key: &str, lost_ack: bool) {
        self.discover().await;
        let (mut socket, request) = self.request("tasks/update").await;
        self.updates.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request["params"]["taskId"], "one");
        assert_eq!(request["params"]["inputResponses"], json!({key:{"roots":[]}}));
        if lost_ack { socket.shutdown().await.unwrap(); }
        else { reply(&mut socket, json!({"jsonrpc":"2.0", "id":request["id"], "result":{"resultType":"complete"}})).await; }
    }
    fn no_extra_request(&self) {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(self.listener.poll_accept(&mut cx).is_pending(), "no hidden POST after driver termination");
    }
}

struct DropProbe(Arc<AtomicUsize>);
impl Drop for DropProbe {
    fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
}

fn run_case(case: Case) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let test = Box::pin(async {
            let peer = Peer::new().await;
            let ((), session) = Box::pin(pair(peer.login(), ManagedOAuthSession::authorize(
                &cx, peer.client(), OAuthSessionPolicy::default(), browser,
            ))).await;
            let session = session.unwrap();
            let capabilities: ClientCapabilities = serde_json::from_value(
                if matches!(case, Case::MissingCapability) { json!({}) } else { json!({"roots":{}}) }
            ).unwrap();
            let client = ManagedTasksClient::new(session.clone(), FinalRequestMeta::new(capabilities), ManagedTasksLimits::default()).unwrap();
            let cancellation = McpRequestCancellation::new();
            let watch = ManagedTaskWatchPolicy::new(Duration::from_secs(10),
                if matches!(case, Case::SnapshotLimit) { 1 } else { 8 }, 16).unwrap();
            let policy = ManagedTaskWatchDrivePolicy::new(watch,
                if matches!(case, Case::Observation) { 0 } else { 4 }, 8, 65536).unwrap();
            let resolved = Mutex::new(Vec::<Vec<String>>::new());
            let observed = AtomicUsize::new(0);
            let dropped = Arc::new(AtomicUsize::new(0));
            let server = Box::pin(async {
                let mut stream = peer.listen().await;
                peer.get(task("input_required")).await;
                match case {
                    Case::Partial | Case::ChangedKey => {
                        peer.update("first", false).await;
                        // Deliberately emit NO notification. A partial answer
                        // leaves status unchanged and still requires a fresh get.
                        let mut next = task("input_required");
                        if matches!(case, Case::ChangedKey) {
                            next["inputRequests"]["second"] = json!({"method":"sampling/createMessage","params":{"messages":[],"maxTokens":1}});
                        }
                        peer.get(next).await;
                        if matches!(case, Case::Partial) {
                            peer.update("second", false).await;
                            peer.get(task("completed")).await;
                        }
                    }
                    Case::LostAck => peer.update("first", true).await,
                    _ => {},
                }
                assert_closed(&mut stream).await;
            });
            let application = Box::pin(async {
                let result = Box::pin(client.drive_task_watching_with_cancellation(
                    &cx, &cancellation, TaskId::parse("one").unwrap(), "driver".to_owned(), policy,
                    |requests| {
                        let keys: Vec<_> = requests.keys().cloned().collect();
                        let key = if matches!(case, Case::InvalidAnswer) { "foreign".to_owned() } else { keys[0].clone() };
                        resolved.lock().unwrap().push(keys);
                        let cancel = cancellation.clone();
                        let probe = DropProbe(dropped.clone());
                        async move {
                            let _probe = probe;
                            if matches!(case, Case::CancelResolver) {
                                poll_fn(|_| {
                                    cancel.cancel();
                                    Poll::<()>::Pending
                                }).await;
                            }
                            Ok(ManagedTaskInputAction::Respond(serde_json::from_value(json!({key:{"roots":[]}})).unwrap()))
                        }
                    },
                    |_| { observed.fetch_add(1, Ordering::SeqCst); Ok(()) },
                )).await;
                match case {
                    Case::Partial => assert!(matches!(result, Ok(ManagedTaskRunOutcome::Terminal(task)) if matches!(*task, Task::Completed { .. }))),
                    Case::Observation => assert!(matches!(result, Ok(ManagedTaskRunOutcome::InputRequired(_)))),
                    Case::SnapshotLimit => assert!(matches!(result, Err(ManagedTaskWatchDriveError::Watch(ManagedTaskWatchError::SnapshotLimit)))),
                    Case::InvalidAnswer => assert!(matches!(result, Err(ManagedTaskWatchDriveError::Input(ManagedTaskDriverError::InvalidInputResponse)))),
                    Case::CancelResolver => assert!(matches!(result, Err(ManagedTaskWatchDriveError::Watch(ManagedTaskWatchError::Session(OAuthSessionError::Cancelled))))),
                    Case::MissingCapability => assert!(matches!(result, Err(ManagedTaskWatchDriveError::Input(ManagedTaskDriverError::CapabilityNotAdvertised)))),
                    Case::ChangedKey => assert!(matches!(result, Err(ManagedTaskWatchDriveError::Input(ManagedTaskDriverError::InputKeyReused)))),
                    Case::LostAck => assert!(result.is_err(), "uncertain update must fail without replay"),
                }
                assert!(cx.checkpoint().is_ok(), "request cancellation cannot cancel the ambient Cx");
                assert!(session.credential(&cx).await.is_ok(), "stopping the driver leaves its login usable");
            });
            pair(server, application).await;
            let (gets, updates, callbacks) = match case {
                Case::Partial => (3, 2, 2),
                Case::ChangedKey => (2, 1, 1),
                Case::LostAck => (1, 1, 1),
                Case::Observation | Case::MissingCapability => (1, 0, 0),
                _ => (1, 0, 1),
            };
            assert_eq!(peer.gets.load(Ordering::SeqCst), gets);
            assert_eq!(peer.updates.load(Ordering::SeqCst), updates);
            assert_eq!(peer.discoveries.load(Ordering::SeqCst), 1 + gets + updates);
            assert_eq!(observed.load(Ordering::SeqCst), gets);
            assert_eq!(resolved.lock().unwrap().len(), callbacks);
            assert_eq!(dropped.load(Ordering::SeqCst), callbacks, "pending resolver must release owned state");
            if matches!(case, Case::Partial) {
                assert_eq!(*resolved.lock().unwrap(), vec![vec!["first".to_owned(), "second".to_owned()], vec!["second".to_owned()]]);
            }
            assert_eq!(peer.seen.lock().unwrap().len(), 2 * (1 + gets + updates));
            peer.no_extra_request();
        });
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), test)
            .await.expect("public OAuth watch driver must settle within its bound");
    });
}

#[test]
fn partial_input_updates_reconcile_without_notifications_and_never_repeat_answers() {
    isolated("partial_input_updates_reconcile_without_notifications_and_never_repeat_answers", Case::Partial);
}
#[test]
fn reconciliation_budget_is_reserved_before_any_input_update() {
    isolated("reconciliation_budget_is_reserved_before_any_input_update", Case::SnapshotLimit);
}
#[test]
fn invalid_host_answer_cannot_reach_the_remote_task() {
    isolated("invalid_host_answer_cannot_reach_the_remote_task", Case::InvalidAnswer);
}
#[test]
fn cancelling_a_pending_resolver_drops_it_without_remote_mutation() {
    isolated("cancelling_a_pending_resolver_drops_it_without_remote_mutation", Case::CancelResolver);
}
#[test]
fn observation_only_returns_input_without_invoking_the_host() {
    isolated("observation_only_returns_input_without_invoking_the_host", Case::Observation);
}
#[test]
fn missing_capability_rejects_before_host_input_or_mutation() {
    isolated("missing_capability_rejects_before_host_input_or_mutation", Case::MissingCapability);
}
#[test]
fn lost_update_acknowledgement_never_retries_or_reconciles_uncertain_effects() {
    isolated("lost_update_acknowledgement_never_retries_or_reconciles_uncertain_effects", Case::LostAck);
}
#[test]
fn changed_unanswered_key_after_partial_update_never_reaches_the_host_again() {
    isolated("changed_unanswered_key_after_partial_update_never_reaches_the_host_again", Case::ChangedKey);
}

#[path = "oauth_task_watch_drive/journal.rs"]
mod journal;
