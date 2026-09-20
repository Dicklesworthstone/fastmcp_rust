//! Real loopback HTTPS composition using a pre-acquired machine credential.
//! No production transport, watcher, input ledger or decoder is mocked. Issuer
//! discovery and grant acquisition are deliberately outside these test cases.
use super::*;
use std::collections::BTreeSet;
use std::future::poll_fn;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::tls::{CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::FINAL_SUBSCRIPTION_ID_META_KEY;
use crate::http_auth::BoundBearerCredential;
use crate::http_auth::discovery::client_credentials::{CLIENT_CREDENTIALS_EXTENSION, ServiceToken};
use crate::http_auth::discovery::client_credentials::tasks::subscriptions::watch::ManagedTaskSnapshotCause;
use fastmcp_protocol::tasks_extension::TASKS_EXTENSION;

const CHILD: &str = "FASTMCP_TEST_MACHINE_WATCH_DRIVE_CASE";
// TEST ONLY. Same non-production localhost identity as the existing public
// OAuth TLS fixtures; its CA is installed only in an isolated child process.
// All three are inlined rather than read from `tests/fixtures/`: the remote
// build worker never receives `*.pem`, so `include_bytes!` made this target
// unbuildable there. `tests/oauth_interaction.rs` states the rule for this
// feature - no external fixture asset must be copied to the RCH worker.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

#[derive(Clone, Copy)]
enum Case { PartialInputs, RejectUpdate, CancelResolver, ObservationOnly, PartialAck, Multi, Abandon }

fn isolated(name: &str, case: Case) {
    let name = format!("{}::{name}", module_path!().split_once("::").unwrap().1);
    if let Ok(selected) = std::env::var(CHILD) {
        assert_eq!(selected, name);
        run(case);
        return;
    }
    struct Root(std::path::PathBuf);
    impl Drop for Root { fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); } }
    struct Child(std::process::Child);
    impl Drop for Child { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    let root = Root(std::env::temp_dir().join(format!("fastmcp-machine-watch-{}-{}.pem", std::process::id(), name.rsplit("::").next().unwrap())));
    std::fs::write(&root.0, ROOT).unwrap();
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--nocapture", "--test-threads=1"])
        .env(CHILD, &name).env("SSL_CERT_FILE", &root.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() { assert!(status.success()); return; }
        assert!(Instant::now() < deadline, "machine watch TLS child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let (mut one, mut two) = (None, None);
    poll_fn(|cx| {
        if one.is_none() { if let Poll::Ready(value) = left.as_mut().poll(cx) { one = Some(value); } }
        if two.is_none() { if let Poll::Ready(value) = right.as_mut().poll(cx) { two = Some(value); } }
        if one.is_some() && two.is_some() { Poll::Ready((one.take().unwrap(), two.take().unwrap())) }
        else { Poll::Pending }
    }).await
}
async fn request(socket: &mut TlsStream<TcpStream>) -> (String, serde_json::Value) {
    let mut bytes = Vec::new();
    let mut chunk = [0; 2048];
    let end = loop {
        let n = socket.read(&mut chunk).await.unwrap();
        assert!(n > 0 && bytes.len() + n <= 64 * 1024);
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(offset) = bytes.windows(4).position(|v| v == b"\r\n\r\n") { break offset + 4; }
    };
    let head = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
    let size = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
    }).unwrap();
    assert!(end + size <= 64 * 1024);
    while bytes.len() < end + size {
        let n = socket.read(&mut chunk).await.unwrap();
        assert!(n > 0 && bytes.len() + n <= 64 * 1024);
        bytes.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(bytes.len(), end + size);
    (head, serde_json::from_slice(&bytes[end..]).unwrap())
}
async fn reply(socket: &mut TlsStream<TcpStream>, value: serde_json::Value) {
    let body = value.to_string();
    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
    socket.shutdown().await.unwrap();
}
async fn event(socket: &mut TlsStream<TcpStream>, value: serde_json::Value) {
    let body = format!("data: {value}\n\n");
    socket.write_all(format!("{:X}\r\n{body}\r\n",body.len()).as_bytes()).await.unwrap();
    socket.flush().await.unwrap();
}
async fn closed(socket: &mut TlsStream<TcpStream>) {
    let mut byte = [0];
    assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0), "subscription must be released");
}
fn task(id: &str, status: &str) -> serde_json::Value {
    let mut task = json!({"taskId":id,"status":status,"createdAt":"2026-09-19T00:00:00Z",
        "lastUpdatedAt":"2026-09-19T00:00:00Z","ttlMs":60000});
    if status == "input_required" { task["inputRequests"] = serde_json::to_value(two()).unwrap(); }
    task
}
struct Peer { listener: TcpListener, tls: TlsAcceptor, seen: Mutex<BTreeSet<String>>, updates: AtomicUsize }
impl Peer {
    async fn new() -> Self {
        Self { listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            tls: TlsAcceptorBuilder::new(CertificateChain::from_pem(LEAF).unwrap(),PrivateKey::from_pem(KEY).unwrap())
                .alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap(),
            seen: Mutex::new(BTreeSet::new()), updates: AtomicUsize::new(0) }
    }
    fn client(&self) -> ClientCredentialsTasksClient {
        let mut client = consumer();
        let inner = Arc::get_mut(&mut client.client.inner).unwrap();
        inner.resource = CanonicalHttpUrl::parse(&format!("https://{}/mcp",self.listener.local_addr().unwrap())).unwrap();
        let expires_at = Instant::now() + Duration::from_secs(600);
        let bearer = BoundBearerCredential::bind_with_expiry(inner.resource.clone(),"watched-access",expires_at)
            .unwrap().for_owner(&inner.closed).unwrap();
        let mut state = inner.state.try_lock_owned().unwrap();
        state.current = Some(ServiceToken { bearer, scopes:vec![], expires_at, renew_after:expires_at });
        state.generation = 7;
        drop(state);
        client.metadata[FINAL_CLIENT_CAPABILITIES_META_KEY]["roots"] = json!({"listChanged":true});
        client
    }
    async fn rpc(&self, method: &str) -> (TlsStream<TcpStream>, serde_json::Value) {
        let (socket,_) = self.listener.accept().await.unwrap();
        let mut socket = self.tls.accept(socket).await.unwrap();
        let (head, request) = request(&mut socket).await;
        assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
        let headers = head.to_ascii_lowercase();
        assert!(headers.contains("authorization: bearer watched-access\r\n"));
        assert!(!headers.contains("mcp-session-id:") && !headers.contains("last-event-id:"));
        assert_eq!(request["method"], method);
        assert_eq!(request["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],
            json!({TASKS_EXTENSION:{},CLIENT_CREDENTIALS_EXTENSION:{}}));
        assert!(self.seen.lock().unwrap().insert(request["id"].as_str().unwrap().to_owned()));
        (socket,request)
    }
    async fn discover(&self) {
        let (mut socket, request) = self.rpc("server/discover").await;
        reply(&mut socket,json!({"jsonrpc":"2.0","id":request["id"],"result":{
            "resultType":"complete","supportedVersions":["2026-07-28"],"ttlMs":0,"cacheScope":"private",
            "capabilities":{"extensions":{TASKS_EXTENSION:{},CLIENT_CREDENTIALS_EXTENSION:{}}}}})).await;
    }
    async fn listen(&self, selected: serde_json::Value, partial: bool) -> (TlsStream<TcpStream>,serde_json::Value) {
        self.discover().await;
        let (mut socket, request) = self.rpc("subscriptions/listen").await;
        assert_eq!(request["params"]["notifications"],json!({"taskIds":selected}));
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
        let accepted = if partial { json!(["one"]) } else { selected };
        event(&mut socket,json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{
            "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):request["id"]},"notifications":{"taskIds":accepted}}})).await;
        (socket,request["id"].clone())
    }
    async fn get(&self, id: &str, status: &str) {
        self.discover().await;
        let (mut socket,request) = self.rpc("tasks/get").await;
        assert_eq!(request["params"]["taskId"],id);
        let mut result = task(id,status);
        result["resultType"] = json!("complete");
        reply(&mut socket,json!({"jsonrpc":"2.0","id":request["id"],"result":result})).await;
    }
    async fn update(&self, key: &str, reject: bool) {
        self.discover().await;
        let (mut socket,request) = self.rpc("tasks/update").await;
        assert_eq!(request["params"]["taskId"],"one");
        assert_eq!(request["params"]["inputResponses"],json!({key:{"roots":[]}}));
        self.updates.fetch_add(1,Ordering::SeqCst);
        let response = if reject { json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32603,"message":"private-peer-detail"}}) }
            else { json!({"jsonrpc":"2.0","id":request["id"],"result":{"resultType":"complete"}}) };
        reply(&mut socket,response).await;
    }
    fn quiet(&self) {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(self.listener.poll_accept(&mut cx).is_pending(), "unexpected polling, retry or mutation");
    }
}

fn run(case: Case) {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let scenario = async {
            let peer = Peer::new().await;
            let client = peer.client();
            let cancel = McpRequestCancellation::new();
            let watch_policy = ClientCredentialsTaskWatchPolicy::new(Duration::from_secs(10),16,32).unwrap();
            let watching = matches!(case,Case::PartialAck|Case::Multi|Case::Abandon);
            let multi = matches!(case,Case::PartialAck|Case::Multi);
            let selected = if multi { json!(["one","two"]) } else { json!(["one"]) };
            let server = async {
                let (mut stream,listen_id) = peer.listen(selected.clone(),matches!(case,Case::PartialAck)).await;
                if matches!(case,Case::PartialAck) { closed(&mut stream).await; peer.quiet(); return; }
                if watching {
                    peer.get("one","working").await;
                    if multi {
                        peer.get("two","cancelled").await;
                        for id in ["two","one"] {
                            let mut notice = task(id,"working");
                            notice["_meta"] = json!({(FINAL_SUBSCRIPTION_ID_META_KEY):listen_id});
                            event(&mut stream,json!({"jsonrpc":"2.0","method":"notifications/tasks","params":notice})).await;
                        }
                        peer.get("one","cancelled").await;
                    }
                } else {
                    peer.get("one","input_required").await;
                    if matches!(case,Case::PartialInputs|Case::RejectUpdate) {
                        peer.update("one",matches!(case,Case::RejectUpdate)).await;
                        if matches!(case,Case::PartialInputs) {
                            // Deliberately no notifications, and a stale snapshot
                            // still containing the acknowledged first input key.
                            peer.get("one","input_required").await;
                            peer.update("two",false).await;
                            peer.get("one","cancelled").await;
                        }
                    }
                }
                closed(&mut stream).await;
                peer.quiet();
            };
            let application = async {
                if watching {
                    let ids = serde_json::from_value(selected.clone()).unwrap();
                    let opened = Box::pin(client.watch_tasks(&cx,ids,"watch".to_owned(),watch_policy)).await;
                    if matches!(case,Case::PartialAck) {
                        assert!(matches!(opened,Err(ClientCredentialsTaskWatchError::IncompleteAcknowledgement)));
                        return;
                    }
                    let mut watch = opened.unwrap();
                    // The ordinary client would now renew. Protected watch reads
                    // must keep their original token and perform no token POST.
                    client.client.inner.state.try_lock_owned().unwrap().current.as_mut().unwrap().renew_after = Instant::now();
                    assert_eq!(watch.credential_generation(),7);
                    assert_eq!(watch.next_snapshot(&cx).await.unwrap().unwrap().cause,ManagedTaskSnapshotCause::Initial);
                    if multi {
                        assert!(matches!(*watch.next_snapshot(&cx).await.unwrap().unwrap().task,Task::Cancelled(_)));
                        let final_snapshot = watch.next_snapshot(&cx).await.unwrap().unwrap();
                        assert_eq!(final_snapshot.cause,ManagedTaskSnapshotCause::ChangeNotification);
                        assert!(matches!(*final_snapshot.task,Task::Cancelled(_)));
                        assert_eq!(watch.remaining_tasks(),0);
                        assert!(watch.next_snapshot(&cx).await.unwrap().is_none());
                    } else {
                        let mut next = Box::pin(watch.next_snapshot(&cx));
                        poll_fn(|cx| { assert!(next.as_mut().poll(cx).is_pending()); Poll::Ready(()) }).await;
                        drop(next);
                        assert!(matches!(watch.next_snapshot(&cx).await,Err(ClientCredentialsTaskWatchError::Closed)));
                    }
                    return;
                }
                let policy = ClientCredentialsTaskWatchDrivePolicy::new(watch_policy,
                    if matches!(case,Case::ObservationOnly) {0} else {8},8,4096).unwrap();
                let mut resolutions = 0;
                let mut snapshots = 0;
                let result = Box::pin(client.drive_task_watching_with_cancellation(&cx,&cancel,TaskId::parse("one").unwrap(),"drive".to_owned(),policy,
                    |pending| {
                        assert!(!matches!(case,Case::ObservationOnly));
                        resolutions += 1;
                        assert_eq!(pending.len(),if resolutions == 1 {2} else {1});
                        let key = if resolutions == 1 {"one"} else {"two"};
                        assert!(pending.contains_key(key));
                        if resolutions == 2 { assert!(!pending.contains_key("one")); }
                        if matches!(case,Case::CancelResolver) { cancel.cancel(); }
                        std::future::ready(Ok(ManagedTaskInputAction::Respond(answers(json!({key:{"roots":[]}})))))
                    }, |_| { snapshots += 1; Ok(()) })).await;
                match case {
                    Case::PartialInputs => {
                        assert!(matches!(result,Ok(ManagedTaskRunOutcome::Terminal(task)) if matches!(*task,Task::Cancelled(_))));
                        assert_eq!((resolutions,snapshots),(2,3));
                    }
                    Case::ObservationOnly => {
                        assert!(matches!(result,Ok(ManagedTaskRunOutcome::InputRequired(_))));
                        assert_eq!((resolutions,snapshots),(0,1));
                    }
                    Case::CancelResolver => { assert!(result.is_err()); assert_eq!((resolutions,snapshots),(1,1)); }
                    Case::RejectUpdate => {
                        let Err(error) = result else { panic!("rejected update cannot succeed"); };
                        assert!(!format!("{error:?} {error}").contains("private-peer-detail"));
                        assert_eq!((resolutions,snapshots),(1,1));
                    }
                    _ => unreachable!(),
                }
            };
            Box::pin(pair(server,application)).await;
            assert_eq!(peer.updates.load(Ordering::SeqCst), match case { Case::PartialInputs=>2,Case::RejectUpdate=>1,_=>0 });
        };
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(15_000_000_000),Box::pin(scenario)).await.unwrap();
    });
}

#[test]
fn tls_partial_inputs_progress_without_notifications() { isolated("tls_partial_inputs_progress_without_notifications",Case::PartialInputs); }
#[test]
fn tls_rejected_update_is_never_replayed() { isolated("tls_rejected_update_is_never_replayed",Case::RejectUpdate); }
#[test]
fn tls_resolver_cancellation_prevents_update() { isolated("tls_resolver_cancellation_prevents_update",Case::CancelResolver); }
#[test]
fn tls_observation_only_never_resolves_input() { isolated("tls_observation_only_never_resolves_input",Case::ObservationOnly); }
#[test]
fn tls_partial_ack_prevents_initial_gets() { isolated("tls_partial_ack_prevents_initial_gets",Case::PartialAck); }
#[test]
fn tls_multiple_tasks_use_one_credential_and_ignore_late_terminals() { isolated("tls_multiple_tasks_use_one_credential_and_ignore_late_terminals",Case::Multi); }
#[test]
fn tls_abandoned_watch_read_releases_socket() { isolated("tls_abandoned_watch_read_releases_socket",Case::Abandon); }
