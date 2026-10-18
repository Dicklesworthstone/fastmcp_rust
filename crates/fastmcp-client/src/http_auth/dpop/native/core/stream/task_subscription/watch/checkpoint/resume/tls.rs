//! Real loopback TLS and protected-file adapter recovery, not provider/crypto
//! qualification. The identity below is the existing public TEST ONLY fixture.
//! Private roots are installed only on the selected DPoP client.

use super::*;
use super::tests::{binding, record, snapshot};
use std::collections::BTreeSet;
use std::future::{Future, poll_fn};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{Runtime, RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream};
use fastmcp_protocol::{ClientCapabilities, FINAL_PROTOCOL_VERSION};
use fastmcp_protocol::dpop::DpopKey;
use fastmcp_protocol::tasks_extension::TASKS_EXTENSION;
use serde_json::{Value, json};
use crate::http_auth::dpop::DpopSession;
use crate::http_auth::dpop::native::DpopHttpPolicy;

const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";
const SSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nDPoP-Nonce: next\r\nConnection: close\r\n\r\n";

fn runtime() -> Runtime {
    RuntimeBuilder::current_thread().blocking_threads(0, 0)
        .with_reactor(create_reactor().unwrap()).build().unwrap()
}
fn run(future: impl Future<Output = ()>) {
    let rt = runtime();
    rt.block_on(async {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(15_000_000_000), future)
            .await.expect("protected recovery must settle before its 30-second native budget");
    });
    assert!(rt.shutdown_timeout(Duration::from_secs(1)));
}
async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let (mut a, mut b) = (None, None);
    poll_fn(|cx| {
        if a.is_none() { if let Poll::Ready(value) = left.as_mut().poll(cx) { a = Some(value); } }
        if b.is_none() { if let Poll::Ready(value) = right.as_mut().poll(cx) { b = Some(value); } }
        if a.is_some() && b.is_some() { Poll::Ready((a.take().unwrap(), b.take().unwrap())) }
        else { Poll::Pending }
    }).await
}
fn meta() -> FinalRequestMeta {
    let mut value = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    value["progressToken"] = json!("work");
    serde_json::from_value(value).unwrap()
}
fn limits() -> DpopStreamLimits {
    DpopStreamLimits::new(
        crate::http_auth::rpc::ManagedCoreLimits::new(8192, 8192, 32768, 4, Duration::from_secs(30)).unwrap(),
        Duration::from_secs(30),
    ).unwrap()
}
fn envelope(prefix: &str, discovery: bool, result: Value) -> Vec<u8> {
    let suffix = if discovery { "discover" } else { "get" };
    serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":format!("{prefix}.0.{suffix}"), "result":result})).unwrap()
}
fn progress() -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0", "method":"notifications/progress",
        "params":{"progressToken":"work", "progress":1}})).unwrap()
}
fn event(bytes: &[u8]) -> Vec<u8> {
    let mut data = b"data: ".to_vec();
    data.extend_from_slice(bytes);
    data.extend_from_slice(b"\n\n");
    let mut wire = format!("{:X}\r\n", data.len()).into_bytes();
    wire.extend_from_slice(&data);
    wire.extend_from_slice(b"\r\n");
    wire
}
async fn json_reply(socket: &mut TlsStream<TcpStream>, status: u16, bytes: &[u8]) {
    let mut wire = format!("HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nDPoP-Nonce: next\r\nConnection: close\r\n\r\n", bytes.len()).into_bytes();
    wire.extend_from_slice(bytes);
    socket.write_all(&wire).await.unwrap();
    let _ = socket.shutdown().await;
}
async fn closed(socket: &mut TlsStream<TcpStream>) {
    let cx = Cx::current().unwrap();
    let mut byte = [0];
    let result = asupersync::time::timeout_at(cx.now().saturating_add_nanos(8_000_000_000), socket.read(&mut byte))
        .await.expect("owned response socket must retire before the native deadline");
    assert!(matches!(result, Ok(0) | Err(_)));
}

struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    proofs: BTreeSet<String>,
}
impl Peer {
    async fn new() -> (Self, DpopHttpClient, DpopCredential) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = fastmcp_core::CanonicalHttpUrl::parse(&format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap())).unwrap();
        let issuer = fastmcp_core::CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
        let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(), endpoint).unwrap();
        let credential = session.admit_token_response(&issuer, 200,
            br#"{"access_token":"protected-test-token","token_type":"DPoP","expires_in":120}"#,
            Instant::now(), Duration::from_secs(120)).unwrap();
        let root = Certificate::from_pem(ROOT).unwrap().remove(0);
        let client = DpopHttpClient::new(session, DpopHttpPolicy::default()
            .with_resource_root_der(root.as_der().to_vec()).unwrap()).unwrap();
        let acceptor = TlsAcceptorBuilder::new(CertificateChain::from_pem(LEAF).unwrap(),
            PrivateKey::from_pem(KEY).unwrap()).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();
        (Self { listener, acceptor, proofs: BTreeSet::new() }, client, credential)
    }
    async fn request(&mut self, prefix: &str, discovery: bool) -> TlsStream<TcpStream> {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut socket = self.acceptor.accept(socket).await.unwrap();
        let mut bytes = Vec::new();
        let mut block = [0; 2048];
        let end = loop {
            let n = socket.read(&mut block).await.unwrap();
            assert!(n > 0 && bytes.len() + n <= 32768);
            bytes.extend_from_slice(&block[..n]);
            if let Some(n) = bytes.windows(4).position(|b| b == b"\r\n\r\n") { break n + 4; }
        };
        let head = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
        let header = |name: &str| -> String {
            let values: Vec<_> = head.lines().filter_map(|line| line.split_once(':'))
                .filter(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()).collect();
            assert_eq!(values.len(), 1);
            values[0].to_owned()
        };
        let length = header("content-length").parse::<usize>().unwrap();
        assert!(end + length <= 32768);
        while bytes.len() < end + length {
            let n = socket.read(&mut block).await.unwrap();
            assert!(n > 0 && bytes.len() + n <= end + length);
            bytes.extend_from_slice(&block[..n]);
        }
        assert_eq!(bytes.len(), end + length);
        let body: Value = serde_json::from_slice(&bytes[end..]).unwrap();
        let method = if discovery { "server/discover" } else { "tasks/get" };
        let suffix = if discovery { "discover" } else { "get" };
        assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
        assert_eq!(header("authorization"), "DPoP protected-test-token");
        assert_eq!(header("mcp-method"), method);
        assert_eq!(body["method"], method, "recovery must not create, update or cancel");
        assert_eq!(body["id"], format!("{prefix}.0.{suffix}"));
        assert_eq!(header("accept"), if discovery { "application/json" } else { "application/json, text/event-stream" });
        assert!(!header("dpop").is_empty());
        assert!(self.proofs.insert(header("dpop")), "each request needs a fresh proof");
        if discovery { assert!(body["params"].get("taskId").is_none()); }
        else { assert_eq!(body["params"]["taskId"], "task-secret"); }
        assert!(body["params"].get("inputResponses").is_none());
        socket
    }
    async fn get(&mut self, prefix: &str) -> TlsStream<TcpStream> {
        let mut discovery = self.request(prefix, true).await;
        let offer = json!({"resultType":"complete", "supportedVersions":[FINAL_PROTOCOL_VERSION],
            "capabilities":{"tools":{},"extensions":{TASKS_EXTENSION:{}}}, "ttlMs":0,"cacheScope":"private",
            "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"protected-peer","version":"1"}}});
        json_reply(&mut discovery, 200, &envelope(prefix, true, offer)).await;
        self.request(prefix, false).await
    }
    fn no_extra(&self, expected: usize) {
        assert_eq!(self.proofs.len(), expected);
        assert!(self.listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
    }
}

#[test]
fn protected_live_json_and_incremental_sse_return_controls_without_losing_metadata() {
    for streamed in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let current = binding("owner", client.resource().as_str());
            let saved = record(&cx, &current);
            let bytes = saved.encode().unwrap();
            let cancellation = McpRequestCancellation::new();
            let observed = McpRequestCancellation::new();
            let mut notifications = 0;
            let expected = serde_json::to_value(snapshot("input_required", 2)).unwrap();
            let call = client.reconcile_task_resume_with_events(&cx, &cancellation, &credential,
                meta(), &current, &saved, "live", limits(), |_| {
                    notifications += 1;
                    observed.cancel();
                    true
                });
            let server = async {
                let mut socket = peer.get("live").await;
                let terminal = envelope("live", false, expected.clone());
                if streamed {
                    socket.write_all(SSE).await.unwrap();
                    socket.write_all(&event(&progress())).await.unwrap();
                    observed.cancelled().await; // terminal does not exist before callback
                    let mut tail = event(&terminal);
                    tail.extend_from_slice(b"0\r\n\r\n");
                    socket.write_all(&tail).await.unwrap();
                    let _ = socket.shutdown().await;
                } else { json_reply(&mut socket, 200, &terminal).await; }
            };
            let (result, ()) = pair(call, server).await;
            let result = result.unwrap();
            assert_eq!(serde_json::to_value(result.snapshot()).unwrap(), expected);
            assert_eq!(result.change().previous(), &saved);
            assert!(result.change().replacement().is_some());
            assert!(result.selection().is_some());
            assert_eq!(notifications, usize::from(streamed));
            assert_eq!(saved.encode().unwrap(), bytes);
            peer.no_extra(2);
            assert!(!client.revocation_handle().is_revoked());
        });
    }
}

#[test]
fn protected_retention_retires_stalled_get_without_extending_or_revoking_login() {
    for body_started in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let current = binding("owner", client.resource().as_str());
            let saved = TaskResumeRecord::capture(&cx, &current, &snapshot("working", 1).task,
                Duration::from_secs(3)).unwrap();
            let cancellation = McpRequestCancellation::new();
            let call = client.reconcile_task_resume(&cx, &cancellation, &credential,
                meta(), &current, &saved, "expiry", limits());
            let server = async {
                let mut socket = peer.get("expiry").await;
                if body_started { socket.write_all(SSE).await.unwrap(); }
                closed(&mut socket).await;
            };
            let (result, ()) = pair(call, server).await;
            assert!(matches!(result, Err(DpopTaskResumeError::Resume(TaskResumeError::Unavailable))));
            peer.no_extra(2);
            let fresh = record(&cx, &current);
            let call = client.reconcile_task_resume(&cx, &cancellation, &credential,
                meta(), &current, &fresh, "followup", limits());
            let server = async {
                let mut socket = peer.get("followup").await;
                json_reply(&mut socket, 200, &envelope("followup", false,
                    serde_json::to_value(snapshot("working", 2)).unwrap())).await;
            };
            assert!(pair(call, server).await.0.is_ok(), "retention ends only its owned read");
            peer.no_extra(4);
        });
    }
}

#[test]
fn protected_unavailable_http_statuses_never_trigger_recreation_or_refresh() {
    for discovery in [false, true] {
        for status in [401, 403, 404, 500] {
            run(async {
                let cx = Cx::current().unwrap();
                let (mut peer, mut client, credential) = Peer::new().await;
                let current = binding("owner", client.resource().as_str());
                let saved = record(&cx, &current);
                let cancellation = McpRequestCancellation::new();
                let call = client.reconcile_task_resume(&cx, &cancellation, &credential,
                    meta(), &current, &saved, "refused", limits());
                let server = async {
                    let mut socket = if discovery { peer.request("refused", true).await }
                        else { peer.get("refused").await };
                    json_reply(&mut socket, status, b"{}").await;
                };
                let (result, ()) = pair(call, server).await;
                assert_eq!(matches!(&result, Err(DpopTaskResumeError::Resume(TaskResumeError::Unavailable))), status != 500);
                assert!(result.is_err());
                peer.no_extra(if discovery { 1 } else { 2 });
            });
        }
    }
}

#[test]
fn protected_provisional_or_regressed_snapshots_leave_saved_controls_unchanged() {
    for case in 0..4 {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let current = binding("owner", client.resource().as_str());
            let saved = record(&cx, &current);
            let original = saved.encode().unwrap();
            let cancellation = McpRequestCancellation::new();
            let call = client.reconcile_task_resume(&cx, &cancellation, &credential,
                meta(), &current, &saved, "tail", limits());
            let server = async {
                let mut socket = peer.get("tail").await;
                let terminal = envelope("tail", false, serde_json::to_value(snapshot("working", if case == 3 { 0 } else { 2 })).unwrap());
                let mut wire = SSE.to_vec();
                wire.extend_from_slice(&event(&terminal));
                if case == 1 { wire.extend_from_slice(&event(&terminal)); }
                if case != 2 { wire.extend_from_slice(b"0\r\n\r\n"); }
                socket.write_all(&wire).await.unwrap();
                let _ = socket.shutdown().await;
            };
            let (result, ()) = pair(call, server).await;
            assert_eq!(result.is_ok(), case == 0);
            assert_eq!(saved.encode().unwrap(), original);
            peer.no_extra(2);
        });
    }
}

#[test]
fn protected_notification_stops_keep_storage_and_cancellation_domains_separate() {
    for stop in 0..5 {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let current = binding("owner", client.resource().as_str());
            let saved = record(&cx, &current);
            let original = saved.encode().unwrap();
            let cancellation = McpRequestCancellation::new();
            let session = client.revocation_handle();
            let mut delivered = 0;
            let call = client.reconcile_task_resume_with_events(&cx, &cancellation, &credential,
                meta(), &current, &saved, "stop", limits(), |_| {
                    delivered += 1;
                    match stop {
                        1 => { cancellation.cancel(); }
                        2 => { credential.revoke(); }
                        3 => { session.revoke(); }
                        4 => panic!("fixture observer failure"),
                        _ => {}
                    }
                    false
                });
            let server = async {
                let mut socket = peer.get("stop").await;
                let mut wire = SSE.to_vec();
                wire.extend_from_slice(&event(&progress()));
                socket.write_all(&wire).await.unwrap();
                closed(&mut socket).await;
            };
            let (result, ()) = pair(call, server).await;
            assert_eq!(delivered, 1);
            let DpopTaskResumeError::Checkpoint(DpopTaskCheckpointError::Watch(
                DpopTaskWatchError::Stream(error),
            )) = result.unwrap_err() else { panic!("expected an owned stream failure"); };
            assert!(match stop {
                0 => matches!(error, DpopStreamError::ObserverStopped),
                4 => matches!(error, DpopStreamError::ObserverPanicked),
                1 => matches!(error, DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled))),
                2 | 3 => matches!(error, DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Authorization(_)))),
                _ => false,
            });
            assert_eq!(saved.encode().unwrap(), original);
            assert_eq!(session.is_revoked(), stop == 3);
            assert!(cx.checkpoint().is_ok());
            peer.no_extra(2);
        });
    }
}

#[cfg(target_os = "linux")]
mod persistence {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicU64, Ordering};
    use fastmcp_core::runtime::ProcessGenerationGuard;
    use crate::http_auth::secure_file::SecureAtomicFile;
    use crate::http_auth::managed::tasks::watch::checkpoint::resume::store::{
        TaskResumeProtector, TaskResumeStore, TaskResumeStoreLimits,
    };

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            for _ in 0..64 {
                let path = std::env::temp_dir().join(format!("fastmcp-dpop-resume-{}-{}",
                    std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("private fixture directory failed: {error}"),
                }
            }
            panic!("private fixture name bound exceeded");
        }
        fn file(&self, cx: &Cx) -> SecureAtomicFile {
            SecureAtomicFile::open(cx, File::open(&self.0).unwrap(), "tasks", 65536).unwrap()
        }
        fn bytes(&self) -> Vec<u8> { fs::read(self.0.join("tasks")).unwrap() }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            // Only the fixture's create-new directory and fixed owned names.
            let _ = fs::remove_file(self.0.join("tasks"));
            let _ = fs::remove_file(self.0.join(".tasks.lock"));
            let _ = fs::remove_dir(&self.0);
        }
    }

    // Bounded in-process reference vault. NOT encryption or cross-process key
    // persistence: this test qualifies the actual file/API bridge, not a host
    // protection provider. The production store still requires a real protector.
    #[derive(Default)]
    struct VaultState {
        next: u64,
        entries: BTreeMap<Vec<u8>, ([u8; 32], Vec<u8>)>,
    }
    #[derive(Clone, Default)]
    struct Vault(Arc<Mutex<VaultState>>);
    impl TaskResumeProtector for Vault {
        fn profile(&self) -> [u8; 32] { [4; 32] }
        fn seal(&mut self, _: &Cx, binding: &[u8; 32], plaintext: &[u8], maximum: usize)
            -> Result<Vec<u8>, TaskResumeError>
        {
            if maximum < 16 || plaintext.len() > 65536 { return Err(TaskResumeError::Protection); }
            let mut state = self.0.lock().unwrap();
            if state.entries.len() >= 64 { return Err(TaskResumeError::Capacity); }
            state.next = state.next.checked_add(1).ok_or(TaskResumeError::GenerationExhausted)?;
            let mut token = b"TESTVAUL".to_vec();
            token.extend_from_slice(&state.next.to_be_bytes());
            state.entries.insert(token.clone(), (*binding, plaintext.to_vec()));
            Ok(token)
        }
        fn open(&mut self, _: &Cx, binding: &[u8; 32], ciphertext: &[u8], maximum: usize)
            -> Result<Vec<u8>, TaskResumeError>
        {
            let state = self.0.lock().unwrap();
            let (owner, bytes) = state.entries.get(ciphertext).ok_or(TaskResumeError::Protection)?;
            if owner != binding || bytes.len() > maximum { return Err(TaskResumeError::Protection); }
            Ok(bytes.clone())
        }
    }

    #[test]
    fn protected_file_reopen_live_reconcile_and_exact_terminal_cleanup_form_one_workflow() {
        // Storage is synchronous ONLY between block_on calls, never in a live
        // async poll. The runtime, public client and actual TLS peer stay owned.
        let rt = runtime();
        let (mut peer, mut client, credential) = rt.block_on(Peer::new());
        let current = binding("owner", client.resource().as_str());
        let cx = Cx::for_testing();
        let saved = record(&cx, &current);
        let directory = Directory::new();
        let vault = Vault::default();
        let open = || TaskResumeStore::open(
            &cx, ProcessGenerationGuard::install().unwrap().token(), directory.file(&cx),
            vault.clone(), current.clone(), TaskResumeStoreLimits::new(8, 65536).unwrap(),
        ).unwrap();
        let mut store = open();
        store.put(&cx, &current, saved.clone()).unwrap();
        let protected = directory.bytes();
        drop(store);
        let mut store = open();
        let restored = store.get(&cx, &current, saved.key()).unwrap().unwrap();
        assert_eq!(restored, saved);

        let active = rt.block_on(async {
            let cx = Cx::current().unwrap();
            let cancellation = McpRequestCancellation::new();
            let call = client.reconcile_task_resume(&cx, &cancellation, &credential,
                meta(), &current, &restored, "stored", limits());
            let server = async {
                let mut socket = peer.get("stored").await;
                json_reply(&mut socket, 200, &envelope("stored", false,
                    serde_json::to_value(snapshot("input_required", 2)).unwrap())).await;
            };
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(15_000_000_000), pair(call, server))
                .await.unwrap().0.unwrap()
        });
        assert_eq!(directory.bytes(), protected, "network observation is not a file mutation");
        active.change().apply(&cx, &current, &mut store).unwrap();
        let written = directory.bytes();
        assert_ne!(written, protected);
        assert!(!written.windows(6).any(|bytes| bytes == b"SECRET"));
        assert!(active.change().apply(&cx, &current, &mut store).is_err(), "old expected version must not overwrite new controls");
        assert_eq!(directory.bytes(), written);
        let updated = store.get(&cx, &current, saved.key()).unwrap().unwrap();
        assert_eq!(Some(&updated), active.change().replacement());

        let terminal = rt.block_on(async {
            let cx = Cx::current().unwrap();
            let cancellation = McpRequestCancellation::new();
            let call = client.reconcile_task_resume(&cx, &cancellation, &credential,
                meta(), &current, &updated, "terminal", limits());
            let server = async {
                let mut socket = peer.get("terminal").await;
                json_reply(&mut socket, 200, &envelope("terminal", false,
                    serde_json::to_value(snapshot("cancelled", 3)).unwrap())).await;
            };
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(15_000_000_000), pair(call, server))
                .await.unwrap().0.unwrap()
        });
        assert!(terminal.selection().is_none());
        assert_eq!(store.get(&cx, &current, saved.key()).unwrap(), Some(updated));
        assert_eq!(directory.bytes(), written, "terminal delivery must not silently delete its lookup");
        assert!(matches!(terminal.snapshot().task, fastmcp_protocol::tasks_extension::Task::Cancelled(_)));
        terminal.change().apply(&cx, &current, &mut store).unwrap();
        assert!(store.get(&cx, &current, saved.key()).unwrap().is_none());
        peer.no_extra(4);
        assert!(!client.revocation_handle().is_revoked());
        drop(store);
        assert!(rt.shutdown_timeout(Duration::from_secs(1)));
    }
}
