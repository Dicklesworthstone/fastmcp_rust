//! Public DPoP restart recovery against a real loopback HTTPS peer.
//! Uses the existing public TEST ONLY certificate fixture, scoped to the
//! selected client. No process trust, production transport or runtime is mocked.
//! Run with --features tasks,native-tls-roots --test dpop_task_recovery;
//! eight discovered tests are expected, never a zero-test acceptance receipt.
#![cfg(all(feature = "tasks", feature = "native-tls-roots", not(target_arch = "wasm32")))]

use std::collections::BTreeSet;
use std::future::{Future, poll_fn};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream};
use fastmcp_client::http_auth::dpop::{DpopCredential, DpopSession};
use fastmcp_client::http_auth::dpop::native::{DpopHttpClient, DpopHttpError, DpopHttpPolicy};
use fastmcp_client::http_auth::dpop::native::core::DpopCoreError;
use fastmcp_client::http_auth::dpop::native::core::stream::{DpopStreamError, DpopStreamLimits};
use fastmcp_client::http_auth::dpop::native::core::stream::task_subscription::watch::{
    DpopTaskWatchError, DpopTaskWatchPolicy,
};
use fastmcp_client::http_auth::dpop::native::core::stream::task_subscription::watch::checkpoint::{
    DpopTaskCheckpointError, DpopTaskWatchCheckpoint,
};
use fastmcp_client::http_auth::dpop::native::core::tasks::wait::DpopTaskWaitOutcome;
use fastmcp_client::http_auth::rpc::{ManagedCoreError, ManagedCoreLimits};
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::dpop::DpopKey;
use fastmcp_protocol::tasks_extension::{TASKS_EXTENSION, TaskId};
use fastmcp_protocol::{ClientCapabilities, FINAL_PROTOCOL_VERSION, FinalRequestMeta};
use serde_json::{Value, json};

const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";
const SSE_HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nDPoP-Nonce: recovery-next\r\nConnection: close\r\n\r\n";

type Socket = TlsStream<TcpStream>;

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let (mut one, mut two) = (None, None);
    poll_fn(|cx| {
        if one.is_none() {
            if let Poll::Ready(value) = left.as_mut().poll(cx) { one = Some(value); }
        }
        if two.is_none() {
            if let Poll::Ready(value) = right.as_mut().poll(cx) { two = Some(value); }
        }
        if one.is_some() && two.is_some() {
            Poll::Ready((one.take().unwrap(), two.take().unwrap()))
        } else { Poll::Pending }
    }).await
}

fn run(future: impl Future<Output = ()>) {
    let runtime = RuntimeBuilder::current_thread().blocking_threads(0, 0)
        .with_reactor(create_reactor().unwrap()).build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(30_000_000_000), future)
            .await.expect("recovery must settle without replay or detached work");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

fn configured(target: &str) -> (DpopHttpClient, DpopCredential, TlsAcceptor) {
    let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
    let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(),
        CanonicalHttpUrl::parse(target).unwrap()).unwrap();
    let credential = session.admit_token_response(&issuer, 200,
        br#"{"access_token":"recovery-test-token","token_type":"DPoP","expires_in":120}"#,
        Instant::now(), Duration::from_secs(120)).unwrap();
    let root = Certificate::from_pem(ROOT).unwrap().remove(0);
    let policy = DpopHttpPolicy::default().with_resource_root_der(root.as_der().to_vec()).unwrap();
    let client = DpopHttpClient::new(session, policy).unwrap();
    let acceptor = TlsAcceptorBuilder::new(CertificateChain::from_pem(LEAF).unwrap(),
        PrivateKey::from_pem(KEY).unwrap()).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();
    (client, credential, acceptor)
}

fn metadata() -> FinalRequestMeta {
    let mut value = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    value["progressToken"] = json!("work");
    let mut meta: FinalRequestMeta = serde_json::from_value(value).unwrap();
    meta.client_capabilities = serde_json::from_value(json!({"roots":{}})).unwrap();
    meta
}

fn limits() -> DpopStreamLimits {
    DpopStreamLimits::new(
        ManagedCoreLimits::new(8192, 8192, 65536, 16, Duration::from_secs(10)).unwrap(),
        Duration::from_secs(5),
    ).unwrap()
}

fn saved(client: &DpopHttpClient, ids: &[&str]) -> Vec<DpopTaskWatchCheckpoint> {
    ids.iter().map(|id| {
        let checkpoint = client.task_watch_checkpoint(TaskId::parse(*id).unwrap()).unwrap();
        DpopTaskWatchCheckpoint::decode(&checkpoint.encode().unwrap()).unwrap()
    }).collect()
}

fn discovery() -> Value {
    json!({"resultType":"complete", "supportedVersions":[FINAL_PROTOCOL_VERSION],
        "capabilities":{"tools":{},"extensions":{TASKS_EXTENSION:{}}},
        "ttlMs":0,"cacheScope":"private",
        "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"recovery-peer","version":"1"}}})
}

fn snapshot(id: &str, status: &str) -> Value {
    let mut result = json!({
        "resultType":"complete", "taskId":id, "status":status,
        "createdAt":"2026-09-16T00:00:00Z", "lastUpdatedAt":"2026-09-16T00:00:00Z",
        "ttlMs":60000, "_meta":{"recovered":id},
    });
    if status == "input_required" {
        result["inputRequests"] = json!({"roots":{"method":"roots/list"}});
    }
    result
}

fn frame(prefix: &str, round: usize, discovery: bool, result: Value) -> Vec<u8> {
    let suffix = if discovery { "discover" } else { "get" };
    serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":format!("{prefix}.{round}.{suffix}"),
        "result":result})).unwrap()
}

fn progress() -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0", "method":"notifications/progress",
        "params":{"progressToken":"work", "progress":1}})).unwrap()
}

fn header<'a>(head: &'a str, name: &str) -> &'a str {
    let values = head.lines().filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim()).collect::<Vec<_>>();
    assert_eq!(values.len(), 1, "exactly one {name} header");
    values[0]
}

// Decode captured claims to check binding and freshness, not signature validity.
fn claims(proof: &str) -> Value {
    let parts = proof.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    let (mut acc, mut bits) = (0_u32, 0_u32);
    let mut bytes = Vec::new();
    for byte in parts[1].bytes() {
        let n = match byte {
            b'A'..=b'Z' => byte - b'A', b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52, b'-' => 62, b'_' => 63,
            _ => panic!("invalid base64url proof"),
        };
        acc = (acc << 6) | u32::from(n);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    assert_eq!(acc, 0);
    serde_json::from_slice(&bytes).unwrap()
}

async fn read(socket: &mut Socket) -> (String, Value) {
    let mut bytes = Vec::new();
    let mut block = [0; 2048];
    let end = loop {
        let n = socket.read(&mut block).await.unwrap();
        assert!(n > 0 && bytes.len() + n <= 32768);
        bytes.extend_from_slice(&block[..n]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") { break index + 4; }
    };
    let head = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
    let length = header(&head, "content-length").parse::<usize>().unwrap();
    assert!(end + length <= 32768);
    while bytes.len() < end + length {
        let n = socket.read(&mut block).await.unwrap();
        assert!(n > 0 && bytes.len() + n <= 32768);
        bytes.extend_from_slice(&block[..n]);
    }
    assert_eq!(bytes.len(), end + length);
    (head, serde_json::from_slice(&bytes[end..]).unwrap())
}

async fn json_reply(socket: &mut Socket, bytes: &[u8]) {
    let mut wire = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nDPoP-Nonce: recovery-next\r\nConnection: close\r\n\r\n", bytes.len()).into_bytes();
    wire.extend_from_slice(bytes);
    socket.write_all(&wire).await.unwrap();
    let _ = socket.shutdown().await;
}

fn event_chunk(payload: &[u8]) -> Vec<u8> {
    let mut data = b"data: ".to_vec();
    data.extend_from_slice(payload);
    data.extend_from_slice(b"\n\n");
    let mut wire = format!("{:X}\r\n", data.len()).into_bytes();
    wire.extend_from_slice(&data);
    wire.extend_from_slice(b"\r\n");
    wire
}

async fn sse_reply(socket: &mut Socket, terminal: &[u8]) {
    let mut wire = SSE_HEAD.to_vec();
    wire.extend_from_slice(&event_chunk(&progress()));
    wire.extend_from_slice(&event_chunk(terminal));
    wire.extend_from_slice(b"0\r\n\r\n");
    socket.write_all(&wire).await.unwrap();
    let _ = socket.shutdown().await;
}

async fn closed(socket: &mut Socket) {
    let cx = Cx::current().unwrap();
    let mut byte = [0];
    let read = asupersync::time::timeout_at(cx.now().saturating_add_nanos(2_000_000_000),
        socket.read(&mut byte)).await.expect("owned recovery socket must retire promptly");
    assert!(matches!(read, Ok(0) | Err(_)), "no hidden request on the retired connection");
}

struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    target: String,
    proofs: BTreeSet<String>,
}

impl Peer {
    async fn new() -> (Self, DpopHttpClient, DpopCredential) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
        let (client, credential, acceptor) = configured(&target);
        (Self { listener, acceptor, target, proofs: BTreeSet::new() }, client, credential)
    }

    async fn receive(&mut self, prefix: &str, round: usize, task: Option<&str>) -> Socket {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut socket = self.acceptor.accept(socket).await.unwrap();
        let (head, body) = read(&mut socket).await;
        let (method, suffix, accept) = if task.is_some() {
            ("tasks/get", "get", "application/json, text/event-stream")
        } else { ("server/discover", "discover", "application/json") };
        assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
        assert_eq!(body["id"], format!("{prefix}.{round}.{suffix}"));
        assert_eq!(body["method"], method, "recovery cannot mutate or replay work");
        assert_eq!(header(&head, "mcp-method"), method);
        assert_eq!(header(&head, "mcp-protocol-version"), FINAL_PROTOCOL_VERSION);
        assert_eq!(header(&head, "authorization"), "DPoP recovery-test-token");
        assert_eq!(header(&head, "accept"), accept);
        let proof = claims(header(&head, "dpop"));
        assert_eq!(proof["htm"], "POST");
        assert_eq!(proof["htu"], self.target.split('?').next().unwrap());
        assert!(proof["ath"].as_str().is_some_and(|hash| !hash.is_empty()));
        if self.proofs.is_empty() { assert!(proof.get("nonce").is_none()); }
        else { assert_eq!(proof["nonce"], "recovery-next"); }
        assert!(self.proofs.insert(proof["jti"].as_str().unwrap().to_owned()), "a fresh proof per request");
        assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
            json!({TASKS_EXTENSION:{}}));
        for field in ["inputResponses", "requestState", "arguments"] {
            assert!(body["params"].get(field).is_none(), "saved selection cannot replay {field}");
        }
        if let Some(id) = task {
            assert_eq!(body["params"]["taskId"], id);
            assert_eq!(header(&head, "mcp-name"), id);
        } else { assert!(body["params"].get("taskId").is_none()); }
        socket
    }

    async fn round(&mut self, prefix: &str, round: usize, task: &str) -> Socket {
        let mut socket = self.receive(prefix, round, None).await;
        json_reply(&mut socket, &frame(prefix, round, true, discovery())).await;
        self.receive(prefix, round, Some(task)).await
    }

    fn no_extra(&self, pairs: usize) {
        assert_eq!(self.proofs.len(), pairs * 2);
        assert!(self.listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending(),
            "no retry, subscription, recreation or remote cancellation after recovery");
    }
}

fn stream_error(error: DpopTaskCheckpointError) -> DpopStreamError {
    match error {
        DpopTaskCheckpointError::Watch(DpopTaskWatchError::Stream(error)) => error,
        other => panic!("unexpected recovery error: {other:?}"),
    }
}

async fn followup(peer: &mut Peer, client: &mut DpopHttpClient, credential: &DpopCredential) {
    let cx = Cx::current().unwrap();
    let checkpoints = saved(client, &["task-one"]);
    let cancellation = McpRequestCancellation::new();
    let mut seen = 0;
    let application = client.reconcile_task_checkpoints(&cx, &cancellation, credential,
        metadata(), &checkpoints, "followup", limits(), |_| { seen += 1; true });
    let server = async {
        let mut socket = peer.round("followup", 0, "task-one").await;
        json_reply(&mut socket, &frame("followup", 0, false, snapshot("task-one", "cancelled"))).await;
    };
    let (result, ()) = pair(application, server).await;
    assert_eq!(result.unwrap(), 1);
    assert_eq!(seen, 1);
    assert!(!client.revocation_handle().is_revoked());
}

#[test]
fn recovery_uses_a_fresh_login_and_publishes_distinct_tasks_incrementally() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, old_client, old_credential) = Peer::new().await;
        let checkpoints = saved(&old_client, &["task-one", "task-two", "task-three"]);
        old_credential.revoke();
        drop(old_client);
        let (mut client, credential, _) = configured(&peer.target);
        let cancellation = McpRequestCancellation::new();
        let first_seen = McpRequestCancellation::new();
        let notified = McpRequestCancellation::new();
        let (mut snapshots, mut notifications) = (Vec::new(), 0);
        let application = client.reconcile_task_checkpoints_with_events(
            &cx, &cancellation, &credential, metadata(), &checkpoints, "restart", limits(),
            |snapshot| {
                snapshots.push(serde_json::to_value(snapshot).unwrap());
                first_seen.cancel();
                true
            },
            |_| { notifications += 1; notified.cancel(); true },
        );
        let server = async {
            let mut first = peer.round("restart", 0, "task-one").await;
            json_reply(&mut first, &frame("restart", 0, false, snapshot("task-one", "working"))).await;
            // Later replies cannot exist until the first snapshot has reached
            // its host. Buffering the whole selection cannot pass this barrier.
            first_seen.cancelled().await;
            let mut second = peer.round("restart", 1, "task-two").await;
            second.write_all(SSE_HEAD).await.unwrap();
            second.write_all(&event_chunk(&progress())).await.unwrap();
            notified.cancelled().await;
            let mut tail = event_chunk(&frame("restart", 1, false, snapshot("task-two", "input_required")));
            tail.extend_from_slice(b"0\r\n\r\n");
            second.write_all(&tail).await.unwrap();
            let _ = second.shutdown().await;
            let mut third = peer.round("restart", 2, "task-three").await;
            json_reply(&mut third, &frame("restart", 2, false, snapshot("task-three", "cancelled"))).await;
        };
        let (result, ()) = pair(application, server).await;
        assert_eq!(result.unwrap(), 3);
        assert_eq!(notifications, 1);
        assert_eq!(snapshots, [snapshot("task-one", "working"), snapshot("task-two", "input_required"),
            snapshot("task-three", "cancelled")]);
        peer.no_extra(3);
    });
}

#[test]
fn recovery_preserves_exact_cumulative_bytes_and_notifications_across_tasks() {
    for shortage in [0, 1, 2] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let checkpoints = saved(&client, &["task-one", "task-two"]);
            let cancellation = McpRequestCancellation::new();
            let mut total = 0;
            let mut maximum = 0;
            for (round, id) in [(0, "task-one"), (1, "task-two")] {
                for bytes in [frame("quota", round, true, discovery()), progress(),
                    frame("quota", round, false, snapshot(id, "cancelled"))]
                {
                    total += bytes.len();
                    maximum = maximum.max(bytes.len());
                }
            }
            let core = ManagedCoreLimits::new(8192, maximum, total - usize::from(shortage == 1),
                if shortage == 2 { 1 } else { 2 }, Duration::from_secs(10)).unwrap();
            let selected = DpopStreamLimits::new(core, Duration::from_secs(5)).unwrap();
            let (mut snapshots, mut notifications) = (0, 0);
            let application = client.reconcile_task_checkpoints_with_events(
                &cx, &cancellation, &credential, metadata(), &checkpoints, "quota", selected,
                |_| { snapshots += 1; true }, |_| { notifications += 1; true },
            );
            let server = async {
                for (round, id) in [(0, "task-one"), (1, "task-two")] {
                    let mut socket = peer.round("quota", round, id).await;
                    sse_reply(&mut socket, &frame("quota", round, false, snapshot(id, "cancelled"))).await;
                }
            };
            let (result, ()) = pair(application, server).await;
            match shortage {
                0 => { assert_eq!(result.unwrap(), 2); assert_eq!((snapshots, notifications), (2, 2)); }
                1 => {
                    assert!(matches!(stream_error(result.unwrap_err()), DpopStreamError::Core(
                        DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit))));
                    assert_eq!((snapshots, notifications), (1, 2));
                }
                _ => {
                    assert!(matches!(stream_error(result.unwrap_err()), DpopStreamError::Core(
                        DpopCoreError::Protocol(ManagedCoreError::NotificationLimit))));
                    assert_eq!((snapshots, notifications), (1, 1));
                }
            }
            peer.no_extra(2);
        });
    }
}

#[derive(Clone, Copy)]
enum Stop { Refuse, Panic, Cancel, Credential, Session }

#[test]
fn recovery_observer_retirement_prevents_successors_and_preserves_reusable_logins() {
    for stop in [Stop::Refuse, Stop::Panic, Stop::Cancel, Stop::Credential, Stop::Session] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let checkpoints = saved(&client, &["task-one", "task-two"]);
            let cancellation = McpRequestCancellation::new();
            let session = client.revocation_handle();
            let mut seen = 0;
            let application = client.reconcile_task_checkpoints(&cx, &cancellation, &credential,
                metadata(), &checkpoints, "stop", limits(), |_| {
                    seen += 1;
                    match stop {
                        Stop::Refuse => false,
                        Stop::Panic => panic!("private recovery observer payload"),
                        Stop::Cancel => { cancellation.cancel(); false }
                        Stop::Credential => { credential.revoke(); false }
                        Stop::Session => { session.revoke(); false }
                    }
                });
            let server = async {
                let mut socket = peer.round("stop", 0, "task-one").await;
                json_reply(&mut socket, &frame("stop", 0, false, snapshot("task-one", "working"))).await;
            };
            let (result, ()) = pair(application, server).await;
            let error = stream_error(result.unwrap_err());
            match stop {
                Stop::Refuse => assert!(matches!(error, DpopStreamError::ObserverStopped)),
                Stop::Panic => assert!(matches!(error, DpopStreamError::ObserverPanicked)),
                Stop::Cancel => assert!(matches!(error, DpopStreamError::Core(
                    DpopCoreError::Transport(DpopHttpError::Cancelled)))),
                Stop::Credential | Stop::Session => assert!(matches!(error, DpopStreamError::Core(
                    DpopCoreError::Transport(DpopHttpError::Authorization(_))))),
            }
            assert!(!format!("{error:?}").contains("private recovery observer payload"));
            assert_eq!(seen, 1);
            peer.no_extra(1);
            assert!(cx.checkpoint().is_ok());
            if matches!(stop, Stop::Refuse | Stop::Panic | Stop::Cancel) {
                followup(&mut peer, &mut client, &credential).await;
                peer.no_extra(2);
            }
        });
    }
}

#[test]
fn recovery_never_publishes_a_late_corrupt_or_unfinished_snapshot() {
    for corruption in 0..5 {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let checkpoints = saved(&client, &["task-one", "task-two"]);
            let cancellation = McpRequestCancellation::new();
            let mut seen = Vec::new();
            let application = client.reconcile_task_checkpoints(&cx, &cancellation, &credential,
                metadata(), &checkpoints, "corrupt", limits(), |snapshot| {
                    seen.push(snapshot.task.base().task_id.as_str().to_owned()); true
                });
            let server = async {
                let mut first = peer.round("corrupt", 0, "task-one").await;
                json_reply(&mut first, &frame("corrupt", 0, false, snapshot("task-one", "working"))).await;
                let mut second = peer.round("corrupt", 1, "task-two").await;
                let mut value: Value = serde_json::from_slice(&frame("corrupt", 1, false,
                    snapshot("task-two", "cancelled"))).unwrap();
                if corruption == 0 { value["result"]["taskId"] = json!("foreign-task"); }
                if corruption == 1 { value["id"] = json!("unrelated.get"); }
                if corruption == 4 {
                    value.as_object_mut().unwrap().remove("result");
                    value["error"] = json!({"code":-32001, "message":"Task is unavailable"});
                }
                let terminal = serde_json::to_vec(&value).unwrap();
                let mut wire = SSE_HEAD.to_vec();
                wire.extend_from_slice(&event_chunk(&terminal));
                if corruption == 2 { wire.extend_from_slice(&event_chunk(&terminal)); }
                if corruption != 3 { wire.extend_from_slice(b"0\r\n\r\n"); }
                second.write_all(&wire).await.unwrap();
                let _ = second.shutdown().await;
            };
            let (result, ()) = pair(application, server).await;
            assert!(result.is_err(), "corruption case {corruption} cannot complete recovery");
            assert_eq!(seen, ["task-one"]);
            peer.no_extra(2);
            followup(&mut peer, &mut client, &credential).await;
            peer.no_extra(3);
        });
    }
}

#[test]
fn recovery_cancellation_and_abandonment_retire_a_stalled_later_task() {
    for retirement in 0..4 {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let checkpoints = saved(&client, &["task-one", "task-two"]);
            let cancellation = McpRequestCancellation::new();
            let reached = McpRequestCancellation::new();
            let session = client.revocation_handle();
            let mut seen = 0;
            let application = async {
                let mut recovery = Box::pin(client.reconcile_task_checkpoints(&cx, &cancellation,
                    &credential, metadata(), &checkpoints, "retire", limits(), |_| { seen += 1; true }));
                if retirement == 3 {
                    let mut ready = std::pin::pin!(reached.cancelled());
                    poll_fn(|context| {
                        assert!(recovery.as_mut().poll(context).is_pending());
                        ready.as_mut().poll(context)
                    }).await;
                    drop(recovery);
                } else {
                    let error = stream_error(recovery.await.unwrap_err());
                    if retirement == 0 {
                        assert!(matches!(error, DpopStreamError::Core(
                            DpopCoreError::Transport(DpopHttpError::Cancelled))));
                    } else {
                        assert!(matches!(error, DpopStreamError::Core(
                            DpopCoreError::Transport(DpopHttpError::Authorization(_)))));
                    }
                }
            };
            let server = async {
                let mut first = peer.round("retire", 0, "task-one").await;
                json_reply(&mut first, &frame("retire", 0, false, snapshot("task-one", "working"))).await;
                let mut second = peer.round("retire", 1, "task-two").await;
                second.write_all(SSE_HEAD).await.unwrap();
                second.write_all(&event_chunk(&progress())).await.unwrap();
                reached.cancel();
                match retirement {
                    0 => { cancellation.cancel(); }
                    1 => { credential.revoke(); }
                    2 => { session.revoke(); }
                    _ => {}
                }
                closed(&mut second).await;
            };
            pair(application, server).await;
            assert_eq!(seen, 1);
            peer.no_extra(2);
            assert!(cx.checkpoint().is_ok());
            if retirement == 0 || retirement == 3 {
                followup(&mut peer, &mut client, &credential).await;
                peer.no_extra(3);
            }
        });
    }
}

#[test]
fn recovery_admits_the_entire_selection_before_any_https_request() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let valid = saved(&client, &["task-one", "task-two"]);
        let foreign = DpopTaskWatchCheckpoint::new(
            &CanonicalHttpUrl::parse(&peer.target.replace("tenant=one", "tenant=two")).unwrap(),
            TaskId::parse("task-two").unwrap(),
        ).unwrap();
        let cancellation = McpRequestCancellation::new();
        for (selection, prefix) in [(vec![valid[0].clone(), foreign], "admit"),
            (vec![valid[0].clone(), valid[0].clone()], "admit"), (valid.clone(), "bad prefix")]
        {
            let result = client.reconcile_task_checkpoints_with_events(&cx, &cancellation,
                &credential, metadata(), &selection, prefix, limits(),
                |_| panic!("no snapshot before whole-selection admission"),
                |_| panic!("no notification before whole-selection admission")).await;
            assert!(result.is_err());
            peer.no_extra(0);
        }
        followup(&mut peer, &mut client, &credential).await;
        peer.no_extra(1);
    });
}

#[test]
fn restored_single_task_watch_reads_fresh_state_without_recreating_work() {
    for status in ["input_required", "cancelled"] {
        for sse in [false, true] {
            run(async {
                let cx = Cx::current().unwrap();
                let (mut peer, mut client, credential) = Peer::new().await;
                let checkpoints = saved(&client, &["task-one"]);
                let cancellation = McpRequestCancellation::new();
                let application = client.resume_task_watch_with_cancellation(&cx, &cancellation,
                    &credential, metadata(), &checkpoints[0], "resume", DpopTaskWatchPolicy::new(1).unwrap(), limits());
                let server = async {
                    let mut socket = peer.round("resume", 0, "task-one").await;
                    let terminal = frame("resume", 0, false, snapshot("task-one", status));
                    if sse { sse_reply(&mut socket, &terminal).await; }
                    else { json_reply(&mut socket, &terminal).await; }
                };
                let (result, ()) = pair(application, server).await;
                let result = match result.unwrap() {
                    DpopTaskWaitOutcome::InputRequired(value) => {
                        assert_eq!(status, "input_required"); value
                    }
                    DpopTaskWaitOutcome::Terminal(value) => { assert_eq!(status, "cancelled"); value }
                };
                assert_eq!(serde_json::to_value(&*result).unwrap(), snapshot("task-one", status));
                peer.no_extra(1);
            });
        }
    }
}

#[test]
fn recovery_does_not_reset_the_absolute_deadline_for_a_later_task() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let checkpoints = saved(&client, &["task-one", "task-two"]);
        let cancellation = McpRequestCancellation::new();
        let selected = DpopStreamLimits::new(
            ManagedCoreLimits::new(8192, 8192, 65536, 16, Duration::from_secs(3)).unwrap(),
            Duration::from_secs(3),
        ).unwrap();
        let start = cx.now();
        let mut seen = 0;
        let application = async {
            let recovery = client.reconcile_task_checkpoints(&cx, &cancellation, &credential,
                metadata(), &checkpoints, "deadline", selected, |_| { seen += 1; true });
            let result = asupersync::time::timeout_at(start.saturating_add_nanos(4_000_000_000), recovery)
                .await.expect("the original three-second deadline must win over a reset five-second deadline");
            assert!(matches!(stream_error(result.unwrap_err()), DpopStreamError::Core(
                DpopCoreError::Transport(DpopHttpError::TimedOut))));
        };
        let server = async {
            let mut first = peer.round("deadline", 0, "task-one").await;
            // Spend most of the original allowance before the next Task starts.
            assert!(asupersync::time::timeout_at(start.saturating_add_nanos(2_000_000_000),
                std::future::pending::<()>()).await.is_err());
            json_reply(&mut first, &frame("deadline", 0, false, snapshot("task-one", "working"))).await;
            let mut second = peer.round("deadline", 1, "task-two").await;
            closed(&mut second).await;
        };
        pair(application, server).await;
        assert_eq!(seen, 1);
        peer.no_extra(2);
        followup(&mut peer, &mut client, &credential).await;
        peer.no_extra(3);
    });
}
