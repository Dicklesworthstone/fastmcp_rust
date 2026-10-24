//! Real TLS rollover of the public DPoP Task watch and input driver.
//! Uses the repository's TEST ONLY OAuth CA and key. Proof decoding checks
//! client claims/nonce continuity; it is not a server-side signature verifier.

use super::*;
use std::collections::HashSet;
use std::task::Poll;
use std::time::Instant;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::ClientCapabilities;
use fastmcp_protocol::dpop::DpopKey;
use serde_json::{Value, json};
use crate::http_auth::dpop::DpopSession;
use crate::http_auth::dpop::native::DpopHttpPolicy;
use crate::http_auth::dpop::native::core::DpopCoreError;

const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

type Socket = TlsStream<TcpStream>;

#[derive(Clone, Copy, Debug)]
enum Case {
    Complete,
    InputHandoff,
    TerminalBeforeReconnect,
    Disabled,
    StaleAck,
    MalformedTail,
    MissingTerminal,
    SnapshotCap,
    AckCap,
    ReconnectCap,
    PollFallback,
    Deadline,
    CancelDelay,
}

fn discovery() -> Value {
    json!({"resultType":"complete", "supportedVersions":[FINAL_PROTOCOL_VERSION],
        "capabilities":{"extensions":{TASKS_EXTENSION:{}}}, "ttlMs":0,"cacheScope":"private",
        "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"rollover-peer","version":"1"}}})
}

fn snapshot(index: usize, status: &str) -> Value {
    let mut task = json!({"resultType":"complete", "taskId":"task-one", "status":status,
        "createdAt":"2020-01-01T00:00:00Z", "lastUpdatedAt":format!("2020-01-01T00:00:{index:02}Z"),
        "ttlMs":null, "pollIntervalMs":10});
    if status == "completed" { task["result"] = json!({"content":[]}); }
    if status == "input_required" {
        task["inputRequests"] = json!({"fresh-input":{"method":"roots/list"}});
    }
    task
}

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

fn field<'a>(headers: &'a str, name: &str) -> &'a str {
    let fields: Vec<_> = headers.lines().filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.trim()).collect();
    assert_eq!(fields.len(), 1, "one {name} field");
    fields[0]
}

async fn read_request<IO: AsyncRead + Unpin>(io: &mut IO) -> (String, Value) {
    let mut bytes = Vec::new();
    let mut buffer = [0; 2048];
    let end = loop {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32768);
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(offset) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break offset + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
    let length: usize = field(&headers, "content-length").parse().unwrap();
    assert!(end + length <= 32768);
    while bytes.len() < end + length {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32768);
        bytes.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(bytes.len(), end + length);
    (headers, serde_json::from_slice(&bytes[end..]).unwrap())
}

// Assertion-only compact-JWT payload decoder, bounded to fixture headers.
fn claims(segment: &str) -> Value {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    assert!(segment.len() <= 8192);
    let (mut bits, mut accumulator) = (0_u32, 0_u32);
    let mut bytes = Vec::new();
    for byte in segment.bytes() {
        let value = ALPHABET.iter().position(|candidate| *candidate == byte).unwrap() as u32;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    assert_eq!(accumulator, 0);
    serde_json::from_slice(&bytes).unwrap()
}

async fn chunk<IO: AsyncWrite + Unpin>(io: &mut IO, bytes: &[u8]) {
    io.write_all(format!("{:X}\r\n", bytes.len()).as_bytes()).await.unwrap();
    io.write_all(bytes).await.unwrap();
    io.write_all(b"\r\n").await.unwrap();
    io.flush().await.unwrap();
}
async fn event(io: &mut Socket, value: Value) {
    let payload = serde_json::to_vec(&value).unwrap();
    chunk(io, &[b"data: ".as_slice(), &payload, b"\r\n\r\n"].concat()).await;
}
async fn ended(io: &mut Socket, id: &str, case: Case) {
    if !matches!(case, Case::MissingTerminal) {
        event(io, json!({"jsonrpc":"2.0", "id":id,
            "result":{"resultType":"complete", "_meta":{FINAL_SUBSCRIPTION_ID_META_KEY:id}}})).await;
    }
    if matches!(case, Case::MalformedTail) {
        chunk(io, b"data: {\"jsonrpc\":").await;
    }
    io.write_all(b"0\r\n\r\n").await.unwrap();
    io.shutdown().await.unwrap();
}
async fn expect_closed(io: &mut Socket) {
    let mut byte = [0; 1];
    match io.read(&mut byte).await {
        Ok(0) | Err(_) => {}
        Ok(_) => panic!("retired listen received unexpected application bytes"),
    }
}

struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    target: String,
    nonce: usize,
    ids: HashSet<String>,
    proofs: HashSet<String>,
    posts: usize,
}
impl Peer {
    async fn new() -> (Self, DpopHttpClient, DpopCredential) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
        let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
        let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(),
            CanonicalHttpUrl::parse(&target).unwrap()).unwrap();
        let credential = session.admit_token_response(&issuer, 200,
            br#"{"access_token":"rollover-access","token_type":"DPoP","expires_in":60}"#,
            Instant::now(), Duration::from_secs(60)).unwrap();
        let root = Certificate::from_pem(ROOT).unwrap().remove(0);
        let policy = DpopHttpPolicy::default().with_resource_root_der(root.as_der().to_vec()).unwrap();
        let client = DpopHttpClient::new(session, policy).unwrap();
        let acceptor = TlsAcceptorBuilder::new(CertificateChain::from_pem(LEAF).unwrap(),
            PrivateKey::from_pem(KEY).unwrap()).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();
        (Self { listener, acceptor, target, nonce:0, ids:HashSet::new(), proofs:HashSet::new(), posts:0 }, client, credential)
    }

    async fn request(&mut self, method: &str, id: &str) -> Socket {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut socket = self.acceptor.accept(socket).await.unwrap();
        let (headers, body) = read_request(&mut socket).await;
        assert!(headers.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
        assert_eq!(field(&headers, "authorization"), "DPoP rollover-access");
        assert_eq!(field(&headers, "mcp-method"), method);
        assert_eq!(body["method"], method);
        assert_eq!(body["id"], id);
        assert!(self.ids.insert(id.to_owned()), "every wire request identity is fresh");
        let pieces: Vec<_> = field(&headers, "dpop").split('.').collect();
        assert_eq!(pieces.len(), 3);
        let proof = claims(pieces[1]);
        assert!(self.proofs.insert(proof["jti"].as_str().unwrap().to_owned()));
        assert_eq!(proof["htm"], "POST");
        assert_eq!(proof["htu"], self.target.split('?').next().unwrap());
        assert!(proof["ath"].as_str().is_some());
        if self.nonce == 0 { assert!(proof.get("nonce").is_none()); }
        else { assert_eq!(proof["nonce"], format!("resource-{}", self.nonce)); }
        assert!(body["params"].get("inputResponses").is_none());
        assert!(body["params"].get("requestState").is_none());
        if method == "tasks/get" { assert_eq!(body["params"]["taskId"], "task-one"); }
        if method == "subscriptions/listen" {
            assert_eq!(body["params"]["notifications"]["taskIds"], json!(["task-one"]));
        }
        self.posts += 1;
        socket
    }

    async fn reply(&mut self, io: &mut Socket, id: &str, result: Value) {
        self.nonce += 1;
        let body = serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":id, "result":result})).unwrap();
        io.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nDPoP-Nonce: resource-{}\r\nConnection: close\r\n\r\n", body.len(), self.nonce).as_bytes()).await.unwrap();
        io.write_all(&body).await.unwrap();
        io.shutdown().await.unwrap();
    }

    async fn get(&mut self, index: usize, status: &str) {
        let discover_id = format!("watch.{index}.discover");
        let mut discovery_socket = self.request("server/discover", &discover_id).await;
        self.reply(&mut discovery_socket, &discover_id, discovery()).await;
        let get_id = format!("watch.{index}.get");
        let mut get_socket = self.request("tasks/get", &get_id).await;
        self.reply(&mut get_socket, &get_id, snapshot(index, status)).await;
    }

    async fn listen(&mut self, ordinal: usize, stale: bool) -> Socket {
        let id = if ordinal == 0 { "watch.listen".to_owned() } else { format!("watch.listen.{ordinal}") };
        let discover_id = format!("{id}.discover");
        let mut discovery_socket = self.request("server/discover", &discover_id).await;
        self.reply(&mut discovery_socket, &discover_id, discovery()).await;
        let mut socket = self.request("subscriptions/listen", &id).await;
        self.nonce += 1;
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nDPoP-Nonce: resource-{}\r\nConnection: close\r\n\r\n", self.nonce).as_bytes()).await.unwrap();
        let acknowledged = if stale { "watch.listen" } else { &id };
        event(&mut socket, json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged",
            "params":{"notifications":{"taskIds":["task-one"]},
                "_meta":{FINAL_SUBSCRIPTION_ID_META_KEY:acknowledged}}})).await;
        socket
    }

    async fn serve(&mut self, cx: &Cx, cancellation: &McpRequestCancellation, case: Case) {
        self.get(0, "working").await;
        let mut first = self.listen(0, false).await;
        // Keep the listen live until its post-ACK get has completed. Splitting
        // ACK and terminal at this barrier makes the race test deterministic.
        self.get(1, "working").await;
        ended(&mut first, "watch.listen", case).await;
        drop(first);
        if matches!(case, Case::MalformedTail | Case::MissingTerminal) { return; }
        self.get(2, if matches!(case, Case::TerminalBeforeReconnect) { "completed" } else { "working" }).await;
        if matches!(case, Case::TerminalBeforeReconnect | Case::Disabled | Case::SnapshotCap | Case::AckCap | Case::Deadline) { return; }
        if matches!(case, Case::CancelDelay) {
            Sleep::new(cx.now().saturating_add_nanos(50_000_000)).await;
            cancellation.cancel();
            return;
        }
        let mut successor = self.listen(1, matches!(case, Case::StaleAck)).await;
        if matches!(case, Case::StaleAck) { expect_closed(&mut successor).await; return; }
        let status = match case {
            Case::InputHandoff => "input_required",
            Case::ReconnectCap | Case::PollFallback => "working",
            _ => "completed",
        };
        self.get(3, status).await;
        if !matches!(case, Case::ReconnectCap | Case::PollFallback) {
            expect_closed(&mut successor).await;
            return;
        }
        ended(&mut successor, "watch.listen.1", Case::Complete).await;
        drop(successor);
        self.get(4, "working").await;
        if matches!(case, Case::PollFallback) { self.get(5, "completed").await; }
    }
}

fn run_case(case: Case) {
    let runtime = RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
        .blocking_threads(0, 0).build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let scenario = async {
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let snapshots = if matches!(case, Case::SnapshotCap) { 3 } else { 16 };
            let notifications = if matches!(case, Case::AckCap) { 1 } else { 32 };
            let timeout = if matches!(case, Case::Deadline) { Duration::from_secs(5) } else { Duration::from_secs(15) };
            let delay = match case {
                Case::Deadline => Duration::from_secs(10),
                Case::CancelDelay => Duration::from_millis(500),
                _ => Duration::from_millis(1),
            };
            let limits = DpopStreamLimits::new(ManagedCoreLimits::new(
                8192, 8192, 262144, notifications, timeout,
            ).unwrap(), Duration::from_secs(10)).unwrap();
            let mut policy = DpopTaskWatchPolicy::new(snapshots).unwrap();
            if !matches!(case, Case::Disabled) { policy = policy.with_reconnects(1, delay).unwrap(); }
            if matches!(case, Case::PollFallback) {
                policy = policy.with_polling_fallback(1, Duration::from_millis(1)).unwrap();
            }
            let resolver_calls = std::cell::Cell::new(0);
            let started = Instant::now();
            let application = async {
                if matches!(case, Case::InputHandoff) {
                    let driver = DpopTaskWatchDriverPolicy::new(16, 4, 32, 65536, timeout).unwrap()
                        .with_reconnects(1, delay).unwrap();
                    client.drive_task_with_subscription(&cx, &cancellation, &credential,
                        FinalRequestMeta::new(serde_json::from_value(json!({"roots":{}})).unwrap()),
                        TaskId::parse("task-one").unwrap(), "watch", driver, limits,
                        |_| -> Ready<Result<ManagedTaskInputAction, ManagedTaskDriverError>> {
                            resolver_calls.set(resolver_calls.get() + 1);
                            panic!("reconnection cannot revive a resolver or update capability")
                        }, |_| Ok(()),
                    ).await
                } else {
                    client.watch_task_with_cancellation(&cx, &cancellation, &credential,
                        FinalRequestMeta::new(ClientCapabilities::default()), TaskId::parse("task-one").unwrap(),
                        "watch", policy, limits,
                    ).await
                }
            };
            let ((), result) = pair(peer.serve(&cx, &cancellation, case), application).await;
            let expected_posts = match case {
                Case::Complete | Case::InputHandoff => 12,
                Case::StaleAck => 10,
                Case::MalformedTail | Case::MissingTerminal => 6,
                Case::ReconnectCap => 14,
                Case::PollFallback => 16,
                _ => 8,
            };
            assert_eq!(peer.posts, expected_posts, "{case:?}");
            assert_eq!(peer.proofs.len(), peer.posts);
            match case {
                Case::Complete | Case::TerminalBeforeReconnect | Case::PollFallback => {
                    let DpopTaskWaitOutcome::Terminal(result) = result.unwrap() else { panic!("terminal Task required") };
                    assert!(matches!(result.task, Task::Completed { .. }));
                }
                Case::InputHandoff => {
                    assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::InputRequired(_)));
                    assert_eq!(resolver_calls.get(), 0);
                }
                Case::Disabled => assert!(matches!(result, Err(DpopTaskWatchError::SubscriptionEndedWhileWorking))),
                Case::ReconnectCap => assert!(matches!(result, Err(DpopTaskWatchError::ReconnectLimit))),
                Case::SnapshotCap => assert!(matches!(result, Err(DpopTaskWatchError::SnapshotLimit))),
                Case::AckCap => {
                    assert!(matches!(result, Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                        DpopCoreError::Protocol(ManagedCoreError::NotificationLimit)
                    )))));
                }
                Case::CancelDelay => {
                    assert!(matches!(result, Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                        DpopCoreError::Transport(DpopHttpError::Cancelled)
                    )))));
                }
                Case::Deadline => {
                    assert!(result.is_err());
                    assert!(started.elapsed() < Duration::from_secs(10), "reconnect delay cannot reset the absolute deadline");
                }
                Case::StaleAck | Case::MalformedTail | Case::MissingTerminal => assert!(result.is_err()),
            }
            assert!(!client.revocation_handle().is_revoked());
            assert!(!cx.is_cancel_requested());
            assert!(asupersync::time::timeout(cx.now(), Duration::from_millis(30), peer.listener.accept()).await.is_err(),
                "no replay or unowned successor connection after the operation settles");
        };
        asupersync::time::timeout(cx.now(), Duration::from_secs(20), Box::pin(scenario)).await
            .expect("DPoP Task rollover TLS scenario exceeded its external bound");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn tls_clean_rollover_reconciles_after_fresh_ack_and_preserves_default_behavior() {
    for case in [Case::Complete, Case::TerminalBeforeReconnect, Case::Disabled] { run_case(case); }
}
#[test]
fn tls_reconnected_input_is_a_host_handoff_not_an_implicit_update() {
    run_case(Case::InputHandoff);
}
#[test]
fn tls_stale_ack_and_unfinished_endings_never_authorize_successors() {
    for case in [Case::StaleAck, Case::MalformedTail, Case::MissingTerminal] { run_case(case); }
}
#[test]
fn tls_reconnect_preserves_caps_and_can_handoff_to_explicit_polling() {
    for case in [Case::SnapshotCap, Case::AckCap, Case::ReconnectCap, Case::PollFallback] { run_case(case); }
}
#[test]
fn tls_original_deadline_and_cancellation_bound_reconnect_delay() {
    for case in [Case::Deadline, Case::CancelDelay] { run_case(case); }
}
