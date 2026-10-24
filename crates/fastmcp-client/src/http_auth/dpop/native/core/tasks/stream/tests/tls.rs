//! Public DPoP Task streaming over real loopback TLS, without a transport seam.
//! The inline identity is the existing public TEST ONLY fixture. It never
//! changes process trust and requires no PEM file on remote build workers.

mod driver;

use super::*;
use std::future::poll_fn;
use std::collections::BTreeSet;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::net::TcpListener;
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder};
use fastmcp_protocol::{FinalHttpRequestMetadata, RequestVersionMetadata, admit_final_http_request};

const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

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
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(60_000_000_000), future)
            .await.expect("Task streaming fixture must settle, never hang or replay");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

fn configured(target: &str) -> (DpopHttpClient, DpopCredential, TlsAcceptor) {
    let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
    let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(),
        CanonicalHttpUrl::parse(target).unwrap()).unwrap();
    let credential = session.admit_token_response(&issuer, 200,
        br#"{"access_token":"stream-task-token","token_type":"DPoP","expires_in":120}"#,
        Instant::now(), Duration::from_secs(120)).unwrap();
    let root = Certificate::from_pem(ROOT).unwrap().remove(0);
    let policy = DpopHttpPolicy::default().with_resource_root_der(root.as_der().to_vec()).unwrap();
    let client = DpopHttpClient::new(session, policy).unwrap();
    let acceptor = TlsAcceptorBuilder::new(CertificateChain::from_pem(LEAF).unwrap(),
        PrivateKey::from_pem(KEY).unwrap()).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();
    (client, credential, acceptor)
}

async fn read<IO: AsyncRead + Unpin>(io: &mut IO) -> (String, Value) {
    let mut bytes = Vec::new();
    let mut block = [0; 2048];
    let end = loop {
        let n = io.read(&mut block).await.unwrap();
        assert!(n > 0 && bytes.len() + n <= 32 * 1024);
        bytes.extend_from_slice(&block[..n]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") { break index + 4; }
    };
    let head = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
    let length = header(&head, "content-length").parse::<usize>().unwrap();
    assert!(end + length <= 32 * 1024);
    while bytes.len() < end + length {
        let n = io.read(&mut block).await.unwrap();
        assert!(n > 0 && bytes.len() + n <= 32 * 1024);
        bytes.extend_from_slice(&block[..n]);
    }
    assert_eq!(bytes.len(), end + length);
    (head, serde_json::from_slice(&bytes[end..]).unwrap())
}

fn header<'a>(head: &'a str, expected: &str) -> &'a str {
    let values: Vec<_> = head.lines().filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case(expected))
        .map(|(_, value)| value.trim()).collect();
    assert_eq!(values.len(), 1, "one {expected} header");
    values[0]
}

// Captured proof payloads assert binding and freshness, not signature validation.
fn claims(proof: &str) -> Value {
    let parts: Vec<_> = proof.split('.').collect();
    assert_eq!(parts.len(), 3);
    let (mut acc, mut bits) = (0_u32, 0_u32);
    let mut bytes = Vec::new();
    for byte in parts[1].bytes() {
        let n = match byte {
            b'A'..=b'Z' => byte - b'A', b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52, b'-' => 62, b'_' => 63,
            _ => panic!("invalid base64url"),
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

fn inspect(head: &str, body: &Value, target: &str, method: &str, id: i64, proofs: &mut BTreeSet<String>) {
    assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
    assert_eq!(body["id"], id);
    assert_eq!(body["method"], method);
    assert_eq!(header(head, "authorization"), "DPoP stream-task-token");
    assert_eq!(header(head, "mcp-method"), method);
    assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"], json!({TASKS_EXTENSION:{}}));
    let proof = claims(header(head, "dpop"));
    assert_eq!(proof["htm"], "POST");
    assert_eq!(proof["htu"], target.split('?').next().unwrap());
    assert!(proof["ath"].as_str().is_some_and(|hash| !hash.is_empty()));
    if proofs.is_empty() {
        assert!(proof.get("nonce").is_none());
    } else {
        assert_eq!(proof["nonce"], "stream-next");
    }
    assert!(proofs.insert(proof["jti"].as_str().unwrap().to_owned()));
    if method == "server/discover" {
        assert!(body["params"].get("taskId").is_none());
        assert!(body["params"].get("arguments").is_none());
        assert_eq!(header(head, "accept"), "application/json");
        return;
    }
    assert_eq!(header(head, "accept"), "application/json, text/event-stream");
    let key = if method == "tools/call" { "name" } else { "taskId" };
    let mirror = header(head, "mcp-name");
    assert!(admit_final_http_request(FinalHttpRequestMetadata {
        version: RequestVersionMetadata {
            header_version: Some(header(head, "mcp-protocol-version")),
            body_version: body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"].as_str(),
        },
        header_method: Some(header(head, "mcp-method")),
        body_method: body["method"].as_str(),
        header_name: Some(mirror), body_name: body["params"][key].as_str(),
    }).is_ok());
    if method == "tools/call" {
        assert_eq!(body["params"]["arguments"]["private"], "body-only");
        assert!(!head.contains("body-only"));
    }
}

async fn json_reply<IO: AsyncWrite + Unpin>(io: &mut IO, bytes: &[u8]) {
    let mut wire = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nDPoP-Nonce: stream-next\r\nConnection: close\r\n\r\n", bytes.len()).into_bytes();
    wire.extend_from_slice(bytes);
    io.write_all(&wire).await.unwrap();
    io.shutdown().await.unwrap();
}

fn chunk(data: &[u8]) -> Vec<u8> {
    let mut wire = format!("{:X}\r\n", data.len()).into_bytes();
    wire.extend_from_slice(data);
    wire.extend_from_slice(b"\r\n");
    wire
}

fn event_chunk(payload: &[u8]) -> Vec<u8> {
    let mut data = b"data: ".to_vec();
    data.extend_from_slice(payload);
    data.extend_from_slice(b"\n\n");
    chunk(&data)
}

async fn event<IO: AsyncWrite + Unpin>(io: &mut IO, payload: &[u8]) {
    // Keep the complete frame and chunk trailer in one write: an observer may
    // close as soon as it sees the last data LF, before a separate trailer write.
    io.write_all(&event_chunk(payload)).await.unwrap();
    io.flush().await.unwrap();
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Json, Sse, ForeignId, WrongTask, DuplicateTerminal, IncompleteTail, MissingTerminal,
    RemoteError, NoOffer, NonceChallenge, Stop, Cancel, Revoke, Quota, BadProgress,
}

async fn exercise(kind: usize, case: Case) {
    let cx = Cx::current().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
    let (mut client, credential, acceptor) = configured(&target);
    let cancellation = McpRequestCancellation::new();
    let observed = McpRequestCancellation::new();
    let mut calls = 0;
    let mut proofs = BTreeSet::new();
    let selected = limits(if matches!(case, Case::Quota) { 1 } else { 8 });
    let application = client.request_task_with_events(
        &cx, &cancellation, &credential, metadata(), operation(kind, 1), selected,
        |notification| {
            assert!(matches!(notification, ServerNotification::Progress(_)));
            calls += 1;
            observed.cancel();
            if matches!(case, Case::Cancel) { cancellation.cancel(); }
            if matches!(case, Case::Revoke) { credential.revoke(); }
            !matches!(case, Case::Stop)
        },
    );
    let peer = async {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let (head, body) = read(&mut socket).await;
        inspect(&head, &body, &target, "server/discover", 1, &mut proofs);
        let mut offer = discovery_result();
        if matches!(case, Case::NoOffer) { offer["capabilities"]["extensions"] = json!({}); }
        json_reply(&mut socket, &frame(1, &offer.to_string())).await;
        if matches!(case, Case::NoOffer) { return; }
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let (head, body) = read(&mut socket).await;
        let method = ["tools/call", "tasks/get", "tasks/update", "tasks/cancel"][kind];
        inspect(&head, &body, &target, method, 2, &mut proofs);
        if matches!(case, Case::NonceChallenge) {
            // Withhold the advertised body: a challenge must not await it or replay.
            socket.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 1024\r\nDPoP-Nonce: stream-next\r\nConnection: close\r\n\r\n").await.unwrap();
            socket.flush().await.unwrap();
        } else if matches!(case, Case::Json) {
            json_reply(&mut socket, &frame(2, &terminal(kind))).await;
            return;
        } else {
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nDPoP-Nonce: stream-next\r\nConnection: close\r\n\r\n").await.unwrap();
            event(&mut socket, &progress(json!("work"), "1")).await;
            // Terminal bytes do not exist until the public observer has run.
            observed.cancelled().await;
            if matches!(case, Case::Stop | Case::Cancel | Case::Revoke) {
                // The failed caller must release this socket before any terminal.
            } else if matches!(case, Case::Quota | Case::BadProgress) {
                event(&mut socket, &progress(json!("work"), if matches!(case, Case::Quota) { "2" } else { "1" })).await;
            } else {
                let mut tail = Vec::new();
                if !matches!(case, Case::MissingTerminal) {
                    let bytes = if matches!(case, Case::RemoteError) {
                        br#"{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"private-peer-canary","data":"private-data-canary"}}"#.to_vec()
                    } else {
                        let result = if matches!(case, Case::WrongTask) { terminal(kind).replace("task-one", "other-task") } else { terminal(kind) };
                        frame(if matches!(case, Case::ForeignId) { 3 } else { 2 }, &result)
                    };
                    tail.extend_from_slice(&event_chunk(&bytes));
                    if matches!(case, Case::DuplicateTerminal) {
                        tail.extend_from_slice(&event_chunk(&bytes));
                    }
                }
                if matches!(case, Case::IncompleteTail) {
                    tail.extend_from_slice(&chunk(b"data: unfinished"));
                }
                tail.extend_from_slice(b"0\r\n\r\n");
                // Do not let a product's intentional early rejection race a
                // separate write of a trailing marker and obscure its error.
                socket.write_all(&tail).await.unwrap();
                let shutdown = socket.shutdown().await;
                if matches!(case, Case::Sse) { shutdown.unwrap(); }
                return;
            }
        }
        let mut byte = [0];
        assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0));
    };
    let (outcome, ()) = pair(application, peer).await;
    match case {
        Case::Json | Case::Sse => assert_result(kind, outcome.unwrap()),
        case => {
            let error = outcome.err().expect("planted failure must not publish a result");
            assert!(!format!("{error:?} {error}").contains("canary"));
            assert!(match (case, error) {
                (Case::ForeignId, DpopStreamError::Task(DpopTasksError::Task(ManagedTasksError::ResponseIdMismatch)))
                | (Case::WrongTask, DpopStreamError::Task(DpopTasksError::Task(ManagedTasksError::TaskIdMismatch)))
                | (Case::RemoteError, DpopStreamError::Task(DpopTasksError::Task(ManagedTasksError::Remote { .. })))
                | (Case::NoOffer, DpopStreamError::Task(DpopTasksError::Task(ManagedTasksError::Negotiation)))
                | (Case::DuplicateTerminal | Case::IncompleteTail, DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidResponse)))
                | (Case::MissingTerminal, DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::MissingTerminal)))
                | (Case::NonceChallenge, DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::HttpStatus { status:401 })))
                | (Case::Stop, DpopStreamError::ObserverStopped)
                | (Case::Cancel, DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled)))
                | (Case::Revoke, DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Authorization(_))))
                | (Case::Quota, DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::NotificationLimit)))
                | (Case::BadProgress, DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidProgress))) => true,
                _ => false,
            }, "wrong failure disposition for {case:?}");
        }
    }
    assert_eq!(calls, usize::from(!matches!(case, Case::Json | Case::NoOffer | Case::NonceChallenge)));
    assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
    assert!(cx.checkpoint().is_ok());
    assert!(!client.revocation_handle().is_revoked());
    if matches!(case, Case::Revoke) { return; }
    // This is a fresh EXPLICIT call, with a different local cancellation domain.
    // A previous failure may retire its socket, but not the usable shared client.
    let follow_cancel = McpRequestCancellation::new();
    let application = client.request_task_with_events(
        &cx, &follow_cancel, &credential, metadata(), operation(1, 3), limits(0),
        |_| panic!("JSON follow-up cannot deliver a notification"),
    );
    let peer = async {
        for (id, method, result) in [(3, "server/discover", discovery_result().to_string()), (4, "tasks/get", terminal(1))] {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (head, body) = read(&mut socket).await;
            inspect(&head, &body, &target, method, id, &mut proofs);
            json_reply(&mut socket, &frame(id, &result)).await;
        }
    };
    let (result, ()) = pair(application, peer).await;
    assert_result(1, result.unwrap());
    assert_eq!(proofs.len(), if matches!(case, Case::NoOffer) { 3 } else { 4 });
    assert!(!follow_cancel.is_cancel_requested());
    assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
}

#[test]
fn every_public_task_verb_delivers_incrementally_and_keeps_json_interoperability() {
    for kind in 0..4 {
        for case in [Case::Json, Case::Sse] { run(exercise(kind, case)); }
    }
}

#[test]
fn failed_streams_never_replay_or_poison_a_fresh_explicit_operation() {
    for case in [Case::ForeignId, Case::WrongTask, Case::DuplicateTerminal, Case::IncompleteTail,
        Case::MissingTerminal, Case::RemoteError, Case::NoOffer, Case::NonceChallenge, Case::Stop,
        Case::Cancel, Case::Revoke, Case::Quota, Case::BadProgress] {
        run(exercise(1, case));
    }
}
