//! Public registered-extension calls on the existing loopback TLS fixture.
//! Inline certificates are the public TEST ONLY oauth-core identity, so the
//! native tests do not depend on remote-worker PEM transfer or process trust.

use super::*;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::net::TcpListener;
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::ClientCapabilities;
use fastmcp_protocol::dpop::{DpopKey, DpopNonce};
use std::collections::BTreeSet;
use std::future::{Future, poll_fn};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use crate::http_auth::dpop::DpopSession;
use crate::http_auth::dpop::native::{DpopHttpError, DpopHttpPolicy};
use crate::http_auth::dpop::native::core::DpopCoreError;

const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

const SOURCE: &str = r#"{ "resultType" : "com.example/dpop-echo-result", "value" : {"number":1.20e+4,"zero":-0,"large":123456789012345678901234567890,"text":"雪"} }"#;
const SSE_HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nDPoP-Nonce: extension-next\r\nConnection: close\r\n\r\n";

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let (mut one, mut two) = (None, None);
    poll_fn(|task| {
        if one.is_none() {
            if let Poll::Ready(value) = left.as_mut().poll(task) {
                one = Some(value);
            }
        }
        if two.is_none() {
            if let Poll::Ready(value) = right.as_mut().poll(task) {
                two = Some(value);
            }
        }
        if one.is_some() && two.is_some() {
            Poll::Ready((one.take().unwrap(), two.take().unwrap()))
        } else {
            Poll::Pending
        }
    })
    .await
}

fn run(future: impl Future<Output = ()>) {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .with_reactor(create_reactor().unwrap())
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(60_000_000_000), future)
            .await
            .expect("registered extension fixture must settle without hidden retries");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

fn configured(target: &str) -> (DpopHttpClient, DpopCredential, TlsAcceptor) {
    let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
    let session = DpopSession::new(
        DpopKey::generate().unwrap(),
        issuer.clone(),
        CanonicalHttpUrl::parse(target).unwrap(),
    )
    .unwrap();
    let credential = session
        .admit_token_response(
            &issuer,
            200,
            br#"{"access_token":"extension-access","token_type":"DPoP","expires_in":120}"#,
            Instant::now(),
            Duration::from_secs(120),
        )
        .unwrap();
    let root = Certificate::from_pem(ROOT).unwrap().remove(0);
    let policy = DpopHttpPolicy::default()
        .with_resource_root_der(root.as_der().to_vec())
        .unwrap()
        .with_max_body_bytes(8192)
        .unwrap();
    let client = DpopHttpClient::new(session, policy).unwrap();
    let acceptor = TlsAcceptorBuilder::new(
        CertificateChain::from_pem(LEAF).unwrap(),
        PrivateKey::from_pem(KEY).unwrap(),
    )
    .alpn_protocols(vec![b"http/1.1".to_vec()])
    .build()
    .unwrap();
    (client, credential, acceptor)
}

fn metadata() -> FinalRequestMeta {
    FinalRequestMeta::new(ClientCapabilities::default())
}

fn parameters() -> Value {
    json!({
        "private":"body-only-canary",
        "_meta":{"progressToken":"owned", "com.example/note":"retained"},
    })
}

fn operation(discovery: i64) -> DpopExtensionOperation {
    DpopExtensionOperation::new(
        RequestId::Number(discovery),
        RequestId::String((discovery + 1).to_string()),
        extension_id(),
        METHOD,
        parameters(),
    )
    .unwrap()
}

fn limits(notifications: usize) -> DpopStreamLimits {
    DpopStreamLimits::new(
        ManagedCoreLimits::new(8192, 8192, 32768, notifications, Duration::from_secs(60))
            .unwrap(),
        Duration::from_secs(10),
    )
    .unwrap()
}

fn discovery() -> Value {
    json!({
        "resultType":"complete", "supportedVersions":["2026-07-28"],
        "capabilities":{"extensions":{
            EXTENSION:{"format":"echo-v1","capacity":8},
            OTHER_EXTENSION:{"format":"echo-v1","capacity":8},
        }},
        "ttlMs":0, "cacheScope":"private",
    })
}

fn frame(id: &RequestId, source: &str) -> Vec<u8> {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{source}}}",
        serde_json::to_string(id).unwrap()).into_bytes()
}

fn progress(token: Value, value: &str) -> Vec<u8> {
    format!("{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"progressToken\":{token},\"progress\":{value}}}}}").into_bytes()
}

fn header<'a>(head: &'a str, expected: &str) -> &'a str {
    let values: Vec<_> = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case(expected))
        .map(|(_, value)| value.trim())
        .collect();
    assert_eq!(values.len(), 1, "exactly one {expected} header");
    values[0]
}

async fn read<IO: AsyncRead + Unpin>(io: &mut IO) -> (String, Value) {
    let mut bytes = Vec::new();
    let mut block = [0; 2048];
    let end = loop {
        let count = io.read(&mut block).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&block[..count]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let head = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
    let length = header(&head, "content-length").parse::<usize>().unwrap();
    assert!(end + length <= 32 * 1024);
    while bytes.len() < end + length {
        let count = io.read(&mut block).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&block[..count]);
    }
    assert_eq!(bytes.len(), end + length);
    (head, serde_json::from_slice(&bytes[end..]).unwrap())
}

// Captured proof payloads prove freshness and binding, not signature validation.
fn claims(proof: &str) -> Value {
    let parts: Vec<_> = proof.split('.').collect();
    assert_eq!(parts.len(), 3);
    let (mut acc, mut bits) = (0_u32, 0_u32);
    let mut bytes = Vec::new();
    for byte in parts[1].bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => panic!("invalid base64url"),
        };
        acc = (acc << 6) | u32::from(digit);
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

fn inspect(
    head: &str,
    body: &Value,
    target: &str,
    method: &str,
    id: &RequestId,
    proofs: &mut BTreeSet<String>,
) {
    assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
    assert_eq!(body["id"], serde_json::to_value(id).unwrap());
    assert_eq!(body["method"], method);
    assert_eq!(header(head, "authorization"), "DPoP extension-access");
    assert_eq!(header(head, "mcp-method"), method);
    assert_eq!(header(head, "mcp-protocol-version"), "2026-07-28");
    assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], "2026-07-28");
    assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
        json!({EXTENSION:{"format":"echo-v1"},OTHER_EXTENSION:{"format":"echo-v1"}}));
    let proof = claims(header(head, "dpop"));
    assert_eq!(proof["htm"], "POST");
    assert_eq!(proof["htu"], target.split('?').next().unwrap());
    assert!(proof["ath"].as_str().is_some_and(|hash| !hash.is_empty()));
    if proofs.is_empty() {
        assert!(proof.get("nonce").is_none());
    } else {
        assert_eq!(proof["nonce"], "extension-next");
    }
    assert!(proofs.insert(proof["jti"].as_str().unwrap().to_owned()), "every POST signs a fresh proof");
    assert!(!head.contains("body-only-canary"));
    assert!(!head.lines().any(|line| line.to_ascii_lowercase().starts_with("mcp-name:")));
    if method == "server/discover" {
        assert_eq!(header(head, "accept"), "application/json");
        assert!(body["params"].get("private").is_none());
        assert!(body["params"]["_meta"].get("progressToken").is_none());
        assert!(body["params"]["_meta"].get("com.example/note").is_none());
    } else {
        assert_eq!(header(head, "accept"), "application/json, text/event-stream");
        assert_eq!(body["params"]["private"], "body-only-canary");
        assert_eq!(body["params"]["_meta"]["progressToken"], "owned");
        assert_eq!(body["params"]["_meta"]["com.example/note"], "retained");
    }
}

async fn json_reply<IO: AsyncWrite + Unpin>(io: &mut IO, payload: &[u8]) {
    let mut wire = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nDPoP-Nonce: extension-next\r\nConnection: close\r\n\r\n", payload.len()).into_bytes();
    wire.extend_from_slice(payload);
    io.write_all(&wire).await.unwrap();
    let _closed = io.shutdown().await;
}

fn chunk(payload: &[u8]) -> Vec<u8> {
    let mut wire = format!("{:X}\r\n", payload.len()).into_bytes();
    wire.extend_from_slice(payload);
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
    io.write_all(&event_chunk(payload)).await.unwrap();
    io.flush().await.unwrap();
}

fn assert_result(result: DpopExtensionResult, id: &RequestId) {
    assert_eq!(result.request_id(), id);
    assert_eq!(result.raw_result_source(), SOURCE);
    assert_eq!(result.result()["resultType"], RESULT);
    assert_eq!(result.result()["value"]["text"], "雪");
    assert_eq!(result.into_result()["resultType"], RESULT);
}

fn no_extra(listener: &TcpListener) {
    assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending(),
        "no retry, remote cancellation, refresh, or other hidden connection");
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Json,
    Sse,
    ForeignId,
    ForeignResult,
    UnknownResult,
    MissingDiscriminator,
    InvalidResultMeta,
    DuplicateMember,
    DuplicateTerminal,
    IncompleteTail,
    MissingTerminal,
    RemoteError,
    NoOffer,
    InactiveOffer,
    UnknownOffer,
    IncompatibleOffer,
    UnsupportedVersion,
    DiscoveryWrongId,
    NonceChallenge,
    Stop,
    Panic,
    Cancel,
    Revoke,
    NotificationLimit,
    BadProgress,
    ForeignProgress,
    ReverseRequest,
    UnknownNotification,
    BodyLimit,
    FrameLimit,
}

impl Case {
    fn ends_at_discovery(self) -> bool {
        matches!(self, Self::NoOffer | Self::InactiveOffer | Self::UnknownOffer
            | Self::IncompatibleOffer | Self::UnsupportedVersion | Self::DiscoveryWrongId)
    }

    fn has_progress(self) -> bool {
        !self.ends_at_discovery()
            && !matches!(self, Self::Json | Self::NonceChallenge | Self::FrameLimit)
    }
}

async fn exercise(case: Case) {
    let cx = Cx::current().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
    let (mut client, credential, acceptor) = configured(&target);
    let mut primary = descriptor();
    if matches!(case, Case::InactiveOffer) {
        primary.resolver.fallback = ExtensionFallbackPolicy::ClientInactiveFallback;
    }
    let (configuration, factories) = configuration(primary, true);
    let cancellation = McpRequestCancellation::new();
    let observed = McpRequestCancellation::new();
    let mut calls = 0;
    let mut proofs = BTreeSet::new();
    let selected = if matches!(case, Case::FrameLimit) {
        DpopStreamLimits::new(
            ManagedCoreLimits::new(8192, 1024, 32768, 8, Duration::from_secs(60)).unwrap(),
            Duration::from_secs(10),
        )
        .unwrap()
    } else {
        limits(if matches!(case, Case::NotificationLimit) { 1 } else { 8 })
    };
    let application = client.request_final_extension_with_events(
        &cx, &cancellation, &credential, &configuration, metadata(), operation(1), selected,
        |notification| {
            assert!(matches!(notification, ServerNotification::Progress(_)));
            calls += 1;
            observed.cancel();
            if matches!(case, Case::Cancel) {
                cancellation.cancel();
            }
            if matches!(case, Case::Revoke) {
                credential.revoke();
            }
            assert!(!matches!(case, Case::Panic), "observer-private-canary");
            !matches!(case, Case::Stop)
        },
    );
    let peer = async {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let (head, body) = read(&mut socket).await;
        inspect(&head, &body, &target, "server/discover", &RequestId::Number(1), &mut proofs);
        let mut offer = discovery();
        if matches!(case, Case::NoOffer | Case::InactiveOffer | Case::UnknownOffer) {
            offer["capabilities"]["extensions"].as_object_mut().unwrap().remove(EXTENSION);
        }
        if matches!(case, Case::UnknownOffer) {
            offer["capabilities"]["extensions"]["com.example/unregistered"] =
                json!({"format":"echo-v1","capacity":8});
        }
        if matches!(case, Case::IncompatibleOffer) {
            offer["capabilities"]["extensions"][EXTENSION]["format"] = json!("different-v1");
        }
        if matches!(case, Case::UnsupportedVersion) {
            offer["supportedVersions"] = json!(["2024-11-05"]);
        }
        let discovery_id = if matches!(case, Case::DiscoveryWrongId) {
            RequestId::String("1".to_owned())
        } else {
            RequestId::Number(1)
        };
        json_reply(&mut socket, &frame(&discovery_id, &offer.to_string())).await;
        if case.ends_at_discovery() {
            return;
        }
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let (head, body) = read(&mut socket).await;
        let operation_id = RequestId::String("2".to_owned());
        inspect(&head, &body, &target, METHOD, &operation_id, &mut proofs);
        if matches!(case, Case::NonceChallenge) {
            // Refusal must retire this socket without waiting for its absent
            // advertised body or replaying the request with a new proof.
            socket.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 1024\r\nDPoP-Nonce: extension-next\r\nConnection: close\r\n\r\n").await.unwrap();
            socket.flush().await.unwrap();
        } else if matches!(case, Case::Json | Case::FrameLimit) {
            let source = if matches!(case, Case::FrameLimit) {
                json!({"resultType":RESULT,"value":"x".repeat(2048)}).to_string()
            } else {
                SOURCE.to_owned()
            };
            json_reply(&mut socket, &frame(&operation_id, &source)).await;
            return;
        } else {
            socket.write_all(SSE_HEAD).await.unwrap();
            event(&mut socket, &progress(json!("owned"), "1")).await;
            // A buffering implementation cannot pass: terminal bytes are not
            // written until the public observer has already seen the progress.
            observed.cancelled().await;
            if matches!(case, Case::Stop | Case::Panic | Case::Cancel | Case::Revoke) {
                // Leave the stream open until the application releases it.
            } else if matches!(case, Case::NotificationLimit | Case::BadProgress | Case::ForeignProgress) {
                let token = if matches!(case, Case::ForeignProgress) { json!(1) } else { json!("owned") };
                event(&mut socket, &progress(token, if matches!(case, Case::BadProgress) { "1" } else { "2" })).await;
            } else if matches!(case, Case::ReverseRequest | Case::UnknownNotification) {
                let record = if matches!(case, Case::ReverseRequest) {
                    br#"{"jsonrpc":"2.0","id":"reverse","method":"example/reverse","params":{}}"#.as_slice()
                } else {
                    br#"{"jsonrpc":"2.0","method":"example/unregistered-notification","params":{}}"#.as_slice()
                };
                event(&mut socket, record).await;
            } else if matches!(case, Case::BodyLimit) {
                // Comments consume the independent native wire budget even
                // though they consume no decoded JSON or notification quota.
                let comment = format!(":{}\n\n", "x".repeat(8192));
                socket.write_all(&chunk(comment.as_bytes())).await.unwrap();
                socket.flush().await.unwrap();
            } else {
                let mut tail = Vec::new();
                if !matches!(case, Case::MissingTerminal) {
                    let payload = if matches!(case, Case::RemoteError) {
                        br#"{"jsonrpc":"2.0","id":"2","error":{"code":-32603,"message":"peer-private-canary","data":"peer-data-canary"}}"#.to_vec()
                    } else if matches!(case, Case::DuplicateMember) {
                        br#"{"jsonrpc":"2.0","id":"2","result":{"resultType":"com.example/dpop-echo-result","value":1,"value":2}}"#.to_vec()
                    } else {
                        let source = match case {
                            Case::ForeignResult => json!({"resultType":OTHER_RESULT}).to_string(),
                            Case::UnknownResult => json!({"resultType":"com.example/unregistered-result"}).to_string(),
                            Case::MissingDiscriminator => json!({"value":7}).to_string(),
                            Case::InvalidResultMeta => json!({"resultType":RESULT,"_meta":[]}).to_string(),
                            _ => SOURCE.to_owned(),
                        };
                        let id = if matches!(case, Case::ForeignId) { RequestId::Number(2) } else { operation_id };
                        frame(&id, &source)
                    };
                    tail.extend_from_slice(&event_chunk(&payload));
                    if matches!(case, Case::DuplicateTerminal) {
                        tail.extend_from_slice(&event_chunk(&payload));
                    }
                }
                if matches!(case, Case::IncompleteTail) {
                    tail.extend_from_slice(&chunk(b"data: unfinished"));
                }
                tail.extend_from_slice(b"0\r\n\r\n");
                socket.write_all(&tail).await.unwrap();
                let closed = socket.shutdown().await;
                if matches!(case, Case::Sse) {
                    closed.unwrap();
                }
                return;
            }
        }
        let mut byte = [0];
        assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0),
            "rejected stream must release its owned socket without a terminal");
    };
    let (outcome, ()) = pair(application, peer).await;
    if matches!(case, Case::Json | Case::Sse) {
        assert_result(outcome.unwrap(), &RequestId::String("2".to_owned()));
    } else {
        let error = outcome.err().expect("planted failure must not publish a result");
        assert!(!format!("{error:?} {error}").contains("canary"));
        let expected = match (&case, &error) {
            (Case::ForeignId | Case::DiscoveryWrongId,
                DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseIdMismatch)))
            | (Case::ForeignResult | Case::UnknownResult | Case::MissingDiscriminator | Case::InvalidResultMeta,
                DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidResult)))
            | (Case::DuplicateMember | Case::DuplicateTerminal | Case::IncompleteTail,
                DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidResponse)))
            | (Case::MissingTerminal,
                DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::MissingTerminal)))
            | (Case::RemoteError,
                DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::Remote { .. })))
            | (Case::NoOffer | Case::InactiveOffer | Case::UnknownOffer | Case::IncompatibleOffer | Case::UnsupportedVersion,
                DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::UnsupportedRequest)))
            | (Case::NonceChallenge,
                DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::HttpStatus { status: 401 })))
            | (Case::Stop, DpopStreamError::ObserverStopped)
            | (Case::Panic, DpopStreamError::ObserverPanicked)
            | (Case::Cancel, DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled)))
            | (Case::Revoke, DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Authorization(_))))
            | (Case::NotificationLimit,
                DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::NotificationLimit)))
            | (Case::BadProgress | Case::ForeignProgress,
                DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidProgress)))
            | (Case::ReverseRequest | Case::UnknownNotification,
                DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::UnexpectedNotification)))
            | (Case::BodyLimit, DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::BodyTooLarge)))
            | (Case::FrameLimit,
                DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit))) => true,
            _ => false,
        };
        assert!(expected, "unexpected disposition for {case:?}: {error:?}");
    }
    assert_eq!(calls, usize::from(case.has_progress()));
    assert_eq!(proofs.len(), if case.ends_at_discovery() { 1 } else { 2 });
    assert_eq!(factories.load(Ordering::SeqCst),
        usize::from(!matches!(case, Case::UnsupportedVersion | Case::DiscoveryWrongId)));
    assert_eq!(client.session.resource_nonce, Some(DpopNonce::new("extension-next").unwrap()));
    assert!(client.session.token_nonce.is_none());
    no_extra(&listener);
    assert!(cx.checkpoint().is_ok());
    assert!(!client.revocation_handle().is_revoked());
    if matches!(case, Case::Revoke) {
        return;
    }

    // A fresh explicit operation has its own cancellation domain, discovery,
    // resolver and proof. Earlier transport refusal cannot poison this client.
    let follow_cancel = McpRequestCancellation::new();
    let application = client.request_final_extension(
        &cx, &follow_cancel, &credential, &configuration, metadata(), operation(3), limits(0),
    );
    let peer = async {
        for (id, method, source) in [
            (RequestId::Number(3), "server/discover", discovery().to_string()),
            (RequestId::String("4".to_owned()), METHOD, SOURCE.to_owned()),
        ] {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (head, body) = read(&mut socket).await;
            inspect(&head, &body, &target, method, &id, &mut proofs);
            json_reply(&mut socket, &frame(&id, &source)).await;
        }
    };
    let (result, ()) = pair(application, peer).await;
    assert_result(result.unwrap(), &RequestId::String("4".to_owned()));
    assert_eq!(proofs.len(), if case.ends_at_discovery() { 3 } else { 4 });
    assert_eq!(factories.load(Ordering::SeqCst),
        1 + usize::from(!matches!(case, Case::UnsupportedVersion | Case::DiscoveryWrongId)));
    assert!(!follow_cancel.is_cancel_requested());
    no_extra(&listener);
}

#[test]
fn public_extension_json_and_sse_keep_source_and_fresh_dpop_authority() {
    for case in [Case::Json, Case::Sse] {
        run(exercise(case));
    }
}

#[test]
fn extension_discovery_cannot_dispatch_absent_incompatible_or_foreign_capability() {
    for case in [Case::NoOffer, Case::InactiveOffer, Case::UnknownOffer,
        Case::IncompatibleOffer, Case::UnsupportedVersion, Case::DiscoveryWrongId] {
        run(exercise(case));
    }
}

#[test]
fn extension_streams_reject_unowned_results_ids_and_unclean_completion() {
    for case in [Case::ForeignId, Case::ForeignResult, Case::UnknownResult,
        Case::MissingDiscriminator, Case::InvalidResultMeta, Case::DuplicateMember,
        Case::DuplicateTerminal, Case::IncompleteTail, Case::MissingTerminal, Case::RemoteError] {
        run(exercise(case));
    }
}

#[test]
fn extension_streams_enforce_progress_and_independent_response_bounds() {
    for case in [Case::NotificationLimit, Case::BadProgress, Case::ForeignProgress,
        Case::ReverseRequest, Case::UnknownNotification, Case::BodyLimit, Case::FrameLimit] {
        run(exercise(case));
    }
}

#[test]
fn stopped_extension_streams_release_sockets_and_keep_explicit_followup_usable() {
    for case in [Case::NonceChallenge, Case::Stop, Case::Panic, Case::Cancel, Case::Revoke] {
        run(exercise(case));
    }
}

#[test]
fn extension_preflight_rejects_unowned_or_invalid_operations_without_a_connection() {
    #[derive(Clone, Copy, Debug)]
    enum Rejection {
        Owner,
        Direction,
        Disabled,
        Method,
        Metadata,
        Capabilities,
        ClientInfo,
        Progress,
        Version,
        BaseCapabilities,
        RequestLimit,
        Cancelled,
        Revoked,
    }
    for rejection in [
        Rejection::Owner, Rejection::Direction, Rejection::Disabled, Rejection::Method,
        Rejection::Metadata, Rejection::Capabilities, Rejection::ClientInfo,
        Rejection::Progress, Rejection::Version, Rejection::BaseCapabilities,
        Rejection::RequestLimit, Rejection::Cancelled, Rejection::Revoked,
    ] {
        run(async {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
            let (mut client, credential, _acceptor) = configured(&target);
            let mut primary = descriptor();
            if matches!(rejection, Rejection::Direction) {
                let method = primary.method.as_mut().unwrap();
                method.direction = ExtensionDirection::ServerToClient;
                method.http_era_disposition = None;
            }
            let (configuration, factories) =
                configuration(primary, !matches!(rejection, Rejection::Disabled));
            let mut metadata = metadata();
            let mut params = parameters();
            match rejection {
                Rejection::Metadata => {
                    params["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2024-11-05");
                }
                Rejection::Capabilities => {
                    params["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
                        json!({"extensions":{"com.example/forged":{}}});
                }
                Rejection::ClientInfo => {
                    params["_meta"]["io.modelcontextprotocol/clientInfo"] =
                        json!({"name":"forged-client","version":"1"});
                }
                Rejection::Progress => params["_meta"]["progressToken"] = json!({"invalid":1}),
                Rejection::Version => metadata.protocol_version = "2024-11-05".to_owned(),
                Rejection::BaseCapabilities => {
                    metadata.client_capabilities.extensions =
                        Some(BTreeMap::from([("com.example/forged".to_owned(), json!({}))]));
                }
                Rejection::RequestLimit => params["oversized"] = json!("x".repeat(2048)),
                _ => {}
            }
            let selected = if matches!(rejection, Rejection::RequestLimit) {
                DpopStreamLimits::new(
                    ManagedCoreLimits::new(1024, 8192, 32768, 8, Duration::from_secs(60)).unwrap(),
                    Duration::from_secs(10),
                ).unwrap()
            } else {
                limits(8)
            };
            let owner = if matches!(rejection, Rejection::Owner) {
                ExtensionId::parse(OTHER_EXTENSION).unwrap()
            } else {
                extension_id()
            };
            let method = if matches!(rejection, Rejection::Method) {
                "example/unregistered"
            } else {
                METHOD
            };
            let operation = DpopExtensionOperation::new(
                RequestId::Number(1), RequestId::String("2".to_owned()), owner, method, params,
            ).unwrap();
            let cancellation = McpRequestCancellation::new();
            if matches!(rejection, Rejection::Cancelled) {
                cancellation.cancel();
            }
            if matches!(rejection, Rejection::Revoked) {
                credential.revoke();
            }
            let error = client.request_final_extension(
                &cx, &cancellation, &credential, &configuration, metadata, operation, selected,
            ).await.err().expect("local refusal cannot succeed");
            let expected = match (rejection, &error) {
                (Rejection::Owner | Rejection::Direction | Rejection::Disabled
                    | Rejection::Method | Rejection::BaseCapabilities,
                    DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::UnsupportedRequest)))
                | (Rejection::Metadata | Rejection::Capabilities | Rejection::ClientInfo
                    | Rejection::Progress | Rejection::Version,
                    DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidRequest)))
                | (Rejection::RequestLimit,
                    DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::RequestTooLarge)))
                | (Rejection::Cancelled,
                    DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled)))
                | (Rejection::Revoked,
                    DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Authorization(_)))) => true,
                _ => false,
            };
            assert!(expected, "unexpected local disposition for {rejection:?}: {error:?}");
            assert_eq!(factories.load(Ordering::SeqCst), 0);
            assert!(client.session.resource_nonce.is_none());
            no_extra(&listener);
            assert!(cx.checkpoint().is_ok());
        });
    }
}

#[test]
fn discovery_and_extension_share_the_exact_aggregate_payload_budget() {
    for short in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
            let (mut client, credential, acceptor) = configured(&target);
            let (configuration, factories) = configuration(descriptor(), true);
            let discovery_frame = frame(&RequestId::Number(1), &discovery().to_string());
            let result_frame = frame(&RequestId::String("2".to_owned()), SOURCE);
            let total = discovery_frame.len() + result_frame.len() - usize::from(short);
            let maximum_frame = discovery_frame.len().max(result_frame.len());
            let selected = DpopStreamLimits::new(
                ManagedCoreLimits::new(
                    8192, maximum_frame, total, 0, Duration::from_secs(60),
                ).unwrap(),
                Duration::from_secs(10),
            ).unwrap();
            let cancellation = McpRequestCancellation::new();
            let mut proofs = BTreeSet::new();
            let application = client.request_final_extension(
                &cx, &cancellation, &credential, &configuration, metadata(), operation(1), selected,
            );
            let peer = async {
                for (id, method, payload) in [
                    (RequestId::Number(1), "server/discover", discovery_frame),
                    (RequestId::String("2".to_owned()), METHOD, result_frame),
                ] {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let (head, body) = read(&mut socket).await;
                    inspect(&head, &body, &target, method, &id, &mut proofs);
                    json_reply(&mut socket, &payload).await;
                }
            };
            let (outcome, ()) = pair(application, peer).await;
            if short {
                assert!(matches!(outcome,
                    Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit)))));
            } else {
                assert_result(outcome.unwrap(), &RequestId::String("2".to_owned()));
            }
            assert_eq!(proofs.len(), 2);
            assert_eq!(factories.load(Ordering::SeqCst), 1);
            no_extra(&listener);
        });
    }
}

#[test]
fn dropping_an_extension_stream_releases_the_socket_without_remote_cancellation() {
    run(async {
        let cx = Cx::current().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
        let (mut client, credential, acceptor) = configured(&target);
        let (configuration, factories) = configuration(descriptor(), true);
        let cancellation = McpRequestCancellation::new();
        let observed = McpRequestCancellation::new();
        let mut proofs = BTreeSet::new();
        let mut calls = 0;
        let application = async {
            let mut call = Box::pin(client.request_final_extension_with_events(
                &cx, &cancellation, &credential, &configuration, metadata(), operation(1), limits(8),
                |_| {
                    calls += 1;
                    observed.cancel();
                    true
                },
            ));
            poll_fn(|task| {
                assert!(call.as_mut().poll(task).is_pending());
                if observed.is_cancel_requested() { Poll::Ready(()) } else { Poll::Pending }
            }).await;
            drop(call);
        };
        let peer = async {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (head, body) = read(&mut socket).await;
            inspect(&head, &body, &target, "server/discover", &RequestId::Number(1), &mut proofs);
            json_reply(&mut socket, &frame(&RequestId::Number(1), &discovery().to_string())).await;
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (head, body) = read(&mut socket).await;
            inspect(&head, &body, &target, METHOD, &RequestId::String("2".to_owned()), &mut proofs);
            socket.write_all(SSE_HEAD).await.unwrap();
            event(&mut socket, &progress(json!("owned"), "1")).await;
            observed.cancelled().await;
            let mut byte = [0];
            assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0),
                "dropping the public future must retire the open response");
        };
        pair(application, peer).await;
        assert_eq!(calls, 1);
        assert_eq!(proofs.len(), 2);
        assert_eq!(factories.load(Ordering::SeqCst), 1);
        assert!(!cancellation.is_cancel_requested());
        assert!(!client.revocation_handle().is_revoked());
        assert!(cx.checkpoint().is_ok());
        no_extra(&listener);
    });
}

#[test]
fn discovery_and_progress_cannot_refund_the_original_extension_deadline() {
    use asupersync::time::{TimerDriverHandle, VirtualClock};

    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .with_reactor(create_reactor().unwrap())
        .with_timer_driver(timer.clone())
        .build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
        let (mut client, credential, acceptor) = configured(&target);
        let (configuration, factories) = configuration(descriptor(), true);
        let cancellation = McpRequestCancellation::new();
        let observed = McpRequestCancellation::new();
        let reached = McpRequestCancellation::new();
        let mut proofs = BTreeSet::new();
        let selected = DpopStreamLimits::new(
            ManagedCoreLimits::new(8192, 8192, 32768, 8, Duration::from_secs(10)).unwrap(),
            Duration::from_secs(10),
        ).unwrap();
        let application = async {
            let mut call = Box::pin(client.request_final_extension_with_events(
                &cx, &cancellation, &credential, &configuration, metadata(), operation(1), selected,
                |_| { observed.cancel(); true },
            ));
            let mut reached_wait = std::pin::pin!(reached.cancelled());
            poll_fn(|task| {
                let result = call.as_mut().poll(task);
                if reached_wait.as_mut().poll(task).is_ready() {
                    // The original ten-second budget, not a restarted budget
                    // at discovery or at the progress frame, must win now.
                    assert!(matches!(result, Poll::Ready(Err(DpopStreamError::Core(
                        DpopCoreError::Transport(DpopHttpError::TimedOut))))));
                    Poll::Ready(())
                } else {
                    assert!(result.is_pending());
                    Poll::Pending
                }
            }).await;
        };
        let peer = async {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (head, body) = read(&mut socket).await;
            inspect(&head, &body, &target, "server/discover", &RequestId::Number(1), &mut proofs);
            clock.advance(6_000_000_000);
            json_reply(&mut socket, &frame(&RequestId::Number(1), &discovery().to_string())).await;
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (head, body) = read(&mut socket).await;
            inspect(&head, &body, &target, METHOD, &RequestId::String("2".to_owned()), &mut proofs);
            socket.write_all(SSE_HEAD).await.unwrap();
            event(&mut socket, &progress(json!("owned"), "1")).await;
            observed.cancelled().await;
            clock.advance(4_000_000_000);
            assert!(timer.process_timers() > 0);
            reached.cancel();
            let mut byte = [0];
            assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0));
        };
        pair(application, peer).await;
        assert_eq!(cx.now().as_nanos(), 10_000_000_000);
        assert_eq!(proofs.len(), 2);
        assert_eq!(factories.load(Ordering::SeqCst), 1);
        assert!(cx.checkpoint().is_ok());
        no_extra(&listener);
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn resolver_cancellation_revocation_and_panics_cannot_dispatch_the_extension() {
    #[derive(Clone, Copy)]
    enum Stop { Cancel, Revoke, Panic, CancelAndPanic }

    for stop in [Stop::Cancel, Stop::Revoke, Stop::Panic, Stop::CancelAndPanic] {
        run(async {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
            let (mut client, credential, acceptor) = configured(&target);
            let owner_revocation = client.revocation_handle();
            let cancellation = Arc::new(McpRequestCancellation::new());
            let resolver_cancellation = Arc::clone(&cancellation);
            let calls = Arc::new(AtomicUsize::new(0));
            let resolver_calls = Arc::clone(&calls);
            let mut registry = ExtensionDescriptorRegistry::new();
            registry.register(descriptor()).unwrap();
            let mut other = descriptor();
            other.id = ExtensionId::parse(OTHER_EXTENSION).unwrap();
            other.method.as_mut().unwrap().name = "example/dpop-other".to_owned();
            other.result_discriminator = Some(OTHER_RESULT.to_owned());
            registry.register(other).unwrap();
            let settings = ClientExtensionDiscovery {
                extensions: BTreeMap::from([
                    (extension_id(), ExtensionSettings::new(json!({"format":"echo-v1"})).unwrap()),
                    (ExtensionId::parse(OTHER_EXTENSION).unwrap(),
                        ExtensionSettings::new(json!({"format":"echo-v1"})).unwrap()),
                ]),
            };
            let configuration = DpopExtensionConfiguration::new(registry, settings, move || {
                resolver_calls.fetch_add(1, Ordering::SeqCst);
                if matches!(stop, Stop::Cancel | Stop::CancelAndPanic) {
                    resolver_cancellation.cancel();
                }
                if matches!(stop, Stop::Revoke) {
                    owner_revocation.revoke();
                }
                assert!(!matches!(stop, Stop::Panic | Stop::CancelAndPanic),
                    "resolver-private-canary");
                compatible
            }).unwrap();
            let mut proofs = BTreeSet::new();
            let application = client.request_final_extension(
                &cx, &cancellation, &credential, &configuration, metadata(), operation(1), limits(8),
            );
            let peer = async {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (head, body) = read(&mut socket).await;
                inspect(&head, &body, &target, "server/discover", &RequestId::Number(1), &mut proofs);
                json_reply(&mut socket, &frame(&RequestId::Number(1), &discovery().to_string())).await;
            };
            let (outcome, ()) = pair(application, peer).await;
            let error = outcome.err().expect("resolver interruption cannot grant execution authority");
            assert!(!format!("{error:?} {error}").contains("canary"));
            match stop {
                Stop::Cancel | Stop::CancelAndPanic => assert!(matches!(error,
                    DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled)))),
                Stop::Revoke => assert!(matches!(error,
                    DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Authorization(_))))),
                Stop::Panic => assert!(matches!(error,
                    DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::UnsupportedRequest)))),
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(proofs.len(), 1);
            assert!(cx.checkpoint().is_ok());
            no_extra(&listener);
        });
    }
}
