//! Live local HTTPS tests through DpopHttpClient::listen_core_with_events.
//! Inline public TEST ONLY certificates avoid dependence on transferred PEM files.

use super::*;
use std::future::{Future, poll_fn};
use std::task::{Context, Poll, Waker};

use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpListener;
use asupersync::runtime::reactor::create_reactor;
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder};
use fastmcp_protocol::dpop::DpopNonce;

use crate::http_auth::dpop::native::DpopHttpPolicy;
use crate::http_executor::MODERN_MCP_ACCEPT;

const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

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

async fn read_request<IO: AsyncRead + Unpin>(io: &mut IO) -> (String, Value) {
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
    let headers = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
    let length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().unwrap())
    }).unwrap();
    assert!(end + length <= 32 * 1024);
    while bytes.len() < end + length {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(bytes.len(), end + length);
    (headers, serde_json::from_slice(&bytes[end..]).unwrap())
}

fn proof_claims(head: &str) -> Value {
    let headers: Vec<_> = head.lines().filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim())).collect();
    assert_eq!(headers.iter().filter(|(name, _)| name == "dpop").count(), 1);
    assert!(headers.iter().any(|(name, value)|
        name == "authorization" && *value == "DPoP subscription-access"));
    assert!(headers.iter().any(|(name, value)|
        name == "accept" && *value == MODERN_MCP_ACCEPT));
    assert!(!headers.iter().any(|(name, _)| name == "mcp-session-id" || name == "last-event-id"));
    let proof = headers.iter().find(|(name, _)| name == "dpop").unwrap().1;
    let parts: Vec<_> = proof.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert!(!parts[2].is_empty());
    let claims: Value = serde_json::from_slice(&base64url_payload(parts[1])).unwrap();
    assert_eq!(claims["htm"], "POST");
    assert!(!claims["jti"].as_str().unwrap().is_empty());
    assert!(!claims["ath"].as_str().unwrap().is_empty());
    claims
}

// Decode a captured proof segment for wire-binding assertions, not signature or
// issuer conformance. `base64` is declared nowhere in this crate's manifest, so
// importing it never compiled; this mirrors the sibling DPoP fixtures
// (`core/tasks/tests/tls.rs`, `core/tasks/stream/tests/tls.rs`), which decode
// locally for the same reason: no production dependency is needed by tests.
fn base64url_payload(segment: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let (mut acc, mut bits) = (0_u32, 0_u32);
    for byte in segment.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => panic!("invalid base64url proof"),
        };
        acc = (acc << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    assert_eq!(acc, 0, "a base64url segment leaves no trailing bits set");
    bytes
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Complete,
    ForeignEventId,
    ExpandedAck,
    UnselectedUri,
    NoAck,
    CancelAfterAck,
    RevokeAfterAck,
    ObserverStop,
    IncompleteTail,
    JsonError,
    JsonSuccess,
    NonceChallenge,
    NotificationLimit,
}

#[test]
fn public_https_subscriptions_deliver_live_changes_and_refuse_invalid_or_retired_streams() {
    for case in [
        Case::Complete, Case::ForeignEventId, Case::ExpandedAck, Case::UnselectedUri,
        Case::NoAck, Case::CancelAfterAck, Case::RevokeAfterAck, Case::ObserverStop,
        Case::IncompleteTail, Case::JsonError, Case::JsonSuccess, Case::NonceChallenge,
        Case::NotificationLimit,
    ] {
        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), async {
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let address = listener.local_addr().unwrap();
                    let target = CanonicalHttpUrl::parse(&format!("https://{address}/mcp?tenant=one")).unwrap();
                    let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
                    let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(), target).unwrap();
                    let credential = session.admit_token_response(
                        &issuer, 200,
                        br#"{"access_token":"subscription-access","token_type":"DPoP","expires_in":60}"#,
                        Instant::now(), Duration::from_secs(60),
                    ).unwrap();
                    let root = Certificate::from_pem(ROOT).unwrap().remove(0);
                    let policy = DpopHttpPolicy::default().with_resource_root_der(root.as_der().to_vec()).unwrap();
                    let mut client = DpopHttpClient::new(session, policy).unwrap();
                    let cancellation = McpRequestCancellation::new();
                    let observed = McpRequestCancellation::new();
                    let acceptor = TlsAcceptorBuilder::new(
                        CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap(),
                    ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();

                    // This is the actual public operation, not only its encoder.
                    // An unnegotiated selector must settle on its first poll and
                    // must not cause even a connection to the listening peer.
                    {
                        let mut rejected = Box::pin(client.listen_core_with_events(
                            &cx, &cancellation, &credential,
                            params(json!({"taskIds":["unnegotiated"]})),
                            RequestId::Number(6), limits(), |_| panic!("invalid filter reached observer"),
                        ));
                        assert!(matches!(rejected.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                            Poll::Ready(Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::UnsupportedRequest))))));
                    }
                    assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
                    let stream_limits = if matches!(case, Case::NotificationLimit) {
                        DpopStreamLimits::new(
                            ManagedCoreLimits::new(8192, 8192, 32768, 1, Duration::from_secs(60)).unwrap(),
                            Duration::from_secs(10),
                        ).unwrap()
                    } else { limits() };
                    let mut observer_calls = 0;
                    let application = async {
                        Box::pin(client.listen_core_with_events(
                            &cx, &cancellation, &credential, params(filter()), RequestId::Number(7), stream_limits,
                            |notification| {
                                observer_calls += 1;
                                assert_eq!(matches!(notification, ServerNotification::SubscriptionsAcknowledged(_)), observer_calls == 1);
                                observed.cancel();
                                if matches!(case, Case::CancelAfterAck) { cancellation.cancel(); }
                                if matches!(case, Case::RevokeAfterAck) { credential.revoke(); }
                                !matches!(case, Case::ObserverStop)
                            },
                        )).await
                    };
                    let server = async {
                        let (socket, _) = listener.accept().await.unwrap();
                        let mut socket = acceptor.accept(socket).await.unwrap();
                        let (head, body) = read_request(&mut socket).await;
                        assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
                        assert_eq!(body["id"], 7);
                        assert_eq!(body["method"], "subscriptions/listen");
                        assert_eq!(body["params"]["notifications"], filter());
                        assert!(head.lines().any(|line| {
                            line.split_once(':').is_some_and(|(name, value)|
                                name.eq_ignore_ascii_case("Mcp-Method") && value.trim() == "subscriptions/listen")
                        }));
                        let proof = proof_claims(&head);
                        assert!(proof.get("nonce").is_none());
                        if matches!(case, Case::NonceChallenge) {
                            // Deliberately absent body: a challenge must not wait
                            // for it, renew credentials or replay this listen.
                            socket.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 1024\r\nDPoP-Nonce: next-explicit-listen\r\nConnection: close\r\n\r\n").await.unwrap();
                            socket.flush().await.unwrap();
                        } else if matches!(case, Case::JsonError | Case::JsonSuccess) {
                            let response = if matches!(case, Case::JsonError) {
                                r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"private-peer-canary"}}"#
                            } else { COMPLETE };
                            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).as_bytes()).await.unwrap();
                            socket.shutdown().await.unwrap();
                            return proof;
                        } else {
                            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nDPoP-Nonce: next-explicit-listen\r\nConnection: close\r\n\r\n").await.unwrap();
                            let first = if matches!(case, Case::NoAck) {
                                change(json!(7))
                            } else if matches!(case, Case::ExpandedAck) {
                                ack(json!(7), json!({"promptsListChanged":true}))
                            } else { ack(json!(7), filter()) };
                            let first = event(&first);
                            socket.write_all(format!("{:X}\r\n{first}\r\n", first.len()).as_bytes()).await.unwrap();
                            socket.flush().await.unwrap();
                            if !matches!(case, Case::NoAck | Case::ExpandedAck) {
                                // A collector that waits for terminal data before
                                // invoking the observer deadlocks this fixture.
                                observed.cancelled().await;
                                if !matches!(case, Case::CancelAfterAck | Case::RevokeAfterAck | Case::ObserverStop) {
                                    let changed = change(if matches!(case, Case::ForeignEventId) { json!(8) } else { json!(7) });
                                    let uri = if matches!(case, Case::UnselectedUri) { "file:///a/b?scope=one" } else { RESOURCE };
                                    let mut last = format!("{}{}{}", event(&changed), event(&updated(uri)), event(COMPLETE));
                                    if matches!(case, Case::IncompleteTail) { last.push_str("data: unfinished"); }
                                    socket.write_all(format!("{:X}\r\n{last}\r\n0\r\n\r\n", last.len()).as_bytes()).await.unwrap();
                                    socket.shutdown().await.unwrap();
                                    return proof;
                                }
                            }
                        }
                        let mut one = [0];
                        assert!(!matches!(socket.read(&mut one).await, Ok(n) if n > 0), "refused or cancelled listen must release its socket");
                        proof
                    };
                    let (outcome, first_proof) = pair(application, server).await;
                    if let Err(error) = &outcome {
                        assert!(!format!("{error:?} {error}").contains("private-peer-canary"));
                    }
                    match case {
                        Case::Complete => {
                            let result = outcome.unwrap();
                            assert!(matches!(&result, CoreResult::Final(FinalCoreResult::SubscriptionsListen { .. })));
                            assert!(result.encode().unwrap().contains("900719925474099312345"));
                        }
                        Case::CancelAfterAck => assert!(matches!(outcome, Err(DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled))))),
                        Case::RevokeAfterAck => assert!(matches!(outcome, Err(DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Authorization(_)))))),
                        Case::ObserverStop => assert!(matches!(outcome, Err(DpopStreamError::ObserverStopped))),
                        Case::ForeignEventId => assert!(matches!(outcome, Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseIdMismatch))))),
                        Case::ExpandedAck | Case::UnselectedUri | Case::NoAck => assert!(matches!(outcome, Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::UnexpectedNotification))))),
                        Case::IncompleteTail | Case::JsonSuccess => assert!(matches!(outcome, Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidResponse))))),
                        Case::JsonError => assert!(matches!(outcome, Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::Remote { .. }))))),
                        Case::NonceChallenge => assert!(matches!(outcome, Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::HttpStatus { status: 401 }))))),
                        Case::NotificationLimit => assert!(matches!(outcome, Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::NotificationLimit))))),
                    }
                    let expected_calls = match case {
                        Case::Complete | Case::IncompleteTail => 3,
                        Case::UnselectedUri => 2,
                        Case::ForeignEventId | Case::CancelAfterAck | Case::RevokeAfterAck
                            | Case::ObserverStop | Case::NotificationLimit => 1,
                        _ => 0,
                    };
                    assert_eq!(observer_calls, expected_calls, "{case:?}");
                    assert!(cx.checkpoint().is_ok(), "one stream cannot retire the caller");
                    assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending(), "no implicit retry or reconnect");
                    if matches!(case, Case::NonceChallenge) {
                        assert_eq!(client.session.resource_nonce, Some(DpopNonce::new("next-explicit-listen").unwrap()));
                        assert!(client.session.token_nonce.is_none());
                    }

                    if matches!(case, Case::CancelAfterAck | Case::ObserverStop | Case::ForeignEventId | Case::NonceChallenge) {
                        // After the failed listen, an explicit ordinary call with
                        // a fresh local cancellation domain still owns its result.
                        let request = CoreRequest::decode(
                            fastmcp_protocol::protocol_policy::ProtocolEra::Modern2026,
                            "tools/list", Some(&json!({"_meta":FinalRequestMeta::new(ClientCapabilities::default())})),
                        ).unwrap();
                        let fresh = McpRequestCancellation::new();
                        let application = async {
                            Box::pin(client.request_core_with_events(
                                &cx, &fresh, &credential, request, RequestId::Number(8), limits(),
                                |_| panic!("JSON follow-up contains no notification"),
                            )).await
                        };
                        let server = async {
                            let (socket, _) = listener.accept().await.unwrap();
                            let mut socket = acceptor.accept(socket).await.unwrap();
                            let (head, body) = read_request(&mut socket).await;
                            assert_eq!(body["id"], 8);
                            assert_eq!(body["method"], "tools/list");
                            let proof = proof_claims(&head);
                            assert_ne!(proof["jti"], first_proof["jti"]);
                            assert_eq!(proof["nonce"], "next-explicit-listen");
                            let response = r#"{"jsonrpc":"2.0","id":8,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#;
                            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).as_bytes()).await.unwrap();
                            socket.shutdown().await.unwrap();
                        };
                        let (result, ()) = pair(application, server).await;
                        assert!(matches!(result.unwrap(), CoreResult::Final(FinalCoreResult::ToolsList { .. })));
                        assert!(!fresh.is_cancel_requested());
                        assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
                    }
                }).await.expect("live subscription fixture must settle without replay");
            });
    }
}
