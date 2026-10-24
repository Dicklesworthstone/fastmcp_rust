//! Public streaming-host execution over real local HTTPS, not a transport mock.
//! The certificate and key below are the repository's public TEST ONLY identity.
//! Inline bytes keep this test independent of remote transfer exclusions.

use super::*;
use std::future::{Future, poll_fn};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::net::TcpListener;
use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::reactor::create_reactor;
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::common_types::SamplingContentBlock;
use fastmcp_protocol::dpop::DpopKey;
use fastmcp_protocol::{
    FinalCreateMessageResult, FinalEmbeddedCreateMessageParams, FinalEmbeddedElicitationResult,
    FinalEmbeddedFormElicitationParams, FinalEmbeddedRootsListParams, FinalEmbeddedRootsListResult,
    FinalEmbeddedUrlElicitationParams,
};

use crate::http_auth::dpop::DpopSession;
use crate::http_auth::dpop::native::DpopHttpPolicy;
use crate::http_auth::sampling::{SamplingHost, SamplingHostError, SamplingHostFuture};
use crate::http_auth::sampling::inputs::mixed::{
    CoreInputHostError, CoreInputHostFuture, CoreInputRequest,
};
use crate::http_executor::MODERN_MCP_ACCEPT;

const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

#[derive(Clone, Copy, Debug)]
enum Case {
    Sse,
    JsonThenSse,
    SseThenJson,
    DenyHost,
    CancelHost,
    CancelObserver,
    RevokeObserver,
    IncompleteTail,
    NotificationLimit,
    NonceChallenge,
}

impl Case {
    fn completes(self) -> bool {
        matches!(self, Self::Sse | Self::JsonThenSse | Self::SseThenJson)
    }

    fn continues(self) -> bool {
        self.completes() || matches!(self, Self::NotificationLimit | Self::NonceChallenge)
    }
}

struct Host {
    approvals: usize,
    roots: usize,
    unexpected: usize,
    case: Case,
    cancellation: McpRequestCancellation,
}

impl SamplingHost for Host {
    fn sample<'a>(
        &'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedCreateMessageParams,
    ) -> SamplingHostFuture<'a, FinalCreateMessageResult> {
        self.unexpected += 1;
        Box::pin(async { Err(SamplingHostError::Denied) })
    }

    fn approve_tools<'a>(
        &'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a [SamplingContentBlock],
    ) -> SamplingHostFuture<'a, ()> {
        self.unexpected += 1;
        Box::pin(async { Err(SamplingHostError::Denied) })
    }

    fn execute_tool<'a>(
        &'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a SamplingContentBlock,
    ) -> SamplingHostFuture<'a, SamplingContentBlock> {
        self.unexpected += 1;
        Box::pin(async { Err(SamplingHostError::Denied) })
    }
}

impl CoreInputHost for Host {
    fn approve_inputs<'a>(
        &'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        requests: &'a [CoreInputRequest],
    ) -> CoreInputHostFuture<'a, ()> {
        self.approvals += 1;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].key(), "r");
        let deny = matches!(self.case, Case::DenyHost);
        Box::pin(async move {
            if deny { Err(CoreInputHostError::Denied) } else { Ok(()) }
        })
    }

    fn roots<'a>(
        &'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedRootsListParams,
    ) -> CoreInputHostFuture<'a, FinalEmbeddedRootsListResult> {
        self.roots += 1;
        let cancel = matches!(self.case, Case::CancelHost);
        let cancellation = self.cancellation.clone();
        Box::pin(async move {
            if cancel { cancellation.cancel(); }
            Ok(serde_json::from_value(json!({"roots":[{"uri":"file:///host-only-private"}]})).unwrap())
        })
    }

    fn form<'a>(
        &'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedFormElicitationParams,
    ) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult> {
        self.unexpected += 1;
        Box::pin(async { Err(CoreInputHostError::Denied) })
    }

    fn url<'a>(
        &'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedUrlElicitationParams,
    ) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult> {
        self.unexpected += 1;
        Box::pin(async { Err(CoreInputHostError::Denied) })
    }
}

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let (mut one, mut two) = (None, None);
    poll_fn(|task| {
        if one.is_none() {
            if let Poll::Ready(value) = left.as_mut().poll(task) { one = Some(value); }
        }
        if two.is_none() {
            if let Poll::Ready(value) = right.as_mut().poll(task) { two = Some(value); }
        }
        if one.is_some() && two.is_some() {
            Poll::Ready((one.take().unwrap(), two.take().unwrap()))
        } else {
            Poll::Pending
        }
    }).await
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
    let length: usize = field(&headers, "content-length").parse().unwrap();
    assert!(end + length <= 32 * 1024);
    while bytes.len() < end + length {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(bytes.len(), end + length);
    (headers, serde_json::from_slice(&bytes[end..]).unwrap())
}

fn field<'a>(headers: &'a str, wanted: &str) -> &'a str {
    let mut fields = headers.lines().filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case(wanted));
    let (_, value) = fields.next().expect("required header exists");
    assert!(fields.next().is_none(), "required header is a singleton");
    value.trim_matches([' ', '\t'])
}

fn check_request(head: &str, body: &Value, original: &Value, round: usize) -> Value {
    assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
    assert_eq!(body["id"], format!("flow:{round}"));
    assert_eq!(body["method"], "tools/call");
    assert_eq!(body["params"]["name"], "echo");
    assert_eq!(body["params"]["arguments"], original["arguments"]);
    assert_eq!(body["params"]["_meta"], original["_meta"]);
    assert_eq!(field(head, "authorization"), "DPoP stream-access");
    assert_eq!(field(head, "accept"), MODERN_MCP_ACCEPT);
    assert_eq!(field(head, "mcp-method"), "tools/call");
    assert_eq!(field(head, "mcp-name"), "echo");
    assert_eq!(field(head, "mcp-param-region"),
        fastmcp_protocol::http_headers::encode_mcp_header_value("eu 雪").unwrap());
    for private in ["body-private", "host-only-private", "opaque-private"] {
        assert!(!head.contains(private), "private body/state must not become a header");
    }
    let proof = field(head, "dpop");
    let parts: Vec<_> = proof.split('.').collect();
    assert_eq!(parts.len(), 3);
    let claims: Value = serde_json::from_slice(&base64url_payload(parts[1])).unwrap();
    assert_eq!(claims["htm"], "POST");
    assert!(claims["jti"].as_str().is_some_and(|id| !id.is_empty()));
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

async fn chunk<IO: AsyncWrite + Unpin>(io: &mut IO, event: &[u8]) {
    let mut bytes = format!("{:X}\r\n", event.len()).into_bytes();
    bytes.extend_from_slice(event);
    bytes.extend_from_slice(b"\r\n");
    io.write_all(&bytes).await.unwrap();
    io.flush().await.unwrap();
}

fn progress(number: usize) -> String {
    format!("data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"progressToken\":\"owned\",\"progress\":{number}}}}}\n\n")
}

#[test]
fn public_https_streaming_host_preserves_reviews_and_never_replays_failed_rounds() {
    for case in [
        Case::Sse, Case::JsonThenSse, Case::SseThenJson, Case::DenyHost, Case::CancelHost,
        Case::CancelObserver, Case::RevokeObserver, Case::IncompleteTail,
        Case::NotificationLimit, Case::NonceChallenge,
    ] {
        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), async {
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let target = CanonicalHttpUrl::parse(
                        &format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap()),
                    ).unwrap();
                    let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
                    let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(), target.clone()).unwrap();
                    let credential = session.admit_token_response(
                        &issuer, 200,
                        br#"{"access_token":"stream-access","token_type":"DPoP","expires_in":60}"#,
                        Instant::now(), Duration::from_secs(60),
                    ).unwrap();
                    let root = Certificate::from_pem(ROOT).unwrap().remove(0);
                    let policy = DpopHttpPolicy::default().with_resource_root_der(root.as_der().to_vec()).unwrap();
                    let mut client = DpopHttpClient::new(session, policy).unwrap();
                    let cancellation = McpRequestCancellation::new();
                    let observed = McpRequestCancellation::new();
                    let mut host = Host {
                        approvals: 0, roots: 0, unexpected: 0, case,
                        cancellation: cancellation.clone(),
                    };
                    let mut params = with_arguments(json!({"region":"eu 雪","private":"body-private"}))
                        .encode_params().unwrap().unwrap();
                    params["_meta"]["progressToken"] = json!("owned");
                    let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap();
                    let reviewed = review(target.as_str(), "echo");
                    let limits = DpopStreamHostLimits::new(
                        limits(32768, if matches!(case, Case::NotificationLimit) { 1 } else { 4 }, 2),
                        CoreInputLimits::default(), 2, Duration::from_secs(5),
                    ).unwrap();
                    let acceptor = TlsAcceptorBuilder::new(
                        CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap(),
                    ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();
                    let mut observations = 0;
                    let application = async {
                        client.execute_core_with_streaming_input_host_and_headers(
                            &cx, &cancellation, &credential, request, "flow".to_owned(), limits,
                            &reviewed, &mut host,
                            |notification| {
                                assert!(matches!(notification, ServerNotification::Progress(_)));
                                observations += 1;
                                observed.cancel();
                                if matches!(case, Case::CancelObserver) { cancellation.cancel(); }
                                if matches!(case, Case::RevokeObserver) { credential.revoke(); }
                                true
                            },
                        ).await
                    };
                    let server = async {
                        let (socket, _) = listener.accept().await.unwrap();
                        let mut socket = acceptor.accept(socket).await.unwrap();
                        let (head, body) = read_request(&mut socket).await;
                        let first_claims = check_request(&head, &body, &params, 0);
                        assert!(first_claims.get("nonce").is_none());
                        assert!(body["params"].get("requestState").is_none());
                        assert!(body["params"].get("inputResponses").is_none());
                        let input = response(&request_id("flow", 0).unwrap(), challenge(" opaque-private\0 /% "));
                        if matches!(case, Case::JsonThenSse) {
                            let head = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nDPoP-Nonce: continue-nonce\r\nConnection: close\r\n\r\n", input.len());
                            socket.write_all(head.as_bytes()).await.unwrap();
                            socket.write_all(&input).await.unwrap();
                            socket.flush().await.unwrap();
                        } else {
                            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nDPoP-Nonce: continue-nonce\r\nConnection: close\r\n\r\n").await.unwrap();
                            chunk(&mut socket, progress(1).as_bytes()).await;
                            // Terminal bytes do not exist until the observer runs.
                            // A buffered-only implementation cannot pass this wait.
                            observed.cancelled().await;
                            if matches!(case, Case::CancelObserver | Case::RevokeObserver) {
                                let mut byte = [0];
                                assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0));
                                return 1;
                            }
                            let mut event = format!("data: {}\n\n", std::str::from_utf8(&input).unwrap());
                            if matches!(case, Case::IncompleteTail) { event.push_str("data: unfinished"); }
                            chunk(&mut socket, event.as_bytes()).await;
                            socket.write_all(b"0\r\n\r\n").await.unwrap();
                            socket.flush().await.unwrap();
                        }
                        let _ = socket.shutdown().await;
                        drop(socket);
                        if !case.continues() { return 1; }

                        let (socket, _) = listener.accept().await.unwrap();
                        let mut socket = acceptor.accept(socket).await.unwrap();
                        let (head, body) = read_request(&mut socket).await;
                        let second_claims = check_request(&head, &body, &params, 1);
                        assert_ne!(second_claims["jti"], first_claims["jti"], "each authorized continuation needs a fresh proof");
                        assert_eq!(second_claims["nonce"], "continue-nonce");
                        assert_eq!(body["params"]["requestState"], " opaque-private\0 /% ");
                        assert_eq!(body["params"]["inputResponses"], json!({"r":{"roots":[{"uri":"file:///host-only-private"}]}}));
                        if matches!(case, Case::NonceChallenge) {
                            // Withhold the body: this is an HTTP failure, not an
                            // invitation to wait indefinitely or repeat the call.
                            socket.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 1024\r\nDPoP-Nonce: do-not-retry\r\nConnection: close\r\n\r\n").await.unwrap();
                            socket.flush().await.unwrap();
                            let mut byte = [0];
                            assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0));
                            return 2;
                        }
                        let complete = response(&request_id("flow", 1).unwrap(), terminal("tools/call"));
                        if matches!(case, Case::SseThenJson) {
                            let head = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", complete.len());
                            socket.write_all(head.as_bytes()).await.unwrap();
                            socket.write_all(&complete).await.unwrap();
                        } else {
                            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
                            let events = format!("{}data: {}\n\n", progress(2), std::str::from_utf8(&complete).unwrap());
                            // One final chunk avoids racing the quota rejection
                            // with a later fixture write; the reader must refuse
                            // before a second observer effect even in one chunk.
                            let bytes = format!("{:X}\r\n{events}\r\n0\r\n\r\n", events.len());
                            socket.write_all(bytes.as_bytes()).await.unwrap();
                        }
                        socket.flush().await.unwrap();
                        let _ = socket.shutdown().await;
                        2
                    };
                    let (outcome, posts) = pair(application, server).await;
                    assert_eq!(posts, if case.continues() { 2 } else { 1 }, "{case:?}");
                    match outcome {
                        Ok(completed) => {
                            assert!(case.completes(), "{case:?} must fail");
                            assert_eq!(completed.continuations, 1);
                            assert!(completed.result.encode().unwrap().contains("done"));
                        }
                        Err(error) => {
                            assert!(!case.completes(), "{case:?}: {error:?}");
                            assert!(!format!("{error:?} {error}").contains("opaque-private"));
                            match case {
                                Case::DenyHost => assert!(matches!(error, DpopStreamHostError::Host(_))),
                                Case::CancelHost | Case::CancelObserver => assert!(matches!(error, DpopStreamHostError::Stream(DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled))))),
                                Case::RevokeObserver => assert!(matches!(error, DpopStreamHostError::Stream(DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Authorization(_)))))),
                                Case::IncompleteTail => assert!(matches!(error, DpopStreamHostError::Stream(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidResponse))))),
                                Case::NotificationLimit => assert!(matches!(error, DpopStreamHostError::Stream(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::NotificationLimit))))),
                                Case::NonceChallenge => assert!(matches!(error, DpopStreamHostError::Stream(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::HttpStatus { status: 401 }))))),
                                _ => unreachable!(),
                            }
                        }
                    }
                    let host_reached = case.continues() || matches!(case, Case::DenyHost | Case::CancelHost);
                    assert_eq!(host.approvals, usize::from(host_reached), "{case:?}");
                    assert_eq!(host.roots, usize::from(host_reached && !matches!(case, Case::DenyHost)), "{case:?}");
                    assert_eq!(host.unexpected, 0);
                    assert_eq!(observations, if matches!(case, Case::Sse) { 2 } else { 1 }, "{case:?}");
                    assert!(!cx.is_cancel_requested(), "operation-local cancellation must preserve the caller");
                    assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending(), "no failed operation or nonce challenge may be replayed");
                }).await.expect("streaming host fixture must settle inside its bound");
            });
    }
}
