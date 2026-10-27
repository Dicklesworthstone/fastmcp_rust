//! Real local HTTPS request/response exchange through the public stream method.
//! Certificates are the existing public, TEST ONLY oauth-core fixture identity.

use super::*;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpListener;
use asupersync::runtime::reactor::create_reactor;
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder};
use fastmcp_protocol::dpop::DpopNonce;
use crate::http_auth::dpop::native::DpopHttpPolicy;

// Inlined rather than included: `*.pem` is transfer-excluded, so an
// `include_bytes!` of this fixture makes the target UNBUILDABLE on a remote
// worker, and a test target that fails to build can report `0 passed` instead
// of failing. Same remedy and same bytes as LEAF and KEY below.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

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

async fn read_request<IO: AsyncRead + Unpin>(io: &mut IO) -> (String, serde_json::Value) {
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
        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
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

#[derive(Clone, Copy)]
enum Case { Sse, Json, RevokeInObserver, IncompleteTail, ForeignId, NonceChallenge }

#[test]
fn public_https_stream_delivers_before_terminal_and_never_replays_failed_calls() {
    for case in [Case::Sse, Case::Json, Case::RevokeInObserver, Case::IncompleteTail, Case::ForeignId, Case::NonceChallenge] {
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
                        br#"{"access_token":"stream-access","token_type":"DPoP","expires_in":60}"#,
                        Instant::now(), Duration::from_secs(60),
                    ).unwrap();
                    let root = Certificate::from_pem(ROOT).unwrap().remove(0);
                    let policy = DpopHttpPolicy::default().with_resource_root_der(root.as_der().to_vec()).unwrap();
                    let mut client = DpopHttpClient::new(session, policy).unwrap();
                    let cancellation = McpRequestCancellation::new();
                    let observed = McpRequestCancellation::new();
                    let mut observer_calls = 0;
                    let acceptor = TlsAcceptorBuilder::new(
                        CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap(),
                    ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();
                    let application = async {
                        client.request_core_with_events(
                            &cx, &cancellation, &credential, request(), RequestId::Number(7), limits(),
                            |notification| {
                                assert!(matches!(notification, ServerNotification::Progress(_)));
                                observer_calls += 1;
                                observed.cancel();
                                if matches!(case, Case::RevokeInObserver) { credential.revoke(); }
                                true
                            },
                        ).await
                    };
                    let server = async {
                        let (socket, _) = listener.accept().await.unwrap();
                        let mut socket = acceptor.accept(socket).await.unwrap();
                        let (head, body) = read_request(&mut socket).await;
                        assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
                        assert_eq!(body["id"], 7);
                        assert_eq!(body["params"]["_meta"]["progressToken"], "owned");
                        let headers: Vec<_> = head.lines().filter_map(|line| line.split_once(':'))
                            .map(|(name, value)| (name.to_ascii_lowercase(), value.trim())).collect();
                        assert_eq!(headers.iter().filter(|(name, _)| name == "dpop").count(), 1);
                        assert!(headers.iter().any(|(name, value)| name == "authorization" && *value == "DPoP stream-access"));
                        assert!(headers.iter().any(|(name, value)| name == "accept" && *value == MODERN_MCP_ACCEPT));
                        assert!(headers.iter().any(|(name, value)| name == "mcp-method" && *value == "tools/list"));
                        if matches!(case, Case::NonceChallenge) {
                            // Deliberately withhold the declared body: a challenge
                            // is a header outcome, never an excuse to await or retry.
                            socket.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 1024\r\nDPoP-Nonce: next-explicit-call\r\nConnection: close\r\n\r\n").await.unwrap();
                            socket.flush().await.unwrap();
                        } else if matches!(case, Case::Json) {
                            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{COMPLETE}", COMPLETE.len()).as_bytes()).await.unwrap();
                            socket.shutdown().await.unwrap();
                            return;
                        } else {
                            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nDPoP-Nonce: next-explicit-call\r\nConnection: close\r\n\r\n").await.unwrap();
                            let first = progress("\"owned\"", "1");
                            socket.write_all(format!("{:X}\r\n{first}\r\n", first.len()).as_bytes()).await.unwrap();
                            socket.flush().await.unwrap();
                            // The final bytes do not exist on the wire until the
                            // observer runs. A buffered-only implementation hangs.
                            observed.cancelled().await;
                            if !matches!(case, Case::RevokeInObserver) {
                                let result = if matches!(case, Case::ForeignId) {
                                    COMPLETE.replacen("\"id\":7", "\"id\":8", 1)
                                } else { COMPLETE.to_owned() };
                                let mut last = event(&result);
                                if matches!(case, Case::IncompleteTail) { last.push_str("data: unfinished"); }
                                socket.write_all(format!("{:X}\r\n{last}\r\n0\r\n\r\n", last.len()).as_bytes()).await.unwrap();
                                socket.shutdown().await.unwrap();
                                return;
                            }
                        }
                        let mut one = [0];
                        assert!(!matches!(socket.read(&mut one).await, Ok(n) if n > 0), "failed operation must release its socket");
                    };
                    let (outcome, ()) = pair(application, server).await;
                    match case {
                        Case::Sse | Case::Json => assert!(outcome.unwrap().encode().unwrap().contains("900719925474099312345")),
                        Case::RevokeInObserver => assert!(matches!(outcome, Err(DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Authorization(_)))))),
                        Case::IncompleteTail => assert!(matches!(outcome, Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidResponse))))),
                        Case::ForeignId => assert!(matches!(outcome, Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseIdMismatch))))),
                        Case::NonceChallenge => assert!(matches!(outcome, Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::HttpStatus { status: 401 }))))),
                    }
                    assert_eq!(observer_calls, usize::from(!matches!(case, Case::Json | Case::NonceChallenge)));
                    if matches!(case, Case::NonceChallenge) {
                        assert_eq!(client.session.resource_nonce, Some(DpopNonce::new("next-explicit-call").unwrap()));
                        assert!(client.session.token_nonce.is_none());
                    }
                    assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
                }).await.expect("DPoP streaming fixture must settle without hidden retries");
            });
    }
}

#[test]
fn public_https_large_image_result_matches_json_and_sse_and_preserves_tighter_limits() {
    #[derive(Clone, Copy)]
    enum ImageCase { Json, Sse, TightSse }
    let cases = [ImageCase::Json, ImageCase::Sse, ImageCase::TightSse];
    RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(60_000_000_000), async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let target = CanonicalHttpUrl::parse(&format!(
                    "https://{}/mcp", listener.local_addr().unwrap(),
                )).unwrap();
                let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
                let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(), target).unwrap();
                let credential = session.admit_token_response(
                    &issuer, 200,
                    br#"{"access_token":"image-access","token_type":"DPoP","expires_in":300}"#,
                    Instant::now(), Duration::from_secs(300),
                ).unwrap();
                let root = Certificate::from_pem(ROOT).unwrap().remove(0);
                let policy = DpopHttpPolicy::default().with_resource_root_der(root.as_der().to_vec()).unwrap();
                let mut client = DpopHttpClient::new(session, policy).unwrap();
                let cancellation = McpRequestCancellation::new();
                let acceptor = TlsAcceptorBuilder::new(
                    CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap(),
                ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();

                // LIMIT-01 permits one 3 MiB decoded binary block, whose
                // Base64 string occupies 4 MiB on a single JSON/SSE line.
                // The known quantum "AAAA" encodes three zero bytes. A whole
                // number of quanta needs no padding or fixture-side codec.
                let data = "AAAA".repeat(1024 * 1024);
                assert_eq!(data.len(), 4 * 1024 * 1024);
                let result = json!({
                    "resultType":"complete", "isError":false,
                    "content":[{"type":"image", "mimeType":"image/png", "data":data}],
                });
                let envelope = serde_json::to_string(&json!({"jsonrpc":"2.0", "id":7, "result":result})).unwrap();
                let sse = event(&envelope);
                assert!(sse.len() < 8 * 1024 * 1024, "the native raw-body cap is unchanged");
                let params = json!({
                    "name":"render_image", "arguments":{},
                    "_meta":FinalRequestMeta::new(ClientCapabilities::default()),
                });
                let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap();

                let application = async {
                    let mut accepted = Vec::new();
                    for case in cases {
                        let mut limits = DpopStreamLimits::default();
                        if matches!(case, ImageCase::TightSse) {
                            // Change only the caller's line ceiling. The same
                            // response remains inside every other budget.
                            limits = limits.with_sse_limits(SseLimits::with_data_lines(
                                64 * 1024, limits.sse.max_event_bytes(),
                                limits.sse.max_keepalive_lines(), limits.sse.max_data_lines(),
                            ).unwrap()).unwrap();
                        }
                        let mut notifications = 0;
                        let outcome = client.request_core_with_events(
                            &cx, &cancellation, &credential, request.clone(), RequestId::Number(7), limits,
                            |_| { notifications += 1; true },
                        ).await;
                        assert_eq!(notifications, 0);
                        assert!(!cancellation.is_cancel_requested());
                        assert!(cx.checkpoint().is_ok());
                        if matches!(case, ImageCase::TightSse) {
                            assert!(matches!(outcome, Err(DpopStreamError::Core(
                                DpopCoreError::Protocol(ManagedCoreError::InvalidResponse)
                            ))));
                        } else {
                            let outcome = outcome.expect("a valid large tool image must be admitted");
                            let CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) = &outcome else {
                                panic!("the image must retain its typed tools/call result");
                            };
                            let [fastmcp_protocol::common_types::ContentBlock::Image { data, mime_type, .. }] = result.payload.content.as_slice() else {
                                panic!("the result must contain exactly its original image");
                            };
                            assert_eq!(mime_type, "image/png");
                            assert_eq!(data.len(), 4 * 1024 * 1024);
                            assert!(data.bytes().all(|byte| byte == b'A'),
                                "the canonical encoding of all 3 MiB of zero bytes must be preserved");
                            accepted.push(outcome.encode().unwrap());
                        }
                    }
                    assert_eq!(accepted.len(), 2);
                    assert!(accepted[0] == accepted[1], "JSON and single-line SSE must preserve the same complete result");
                };
                let server = async {
                    for case in cases {
                        let (socket, _) = listener.accept().await.unwrap();
                        let mut socket = acceptor.accept(socket).await.unwrap();
                        let (head, body) = read_request(&mut socket).await;
                        assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
                        assert_eq!(body["id"], 7);
                        assert_eq!(body["method"], "tools/call");
                        assert_eq!(body["params"]["name"], "render_image");
                        let headers: Vec<_> = head.lines().filter_map(|line| line.split_once(':'))
                            .map(|(name, value)| (name.to_ascii_lowercase(), value.trim())).collect();
                        assert_eq!(headers.iter().filter(|(name, _)| name == "dpop").count(), 1);
                        assert!(headers.iter().any(|(name, value)| name == "authorization" && *value == "DPoP image-access"));
                        if matches!(case, ImageCase::Json) {
                            socket.write_all(format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                envelope.len(),
                            ).as_bytes()).await.unwrap();
                            socket.write_all(envelope.as_bytes()).await.unwrap();
                        } else {
                            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
                            socket.write_all(format!("{:X}\r\n", sse.len()).as_bytes()).await.unwrap();
                            let sent = async {
                                socket.write_all(sse.as_bytes()).await?;
                                socket.write_all(b"\r\n0\r\n\r\n").await?;
                                socket.flush().await
                            }.await;
                            if matches!(case, ImageCase::TightSse) {
                                // Refusal may interrupt the large write. The
                                // request must release that same body/socket.
                                let mut byte = [0];
                                assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0));
                                continue;
                            }
                            sent.unwrap();
                        }
                        socket.shutdown().await.unwrap();
                    }
                };
                pair(application, server).await;
                assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
            }).await.expect("large DPoP image cases must settle without retries");
        });
}
