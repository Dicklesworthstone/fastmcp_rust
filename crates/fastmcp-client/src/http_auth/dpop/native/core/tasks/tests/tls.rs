//! Local HTTPS coverage of the public DPoP Tasks operation.
//! The PEM material is the repository's existing, public TEST ONLY identity;
//! it is inline so remote compilation never depends on excluded PEM files.

mod wait;

use super::*;
use std::pin::{Pin, pin};
use std::future::poll_fn;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::net::TcpListener;
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder};

const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = pin!(left);
    let mut right = pin!(right);
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
        } else { Poll::Pending }
    }).await
}

fn run<F: Future<Output = ()>>(future: F) {
    let runtime = RuntimeBuilder::current_thread().blocking_threads(0, 0)
        .with_reactor(create_reactor().unwrap()).build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), future)
            .await.expect("public DPoP Tasks must finish inside the fixture deadline");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

fn configured(target: &str) -> (DpopHttpClient, DpopCredential, TlsAcceptor) {
    let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
    let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(),
        CanonicalHttpUrl::parse(target).unwrap()).unwrap();
    let credential = session.admit_token_response(&issuer, 200,
        br#"{"access_token":"tasks-token","token_type":"DPoP","expires_in":60}"#,
        Instant::now(), Duration::from_secs(60)).unwrap();
    let root = Certificate::from_pem(ROOT).unwrap().remove(0);
    let policy = DpopHttpPolicy::default().with_resource_root_der(root.as_der().to_vec()).unwrap();
    let client = DpopHttpClient::new(session, policy).unwrap();
    let acceptor = TlsAcceptorBuilder::new(CertificateChain::from_pem(LEAF).unwrap(),
        PrivateKey::from_pem(KEY).unwrap()).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();
    (client, credential, acceptor)
}

async fn read_request<IO: AsyncRead + Unpin>(socket: &mut IO) -> (String, Value) {
    let mut bytes = Vec::new();
    let mut block = [0; 2048];
    let start = loop {
        let count = socket.read(&mut block).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&block[..count]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let header = std::str::from_utf8(&bytes[..start]).unwrap().to_owned();
    let length = header.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
    }).unwrap();
    assert!(start + length <= 32 * 1024);
    while bytes.len() < start + length {
        let count = socket.read(&mut block).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&block[..count]);
    }
    assert_eq!(bytes.len(), start + length);
    (header, serde_json::from_slice(&bytes[start..]).unwrap())
}

async fn send<IO: AsyncWrite + Unpin>(socket: &mut IO, response: DpopHttpResponse) {
    socket.write_all(format!("HTTP/1.1 {} Reply\r\nContent-Type: application/json\r\nContent-Length: {}\r\nDPoP-Nonce: resource-next\r\nConnection: close\r\n\r\n", response.status, response.body.len()).as_bytes()).await.unwrap();
    socket.write_all(&response.body).await.unwrap();
    socket.shutdown().await.unwrap();
}

fn header<'a>(head: &'a str, expected: &str) -> &'a str {
    let values: Vec<_> = head.lines().filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case(expected))
        .map(|(_, value)| value.trim()).collect();
    assert_eq!(values.len(), 1, "one {expected} header");
    values[0]
}

// Decode captured proof claims for wire binding assertions, not signature or
// issuer conformance. No additional production dependency is needed by tests.
fn claims(proof: &str) -> Value {
    let parts: Vec<_> = proof.split('.').collect();
    assert_eq!(parts.len(), 3);
    let mut bytes = Vec::new();
    let (mut acc, mut bits) = (0_u32, 0_u32);
    for byte in parts[1].bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A', b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52, b'-' => 62, b'_' => 63,
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
    assert_eq!(acc, 0);
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn all_task_verbs_negotiate_with_the_same_token_and_fresh_resource_bound_proofs() {
    for kind in 0..4 {
        run(async move {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
            let (mut client, credential, acceptor) = configured(&target);
            let (request, method, result) = match kind {
                0 => (tool(), "tools/call", task_result("task")),
                1 => (ManagedTaskRequest::Get(id()), TASK_GET, task_result("complete")),
                2 => (update(), TASK_UPDATE, r#"{"resultType":"complete"}"#.to_owned()),
                _ => (ManagedTaskRequest::Cancel(id()), TASK_CANCEL, r#"{"resultType":"complete"}"#.to_owned()),
            };
            let application = client.request_task(&cx, &credential, metadata(), operation(request), ManagedCoreLimits::default());
            let peer = async {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (head, body) = read_request(&mut socket).await;
                assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
                assert_eq!(body["id"], 1);
                assert_eq!(body["method"], "server/discover");
                assert!(body["params"].get("arguments").is_none());
                assert_eq!(header(&head, "authorization"), "DPoP tasks-token");
                let first = claims(header(&head, "dpop"));
                assert!(first.get("nonce").is_none());
                send(&mut socket, discovery()).await;
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (head, body) = read_request(&mut socket).await;
                assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
                assert_eq!(body["id"], 2);
                assert_eq!(body["method"], method);
                assert_eq!(body["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"], json!({TASKS_EXTENSION:{}}));
                assert_eq!(header(&head, "authorization"), "DPoP tasks-token");
                assert_eq!(header(&head, "accept"), "application/json");
                assert_eq!(header(&head, "mcp-method"), method);
                let second = claims(header(&head, "dpop"));
                assert_eq!(second["nonce"], "resource-next");
                assert_ne!(first["jti"], second["jti"]);
                assert_eq!(first["ath"], second["ath"]);
                assert!(second["ath"].as_str().is_some_and(|hash| !hash.is_empty()));
                assert_eq!(second["htm"], "POST");
                assert_eq!(second["htu"], target.split('?').next().unwrap());
                send(&mut socket, terminal(&result)).await;
            };
            let (result, ()) = pair(application, peer).await;
            let event = result.unwrap();
            assert!(match (kind, event) {
                (0, ManagedTaskEvent::ToolResult(result)) => matches!(*result, FinalCoreResult::ToolsCallTask { .. }),
                (1, ManagedTaskEvent::Snapshot(_)) | (2, ManagedTaskEvent::Updated(_)) | (3, ManagedTaskEvent::Cancelled(_)) => true,
                _ => false,
            });
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
            assert!(cx.checkpoint().is_ok());
        });
    }
}

#[test]
fn discovery_refusals_and_failed_mutations_never_trigger_an_extra_post() {
    for case in 0..5 {
        run(async move {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = format!("https://{}/mcp", listener.local_addr().unwrap());
            let (mut client, credential, acceptor) = configured(&target);
            let application = client.request_task(&cx, &credential, metadata(), operation(tool()), ManagedCoreLimits::default());
            let peer = async {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (_, request) = read_request(&mut socket).await;
                assert_eq!(request["method"], "server/discover");
                let mut first = discovery();
                match case {
                    0 => {
                        let mut result = discovery_result();
                        result["capabilities"]["extensions"] = json!({});
                        first.body = envelope(&RequestId::Number(1), &result.to_string());
                    }
                    1 => { first.status = 401; }
                    2 => { first.body = envelope(&RequestId::String("1".to_owned()), &discovery_result().to_string()); }
                    _ => {}
                }
                send(&mut socket, first).await;
                if case >= 3 {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let (_, request) = read_request(&mut socket).await;
                    assert_eq!(request["method"], "tools/call");
                    let last = if case == 3 {
                        response(401, b"{}".to_vec())
                    } else {
                        response(200, envelope(&RequestId::Number(3), &task_result("task")))
                    };
                    send(&mut socket, last).await;
                }
            };
            let (result, ()) = pair(application, peer).await;
            assert!(result.is_err());
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending(),
                "neither discovery refusal nor a mutation error may authorize replay");
            assert!(cx.checkpoint().is_ok());
        });
    }
}

#[test]
fn silent_task_reads_release_the_socket_on_cancel_revocation_or_abandonment() {
    for case in 0..4 {
        run(async move {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = format!("https://{}/mcp", listener.local_addr().unwrap());
            let (mut client, credential, acceptor) = configured(&target);
            let revocation = client.revocation_handle();
            let cancellation = McpRequestCancellation::new();
            let seen = McpRequestCancellation::new();
            let application = async {
                let mut call = Some(Box::pin(client.request_task_with_cancellation(&cx, &cancellation,
                    &credential, metadata(), operation(tool()), ManagedCoreLimits::default())));
                let mut observed = pin!(seen.cancelled());
                let mut acted = false;
                let result = poll_fn(|task| {
                    if let Poll::Ready(result) = call.as_mut().unwrap().as_mut().poll(task) {
                        return Poll::Ready(Some(result));
                    }
                    if !acted && observed.as_mut().poll(task).is_ready() {
                        acted = true;
                        match case {
                            0 => { cancellation.cancel(); }
                            1 => { credential.revoke(); }
                            2 => { revocation.revoke(); }
                            _ => {
                                drop(call.take());
                                return Poll::Ready(None);
                            }
                        }
                    }
                    Poll::Pending
                }).await;
                drop(call);
                assert!(acted, "must first observe a real second POST and pending body");
                match case {
                    0 => assert!(matches!(result, Some(Err(DpopTasksError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled)))))),
                    1 | 2 => assert!(matches!(result, Some(Err(DpopTasksError::Core(DpopCoreError::Transport(DpopHttpError::Authorization(_))))))),
                    _ => assert!(result.is_none()),
                }
            };
            let peer = async {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                read_request(&mut socket).await;
                send(&mut socket, discovery()).await;
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (_, request) = read_request(&mut socket).await;
                assert_eq!(request["method"], "tools/call");
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n{").await.unwrap();
                socket.flush().await.unwrap();
                seen.cancel();
                let mut byte = [0];
                assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0),
                    "abandoned response must not keep the owned TLS socket live");
            };
            pair(application, peer).await;
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
            assert!(cx.checkpoint().is_ok());
            if case == 0 || case == 3 {
                // Stopping one operation is not session revocation. A fresh
                // explicit operation must rediscover and can still complete.
                assert!(!revocation.is_revoked());
                let application = client.request_task(&cx, &credential, metadata(),
                    DpopTaskOperation::new(RequestId::Number(3), RequestId::Number(4), ManagedTaskRequest::Get(id())).unwrap(),
                    ManagedCoreLimits::default());
                let peer = async {
                    for (request_id, method, source) in [
                        (3, "server/discover", discovery_result().to_string()),
                        (4, TASK_GET, task_result("complete")),
                    ] {
                        let (socket, _) = listener.accept().await.unwrap();
                        let mut socket = acceptor.accept(socket).await.unwrap();
                        let (_, request) = read_request(&mut socket).await;
                        assert_eq!(request["id"], request_id);
                        assert_eq!(request["method"], method);
                        send(&mut socket, response(200, envelope(&RequestId::Number(request_id), &source))).await;
                    }
                };
                let (result, ()) = pair(application, peer).await;
                assert!(matches!(result, Ok(ManagedTaskEvent::Snapshot(_))));
            }
        });
    }
}

#[test]
fn discovery_time_is_not_refunded_when_the_task_post_starts() {
    use std::sync::Arc;
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let runtime = RuntimeBuilder::current_thread().blocking_threads(0, 0)
        .with_reactor(create_reactor().unwrap()).with_timer_driver(timer.clone()).build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = format!("https://{}/mcp", listener.local_addr().unwrap());
        let (mut client, credential, acceptor) = configured(&target);
        let limits = ManagedCoreLimits::new(8192, 8192, 16384, 0, Duration::from_secs(10)).unwrap();
        let reached = McpRequestCancellation::new();
        let application = async {
            let mut call: Pin<Box<_>> = Box::pin(client.request_task(&cx, &credential, metadata(), operation(tool()), limits));
            let mut reached_wait = pin!(reached.cancelled());
            poll_fn(|task| {
                let result = call.as_mut().poll(task);
                if reached_wait.as_mut().poll(task).is_ready() {
                    // Fail immediately, rather than waiting for a mistakenly
                    // restarted 16-second deadline to make the test look green.
                    assert!(matches!(result,
                        Poll::Ready(Err(DpopTasksError::Core(DpopCoreError::Transport(DpopHttpError::TimedOut))))));
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
            let (_, request) = read_request(&mut socket).await;
            assert_eq!(request["method"], "server/discover");
            clock.advance(6_000_000_000);
            send(&mut socket, discovery()).await;
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (_, request) = read_request(&mut socket).await;
            assert_eq!(request["method"], "tools/call");
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n{").await.unwrap();
            socket.flush().await.unwrap();
            clock.advance(4_000_000_000);
            // The fired count is the property this test is named for: discovery
            // spent 6s, so the deadline must come due at 10s rather than being
            // refunded to 6+10. Bare-discarding it let the test pass even if
            // the advance fired nothing. This was the only BARE discard among
            // the workspace's 44 `process_timers` call sites; 43 state an
            // expectation (now 28 `> 0`, 15 `== 0`) and one discards
            // explicitly with `let _` in a drain arm that does not care
            // (http_auth/discovery/client_credentials/lifetime.rs:338).
            assert!(timer.process_timers() > 0);
            reached.cancel();
        };
        pair(application, peer).await;
        assert_eq!(cx.now().as_nanos(), 10_000_000_000);
        assert!(cx.checkpoint().is_ok());
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn reviewed_task_tool_headers_survive_discovery_and_all_json_sse_result_kinds() {
    use std::sync::Arc;
    use crate::http_auth::dpop::native::core::stream::{DpopStreamError, DpopStreamLimits};
    use crate::http_executor::parameter_headers::{ReviewedToolHeaders, ToolHeaderDispatchError};
    use fastmcp_protocol::http_headers::{AdmittedToolHeaderSchema, McpHeaderError, decode_mcp_header_value};

    // JSON collector, streaming API with JSON, and genuinely incremental SSE.
    // Each must preserve complete/input-required/task as distinct outcomes.
    for mode in 0..3 {
        for kind in 0..3 {
            run(async move {
                let cx = Cx::current().unwrap();
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
                let (mut client, credential, acceptor) = configured(&target);
                let schema = json!({"type":"object","properties":{
                    "region":{"type":"string","x-mcp-header":"Region"},
                    "private":{"type":"string","writeOnly":true}
                }});
                let review = |resource: &str| Arc::new(ReviewedToolHeaders::new(
                    CanonicalHttpUrl::parse(resource).unwrap(), "echo", schema.clone(), |_| true,
                ).unwrap());
                let reviewed = review(&target);
                let arguments = json!({"region":" 雪 ","private":"body-only-canary"});
                let mut meta = serde_json::to_value(metadata()).unwrap();
                meta["progressToken"] = json!("reviewed-work");
                let meta: FinalRequestMeta = serde_json::from_value(meta).unwrap();
                let limits = DpopStreamLimits::new(ManagedCoreLimits::default(), Duration::from_secs(30)).unwrap();
                let cancellation = McpRequestCancellation::new();

                // Differ only in the forbidden dimension. Neither bad plan may
                // open even the discovery socket, spend a proof or invoke an observer.
                for (selected, args, foreign) in [
                    (review("https://other.example/mcp"), arguments.clone(), true),
                    (Arc::clone(&reviewed), json!({"region":7,"private":"body-only-canary"}), false),
                ] {
                    let selected = operation(ManagedTaskRequest::CallTool {
                        name: "echo".to_owned(), arguments: Some(args),
                    }).with_reviewed_tool_headers(selected).unwrap();
                    let mut failed = Box::pin(async {
                        if mode == 0 {
                            client.request_task(&cx, &credential, meta.clone(), selected, ManagedCoreLimits::default())
                                .await.map_err(DpopStreamError::from)
                        } else {
                            client.request_task_with_events(&cx, &cancellation, &credential, meta.clone(),
                                selected, limits, |_| panic!("invalid projection cannot emit events")).await
                        }
                    });
                    let error = poll_fn(|task| {
                        let Poll::Ready(result) = failed.as_mut().poll(task) else {
                            panic!("header refusal must precede every network wait");
                        };
                        Poll::Ready(result.err().unwrap())
                    }).await;
                    drop(failed);
                    if foreign {
                        assert!(matches!(error, DpopStreamError::Task(DpopTasksError::Header(
                            ToolHeaderDispatchError::TargetMismatch))));
                    } else {
                        assert!(matches!(error, DpopStreamError::Task(DpopTasksError::Header(
                            ToolHeaderDispatchError::Projection(McpHeaderError::InvalidParameter)))));
                    }
                    assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
                    assert!(!client.revocation_handle().is_revoked());
                }

                let selected = operation(ManagedTaskRequest::CallTool {
                    name: "echo".to_owned(), arguments: Some(arguments.clone()),
                }).with_reviewed_tool_headers(Arc::clone(&reviewed)).unwrap();
                let observed = McpRequestCancellation::new();
                let mut observer_calls = 0;
                let application = async {
                    if mode == 0 {
                        client.request_task(&cx, &credential, meta.clone(), selected, ManagedCoreLimits::default())
                            .await.map_err(DpopStreamError::from)
                    } else {
                        client.request_task_with_events(&cx, &cancellation, &credential, meta.clone(),
                            selected, limits, |notification| {
                                assert!(matches!(notification, fastmcp_protocol::ServerNotification::Progress(_)));
                                observer_calls += 1;
                                observed.cancel();
                                true
                            }).await
                    }
                };
                let peer = async {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let (head, body) = read_request(&mut socket).await;
                    assert_eq!(body["method"], "server/discover");
                    assert_eq!(body["id"], 1);
                    assert!(body["params"].get("arguments").is_none());
                    assert!(!head.to_ascii_lowercase().contains("mcp-param-"));
                    assert!(!head.contains("body-only-canary"));
                    assert_eq!(header(&head, "authorization"), "DPoP tasks-token");
                    let first = claims(header(&head, "dpop"));
                    assert!(first.get("nonce").is_none());
                    send(&mut socket, discovery()).await;

                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let (head, body) = read_request(&mut socket).await;
                    assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
                    assert_eq!(body["id"], 2);
                    assert_eq!(body["method"], "tools/call");
                    assert_eq!(body["params"]["arguments"], arguments);
                    assert_eq!(body["params"]["_meta"]["progressToken"], "reviewed-work");
                    assert_eq!(body["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],
                        json!({TASKS_EXTENSION:{}}));
                    assert_eq!(header(&head, "authorization"), "DPoP tasks-token");
                    assert_eq!(header(&head, "mcp-name"), "echo");
                    assert_eq!(decode_mcp_header_value(header(&head, "mcp-param-region").as_bytes()).unwrap(), " 雪 ");
                    assert!(!head.contains("body-only-canary"));
                    assert_eq!(header(&head, "accept"), if mode == 0 { "application/json" }
                        else { crate::http_executor::MODERN_MCP_ACCEPT });
                    let second = claims(header(&head, "dpop"));
                    assert_ne!(first["jti"], second["jti"]);
                    assert_eq!(first["ath"], second["ath"]);
                    assert_eq!(second["nonce"], "resource-next");
                    assert_eq!(second["htu"], target.split('?').next().unwrap());
                    assert_eq!(second["htm"], "POST");
                    let fields: Vec<_> = head.lines().filter_map(|line| line.split_once(':'))
                        .map(|(name, value)| (name.to_owned(), value.trim().to_owned())).collect();
                    let admitted = AdmittedToolHeaderSchema::admit(schema.clone()).unwrap();
                    admitted.header_plan().validate(body["params"].get("arguments"), &fields).unwrap();
                    let missing: Vec<_> = fields.into_iter()
                        .filter(|(name, _)| !name.eq_ignore_ascii_case("mcp-param-region")).collect();
                    assert!(admitted.header_plan().validate(body["params"].get("arguments"), &missing).is_err());
                    let result = match kind {
                        0 => r#"{"resultType":"complete","content":[{"type":"text","text":"done"}]}"#.to_owned(),
                        1 => task_result("task"),
                        _ => r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"opaque-state"}"#.to_owned(),
                    };
                    if mode != 2 {
                        send(&mut socket, terminal(&result)).await;
                    } else {
                        let progress = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":\"reviewed-work\",\"progress\":1}}\r\n\r\n";
                        let terminal = String::from_utf8(envelope(&RequestId::Number(2), &result)).unwrap();
                        let terminal = format!("data: {terminal}\r\n\r\n");
                        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{progress}",
                            progress.len() + terminal.len()).as_bytes()).await.unwrap();
                        socket.flush().await.unwrap();
                        // The terminal does not exist on the wire until the
                        // public observer has received the progress event.
                        observed.cancelled().await;
                        socket.write_all(terminal.as_bytes()).await.unwrap();
                        socket.shutdown().await.unwrap();
                    }
                };
                let (result, ()) = Box::pin(pair(application, peer)).await;
                let ManagedTaskEvent::ToolResult(result) = result.unwrap() else {
                    panic!("reviewed operation must retain the tool result family");
                };
                assert!(matches!((kind, *result),
                    (0, FinalCoreResult::ToolsCall { .. })
                        | (1, FinalCoreResult::ToolsCallTask { .. })
                        | (2, FinalCoreResult::ToolsCallInputRequired { .. })));
                assert_eq!(observer_calls, usize::from(mode == 2));
                assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
                assert!(!client.revocation_handle().is_revoked());
                assert!(cx.checkpoint().is_ok());
            });
        }
    }
}
