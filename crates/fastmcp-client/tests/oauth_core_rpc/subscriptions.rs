//! Public SUB-03/OAuth composition, using the same TLS peer and isolated trust
//! root as the surrounding core-call integration target. Every test performs
//! real login and real authenticated subscription POSTs; no transport is mocked.

use super::*;
use fastmcp_client::http_auth::managed::OAuthSessionError;
use fastmcp_client::http_auth::managed::subscriptions::{
    ManagedSubscription, ManagedSubscriptionError, ManagedSubscriptionEvent,
    ManagedSubscriptionLimits,
};
use fastmcp_protocol::{FINAL_SUBSCRIPTION_ID_META_KEY, SubscriptionFilter};

#[derive(Clone, Copy)]
enum SubscriptionCase {
    Live, BadAcknowledgement, BadEvent, Truncated, Cancel, SessionClose,
    AbandonRead, Expiry, Deadline, RecordLimit, Preflight, HttpFailure,
}

fn isolated_subscription(name: &str, case: SubscriptionCase) {
    if let Ok(selected) = std::env::var(CHILD_CASE) {
        assert_eq!(selected, name);
        run_subscription(case);
        return;
    }
    // Retain child custody even if an assertion/I/O error unwinds the harness.
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    // Materialized from the parent target's inlined TEST ONLY root: the remote
    // build worker never receives `*.pem`, so reading it from `tests/fixtures/`
    // failed every case here with "public subscription case failed".
    let roots = std::env::temp_dir().join(format!("fastmcp-oauth-core-ca-{}.pem", name.replace("::", "_")));
    std::fs::write(&roots, ROOT).expect("materialize the TEST ONLY root for the child trust store");
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD_CASE, name).env("SSL_CERT_FILE", roots).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit())
        .spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "public subscription case failed");
            return;
        }
        assert!(Instant::now() < deadline, "public subscription exceeded its process bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn selected_filter() -> SubscriptionFilter {
    let mut filter = SubscriptionFilter::default();
    filter.tools_list_changed = Some(true);
    filter.resource_subscriptions = Some(serde_json::from_value(json!(["file:///watched"])).unwrap());
    filter
}

fn listen_request() -> CoreRequest {
    core("subscriptions/listen", json!({"notifications": selected_filter()}))
}

fn acknowledged(id: i64, filter: SubscriptionFilter) -> String {
    json!({
        "jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
        "params": {"_meta": {(FINAL_SUBSCRIPTION_ID_META_KEY): id}, "notifications": filter},
    }).to_string()
}

fn subscription_terminal(id: i64) -> String {
    terminal(id, &json!({"resultType": "complete", "_meta": {(FINAL_SUBSCRIPTION_ID_META_KEY): id}}).to_string())
}

fn resource_updated(uri: &str) -> String {
    json!({"jsonrpc": "2.0", "method": "notifications/resources/updated", "params": {"uri": uri}}).to_string()
}

async fn subscription_stream(peer: &Peer, id: i64) -> TlsStream<TcpStream> {
    let (mut tls, request) = peer.request("/mcp").await;
    let request: Value = serde_json::from_slice(&request).unwrap();
    assert_eq!(request["id"], id);
    assert_eq!(request["method"], "subscriptions/listen");
    assert_eq!(request["params"]["notifications"], serde_json::to_value(selected_filter()).unwrap());
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
    tls.flush().await.unwrap();
    tls
}

async fn consume_ack(listener: &mut ManagedSubscription, cx: &Cx) {
    let Some(ManagedSubscriptionEvent::Acknowledged { accepted_filter }) = listener.next_event(cx).await.unwrap() else {
        panic!("the first delivered record must be an acknowledgement");
    };
    assert_eq!(accepted_filter.tools_list_changed, Some(true));
    assert!(listener.accepted_filter().is_some());
    assert_eq!(listener.credential_generation(), 1);
}

async fn consume_terminal(listener: &mut ManagedSubscription, cx: &Cx, id: i64) {
    let Some(ManagedSubscriptionEvent::Terminal { subscription_id, .. }) = listener.next_event(cx).await.unwrap() else {
        panic!("the stream must deliver its correlated terminal");
    };
    assert!(subscription_id.correlates_with(&RequestId::Number(id)));
    assert!(listener.next_event(cx).await.unwrap().is_none());
}

async fn fresh_listen_after_gap(peer: &Peer, session: &ManagedOAuthSession, cx: &Cx) {
    let server = async {
        let mut tls = subscription_stream(peer, 42).await;
        chunk(&mut tls, &[acknowledged(42, selected_filter()), subscription_terminal(42)], true).await;
    };
    let application = async {
        let mut listener = session.subscribe_core(cx, listen_request(), RequestId::Number(42), ManagedSubscriptionLimits::default()).await.unwrap();
        consume_ack(&mut listener, cx).await;
        consume_terminal(&mut listener, cx, 42).await;
    };
    Box::pin(pair(server, application)).await;
}

fn run_subscription(case: SubscriptionCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let test = async {
            let peer = Peer::new().await;
            let login = async {
                let (mut tls, _) = peer.request("/token").await;
                let seconds = if matches!(case, SubscriptionCase::Expiry) { 2 } else { 300 };
                json_reply(&mut tls, 200, &json!({
                    "access_token": "typed-access", "token_type": "Bearer", "expires_in": seconds,
                    "refresh_token": "typed-refresh",
                }).to_string()).await;
            };
            // The expiry case tests the original stream, not an early renewal.
            let policy = OAuthSessionPolicy::new(Duration::ZERO, Duration::from_secs(30), Duration::from_secs(20), 64).unwrap();
            let ((), session) = Box::pin(pair(login, ManagedOAuthSession::authorize(&cx, peer.client(), policy, browser))).await;
            let session = session.unwrap();
            // Boxed so the twelve cases' locals live on the heap. Inlined, this
            // match makes one state machine large enough to abort the child with
            // `fatal runtime error: stack overflow` before any assertion runs.
            Box::pin(async { match case {
                SubscriptionCase::Live => {
                    let (release_tx, mut release_rx) = oneshot::channel::<()>();
                    let server = async {
                        let mut tls = subscription_stream(&peer, 41).await;
                        chunk(&mut tls, &[acknowledged(41, selected_filter())], false).await;
                        release_rx.recv(&cx).await.unwrap();
                        chunk(&mut tls, &[CHANGED.to_owned(), resource_updated("file:///watched"), subscription_terminal(41)], true).await;
                    };
                    let application = async {
                        let mut listener = session.subscribe_core(&cx, listen_request(), RequestId::Number(41), ManagedSubscriptionLimits::default()).await.unwrap();
                        assert!(listener.accepted_filter().is_none());
                        assert!(listener.request_id().correlates_with(&RequestId::Number(41)));
                        consume_ack(&mut listener, &cx).await;
                        release_tx.send(&cx, ()).unwrap();
                        let Some(ManagedSubscriptionEvent::Notification(notification)) = listener.next_event(&cx).await.unwrap() else { panic!("catalog change expected") };
                        assert!(matches!(*notification, ServerNotification::ToolsListChanged(_)));
                        let Some(ManagedSubscriptionEvent::Notification(notification)) = listener.next_event(&cx).await.unwrap() else { panic!("resource change expected") };
                        assert!(matches!(*notification, ServerNotification::ResourceUpdated(_)));
                        consume_terminal(&mut listener, &cx, 41).await;
                    };
                    Box::pin(pair(server, application)).await;
                }
                SubscriptionCase::BadAcknowledgement => {
                    let mut widened = selected_filter();
                    widened.prompts_list_changed = Some(true);
                    let mut foreign_uri = selected_filter();
                    foreign_uri.resource_subscriptions = Some(serde_json::from_value(json!(["file:///not-requested"])).unwrap());
                    let mut extension = selected_filter();
                    extension.additional.insert("taskIds".to_owned(), json!(["unrequested-task"]));
                    for frames in [
                        vec![acknowledged(999, selected_filter())],
                        vec![acknowledged(41, widened)],
                        vec![acknowledged(41, foreign_uri)],
                        vec![acknowledged(41, extension)],
                        vec![acknowledged(41, selected_filter()), acknowledged(41, selected_filter())],
                        vec![subscription_terminal(41)],
                        vec![CHANGED.to_owned()],
                    ] {
                        let server = async {
                            let mut tls = subscription_stream(&peer, 41).await;
                            chunk(&mut tls, &frames, true).await;
                        };
                        let application = async {
                            let mut listener = session.subscribe_core(&cx, listen_request(), RequestId::Number(41), ManagedSubscriptionLimits::default()).await.unwrap();
                            if frames.len() == 2 { consume_ack(&mut listener, &cx).await; }
                            assert!(matches!(listener.next_event(&cx).await, Err(ManagedSubscriptionError::InvalidResponse)));
                            assert!(matches!(listener.next_event(&cx).await, Err(ManagedSubscriptionError::Closed)));
                        };
                        Box::pin(pair(server, application)).await;
                    }
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 7);
                    Box::pin(fresh_listen_after_gap(&peer, &session, &cx)).await;
                }
                SubscriptionCase::BadEvent => {
                    for frame in [
                        resource_updated("file:///not-requested"),
                        r#"{"jsonrpc":"2.0","method":"notifications/prompts/list_changed"}"#.to_owned(),
                        PROGRESS.to_owned(),
                        r#"{"jsonrpc":"2.0","id":9,"method":"roots/list"}"#.to_owned(),
                        subscription_terminal(999),
                        format!("[{}]", CHANGED),
                        r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed","method":"notifications/resources/list_changed"}"#.to_owned(),
                    ] {
                        let server = async {
                            let mut tls = subscription_stream(&peer, 41).await;
                            chunk(&mut tls, &[acknowledged(41, selected_filter()), frame], true).await;
                        };
                        let application = async {
                            let mut listener = session.subscribe_core(&cx, listen_request(), RequestId::Number(41), ManagedSubscriptionLimits::default()).await.unwrap();
                            consume_ack(&mut listener, &cx).await;
                            assert!(matches!(listener.next_event(&cx).await, Err(ManagedSubscriptionError::InvalidResponse)));
                            assert!(matches!(listener.next_event(&cx).await, Err(ManagedSubscriptionError::Closed)));
                        };
                        Box::pin(pair(server, application)).await;
                    }
                    Box::pin(fresh_listen_after_gap(&peer, &session, &cx)).await;
                }
                SubscriptionCase::Truncated => {
                    let server = async {
                        let mut tls = subscription_stream(&peer, 41).await;
                        chunk(&mut tls, &[acknowledged(41, selected_filter())], true).await;
                    };
                    let application = async {
                        let mut listener = session.subscribe_core(&cx, listen_request(), RequestId::Number(41), ManagedSubscriptionLimits::default()).await.unwrap();
                        consume_ack(&mut listener, &cx).await;
                        assert!(matches!(listener.next_event(&cx).await, Err(ManagedSubscriptionError::MissingTerminal)));
                        assert!(matches!(listener.next_event(&cx).await, Err(ManagedSubscriptionError::Closed)));
                    };
                    Box::pin(pair(server, application)).await;
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 1);
                    Box::pin(fresh_listen_after_gap(&peer, &session, &cx)).await;
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 2);
                }
                SubscriptionCase::Cancel | SubscriptionCase::SessionClose | SubscriptionCase::AbandonRead
                | SubscriptionCase::Expiry | SubscriptionCase::Deadline => {
                    let server = async {
                        let mut tls = subscription_stream(&peer, 41).await;
                        chunk(&mut tls, &[acknowledged(41, selected_filter())], false).await;
                        let mut byte = [0];
                        assert!(!matches!(tls.read(&mut byte).await, Ok(count) if count > 0), "terminal local state must close the owned socket");
                    };
                    let application = async {
                        let cancellation = McpRequestCancellation::new();
                        let timeout = if matches!(case, SubscriptionCase::Deadline) { Duration::from_secs(1) } else { Duration::from_secs(15) };
                        let limits = ManagedSubscriptionLimits::new(4096, 4096, 10, timeout).unwrap();
                        let mut listener = session.subscribe_core_with_cancellation(&cx, &cancellation, listen_request(), RequestId::Number(41), limits).await.unwrap();
                        consume_ack(&mut listener, &cx).await;
                        if matches!(case, SubscriptionCase::Deadline) {
                            Sleep::new(cx.now().saturating_add_nanos(1_100_000_000)).await;
                            assert!(matches!(listener.next_event(&cx).await, Err(ManagedSubscriptionError::Session(OAuthSessionError::TimedOut))));
                        } else {
                            let mut read = Box::pin(listener.next_event(&cx));
                            poll_fn(|task| { assert!(read.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                            match case {
                                SubscriptionCase::Cancel => { cancellation.cancel(); },
                                SubscriptionCase::SessionClose => session.close(),
                                _ => {},
                            }
                            if matches!(case, SubscriptionCase::AbandonRead) {
                                drop(read);
                            } else {
                                let result = read.await;
                                match case {
                                    SubscriptionCase::Cancel => assert!(matches!(result, Err(ManagedSubscriptionError::Session(OAuthSessionError::Cancelled)))),
                                    SubscriptionCase::SessionClose => assert!(matches!(result, Err(ManagedSubscriptionError::Session(OAuthSessionError::Closed)))),
                                    SubscriptionCase::Expiry => assert!(matches!(result, Err(ManagedSubscriptionError::Session(OAuthSessionError::LoginRequired)))),
                                    _ => unreachable!(),
                                }
                            }
                        }
                        assert!(matches!(listener.next_event(&cx).await, Err(ManagedSubscriptionError::Closed)));
                        assert!(cx.checkpoint().is_ok());
                    };
                    Box::pin(pair(server, application)).await;
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 1);
                    if !matches!(case, SubscriptionCase::SessionClose | SubscriptionCase::Expiry) {
                        Box::pin(pair(peer.catalog(42), complete_catalog(&session, &cx, 42))).await;
                    }
                }
                SubscriptionCase::RecordLimit => {
                    let server = async {
                        let mut tls = subscription_stream(&peer, 41).await;
                        chunk(&mut tls, &[acknowledged(41, selected_filter()), CHANGED.to_owned(), subscription_terminal(41)], true).await;
                    };
                    let application = async {
                        let limits = ManagedSubscriptionLimits::new(4096, 4096, 2, Duration::from_secs(15)).unwrap();
                        let mut listener = session.subscribe_core(&cx, listen_request(), RequestId::Number(41), limits).await.unwrap();
                        consume_ack(&mut listener, &cx).await;
                        assert!(matches!(listener.next_event(&cx).await.unwrap(), Some(ManagedSubscriptionEvent::Notification(_))));
                        assert!(matches!(listener.next_event(&cx).await, Err(ManagedSubscriptionError::RecordLimit)));
                        assert!(matches!(listener.next_event(&cx).await, Err(ManagedSubscriptionError::Closed)));
                    };
                    Box::pin(pair(server, application)).await;
                    Box::pin(fresh_listen_after_gap(&peer, &session, &cx)).await;
                }
                SubscriptionCase::Preflight => {
                    let tiny = ManagedSubscriptionLimits::new(1, 4096, 10, Duration::from_secs(15)).unwrap();
                    assert!(matches!(session.subscribe_core(&cx, listen_request(), RequestId::Number(41), tiny).await, Err(ManagedSubscriptionError::RequestTooLarge)));
                    assert!(matches!(session.subscribe_core(&cx, core("tools/list", json!({})), RequestId::Number(41), ManagedSubscriptionLimits::default()).await, Err(ManagedSubscriptionError::InvalidRequest)));
                    let mut filter = selected_filter();
                    filter.additional.insert("taskIds".to_owned(), json!(["unnegotiated"]));
                    assert!(matches!(session.subscribe_core(&cx, core("subscriptions/listen", json!({"notifications": filter})), RequestId::Number(41), ManagedSubscriptionLimits::default()).await, Err(ManagedSubscriptionError::UnsupportedExtension)));
                    let cancelled = McpRequestCancellation::new();
                    cancelled.cancel();
                    assert!(matches!(session.subscribe_core_with_cancellation(&cx, &cancelled, listen_request(), RequestId::Number(41), ManagedSubscriptionLimits::default()).await, Err(ManagedSubscriptionError::Session(OAuthSessionError::Cancelled))));
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 0);
                    peer.no_extra_connections();
                    Box::pin(fresh_listen_after_gap(&peer, &session, &cx)).await;
                }
                SubscriptionCase::HttpFailure => {
                    for status in [200, 401, 403, 307, 500] {
                        let server = async {
                            let (mut tls, _) = peer.request("/mcp").await;
                            json_reply(&mut tls, status, "peer-error-canary").await;
                        };
                        let ((), result) = Box::pin(pair(server, session.subscribe_core(&cx, listen_request(), RequestId::Number(41), ManagedSubscriptionLimits::default()))).await;
                        let error = result.err().expect("a successful subscription requires SSE");
                        assert!(!format!("{error:?} {error}").contains("peer-error-canary"));
                    }
                    let server = async {
                        let mut tls = subscription_stream(&peer, 41).await;
                        chunk(&mut tls, &[r#"{"jsonrpc":"2.0","id":41,"error":{"code":-32603,"message":"peer-error-canary"}}"#.to_owned()], true).await;
                    };
                    let application = async {
                        let mut listener = session.subscribe_core(&cx, listen_request(), RequestId::Number(41), ManagedSubscriptionLimits::default()).await.unwrap();
                        let error = listener.next_event(&cx).await.err().unwrap();
                        assert!(matches!(error, ManagedSubscriptionError::Remote { .. }), "unexpected subscription error: {error:?}");
                        assert!(!format!("{error:?} {error}").contains("typed-access"));
                        assert!(!format!("{error:?} {error}").contains("peer-error-canary"));
                        assert!(listener.accepted_filter().is_none());
                        assert!(matches!(listener.next_event(&cx).await, Err(ManagedSubscriptionError::Closed)));
                    };
                    Box::pin(pair(server, application)).await;
                    // The same peer error with the actual bearer must be withheld
                    // by HTTP before it can become a subscription Remote error.
                    let server = async {
                        let mut tls = subscription_stream(&peer, 41).await;
                        chunk(&mut tls, &[r#"{"jsonrpc":"2.0","id":41,"error":{"code":-32603,"message":"typed-access peer-error-canary"}}"#.to_owned()], true).await;
                    };
                    let application = async {
                        let mut listener = session.subscribe_core(&cx, listen_request(), RequestId::Number(41), ManagedSubscriptionLimits::default()).await.unwrap();
                        let error = listener.next_event(&cx).await.err().unwrap();
                        assert!(matches!(error, ManagedSubscriptionError::Session(
                            OAuthSessionError::Http(fastmcp_client::http_executor::ModernHttpExecutorError::CredentialInPeerError)
                        )));
                        assert!(!format!("{error:?} {error}").contains("typed-access"));
                        assert!(!format!("{error:?} {error}").contains("peer-error-canary"));
                        assert!(listener.accepted_filter().is_none());
                        assert!(matches!(listener.next_event(&cx).await, Err(ManagedSubscriptionError::Closed)));
                    };
                    Box::pin(pair(server, application)).await;
                    assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 7);
                }
            } }).await;
            assert_eq!(peer.token_posts.load(Ordering::SeqCst), 1, "stream failures must not renew or replay a grant");
            peer.no_extra_connections();
            session.close();
        };
        Box::pin(asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), test)).await
            .expect("complete authenticated subscription fixture must settle within its bound");
    });
}

#[test]
fn managed_subscription_delivers_incrementally() { isolated_subscription("subscriptions::managed_subscription_delivers_incrementally", SubscriptionCase::Live); }
#[test]
fn managed_subscription_acknowledgement_is_bound() { isolated_subscription("subscriptions::managed_subscription_acknowledgement_is_bound", SubscriptionCase::BadAcknowledgement); }
#[test]
fn managed_subscription_events_stay_in_the_accepted_filter() { isolated_subscription("subscriptions::managed_subscription_events_stay_in_the_accepted_filter", SubscriptionCase::BadEvent); }
#[test]
fn managed_subscription_gap_requires_a_fresh_explicit_listen() { isolated_subscription("subscriptions::managed_subscription_gap_requires_a_fresh_explicit_listen", SubscriptionCase::Truncated); }
#[test]
fn managed_subscription_cancellation_leaves_sibling_calls_usable() { isolated_subscription("subscriptions::managed_subscription_cancellation_leaves_sibling_calls_usable", SubscriptionCase::Cancel); }
#[test]
fn managed_subscription_session_close_releases_idle_read() { isolated_subscription("subscriptions::managed_subscription_session_close_releases_idle_read", SubscriptionCase::SessionClose); }
#[test]
fn managed_subscription_abandoned_read_cannot_be_reused() { isolated_subscription("subscriptions::managed_subscription_abandoned_read_cannot_be_reused", SubscriptionCase::AbandonRead); }
#[test]
fn managed_subscription_original_token_expiry_closes_idle_read() { isolated_subscription("subscriptions::managed_subscription_original_token_expiry_closes_idle_read", SubscriptionCase::Expiry); }
#[test]
fn managed_subscription_deadline_includes_paused_consumption() { isolated_subscription("subscriptions::managed_subscription_deadline_includes_paused_consumption", SubscriptionCase::Deadline); }
#[test]
fn managed_subscription_record_limit_is_terminal() { isolated_subscription("subscriptions::managed_subscription_record_limit_is_terminal", SubscriptionCase::RecordLimit); }
#[test]
fn managed_subscription_preflight_has_no_peer_effect() { isolated_subscription("subscriptions::managed_subscription_preflight_has_no_peer_effect", SubscriptionCase::Preflight); }
#[test]
fn managed_subscription_failures_never_replay_or_expose_peer_errors() { isolated_subscription("subscriptions::managed_subscription_failures_never_replay_or_expose_peer_errors", SubscriptionCase::HttpFailure); }
