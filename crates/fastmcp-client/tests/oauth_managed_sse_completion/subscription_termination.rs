//! Public managed `listen_core` terminal control over the parent's real OAuth
//! login and explicitly trusted TLS peer. The peer deliberately omits HTTP EOF.
//! Ordinary finite RPC and DPoP framing contracts are exercised elsewhere.

use super::*;
use fastmcp_client::http_auth::rpc::subscription::ManagedSubscription;
use fastmcp_protocol::{
    CoreResult, FINAL_SUBSCRIPTION_ID_META_KEY, FinalCoreResult,
    FinalSubscriptionsListenParams, ServerNotification,
};

fn params() -> FinalSubscriptionsListenParams {
    serde_json::from_value(json!({
        "_meta": FinalRequestMeta::new(ClientCapabilities::default()),
        "notifications": {},
    }))
    .unwrap()
}

fn acknowledgement() -> Value {
    json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged",
        "params":{"_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):41}, "notifications":{}}})
}

fn cancellation(request_id: Value, subscription_id: Option<Value>) -> Value {
    let mut params = json!({"requestId":request_id, "reason":"subscription maintenance",
        "x-peer":"retained"});
    if let Some(subscription_id) = subscription_id {
        params["_meta"] = json!({(FINAL_SUBSCRIPTION_ID_META_KEY):subscription_id});
    }
    json!({"jsonrpc":"2.0", "method":"notifications/cancelled", "params":params})
}

fn complete() -> Value {
    json!({"jsonrpc":"2.0", "id":41, "result":{"resultType":"complete",
        "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):41}}})
}

async fn open_stream(peer: &Peer, frames: &[Value]) -> TlsStream<TcpStream> {
    let (mut socket, request) = peer.rpc("subscriptions/listen", 41).await;
    assert_eq!(request["params"]["notifications"], json!({}));
    assert_eq!(
        request["params"]["_meta"],
        serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap()
    );
    let body: String = frames.iter().map(|value| format!("data: {value}\n\n")).collect();
    socket.write_all(format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{body}\r\n",
        body.len()
    ).as_bytes()).await.unwrap();
    socket.flush().await.unwrap();
    socket
}

async fn closed(mut socket: TlsStream<TcpStream>) {
    let mut byte = [0];
    assert!(
        !matches!(socket.read(&mut byte).await, Ok(count) if count > 0),
        "the selected terminal or refusal must release its response without waiting for HTTP EOF"
    );
}

async fn receive_ack(listen: &mut ManagedSubscription, cx: &Cx) {
    assert!(matches!(
        listen.next_event(cx).await.unwrap(),
        Some(ManagedCoreEvent::Notification(notification))
            if matches!(*notification, ServerNotification::SubscriptionsAcknowledged(_))
    ));
    assert_eq!(serde_json::to_value(listen.accepted_filter().unwrap()).unwrap(), json!({}));
}

#[test]
fn managed_listen_core_first_terminal_releases_body_without_http_eof() {
    for cancelled_first in [false, true] {
        for both_signals in [false, true] {
            run(|cx| async move {
                let peer = Peer::new().await;
                let session = Box::pin(peer.login(&cx)).await;
                let cancelled = cancellation(
                    serde_json::from_str("41e0").unwrap(),
                    Some(serde_json::from_str("41.0").unwrap()),
                );
                let first = if cancelled_first { cancelled.clone() } else { complete() };
                let mut frames = vec![acknowledgement(), first];
                if both_signals {
                    frames.push(if cancelled_first { complete() } else { cancelled });
                }
                let server = async {
                    closed(open_stream(&peer, &frames).await).await;
                    peer.follow_up().await;
                };
                let application = async {
                    // The ACK consumes this entire event quota. Terminal
                    // control still fits its separate cumulative byte bound.
                    let limits = ManagedCoreLimits::new(
                        4096, 4096, 8192, 1, std::time::Duration::from_secs(10),
                    ).unwrap();
                    let mut listen = session.listen_core(
                        &cx, params(), RequestId::Number(41), limits,
                    ).await.unwrap();
                    receive_ack(&mut listen, &cx).await;
                    let terminal = listen.next_event(&cx).await.unwrap().unwrap();
                    if cancelled_first {
                        let ManagedCoreEvent::Notification(notification) = terminal else {
                            panic!("peer cancellation must not fabricate a result");
                        };
                        let ServerNotification::Cancelled(params) = *notification else {
                            panic!("typed cancellation expected");
                        };
                        assert!(params.request_id.correlates_with(&RequestId::Number(41)));
                        assert_eq!(params.reason.as_deref(), Some("subscription maintenance"));
                        assert_eq!(params.additional.get("x-peer"), Some(&json!("retained")));
                    } else {
                        assert!(matches!(terminal, ManagedCoreEvent::Result(result)
                            if matches!(result.as_ref(), CoreResult::Final(FinalCoreResult::SubscriptionsListen { .. }))));
                    }
                    assert!(listen.next_event(&cx).await.unwrap().is_none());
                    assert!(listen.next_event(&cx).await.unwrap().is_none());
                    assert!(cx.checkpoint().is_ok());
                    follow_up(&cx, &session).await;
                };
                Box::pin(pair(server, application)).await;
                peer.quiet(2);
                session.close();
            });
        }
    }
}

#[test]
fn managed_listen_core_rejects_foreign_unscoped_and_unacknowledged_cancellation() {
    for (acknowledged, frame) in [
        (true, cancellation(json!(42), Some(json!(41)))),
        (true, cancellation(json!(41), Some(json!(42)))),
        (true, cancellation(json!("41"), Some(json!(41)))),
        (true, cancellation(json!(41), Some(json!("41")))),
        (true, cancellation(json!(41), None)),
        (true, cancellation(json!(41), Some(Value::Null))),
        (false, cancellation(json!(41), Some(json!(41)))),
    ] {
        run(|cx| async move {
            let peer = Peer::new().await;
            let session = Box::pin(peer.login(&cx)).await;
            let mut frames = Vec::new();
            if acknowledged {
                frames.push(acknowledgement());
            }
            frames.push(frame);
            let server = async {
                closed(open_stream(&peer, &frames).await).await;
                peer.follow_up().await;
            };
            let application = async {
                let mut listen = session.listen_core(
                    &cx, params(), RequestId::Number(41), ManagedCoreLimits::default(),
                ).await.unwrap();
                if acknowledged {
                    receive_ack(&mut listen, &cx).await;
                }
                let error = listen.next_event(&cx).await.err().expect("invalid control must fail");
                if acknowledged {
                    assert!(matches!(error, ManagedCoreError::ResponseIdMismatch));
                } else {
                    assert!(matches!(error, ManagedCoreError::UnexpectedNotification));
                }
                assert!(matches!(listen.next_event(&cx).await, Err(ManagedCoreError::Closed)));
                assert!(cx.checkpoint().is_ok());
                follow_up(&cx, &session).await;
            };
            Box::pin(pair(server, application)).await;
            peer.quiet(2);
            session.close();
        });
    }
}

#[derive(Clone, Copy)]
enum Retire {
    CallerCancellation,
    Logout,
    CredentialRevocation,
}

#[test]
fn managed_listen_core_buffered_terminals_cannot_outlive_their_original_authority() {
    for retire in [Retire::CallerCancellation, Retire::Logout, Retire::CredentialRevocation] {
        for cancelled in [false, true] {
            run(|cx| async move {
                let peer = Peer::new().await;
                let session = Box::pin(peer.login(&cx)).await;
                let sibling = Box::pin(peer.login(&cx)).await;
                let snapshot = session.credential(&cx).await.unwrap();
                let cancel = McpRequestCancellation::new();
                let terminal = if cancelled {
                    cancellation(json!(41), Some(json!(41)))
                } else {
                    complete()
                };
                let frames = vec![acknowledgement(), terminal];
                let server = async {
                    // ACK and terminal share one write. The application retires
                    // authority after receiving ACK, before taking the terminal.
                    closed(open_stream(&peer, &frames).await).await;
                    peer.follow_up().await;
                };
                let application = async {
                    let mut listen = session.listen_core_with_cancellation(
                        &cx, &cancel, params(), RequestId::Number(41), ManagedCoreLimits::default(),
                    ).await.unwrap();
                    receive_ack(&mut listen, &cx).await;
                    match retire {
                        Retire::CallerCancellation => { cancel.cancel(); }
                        Retire::Logout => {
                            assert!(session.logout(&cx).await.unwrap().local_closed());
                        }
                        Retire::CredentialRevocation => { snapshot.credential().revoke(); }
                    }
                    let error = listen.next_event(&cx).await.err().expect("retired authority cannot publish a terminal");
                    match retire {
                        Retire::CallerCancellation => assert!(matches!(error, ManagedCoreError::Cancelled)),
                        Retire::Logout => assert!(matches!(error, ManagedCoreError::Session(OAuthSessionError::Closed))),
                        Retire::CredentialRevocation => assert!(matches!(error, ManagedCoreError::Session(OAuthSessionError::LoginRequired))),
                    }
                    assert!(matches!(listen.next_event(&cx).await, Err(ManagedCoreError::Closed)));
                    assert!(cx.checkpoint().is_ok());
                    follow_up(&cx, &sibling).await;
                };
                Box::pin(pair(server, application)).await;
                peer.quiet(2);
                session.close();
                sibling.close();
            });
        }
    }
}
