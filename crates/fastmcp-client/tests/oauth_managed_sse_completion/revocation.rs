//! Public login, native TLS, and revocation while a peer deliberately stays idle.
//! These reuse the parent's explicitly trusted issuer/resource fixture. No
//! bearer or response custody is injected; the peer supplies scripted protocol
//! responses rather than executing the native server or revocation endpoint.
use super::*;
use fastmcp_client::http_auth::managed::OAuthCredentialSnapshot;
use fastmcp_client::http_auth::managed::subscriptions::{
    ManagedSubscriptionError, ManagedSubscriptionEvent, ManagedSubscriptionLimits,
};

async fn closed(socket: &mut TlsStream<TcpStream>) {
    let mut byte = [0];
    assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0),
        "revocation must release the response socket without another request");
}

async fn pending<F: Future>(mut future: std::pin::Pin<&mut F>) {
    poll_fn(|task| {
        assert!(future.as_mut().poll(task).is_pending());
        Poll::Ready(())
    }).await;
}

async fn headers(socket: &mut TlsStream<TcpStream>, mime: &str, prefix: &str) {
    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nTransfer-Encoding: chunked\r\n\r\n").as_bytes()).await.unwrap();
    if !prefix.is_empty() {
        socket.write_all(format!("{:X}\r\n{prefix}\r\n", prefix.len()).as_bytes()).await.unwrap();
    }
    socket.flush().await.unwrap();
}

async fn revoke_when_reading(
    peer: &Peer, method: &str, mime: &str, prefix: &str,
    reading: &McpRequestCancellation, snapshot: &OAuthCredentialSnapshot,
) {
    let (mut socket, _) = peer.rpc(method, 41).await;
    headers(&mut socket, mime, prefix).await;
    // This rendezvous is not a timeout: the application has actually obtained
    // the response and polled its pending read before revocation is requested.
    reading.cancelled().await;
    snapshot.credential().revoke();
    closed(&mut socket).await;
}

#[test]
fn revoked_access_wakes_response_head_wait_without_a_peer_reply() {
    run(|cx| async move {
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let sibling = peer.login(&cx).await;
        let snapshot = session.credential(&cx).await.unwrap();
        let server = async {
            let (mut socket, _) = peer.rpc("tools/call", 41).await;
            snapshot.credential().revoke();
            closed(&mut socket).await;
            peer.follow_up().await;
        };
        let application = async {
            let result = session.request_core(&cx, core("tools/call"), RequestId::Number(41), ManagedCoreLimits::default()).await;
            assert!(matches!(result, Err(ManagedCoreError::Session(OAuthSessionError::LoginRequired))));
            assert!(matches!(session.credential(&cx).await, Err(OAuthSessionError::LoginRequired)));
            // Identical token bytes returned to an independent login are not
            // a process-global revocation key and remain a usable lineage.
            follow_up(&cx, &sibling).await;
        };
        pair(server, application).await;
        peer.quiet(2);
        assert!(cx.checkpoint().is_ok());
        session.close(); sibling.close();
    });
}

#[derive(Clone, Copy)]
enum ReadPhase { JsonBody, SseBody, SseCompletion }
fn body_case(phase: ReadPhase) {
    run(|cx| async move {
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let sibling = peer.login(&cx).await;
        let snapshot = session.credential(&cx).await.unwrap();
        let reading = McpRequestCancellation::new();
        let prefix = match phase {
            ReadPhase::JsonBody => "{".to_owned(),
            ReadPhase::SseBody => format!("data: {PROGRESS}\n\n"),
            ReadPhase::SseCompletion => format!("data: {PROGRESS}\n\ndata: {{\"jsonrpc\":\"2.0\",\"id\":41,\"result\":{COMPLETE}}}\n\n"),
        };
        let mime = if matches!(phase, ReadPhase::JsonBody) { "application/json" } else { "text/event-stream" };
        let server = async {
            revoke_when_reading(&peer, "tools/call", mime, &prefix, &reading, &snapshot).await;
            peer.follow_up().await;
        };
        let application = async {
            let mut call = session.request_core(&cx, core("tools/call"), RequestId::Number(41), ManagedCoreLimits::default()).await.unwrap();
            if !matches!(phase, ReadPhase::JsonBody) {
                assert!(matches!(call.next_event(&cx).await.unwrap(), Some(ManagedCoreEvent::Notification(_))));
            }
            let mut read = Box::pin(call.next_event(&cx));
            pending(read.as_mut()).await;
            reading.cancel();
            assert!(matches!(read.await, Err(ManagedCoreError::Session(OAuthSessionError::LoginRequired))));
            assert!(matches!(call.next_event(&cx).await, Err(ManagedCoreError::Closed)));
            follow_up(&cx, &sibling).await;
        };
        pair(server, application).await;
        peer.quiet(2);
        assert!(cx.checkpoint().is_ok());
        session.close(); sibling.close();
    });
}

#[test]
fn revoked_access_wakes_idle_json_body_read() { body_case(ReadPhase::JsonBody); }
#[test]
fn revoked_access_wakes_idle_sse_read_after_delivered_progress() { body_case(ReadPhase::SseBody); }
#[test]
fn revoked_access_withholds_sse_terminal_while_waiting_for_body_completion() { body_case(ReadPhase::SseCompletion); }

fn listen_request(tasks: bool) -> CoreRequest {
    let mut meta = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    let mut filter = json!({"toolsListChanged":true});
    if tasks {
        meta["io.modelcontextprotocol/clientCapabilities"]["extensions"] = json!({"io.modelcontextprotocol/tasks":{}});
        filter["taskIds"] = json!(["task-one"]);
    }
    CoreRequest::decode(ProtocolEra::Modern2026, "subscriptions/listen", Some(&json!({"_meta":meta,"notifications":filter}))).unwrap()
}
fn ack(tasks: bool) -> String {
    let mut filter = json!({"toolsListChanged":true});
    if tasks { filter["taskIds"] = json!(["task-one"]); }
    let ack = json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{
        "_meta":{"io.modelcontextprotocol/subscriptionId":41},"notifications":filter}});
    format!("data: {ack}\n\n")
}

#[test]
fn revoked_access_wakes_acknowledged_core_subscription_without_reconnect() {
    run(|cx| async move {
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let sibling = peer.login(&cx).await;
        let snapshot = session.credential(&cx).await.unwrap();
        let reading = McpRequestCancellation::new();
        let server = async {
            revoke_when_reading(&peer, "subscriptions/listen", "text/event-stream", &ack(false), &reading, &snapshot).await;
            peer.follow_up().await;
        };
        let application = async {
            let mut listen = session.subscribe_core(&cx, listen_request(false), RequestId::Number(41), ManagedSubscriptionLimits::default()).await.unwrap();
            assert!(matches!(listen.next_event(&cx).await.unwrap(), Some(ManagedSubscriptionEvent::Acknowledged { .. })));
            let mut read = Box::pin(listen.next_event(&cx));
            pending(read.as_mut()).await;
            reading.cancel();
            assert!(matches!(read.await, Err(ManagedSubscriptionError::Session(OAuthSessionError::LoginRequired))));
            assert!(matches!(listen.next_event(&cx).await, Err(ManagedSubscriptionError::Closed)));
            assert_eq!(listen.accepted_filter().unwrap().tools_list_changed, Some(true));
            follow_up(&cx, &sibling).await;
        };
        pair(server, application).await;
        peer.quiet(2);
        session.close(); sibling.close();
    });
}

#[cfg(feature = "tasks")]
mod tasks {
    use super::*;
    use fastmcp_client::http_auth::managed::tasks::{
        ManagedTaskEvent, ManagedTaskRequest, ManagedTaskRequestIds,
        ManagedTasksClient, ManagedTasksError, ManagedTasksLimits,
    };

    async fn discover(peer: &Peer) {
        let (mut socket, request) = peer.rpc("server/discover", 40).await;
        assert_eq!(request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"], json!({"io.modelcontextprotocol/tasks":{}}));
        let result = json!({"jsonrpc":"2.0","id":40,"result":{"resultType":"complete",
            "supportedVersions":["2026-07-28"],"capabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}},
            "ttlMs":0,"cacheScope":"private"}});
        json_reply(&mut socket, &result.to_string()).await;
    }
    fn client(session: ManagedOAuthSession) -> ManagedTasksClient {
        let mut metadata = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        metadata["progressToken"] = json!("work");
        ManagedTasksClient::new(session, serde_json::from_value(metadata).unwrap(), ManagedTasksLimits::default()).unwrap()
    }
    fn ids() -> ManagedTaskRequestIds { ManagedTaskRequestIds::new(RequestId::Number(40), RequestId::Number(41)).unwrap() }
    fn tool() -> ManagedTaskRequest { ManagedTaskRequest::CallTool { name:"fixture".to_owned(), arguments:None } }

    #[test]
    fn revoked_discovery_cannot_authorize_a_task_mutation_or_task_listen() {
        for listen in [false, true] {
            run(|cx| async move {
                let peer = Peer::new().await;
                let session = peer.login(&cx).await;
                let snapshot = session.credential(&cx).await.unwrap();
                let server = async {
                    let (mut socket, _) = peer.rpc("server/discover", 40).await;
                    // No discovery reply and no ambient cancellation: only the
                    // original credential's signal can complete the wait now.
                    snapshot.credential().revoke();
                    closed(&mut socket).await;
                };
                let application = async {
                    if listen {
                        let result = session.subscribe_tasks(&cx, listen_request(true), RequestId::Number(40), RequestId::Number(41), ManagedSubscriptionLimits::default()).await;
                        assert!(matches!(result, Err(ManagedSubscriptionError::Session(OAuthSessionError::LoginRequired))));
                    } else {
                        let result = client(session.clone()).request(&cx, ids(), tool()).await;
                        assert!(matches!(result, Err(ManagedTasksError::Session(OAuthSessionError::LoginRequired))));
                    }
                };
                pair(server, application).await;
                peer.quiet(1);
                assert!(cx.checkpoint().is_ok());
                session.close();
            });
        }
    }

    #[test]
    fn revoked_task_response_withholds_its_provisional_result_and_retires_the_socket() {
        run(|cx| async move {
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let sibling = peer.login(&cx).await;
            let snapshot = session.credential(&cx).await.unwrap();
            let reading = McpRequestCancellation::new();
            let prefix = format!("data: {PROGRESS}\n\ndata: {{\"jsonrpc\":\"2.0\",\"id\":41,\"result\":{COMPLETE}}}\n\n");
            let server = async {
                discover(&peer).await;
                revoke_when_reading(&peer, "tools/call", "text/event-stream", &prefix, &reading, &snapshot).await;
                peer.follow_up().await;
            };
            let application = async {
                let mut call = client(session.clone()).request(&cx, ids(), tool()).await.unwrap();
                assert!(matches!(call.next_event(&cx).await.unwrap(), Some(ManagedTaskEvent::Notification(_))));
                let mut read = Box::pin(call.next_event(&cx));
                pending(read.as_mut()).await;
                reading.cancel();
                assert!(matches!(read.await, Err(ManagedTasksError::Session(OAuthSessionError::LoginRequired))));
                assert!(matches!(call.next_event(&cx).await, Err(ManagedTasksError::Closed)));
                follow_up(&cx, &sibling).await;
            };
            pair(server, application).await;
            peer.quiet(3);
            session.close(); sibling.close();
        });
    }

    #[test]
    fn revoked_access_wakes_acknowledged_tasks_subscription_without_reconnect() {
        run(|cx| async move {
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let sibling = peer.login(&cx).await;
            let snapshot = session.credential(&cx).await.unwrap();
            let reading = McpRequestCancellation::new();
            let server = async {
                discover(&peer).await;
                revoke_when_reading(&peer, "subscriptions/listen", "text/event-stream", &ack(true), &reading, &snapshot).await;
                peer.follow_up().await;
            };
            let application = async {
                let mut listen = session.subscribe_tasks(&cx, listen_request(true), RequestId::Number(40), RequestId::Number(41), ManagedSubscriptionLimits::default()).await.unwrap();
                assert!(matches!(listen.next_event(&cx).await.unwrap(), Some(ManagedSubscriptionEvent::Acknowledged { .. })));
                let mut read = Box::pin(listen.next_event(&cx));
                pending(read.as_mut()).await;
                reading.cancel();
                assert!(matches!(read.await, Err(ManagedSubscriptionError::Session(OAuthSessionError::LoginRequired))));
                assert!(matches!(listen.next_event(&cx).await, Err(ManagedSubscriptionError::Closed)));
                follow_up(&cx, &sibling).await;
            };
            pair(server, application).await;
            peer.quiet(3);
            session.close(); sibling.close();
        });
    }
}
