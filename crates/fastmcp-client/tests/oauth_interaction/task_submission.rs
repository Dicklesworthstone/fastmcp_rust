//! Public Task-submission custody over the existing OAuth/MCP HTTPS fixture.
//! Run the complete oauth_interaction target with tasks,native-tls-roots.
//! A feature-disabled or filtered run is not a receipt for this boundary.
use super::*;
use fastmcp_client::http_auth::managed::tasks::{ManagedTaskRequestIds, ManagedTasksClient, ManagedTasksLimits};
use fastmcp_client::http_auth::managed::tasks::interaction::{
    ManagedTaskInteractionEvent, ManagedTaskInteractionPolicy,
};
use fastmcp_client::http_auth::managed::tasks::interaction::submission::{
    ManagedTaskSubmission, ManagedTaskSubmissionError, TaskSubmissionState,
};
use fastmcp_protocol::{ClientCapabilities, FinalCoreResult, FinalRequestMeta};

const SUBMISSION_CASE: &str = "FASTMCP_TEST_TASK_SUBMISSION_CASE";
const DISCOVER: &str = r#"{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{"listChanged":true},"extensions":{"io.modelcontextprotocol/tasks":{}}},"ttlMs":0,"cacheScope":"private"}"#;
const NO_TASKS: &str = r#"{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"}"#;
const TASK: &str = r#"{"resultType":"task","taskId":"actual-peer-task","status":"working","createdAt":"2026-09-21T00:00:00Z","lastUpdatedAt":"2026-09-21T00:00:00Z","ttlMs":null}"#;
const COMPLETE: &str = r#"{"resultType":"complete","content":[],"isError":true,"x-exact":1.20e+4}"#;

#[derive(Clone, Copy)]
enum Case {
    Task, Complete, Continue, ContinueLost, DiscoveryLost, Refused,
    HeaderLost, BodyLost, Trailing, CancelBefore, CancelAfter,
    DropDiscovery, DropSend, DropRead, CloseInput, Timeout,
}

fn isolated(name: &str, case: Case) {
    let exact = format!("driver::task_submission::{name}");
    if let Ok(selected) = std::env::var(SUBMISSION_CASE) {
        assert_eq!(selected, exact);
        run(case);
        return;
    }
    let roots = RootFile::create();
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
    }
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
        .env(SUBMISSION_CASE, &exact).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit())
        .spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "Task submission HTTPS case failed");
            return;
        }
        assert!(Instant::now() < end, "Task submission child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn ids(first: i64) -> ManagedTaskRequestIds {
    ManagedTaskRequestIds::new(RequestId::Number(first), RequestId::Number(first + 1)).unwrap()
}
fn arguments() -> Value { json!({"payload":"unchanged","applicationKey":"host-choice-not-a-framework-key"}) }

async fn tool(peer: &Peer, id: i64, discovery: &Value, continuation: bool) -> TlsStream<TcpStream> {
    let (tls, bytes) = peer.request(false).await;
    let request: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(request["id"], id);
    assert_eq!(request["method"], "tools/call");
    assert_eq!(request["params"]["name"], "echo");
    assert_eq!(request["params"]["arguments"], arguments());
    assert_eq!(request["params"]["_meta"], discovery["params"]["_meta"]);
    assert_eq!(request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
        json!({"io.modelcontextprotocol/tasks":{}}));
    assert!(request["params"].get("task").is_none(), "Tasks negotiation never injects a task preference");
    if continuation {
        assert_eq!(request["params"]["requestState"], "  sealed+/%\0  ");
        assert_eq!(request["params"]["inputResponses"], json!({"first":{"roots":[]}}));
    } else {
        assert!(request["params"].get("requestState").is_none());
        assert!(request["params"].get("inputResponses").is_none());
    }
    // Peer::request independently checks the exact bearer, method/version
    // headers, and absence of legacy session IDs and Last-Event-ID.
    tls
}

async fn lose_body(mut tls: TlsStream<TcpStream>) {
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{\"jsonrpc\":").await.unwrap();
    tls.flush().await.unwrap();
}
async fn require_client_close(mut tls: TlsStream<TcpStream>) {
    let mut byte = [0; 1];
    match tls.read(&mut byte).await {
        Ok(0) | Err(_) => {},
        Ok(_) => panic!("abandoned attempt must close, not write another request"),
    }
}

async fn reject_replay(owner: &mut ManagedTaskSubmission, cx: &Cx) {
    assert_eq!(owner.state(), TaskSubmissionState::DeliveryUnknown);
    assert!(owner.pending_input().is_none());
    assert!(matches!(owner.send(cx).await, Err(ManagedTaskSubmissionError::TaskCreationDeliveryUnknown(_))));
    assert!(matches!(owner.resume(cx, ids(91), Some(answers("first"))).await,
        Err(ManagedTaskSubmissionError::TaskCreationDeliveryUnknown(_))));
    assert!(matches!(owner.next_event(cx).await, Err(ManagedTaskSubmissionError::TaskCreationDeliveryUnknown(_))));
    owner.close();
    assert_eq!(owner.state(), TaskSubmissionState::DeliveryUnknown, "close must not erase delivery uncertainty");
}

fn run(case: Case) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let scenario = Box::pin(async {
            let peer = Peer::new().await;
            let ((), login) = pair(Box::pin(peer.login()), Box::pin(ManagedOAuthSession::authorize(
                &cx, peer.client(), OAuthSessionPolicy::default(), browser,
            ))).await;
            let session = login.unwrap();
            let capabilities: ClientCapabilities = serde_json::from_value(json!({"roots":{}})).unwrap();
            let timeout = if matches!(case, Case::Timeout) { Duration::from_secs(2) } else { Duration::from_secs(15) };
            let limits = ManagedTasksLimits::new(65536, 65536, 16, timeout).unwrap();
            let client = ManagedTasksClient::new(session.clone(), FinalRequestMeta::new(capabilities), limits).unwrap();
            let mut owner = client.prepare_tool_submission(ids(1), "echo".to_owned(), Some(arguments()),
                ManagedTaskInteractionPolicy::new(4, 8, 16).unwrap()).unwrap();
            assert_eq!(owner.state(), TaskSubmissionState::Prepared);
            assert!(!format!("{owner:?}").contains("host-choice"));
            peer.quiet();
            let cancellation = McpRequestCancellation::new();
            if matches!(case, Case::CancelBefore) {
                cancellation.cancel();
                assert!(matches!(owner.send_with_cancellation(&cx, &cancellation).await,
                    Err(ManagedTaskSubmissionError::NotDispatched(_))));
                assert_eq!(owner.state(), TaskSubmissionState::NotDispatched);
                assert!(matches!(owner.send(&cx).await, Err(ManagedTaskSubmissionError::InvalidState)));
                assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
                assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
                assert!(cx.checkpoint().is_ok());
                peer.quiet();
                session.close();
                return;
            }
            let effects = Cell::new(0_usize);
            let (entered_tx, mut entered_rx) = oneshot::channel::<()>();
            let server = Box::pin(async {
                if matches!(case, Case::DiscoveryLost | Case::DropDiscovery) {
                    let (tls, bytes) = peer.request(false).await;
                    let discovery: Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(discovery["id"], 1);
                    assert_eq!(discovery["method"], "server/discover");
                    if matches!(case, Case::DropDiscovery) {
                        entered_tx.send(&cx, ()).unwrap();
                        require_client_close(tls).await;
                    } else { lose_body(tls).await; }
                    return None;
                }
                let discovery = peer.response(1, if matches!(case, Case::Refused) { NO_TASKS } else { DISCOVER }).await;
                assert_eq!(discovery["method"], "server/discover");
                if matches!(case, Case::Refused) { return None; }
                let mut tls = tool(&peer, 2, &discovery, false).await;
                effects.set(effects.get() + 1); // peer accepted the tool BEFORE choosing its reply fate
                match case {
                    Case::HeaderLost => {},
                    Case::BodyLost => lose_body(tls).await,
                    Case::CancelAfter | Case::DropSend => {
                        entered_tx.send(&cx, ()).unwrap();
                        require_client_close(tls).await;
                    }
                    Case::Timeout => require_client_close(tls).await,
                    Case::DropRead => {
                        sse_head(&mut tls).await;
                        tls.flush().await.unwrap();
                        return Some(tls);
                    }
                    Case::Task => {
                        sse_head(&mut tls).await;
                        event(&mut tls, CHANGED, false).await;
                        event(&mut tls, &terminal(2, TASK), true).await;
                    }
                    Case::Trailing => {
                        sse_head(&mut tls).await;
                        event(&mut tls, &terminal(2, TASK), false).await;
                        event(&mut tls, CHANGED, true).await;
                    }
                    Case::Complete => json_reply(&mut tls, &terminal(2, COMPLETE)).await,
                    Case::Continue | Case::ContinueLost | Case::CloseInput => json_reply(&mut tls, &terminal(2, FIRST)).await,
                    _ => unreachable!(),
                }
                None
            });
            let sending = Box::pin(async {
                let mut send = Box::pin(owner.send_with_cancellation(&cx, &cancellation));
                if matches!(case, Case::DropDiscovery | Case::DropSend) {
                    let mut arrived = Box::pin(entered_rx.recv(&cx));
                    poll_fn(|task| {
                        assert!(send.as_mut().poll(task).is_pending(), "peer is withholding its response");
                        match arrived.as_mut().poll(task) {
                            Poll::Ready(received) => { received.unwrap(); Poll::Ready(()) }
                            Poll::Pending => Poll::Pending,
                        }
                    }).await;
                    drop(send);
                    None
                } else if matches!(case, Case::CancelAfter) {
                    let cancel = Box::pin(async {
                        entered_rx.recv(&cx).await.unwrap();
                        cancellation.cancel();
                    });
                    let (result, ()) = pair(send, cancel).await;
                    Some(result)
                } else { Some(send.await) }
            });
            let (held_stream, sent) = pair(server, sending).await;
            match case {
                Case::DiscoveryLost | Case::Refused => {
                    assert!(matches!(sent.unwrap(), Err(ManagedTaskSubmissionError::NotDispatched(_))));
                    assert_eq!(owner.state(), TaskSubmissionState::NotDispatched);
                    assert!(matches!(owner.send(&cx).await, Err(ManagedTaskSubmissionError::InvalidState)));
                }
                Case::DropDiscovery => {
                    assert!(sent.is_none());
                    assert_eq!(owner.state(), TaskSubmissionState::NotDispatched);
                    assert!(matches!(owner.send(&cx).await, Err(ManagedTaskSubmissionError::InvalidState)));
                }
                Case::HeaderLost | Case::CancelAfter | Case::Timeout => {
                    let error = sent.unwrap().err().unwrap();
                    assert!(error.cause().is_some());
                    assert!(!format!("{error:?}").contains("host-choice"));
                    assert!(matches!(error, ManagedTaskSubmissionError::TaskCreationDeliveryUnknown(_)));
                    reject_replay(&mut owner, &cx).await;
                }
                Case::DropSend => {
                    assert!(sent.is_none());
                    reject_replay(&mut owner, &cx).await;
                }
                Case::DropRead => {
                    sent.unwrap().unwrap();
                    assert_eq!(owner.state(), TaskSubmissionState::AwaitingResponse);
                    drop(Box::pin(owner.next_event(&cx))); // no poll: response custody is unchanged
                    assert_eq!(owner.state(), TaskSubmissionState::AwaitingResponse);
                    let mut reading = Box::pin(owner.next_event(&cx));
                    poll_fn(|task| {
                        assert!(reading.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    }).await;
                    drop(reading);
                    require_client_close(held_stream.unwrap()).await;
                    reject_replay(&mut owner, &cx).await;
                }
                Case::BodyLost | Case::Trailing => {
                    sent.unwrap().unwrap();
                    let error = owner.next_event(&cx).await.err().unwrap();
                    assert!(matches!(error, ManagedTaskSubmissionError::TaskCreationDeliveryUnknown(_)));
                    reject_replay(&mut owner, &cx).await;
                }
                Case::Task | Case::Complete => {
                    sent.unwrap().unwrap();
                    if matches!(case, Case::Task) {
                        assert!(matches!(owner.next_event(&cx).await.unwrap(), Some(ManagedTaskInteractionEvent::Notification(_))));
                        assert_eq!(owner.state(), TaskSubmissionState::AwaitingResponse);
                    }
                    let Some(ManagedTaskInteractionEvent::Result(result)) = owner.next_event(&cx).await.unwrap() else { panic!("validated result required") };
                    match case {
                        Case::Task => {
                            assert!(matches!(*result, FinalCoreResult::ToolsCallTask { .. }));
                            assert!(result.encode().unwrap().contains("actual-peer-task"));
                        }
                        Case::Complete => {
                            assert!(matches!(*result, FinalCoreResult::ToolsCall { .. }));
                            let encoded = result.encode().unwrap();
                            assert!(encoded.contains("1.20e+4"));
                            assert_eq!(serde_json::from_str::<Value>(&encoded).unwrap()["isError"], true);
                        }
                        _ => unreachable!(),
                    }
                    assert_eq!(owner.state(), TaskSubmissionState::Resolved);
                    assert!(owner.next_event(&cx).await.unwrap().is_none());
                    assert!(matches!(owner.send(&cx).await, Err(ManagedTaskSubmissionError::InvalidState)));
                }
                Case::Continue | Case::ContinueLost | Case::CloseInput => {
                    sent.unwrap().unwrap();
                    assert!(matches!(owner.next_event(&cx).await.unwrap(), Some(ManagedTaskInteractionEvent::InputRequired(_))));
                    assert_eq!(owner.state(), TaskSubmissionState::AwaitingInput);
                    assert!(matches!(owner.next_event(&cx).await, Err(ManagedTaskSubmissionError::InputPending)));
                    assert!(matches!(owner.send(&cx).await, Err(ManagedTaskSubmissionError::InvalidState)));
                    if matches!(case, Case::CloseInput) {
                        owner.close();
                        assert_eq!(owner.state(), TaskSubmissionState::Closed);
                        assert!(matches!(owner.next_event(&cx).await, Err(ManagedTaskSubmissionError::InvalidState)));
                    } else {
                        // Invalid local answers and reused correlation IDs must
                        // not spend the challenge, IDs or an additional POST.
                        assert!(matches!(owner.resume(&cx, ids(3), Some(serde_json::from_value(json!({})).unwrap())).await,
                            Err(ManagedTaskSubmissionError::NotDispatched(_))));
                        assert!(matches!(owner.resume(&cx, ids(1), Some(answers("first"))).await,
                            Err(ManagedTaskSubmissionError::NotDispatched(_))));
                        assert_eq!(owner.state(), TaskSubmissionState::AwaitingInput);
                        assert_eq!(owner.request_id(), &RequestId::Number(2));
                        assert_eq!(owner.pending_input().unwrap().request_state(), Some("  sealed+/%\0  "));
                        peer.quiet();
                        let continuation = Box::pin(async {
                            let discovery = peer.response(3, DISCOVER).await;
                            assert_eq!(discovery["method"], "server/discover");
                            assert!(discovery["params"].get("requestState").is_none());
                            assert!(discovery["params"].get("inputResponses").is_none());
                            let mut tls = tool(&peer, 4, &discovery, true).await;
                            effects.set(effects.get() + 1);
                            if matches!(case, Case::Continue) { json_reply(&mut tls, &terminal(4, TASK)).await; }
                        });
                        let ((), resumed) = pair(continuation, Box::pin(owner.resume(&cx, ids(3), Some(answers("first"))))).await;
                        assert_eq!(owner.request_id(), &RequestId::Number(4));
                        if matches!(case, Case::ContinueLost) {
                            assert!(matches!(resumed, Err(ManagedTaskSubmissionError::TaskCreationDeliveryUnknown(_))));
                            reject_replay(&mut owner, &cx).await;
                        } else {
                            resumed.unwrap();
                            let Some(ManagedTaskInteractionEvent::Result(result)) = owner.next_event(&cx).await.unwrap() else { panic!("Task after input") };
                            assert!(matches!(*result, FinalCoreResult::ToolsCallTask { .. }));
                            assert_eq!(owner.state(), TaskSubmissionState::Resolved);
                            assert!(owner.next_event(&cx).await.unwrap().is_none());
                        }
                    }
                }
                Case::CancelBefore => unreachable!(),
            }
            let before_tool = matches!(case, Case::DiscoveryLost | Case::Refused | Case::DropDiscovery);
            let continued = matches!(case, Case::Continue | Case::ContinueLost);
            assert_eq!(effects.get(), if before_tool { 0 } else if continued { 2 } else { 1 });
            assert_eq!(peer.posts.load(Ordering::SeqCst), if before_tool { 1 } else if continued { 4 } else { 2 });
            assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
            assert_eq!(cancellation.is_cancel_requested(), matches!(case, Case::CancelAfter));
            assert!(cx.checkpoint().is_ok(), "the caller and siblings must stay live");
            peer.quiet();
            owner.close();
            session.close();
        });
        Box::pin(asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario)).await
            .expect("Task submission fixture must settle within its bound");
    }));
}

#[test]
fn admitted_task_is_delivered_after_incremental_notifications() {
    isolated("admitted_task_is_delivered_after_incremental_notifications", Case::Task);
}
#[test]
fn ordinary_tool_error_result_is_not_promoted_to_a_task() {
    isolated("ordinary_tool_error_result_is_not_promoted_to_a_task", Case::Complete);
}
#[test]
fn valid_continuation_can_create_a_task_after_correctable_local_refusals() {
    isolated("valid_continuation_can_create_a_task_after_correctable_local_refusals", Case::Continue);
}
#[test]
fn lost_continuation_reply_is_unknown_and_never_replayed() {
    isolated("lost_continuation_reply_is_unknown_and_never_replayed", Case::ContinueLost);
}
#[test]
fn lost_discovery_reply_is_not_mistaken_for_a_dispatched_tool() {
    isolated("lost_discovery_reply_is_not_mistaken_for_a_dispatched_tool", Case::DiscoveryLost);
}
#[test]
fn missing_tasks_capability_prevents_tool_dispatch() {
    isolated("missing_tasks_capability_prevents_tool_dispatch", Case::Refused);
}
#[test]
fn lost_response_head_after_tool_acceptance_preserves_uncertainty() {
    isolated("lost_response_head_after_tool_acceptance_preserves_uncertainty", Case::HeaderLost);
}
#[test]
fn lost_response_body_cannot_report_a_safe_retry() {
    isolated("lost_response_body_cannot_report_a_safe_retry", Case::BodyLost);
}
#[test]
fn trailing_sse_activity_withholds_the_provisional_task() {
    isolated("trailing_sse_activity_withholds_the_provisional_task", Case::Trailing);
}
#[test]
fn cancellation_before_send_has_zero_mcp_effects() {
    isolated("cancellation_before_send_has_zero_mcp_effects", Case::CancelBefore);
}
#[test]
fn cancellation_after_tool_acceptance_does_not_claim_rollback() {
    isolated("cancellation_after_tool_acceptance_does_not_claim_rollback", Case::CancelAfter);
}
#[test]
fn dropped_discovery_future_retains_not_dispatched_state() {
    isolated("dropped_discovery_future_retains_not_dispatched_state", Case::DropDiscovery);
}
#[test]
fn dropped_tool_send_retains_unknown_state_and_closes_its_socket() {
    isolated("dropped_tool_send_retains_unknown_state_and_closes_its_socket", Case::DropSend);
}
#[test]
fn only_a_polled_abandoned_read_consumes_response_custody() {
    isolated("only_a_polled_abandoned_read_consumes_response_custody", Case::DropRead);
}
#[test]
fn closing_pending_input_is_not_successful_eof() {
    isolated("closing_pending_input_is_not_successful_eof", Case::CloseInput);
}
#[test]
fn tool_response_deadline_preserves_unknown_delivery() {
    isolated("tool_response_deadline_preserves_unknown_delivery", Case::Timeout);
}
