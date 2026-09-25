//! Real OAuth/TLS coverage for the header-repair-to-MRTR ownership handoff.
//! The peer scripts a trusted pre-dispatch rejection; it does not prove the
//! native server's rejection contract. No fixture changes the client verifier.

use super::*;
use std::cell::Cell;
use std::sync::Arc;
use fastmcp_client::http_auth::rpc::interaction::{
    ManagedInputReply, ManagedInteractionError, ManagedInteractionEvent,
};
use fastmcp_client::http_auth::rpc::tool_headers::repair::interaction::{
    ToolHeaderInteractionError, ToolHeaderInteractionLimits, ToolHeaderInteractionOutcome,
};
use fastmcp_protocol::FinalInputResponses;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InteractionCase {
    Full, Partial, StateOnly, Fresh, Drive, DrivePartial, IdHistory, InvalidAnswers,
    ZeroRounds, InputLimit, Unadvertised, CancelBeforeRefresh, CancelRead, DropRead,
    LostContinuation, RejectedContinuation, RejectedRepair, ByteBudget,
}

fn isolated_interaction(name: &str, case: InteractionCase) {
    if let Ok(selected) = std::env::var(CHILD) {
        assert_eq!(selected, name);
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                asupersync::time::timeout(cx.now(), Duration::from_secs(20), Box::pin(scenario(&cx, case)))
                    .await.expect("bounded repair interaction exchange");
            });
        return;
    }
    struct Child(std::process::Child);
    impl Drop for Child { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    // This fixture creates, owns and removes only its own test trust file.
    struct Root(std::path::PathBuf);
    impl Drop for Root { fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); } }
    let root = Root(std::env::temp_dir().join(format!("fastmcp-repair-interaction-{}-{name}.pem", std::process::id())));
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&root.0).unwrap();
    file.write_all(ROOT).unwrap();
    drop(file);
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name).env("SSL_CERT_FILE", &root.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() { assert!(status.success(), "{case:?}"); return; }
        assert!(Instant::now() < deadline, "repair interaction child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn partial(case: InteractionCase) -> bool {
    matches!(case, InteractionCase::Partial | InteractionCase::DrivePartial)
}
fn two_rounds(case: InteractionCase) -> bool { partial(case) || case == InteractionCase::ByteBudget }
fn state(case: InteractionCase, round: usize) -> &'static str {
    if case == InteractionCase::StateOnly { "" }
    else if round == 0 { "  state-one\0  " }
    else { "state-two" }
}
fn answers(case: InteractionCase, round: usize) -> Option<FinalInputResponses> {
    if case == InteractionCase::StateOnly { return None; }
    let value = if partial(case) {
        if round == 0 { json!({"left":{"roots":[]}}) } else { json!({"right":{"roots":[]}}) }
    } else { json!({"left":{"roots":[]},"right":{"roots":[]}}) };
    Some(serde_json::from_value(value).unwrap())
}
fn challenge(case: InteractionCase, round: usize, id: i64) -> String {
    let mut result = json!({"resultType":"input_required","requestState":state(case, round)});
    if case != InteractionCase::StateOnly {
        result["inputRequests"] = if partial(case) && round == 1 {
            json!({"right":{"method":"roots/list"}})
        } else { json!({"left":{"method":"roots/list"},"right":{"method":"roots/list"}}) };
    }
    if case == InteractionCase::ByteBudget { result["x-padding"] = json!("x".repeat(700)); }
    let wire = json!({"jsonrpc":"2.0","id":id,"result":result}).to_string();
    if case == InteractionCase::ByteBudget { assert!(wire.len() <= 1024); }
    wire
}
fn final_reply(case: InteractionCase, id: i64) -> String {
    if case == InteractionCase::ByteBudget {
        let wire = json!({"jsonrpc":"2.0","id":id,"result":{
            "resultType":"complete","content":[],"x-padding":"x".repeat(700)
        }}).to_string();
        assert!(wire.len() <= 1024);
        wire
    } else { complete(id) }
}

async fn refreshed(peer: &Peer, capabilities: &Value, case: InteractionCase) {
    let mut catalog_bytes = 0;
    for page in 0..2 {
        let (mut socket, request) = peer.rpc("tools/list", 11 + page, None).await;
        assert_eq!(request["params"]["_meta"], json!({
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":capabilities
        }));
        if page == 0 { assert!(request["params"].get("cursor").is_none()); }
        else { assert_eq!(request["params"]["cursor"], "interaction-page-two"); }
        let tools = if page == 0 { vec![definition("lookup", "Fresh")] }
            else { vec![definition("other", "Unused")] };
        let mut result = json!({"resultType":"complete","tools":tools,"ttlMs":0,"cacheScope":"private"});
        if page == 0 { result["nextCursor"] = json!("interaction-page-two"); }
        let body = json!({"jsonrpc":"2.0","id":11+page,"result":result}).to_string();
        catalog_bytes += body.len();
        reply(&mut socket, 200, "application/json", &body, false).await;
    }
    if case == InteractionCase::ByteBudget { assert!(catalog_bytes <= 1024); }
    let (mut socket, _) = peer.rpc("tools/call", 13, Some("mcp-param-fresh")).await;
    if case == InteractionCase::RejectedRepair {
        reply(&mut socket, 400, "application/json", &error(13, -32020), false).await;
    } else { reply(&mut socket, 200, "application/json", &challenge(case, 0, 13), false).await; }
}

async fn continuation(peer: &Peer, original: &Value, case: InteractionCase, round: usize)
    -> Option<TlsStream<TcpStream>>
{
    let id = 14 + round as i64;
    let header = if case == InteractionCase::Fresh { "mcp-param-old" } else { "mcp-param-fresh" };
    let (mut socket, request) = peer.rpc("tools/call", id, Some(header)).await;
    let mut expected = original.clone();
    expected["requestState"] = json!(state(case, round));
    if let Some(answers) = answers(case, round) {
        expected["inputResponses"] = serde_json::to_value(answers).unwrap();
    }
    assert_eq!(request["params"], expected, "only current state and correlated answers may change");
    if case == InteractionCase::LostContinuation { return None; }
    if case == InteractionCase::RejectedContinuation {
        reply(&mut socket, 400, "application/json", &error(id, -32020), false).await;
    } else if matches!(case, InteractionCase::CancelRead | InteractionCase::DropRead) {
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{").await.unwrap();
        socket.flush().await.unwrap();
        return Some(socket);
    } else {
        let body = if two_rounds(case) && round == 0 { challenge(case, 1, id) }
            else { final_reply(case, id) };
        reply(&mut socket, 200, "application/json", &body, false).await;
    }
    None
}
async fn closed(socket: &mut TlsStream<TcpStream>) {
    let mut byte = [0];
    assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0), "owned response must close");
}

async fn scenario(cx: &Cx, case: InteractionCase) {
    let peer = Peer::new().await;
    let ((), session) = pair(peer.login(), ManagedOAuthSession::authorize(cx, peer.client(), OAuthSessionPolicy::default(), browser)).await;
    let session = session.unwrap();
    let cancelled = McpRequestCancellation::new();
    let mut original = core("tools/call", json!({"name":"lookup","arguments":{
        "region":"雪","verbose":null,"private":"body-only"
    }})).encode_params().unwrap().unwrap();
    let capabilities = if case == InteractionCase::Unadvertised { json!({}) } else { json!({"roots":{}}) };
    original["_meta"]["io.modelcontextprotocol/clientCapabilities"] = capabilities.clone();
    let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&original)).unwrap();
    assert_eq!(request.encode_params().unwrap().unwrap(), original);
    let reviewed = Arc::new(ReviewedToolHeaders::new(peer.resource(), "lookup", definition("lookup", "Old").input_schema, |_| true).unwrap());
    let core_limits = if case == InteractionCase::ByteBudget {
        ManagedCoreLimits::new(4096, 1024, 3072, 0, Duration::from_secs(10)).unwrap()
    } else { ManagedCoreLimits::new(4096, 4096, 65536, 0, Duration::from_secs(10)).unwrap() };
    let repair = ToolHeaderRepairLimits::new(core_limits,
        if case == InteractionCase::ByteBudget { 1024 } else { 16384 }, 4, 8).unwrap();
    let limits = ToolHeaderInteractionLimits::new(repair,
        if case == InteractionCase::ZeroRounds { 0 } else { 4 },
        if case == InteractionCase::InputLimit { 1 } else { 8 }).unwrap();
    let initial = session.start_tool_interaction_with_header_repair_and_cancellation(
        cx, &cancelled, request, RequestId::Number(10), reviewed,
        ToolHeaderRepairContract::for_configured_endpoint(peer.resource()).unwrap(), limits,
    );
    let first_peer = async {
        if case == InteractionCase::Fresh {
            let (mut socket, _) = peer.rpc("tools/call", 10, Some("mcp-param-old")).await;
            reply(&mut socket, 200, "application/json", &challenge(case, 0, 10), false).await;
        } else { peer.first(Case::Repair).await; }
    };
    let ((), outcome) = pair(first_peer, initial).await;
    peer.quiet();
    assert_eq!(peer.requests.lock().unwrap().len(), 1, "opening does not automatically refresh or answer");
    let mut expected_posts = 1;
    let mut operation = match outcome.unwrap() {
        ToolHeaderInteractionOutcome::Interaction(operation) => {
            assert_eq!(case, InteractionCase::Fresh);
            Some(*operation)
        }
        ToolHeaderInteractionOutcome::Rejected(rejected) => {
            let ids = Cell::new(11);
            let approvals = Cell::new(0);
            let disclosures = Cell::new(0);
            if case == InteractionCase::CancelBeforeRefresh { cancelled.cancel(); }
            let refresh = (*rejected).refresh_and_start(cx, || {
                let id = ids.get();
                ids.set(id + 1);
                Ok(RequestId::Number(id))
            }, |_| {
                assert_eq!(peer.requests.lock().unwrap().len(), 3, "approve the complete catalog");
                approvals.set(approvals.get() + 1);
                true
            }, |_| { disclosures.set(disclosures.get() + 1); true });
            let server = async {
                if case != InteractionCase::CancelBeforeRefresh { refreshed(&peer, &capabilities, case).await; }
            };
            let ((), outcome) = pair(server, refresh).await;
            if case == InteractionCase::CancelBeforeRefresh {
                assert!(matches!(outcome, Err(ToolHeaderInteractionError::Repair(
                    ToolHeaderRepairError::Core(ManagedCoreError::Cancelled)))));
                assert_eq!(ids.get(), 11);
                assert_eq!(approvals.get(), 0);
                assert_eq!(disclosures.get(), 0);
                None
            } else {
                expected_posts += 3;
                assert_eq!(ids.get(), 14);
                assert_eq!(approvals.get(), 1);
                assert_eq!(disclosures.get(), 2);
                if case == InteractionCase::RejectedRepair {
                    assert!(matches!(outcome, Err(ToolHeaderInteractionError::Repair(
                        ToolHeaderRepairError::Core(ManagedCoreError::HttpStatus { status: 400 })))));
                    None
                } else { Some(outcome.unwrap()) }
            }
        }
    };
    peer.quiet();
    assert_eq!(peer.requests.lock().unwrap().len(), expected_posts, "handoff must not resend the initial call");
    if let Some(mut operation) = operation.take() {
        assert_eq!(operation.continuation_count(), 0, "repair/catalog calls are not input rounds");
        let first = operation.next_event(cx).await;
        match case {
            InteractionCase::ZeroRounds => assert!(matches!(first, Err(ManagedInteractionError::ContinuationLimit))),
            InteractionCase::InputLimit => assert!(matches!(first, Err(ManagedInteractionError::InputLimit))),
            InteractionCase::Unadvertised => assert!(matches!(first, Err(ManagedInteractionError::CapabilityNotAdvertised))),
            _ => {
                assert!(matches!(first.unwrap(), Some(ManagedInteractionEvent::InputRequired(_))));
                assert_eq!(operation.pending_input().unwrap().request_state(), Some(state(case, 0)));
                assert!(matches!(operation.next_event(cx).await, Err(ManagedInteractionError::InputPending)));
                if case == InteractionCase::IdHistory {
                    for id in [10, 11, 12, 13] {
                        assert!(matches!(operation.resume(cx, RequestId::Number(id), answers(case, 0)).await,
                            Err(ManagedInteractionError::RepeatedRequestId)));
                        assert!(operation.pending_input().is_some());
                        assert_eq!(operation.continuation_count(), 0);
                        peer.quiet();
                    }
                }
                if case == InteractionCase::InvalidAnswers {
                    let wrong = serde_json::from_value(json!({"foreign":{"roots":[]}})).unwrap();
                    assert!(matches!(operation.resume(cx, RequestId::Number(14), Some(wrong)).await,
                        Err(ManagedInteractionError::InvalidInputResponses)));
                    assert!(operation.pending_input().is_some());
                    assert_eq!(operation.continuation_count(), 0);
                    peer.quiet();
                }
                if matches!(case, InteractionCase::Drive | InteractionCase::DrivePartial) {
                    let resolved = Cell::new(0);
                    let resolver = |_| {
                        let round = resolved.get();
                        resolved.set(round + 1);
                        std::future::ready(Ok(ManagedInputReply {
                            request_id: RequestId::Number(14 + round as i64), input_responses: answers(case, round),
                        }))
                    };
                    let server = async {
                        let _ = continuation(&peer, &original, case, 0).await;
                        if two_rounds(case) { let _ = continuation(&peer, &original, case, 1).await; }
                    };
                    let drive = async {
                        if partial(case) { Box::pin(operation.drive_partial(cx, resolver, |_| Ok(()))).await }
                        else { Box::pin(operation.drive(cx, resolver, |_| Ok(()))).await }
                    };
                    let ((), result) = pair(server, drive).await;
                    assert!(result.unwrap().encode().unwrap().contains("1.20e+4"));
                    assert_eq!(resolved.get(), if two_rounds(case) { 2 } else { 1 });
                    expected_posts += resolved.get();
                } else {
                    for round in 0..if two_rounds(case) { 2 } else { 1 } {
                        let resume = async {
                            if partial(case) {
                                operation.resume_partial(cx, RequestId::Number(14 + round as i64), answers(case, round).unwrap()).await
                            } else { operation.resume(cx, RequestId::Number(14 + round as i64), answers(case, round)).await }
                        };
                        let (mut stalled, sent) = pair(continuation(&peer, &original, case, round), resume).await;
                        expected_posts += 1;
                        if case == InteractionCase::LostContinuation {
                            assert!(sent.is_err());
                            assert!(matches!(operation.next_event(cx).await, Err(ManagedInteractionError::Closed)));
                            break;
                        }
                        if case == InteractionCase::RejectedContinuation {
                            assert!(matches!(sent, Err(ManagedInteractionError::Core(ManagedCoreError::HttpStatus { status: 400 }))));
                            assert!(matches!(operation.next_event(cx).await, Err(ManagedInteractionError::Closed)));
                            break;
                        }
                        sent.unwrap();
                        assert_eq!(operation.continuation_count(), round + 1);
                        if let Some(socket) = stalled.as_mut() {
                            let mut read = Box::pin(operation.next_event(cx));
                            poll_fn(|task| { assert!(read.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                            if case == InteractionCase::CancelRead {
                                cancelled.cancel();
                                assert!(matches!(read.await, Err(ManagedInteractionError::Core(ManagedCoreError::Cancelled))));
                            } else {
                                drop(read);
                                assert!(matches!(operation.next_event(cx).await, Err(ManagedInteractionError::Closed)));
                            }
                            closed(socket).await;
                            assert!(operation.pending_input().is_none());
                            break;
                        }
                        let next = operation.next_event(cx).await;
                        if round == 0 && two_rounds(case) {
                            assert!(matches!(next.unwrap(), Some(ManagedInteractionEvent::InputRequired(_))));
                            assert_eq!(operation.pending_input().unwrap().request_state(), Some(state(case, 1)));
                        } else if case == InteractionCase::ByteBudget {
                            assert!(matches!(next, Err(ManagedInteractionError::Core(ManagedCoreError::ResponseByteLimit))));
                            assert!(matches!(operation.next_event(cx).await, Err(ManagedInteractionError::Closed)));
                        } else {
                            let Some(ManagedInteractionEvent::Complete(result)) = next.unwrap() else { panic!("complete interaction result"); };
                            assert!(result.encode().unwrap().contains("1.20e+4"));
                            assert!(operation.next_event(cx).await.unwrap().is_none());
                        }
                    }
                }
            }
        }
    }
    assert_eq!(peer.requests.lock().unwrap().len(), expected_posts);
    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
    peer.quiet();
    assert!(cx.checkpoint().is_ok());
    // Closing/abandoning this operation must leave the shared login usable.
    let server = async {
        let (mut socket, _) = peer.rpc("tools/list", 900, None).await;
        reply(&mut socket, 200, "application/json", &json!({"jsonrpc":"2.0","id":900,"result":{
            "resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"
        }}).to_string(), false).await;
    };
    let sibling = async {
        let mut call = Box::pin(session.request_core(cx, core("tools/list", json!({})),
            RequestId::Number(900), ManagedCoreLimits::default())).await.unwrap();
        assert!(matches!(call.next_event(cx).await.unwrap(), Some(ManagedCoreEvent::Result(_))));
    };
    pair(server, sibling).await;
    assert_eq!(peer.requests.lock().unwrap().len(), expected_posts + 1);
    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
    peer.quiet();
}

macro_rules! interaction_cases {
    ($($name:ident => $case:ident),+ $(,)?) => { $(
        #[test]
        fn $name() { isolated_interaction(concat!("interaction::", stringify!($name)), InteractionCase::$case); }
    )+ };
}
interaction_cases! {
    repaired_call_resumes_with_refreshed_headers => Full,
    repaired_call_supports_partial_answers => Partial,
    repaired_call_preserves_empty_state_without_answers => StateOnly,
    fresh_call_becomes_an_interaction_without_catalog_refresh => Fresh,
    repaired_call_runs_the_existing_complete_input_driver => Drive,
    repaired_call_runs_the_existing_partial_input_driver => DrivePartial,
    repaired_interaction_retains_rejection_catalog_and_retry_ids => IdHistory,
    repaired_interaction_preserves_correctable_input_challenges => InvalidAnswers,
    repaired_interaction_keeps_the_configured_round_limit => ZeroRounds,
    repaired_interaction_keeps_the_configured_input_limit => InputLimit,
    repaired_interaction_refuses_unadvertised_input_before_host_effects => Unadvertised,
    repaired_interaction_cancellation_before_refresh_sends_nothing => CancelBeforeRefresh,
    repaired_interaction_cancellation_closes_a_stalled_read => CancelRead,
    repaired_interaction_abandonment_closes_a_stalled_read => DropRead,
    repaired_interaction_never_replays_a_lost_continuation => LostContinuation,
    repaired_interaction_cannot_repair_a_rejected_continuation => RejectedContinuation,
    second_initial_rejection_never_opens_an_interaction => RejectedRepair,
    repaired_interaction_charges_catalog_bytes_across_all_rounds => ByteBudget,
}
