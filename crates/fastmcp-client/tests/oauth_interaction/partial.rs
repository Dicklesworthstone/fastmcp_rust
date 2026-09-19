//! Actual managed OAuth login and partial MRTR POSTs through the native TLS
//! transport. The peer models continuation replies, not the server router's
//! MRTR registry; these are client wire/lifecycle tests, not server conformance.
use super::*;

const TWO: &str = r#"{"resultType":"input_required","inputRequests":{"one":{"method":"roots/list"},"two":{"method":"roots/list"}},"requestState":"  first+/%\u0000  "}"#;
const REMAINING: &str = r#"{"resultType":"input_required","inputRequests":{"two":{"method":"roots/list"}},"requestState":"next-state"}"#;

#[derive(Clone, Copy)]
enum PartialCase { Manual(&'static str), Drive, LostReply, Cancel, RoundLimit, MissingState }

fn isolated_partial(name: &str, case: PartialCase) {
    if let Ok(selected) = std::env::var(CHILD) {
        assert_eq!(selected, name);
        run_partial(case);
        return;
    }
    let roots = RootFile::create();
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
    }
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit())
        .spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() { assert!(status.success()); return; }
        assert!(Instant::now() < deadline, "partial-input TLS child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_continuation(wire: &Value, original: &Value, state: &str, key: &str) {
    assert_eq!(wire["params"]["requestState"], state);
    assert_eq!(wire["params"]["inputResponses"], json!({key:{"roots":[]}}));
    let mut stable = wire["params"].clone();
    stable.as_object_mut().unwrap().remove("requestState");
    stable.as_object_mut().unwrap().remove("inputResponses");
    assert_eq!(&stable, original, "identity, arguments and capabilities are immutable");
}

fn run_partial(case: PartialCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let scenario = async {
            let peer = Peer::new().await;
            let ((), session) = pair(peer.login(), ManagedOAuthSession::authorize(
                &cx, peer.client(), OAuthSessionPolicy::default(), browser,
            )).await;
            let session = session.unwrap();
            let cancellation = McpRequestCancellation::new();
            let method = match case { PartialCase::Manual(method) => method, _ => "tools/call" };
            let request = core(method, true);
            let original = request.encode_params().unwrap().unwrap();
            let limits = ManagedInteractionLimits::new(
                ManagedCoreLimits::new(4096, 4096, 16384, 4, Duration::from_secs(15)).unwrap(),
                if matches!(case, PartialCase::RoundLimit) { 1 } else { 2 }, 2,
            ).unwrap();
            let mut first: Value = serde_json::from_str(TWO).unwrap();
            if matches!(case, PartialCase::MissingState) { first.as_object_mut().unwrap().remove("requestState"); }
            let first = first.to_string();
            let (_, operation) = pair(peer.response(51, &first), session.start_core_interaction_with_cancellation(
                &cx, &cancellation, request, RequestId::Number(51), limits,
            )).await;
            let mut operation = operation.unwrap();
            pending(&mut operation, &cx).await;
            let expected_posts = match case {
                PartialCase::Manual(_) => {
                    // Every local refusal precedes network work and leaves the
                    // same challenge, request-ID space and continuation budget.
                    assert!(matches!(operation.resume(&cx, RequestId::Number(52), Some(answers("one"))).await,
                        Err(ManagedInteractionError::InvalidInputResponses)));
                    for invalid in [serde_json::from_value(json!({})).unwrap(), answers("foreign"),
                        serde_json::from_value(json!({"one":{"action":"decline"}})).unwrap()]
                    {
                        assert!(matches!(operation.resume_partial(&cx, RequestId::Number(52), invalid).await,
                            Err(ManagedInteractionError::InvalidInputResponses)));
                        assert_eq!(operation.continuation_count(), 0);
                        assert_eq!(operation.pending_input().unwrap().input_requests().unwrap().members().len(), 2);
                        peer.quiet();
                    }
                    assert!(matches!(operation.resume_partial(&cx, RequestId::Number(51), answers("one")).await,
                        Err(ManagedInteractionError::RepeatedRequestId)));
                    let (wire, resumed) = pair(peer.response(52, REMAINING),
                        operation.resume_partial(&cx, RequestId::Number(52), answers("one"))).await;
                    resumed.unwrap();
                    assert_continuation(&wire, &original, "  first+/%\0  ", "one");
                    pending(&mut operation, &cx).await;
                    assert!(matches!(operation.resume_partial(&cx, RequestId::Number(53), answers("one")).await,
                        Err(ManagedInteractionError::InvalidInputResponses)));
                    let (wire, resumed) = pair(peer.response(53, complete(method)),
                        operation.resume_partial(&cx, RequestId::Number(53), answers("two"))).await;
                    resumed.unwrap();
                    assert_continuation(&wire, &original, "next-state", "two");
                    finished(&mut operation, &cx).await;
                    assert_eq!(operation.continuation_count(), 2);
                    3
                }
                PartialCase::Drive => {
                    let calls = Cell::new(0);
                    let server = async {
                        let wire = peer.response(52, REMAINING).await;
                        assert_continuation(&wire, &original, "  first+/%\0  ", "one");
                        let wire = peer.response(53, complete(method)).await;
                        assert_continuation(&wire, &original, "next-state", "two");
                    };
                    let driver = operation.drive_partial(&cx, |input| {
                        let round = calls.get();
                        calls.set(round + 1);
                        assert_eq!(input.input_requests().unwrap().members().len(), if round == 0 { 2 } else { 1 });
                        std::future::ready(Ok(ManagedInputReply {
                            request_id: RequestId::Number(52 + round),
                            input_responses: Some(answers(if round == 0 { "one" } else { "two" })),
                        }))
                    }, |_| Ok(()));
                    let ((), result) = pair(server, driver).await;
                    assert!(result.unwrap().encode().unwrap().contains("1.20e+4"));
                    assert_eq!(calls.get(), 2);
                    3
                }
                PartialCase::LostReply => {
                    let server = async {
                        let (tls, bytes) = peer.request(false).await;
                        let wire: Value = serde_json::from_slice(&bytes).unwrap();
                        assert_continuation(&wire, &original, "  first+/%\0  ", "one");
                        drop(tls); // request accepted, no response at all
                    };
                    let ((), outcome) = pair(server,
                        operation.resume_partial(&cx, RequestId::Number(52), answers("one"))).await;
                    if outcome.is_ok() { assert!(operation.next_event(&cx).await.is_err()); }
                    assert!(operation.pending_input().is_none());
                    assert!(matches!(operation.resume_partial(&cx, RequestId::Number(53), answers("one")).await,
                        Err(ManagedInteractionError::Closed)));
                    assert_eq!(operation.continuation_count(), 1);
                    2
                }
                PartialCase::Cancel => {
                    let calls = Cell::new(0);
                    let result = operation.drive_partial(&cx, |_| {
                        calls.set(calls.get() + 1);
                        cancellation.cancel();
                        std::future::ready(Ok(ManagedInputReply {
                            request_id: RequestId::Number(52), input_responses: Some(answers("one")),
                        }))
                    }, |_| Ok(())).await;
                    assert!(matches!(result, Err(ManagedInteractionError::Core(ManagedCoreError::Cancelled))));
                    assert_eq!(calls.get(), 1);
                    1
                }
                PartialCase::RoundLimit => {
                    let (_, resumed) = pair(peer.response(52, REMAINING),
                        operation.resume_partial(&cx, RequestId::Number(52), answers("one"))).await;
                    resumed.unwrap();
                    assert!(matches!(operation.next_event(&cx).await, Err(ManagedInteractionError::ContinuationLimit)));
                    assert!(operation.pending_input().is_none());
                    assert_eq!(operation.continuation_count(), 1);
                    2
                }
                PartialCase::MissingState => {
                    assert!(matches!(operation.resume_partial(&cx, RequestId::Number(52), answers("one")).await,
                        Err(ManagedInteractionError::PartialStateRequired)));
                    peer.quiet();
                    assert_eq!(operation.continuation_count(), 0);
                    // The same ID and challenge remain usable with all answers.
                    let all = serde_json::from_value(json!({"one":{"roots":[]},"two":{"roots":[]}})).unwrap();
                    let (wire, resumed) = pair(peer.response(52, complete(method)),
                        operation.resume_partial(&cx, RequestId::Number(52), all)).await;
                    resumed.unwrap();
                    assert!(wire["params"].get("requestState").is_none());
                    assert_eq!(wire["params"]["inputResponses"].as_object().unwrap().len(), 2);
                    finished(&mut operation, &cx).await;
                    2
                }
            };
            assert_eq!(peer.posts.load(Ordering::SeqCst), expected_posts);
            assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
            peer.quiet();
            session.close();
        };
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario).await.unwrap();
    });
}

#[test]
fn partial_tool_answers_reach_the_wire_without_changing_identity() {
    isolated_partial("driver::partial::partial_tool_answers_reach_the_wire_without_changing_identity", PartialCase::Manual("tools/call"));
}
#[test]
fn partial_resource_answers_reach_the_wire_without_changing_identity() {
    isolated_partial("driver::partial::partial_resource_answers_reach_the_wire_without_changing_identity", PartialCase::Manual("resources/read"));
}
#[test]
fn partial_prompt_answers_reach_the_wire_without_changing_identity() {
    isolated_partial("driver::partial::partial_prompt_answers_reach_the_wire_without_changing_identity", PartialCase::Manual("prompts/get"));
}
#[test]
fn partial_driver_resolves_only_the_answers_its_host_selects() {
    isolated_partial("driver::partial::partial_driver_resolves_only_the_answers_its_host_selects", PartialCase::Drive);
}
#[test]
fn partial_reply_loss_does_not_replay_the_accepted_answer() {
    isolated_partial("driver::partial::partial_reply_loss_does_not_replay_the_accepted_answer", PartialCase::LostReply);
}
#[test]
fn partial_resolver_cancellation_prevents_the_next_post() {
    isolated_partial("driver::partial::partial_resolver_cancellation_prevents_the_next_post", PartialCase::Cancel);
}
#[test]
fn partial_rounds_share_the_original_continuation_budget() {
    isolated_partial("driver::partial::partial_rounds_share_the_original_continuation_budget", PartialCase::RoundLimit);
}
#[test]
fn partial_state_refusal_leaves_the_complete_answer_path_usable() {
    isolated_partial("driver::partial::partial_state_refusal_leaves_the_complete_answer_path_usable", PartialCase::MissingState);
}
