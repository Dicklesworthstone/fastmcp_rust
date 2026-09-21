//! Real login, catalog admission and native secured MRTR through the public
//! ManagedOAuthProvider's returned ToolHandler. No private backend injection.
//! This is a local TLS/issuer composition test, not external interoperability
//! or a downstream HTTP listener test. The parent isolates fixture trust and
//! bounds every child process and caller-owned runtime.

use super::*;
use fastmcp_client::http_auth::rpc::catalog::ManagedCatalogLimits;
use fastmcp_core::McpErrorCode;
use fastmcp_server::providers::managed_oauth::ManagedOAuthProvider;
use fastmcp_server::providers::managed_oauth::interaction::{
    ManagedOAuthInputCapabilities, ManagedOAuthInputHandler, ManagedOAuthInputPolicy,
};

#[derive(Clone, Copy, Debug)]
pub(super) enum Case {
    Complete,
    Decline,
    Unadvertised,
    Cancel,
    RoundLimit,
    LostReply,
    DefaultProvider,
    InvalidAnswers,
}

struct Host {
    case: Case,
    calls: AtomicUsize,
    answers: AtomicUsize,
}

impl ManagedOAuthInputHandler for Host {
    fn resolve<'a>(
        &'a self,
        ctx: &'a McpContext,
        cx: &'a Cx,
        input: Box<InputRequiredResult>,
    ) -> BoxFuture<'a, McpResult<Option<FinalInputResponses>>> {
        // Count construction, not just polling: a rejected challenge must not
        // invoke even this synchronous portion of the application's callback.
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            cx.checkpoint().map_err(|_| McpError::request_cancelled())?;
            ctx.checkpoint()?;
            assert_eq!(input.input_requests().unwrap().members().len(), 2);
            let state = input.request_state().expect("native server seals continuation state");
            assert!(!state.is_empty());
            assert_ne!(state, "handler-private-state");
            match self.case {
                Case::Decline => return Err(McpError::invalid_params("PRIVATE-INPUT-DECLINE")),
                Case::Cancel => {
                    ctx.request_cancellation().cancel();
                    // Even a ready, well-typed answer must not cross cancellation.
                    return Ok(Some(answers(&["left", "right"], &self.answers)));
                }
                Case::InvalidAnswers => {
                    return Ok(Some(answers(&["unrequested"], &self.answers)));
                }
                _ => {}
            }
            Ok(Some(answers(&["left", "right"], &self.answers)))
        })
    }
}

pub(super) async fn scenario(cx: Cx, case: Case) {
    let peer = Peer::new(&cx, true).await;
    let ((), session) = pair(
        peer.login(),
        ManagedOAuthSession::authorize(&cx, peer.client(), OAuthSessionPolicy::default(), browser),
    ).await;
    let session = session.unwrap();
    let host = Arc::new(Host { case, calls: AtomicUsize::new(0), answers: AtomicUsize::new(0) });
    let capabilities = ManagedOAuthInputCapabilities {
        roots: !matches!(case, Case::Unadvertised),
        ..Default::default()
    };
    let input_policy = ManagedOAuthInputPolicy::new(
        capabilities, usize::from(!matches!(case, Case::RoundLimit)), 2,
    ).unwrap();
    let provider = ManagedOAuthProvider::new(session.clone()).with_namespace("remote").unwrap();
    let provider = if matches!(case, Case::DefaultProvider) {
        provider
    } else {
        provider.with_input_handler(input_policy, host.clone())
    };
    // This setter must retain the chosen backend, not silently reinstall the
    // default single-POST backend and make every interaction fail.
    let provider = provider.with_limits(
        ManagedCoreLimits::new(4096, 4096, 65536, 0, Duration::from_secs(10)).unwrap(),
        ManagedCatalogLimits::default(),
    );
    let (catalog, tools) = pair(peer.dispatch(&cx, Delivery::Complete), provider.tools(&cx)).await;
    assert!(catalog.get("error").is_none(), "native catalog must succeed: {catalog}");
    let tool = tools.unwrap().into_iter()
        .find(|tool| tool.catalog_definition().name == "remote/checkout")
        .expect("the authenticated catalog yields the namespaced real tool");
    assert!(!tool.declares_final_mrtr(), "resolution is local, not a downstream MRTR relay");
    let transforms_before = peer.probe.transforms.load(Ordering::SeqCst);
    let ctx = McpContext::new(cx.clone(), 700);
    let arguments = json!({"quantity":7, "_meta":{"application-data":"unchanged"}});
    let second_post = matches!(case, Case::Complete | Case::LostReply);
    let server = async {
        let first = peer.dispatch(&cx, Delivery::Complete).await;
        // An unadvertised challenge can be rejected by native server emission
        // or managed-client admission. In both cases no host action is allowed.
        if !matches!(case, Case::Unadvertised | Case::DefaultProvider) {
            assert_eq!(first["result"]["resultType"], "input_required", "{case:?}: {first}");
        }
        let second = if second_post {
            let delivery = if matches!(case, Case::LostReply) { Delivery::LoseHead } else { Delivery::Complete };
            let response = peer.dispatch(&cx, delivery).await;
            assert!(response.get("error").is_none(), "continuation must execute before delivery: {response}");
            Some(response)
        } else {
            None
        };
        (first, second)
    };
    let ((first, second), result) = pair(
        server,
        tool.call_final_outcome_async_in_request(&ctx, &cx, arguments.clone()),
    ).await;
    match (case, result) {
        (Case::Complete, Outcome::Ok(FinalToolOutcome::Complete(result))) => {
            let structured = result.payload.structured_content.as_ref().unwrap();
            assert_eq!(structured["quantity"], 7);
            assert_eq!(structured["effect"], 1);
            assert_eq!(structured["left"]["roots"][0]["uri"], "file:///left/approved");
            assert_eq!(structured["right"]["roots"][0]["uri"], "file:///right/approved");
            assert_eq!(structured["order"], json!(["left", "right"]));
            assert_eq!(structured, &second.as_ref().unwrap()["result"]["structuredContent"]);
            assert!(!result.payload.is_error);
        }
        (Case::Complete, _) => panic!("host-approved public provider call must complete"),
        (_, Outcome::Err(error)) => {
            let diagnostic = error.to_string();
            assert!(!diagnostic.contains("PRIVATE-INPUT-DECLINE"));
            assert!(!diagnostic.contains(&peer.token));
            if matches!(case, Case::Cancel) {
                assert_eq!(error.code, McpErrorCode::RequestCancelled);
            }
        }
        _ => panic!("{case:?}: refusal or transport loss must not publish a successful tool result"),
    }
    let expected_callbacks = usize::from(!matches!(
        case, Case::Unadvertised | Case::RoundLimit | Case::DefaultProvider,
    ));
    assert_eq!(host.calls.load(Ordering::SeqCst), expected_callbacks);
    assert_eq!(host.answers.load(Ordering::SeqCst), match case {
        Case::Complete | Case::LostReply | Case::Cancel => 2,
        Case::InvalidAnswers => 1,
        _ => 0,
    });
    assert_eq!(peer.probe.effects.load(Ordering::SeqCst), usize::from(second_post));
    assert_eq!(peer.probe.transforms.load(Ordering::SeqCst), transforms_before + usize::from(second_post));
    if !matches!(case, Case::Unadvertised | Case::DefaultProvider) {
        assert_eq!(peer.probe.starts.load(Ordering::SeqCst), 1);
    }
    // Request cancellation is independent of the caller's runtime context.
    assert!(!cx.is_cancel_requested());
    let requests = peer.seen.lock().unwrap();
    assert_eq!(requests.len(), 2 + usize::from(second_post));
    assert_eq!(requests[0]["method"], "tools/list");
    assert_eq!(requests[0]["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"], json!({}));
    assert_eq!(requests[1]["method"], "tools/call");
    assert_eq!(requests[1]["params"]["name"], "checkout");
    assert_eq!(requests[1]["params"]["arguments"], arguments);
    assert!(requests[1]["params"].get("inputResponses").is_none());
    assert!(requests[1]["params"].get("requestState").is_none());
    let expected_capabilities = if matches!(case, Case::Unadvertised | Case::DefaultProvider) {
        json!({})
    } else {
        json!({"roots":{}})
    };
    assert_eq!(requests[1]["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"], expected_capabilities);
    if second_post {
        assert_eq!(requests[2]["params"]["arguments"], arguments);
        assert_eq!(requests[2]["params"]["requestState"], first["result"]["requestState"]);
        assert_eq!(requests[2]["params"]["inputResponses"].as_object().unwrap().len(), 2);
        let mut continuation = requests[2]["params"].clone();
        continuation.as_object_mut().unwrap().remove("requestState");
        continuation.as_object_mut().unwrap().remove("inputResponses");
        assert_eq!(continuation, requests[1]["params"], "no identity, capability, route or argument substitution");
    }
    for (index, request) in requests.iter().enumerate() {
        let id: RequestId = serde_json::from_value(request["id"].clone()).unwrap();
        for previous in &requests[..index] {
            let previous: RequestId = serde_json::from_value(previous["id"].clone()).unwrap();
            assert!(!id.correlates_with(&previous));
        }
    }
    drop(requests);
    peer.quiet();
    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
    session.close();
    peer.journal.close().unwrap();
}

#[test]
fn public_provider_resolves_native_input_and_retains_the_original_call() {
    isolated("managed_provider::public_provider_resolves_native_input_and_retains_the_original_call", super::Case::Provider(Case::Complete));
}
#[test]
fn public_provider_host_decline_never_posts_a_continuation() {
    isolated("managed_provider::public_provider_host_decline_never_posts_a_continuation", super::Case::Provider(Case::Decline));
}
#[test]
fn public_provider_unadvertised_input_never_invokes_the_host() {
    isolated("managed_provider::public_provider_unadvertised_input_never_invokes_the_host", super::Case::Provider(Case::Unadvertised));
}
#[test]
fn public_provider_cancelled_host_answer_never_reaches_the_server() {
    isolated("managed_provider::public_provider_cancelled_host_answer_never_reaches_the_server", super::Case::Provider(Case::Cancel));
}
#[test]
fn public_provider_zero_round_budget_rejects_before_host_work() {
    isolated("managed_provider::public_provider_zero_round_budget_rejects_before_host_work", super::Case::Provider(Case::RoundLimit));
}
#[test]
fn public_provider_lost_terminal_reply_does_not_reexecute_or_reresolve() {
    isolated("managed_provider::public_provider_lost_terminal_reply_does_not_reexecute_or_reresolve", super::Case::Provider(Case::LostReply));
}
#[test]
fn public_provider_defaults_do_not_enable_input_resolution() {
    isolated("managed_provider::public_provider_defaults_do_not_enable_input_resolution", super::Case::Provider(Case::DefaultProvider));
}
#[test]
fn public_provider_wrong_answer_key_never_posts_a_continuation() {
    isolated("managed_provider::public_provider_wrong_answer_key_never_posts_a_continuation", super::Case::Provider(Case::InvalidAnswers));
}
