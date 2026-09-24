use super::*;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::{ClientCapabilities, CoreResult, FinalRequestMeta, FINAL_CLIENT_CAPABILITIES_META_KEY};
use crate::http_auth::discovery::client_credentials::{
    ClientCredentialsClient, ClientInner, ClientSecret, MachineAuthentication, TokenState,
};
use super::super::ClientCredentialsTasksLimits;

fn client() -> ClientCredentialsTasksClient {
    let client = ClientCredentialsClient { inner: Arc::new(ClientInner {
        resource: CanonicalHttpUrl::parse("https://machine.example/mcp").unwrap(),
        token_endpoint: CanonicalHttpUrl::parse("https://issuer.example/token").unwrap(),
        client_id: "submission-fixture".to_owned(), scopes: vec![],
        authentication: MachineAuthentication::Basic(Arc::new(ClientSecret("fixture-secret".to_owned()))),
        issuer_roots: vec![], resource_tls: None, timeout: Duration::from_secs(5), maximum_lifetime: Duration::from_secs(600),
        leeway: Duration::from_secs(30), closed: McpRequestCancellation::new(),
        pending: AtomicUsize::new(0), state: Arc::new(asupersync::sync::Mutex::new(TokenState::default())),
    }) };
    let caps: ClientCapabilities = serde_json::from_value(json!({"roots":{}})).unwrap();
    ClientCredentialsTasksClient::new(client, FinalRequestMeta::new(caps), ClientCredentialsTasksLimits::default()).unwrap()
}
fn submission(policy: ClientCredentialsTaskSubmissionPolicy) -> ClientCredentialsTaskSubmission {
    client().prepare_tool_submission(RequestId::Number(1), RequestId::Number(2),
        "compute".to_owned(), Some(json!({"secret-argument":7})), policy).unwrap()
}
fn result(progress: &Progress, wire: Value) -> ManagedTaskEvent {
    let CoreResult::Final(value) = progress.original.decode_result(&wire.to_string()).unwrap() else { unreachable!() };
    ManagedTaskEvent::ToolResult(Box::new(value))
}
fn challenge(state: Option<&str>) -> Value {
    let mut value = json!({"resultType":"input_required", "inputRequests":{
        "one":{"method":"roots/list"},"two":{"method":"roots/list"}
    }});
    if let Some(state) = state { value["requestState"] = json!(state); }
    value
}
fn admit_input(submission: &mut ClientCredentialsTaskSubmission, wire: Value) {
    let progress = submission.progress.as_mut().unwrap();
    let event = result(progress, wire);
    assert!(matches!(progress.admit(event).unwrap(), ClientCredentialsTaskSubmissionEvent::InputRequired(_)));
}
fn answers(value: Value) -> FinalInputResponses { serde_json::from_value(value).unwrap() }
fn pair() -> (RequestId, RequestId) { (RequestId::Number(3), RequestId::Number(4)) }

#[test]
fn preparation_is_local_preserves_arguments_and_installs_no_task_preference() {
    let mut submission = submission(ClientCredentialsTaskSubmissionPolicy::default());
    assert_eq!(submission.state(), TaskSubmissionState::Prepared);
    assert!(submission.credential.is_none() && submission.deadline.is_none() && submission.call.is_none());
    assert!(submission.client.client.inner.state.try_lock_owned().unwrap().current.is_none());
    let wire: Value = serde_json::from_slice(submission.prepared.as_ref().unwrap().operation.wire.body()).unwrap();
    assert_eq!(wire["method"], "tools/call");
    assert_eq!(wire["params"]["arguments"], json!({"secret-argument":7}));
    assert!(wire["params"].get("task").is_none() && wire["params"].get("requestState").is_none());
    assert!(wire["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"].is_object());
    assert!(!format!("{submission:?}").contains("secret-argument"));
    submission.close();
    assert_eq!(submission.state(), TaskSubmissionState::NotDispatched);
    assert!(submission.prepared.is_none() && submission.progress.is_none());
}

#[test]
fn identity_admission_counts_escaped_wire_bytes_and_numeric_aliases() {
    let exact = RequestId::String("x".repeat(MAX_ID_WIRE_BYTES - 2));
    assert!(admit_pair(&(exact, RequestId::Number(2))).is_ok());
    for excessive in ["x".repeat(MAX_ID_WIRE_BYTES - 1), "\n".repeat(MAX_ID_WIRE_BYTES / 2)] {
        assert!(admit_pair(&(RequestId::String(excessive), RequestId::Number(2))).is_err());
    }
    let alias: RequestId = serde_json::from_str("1e0").unwrap();
    assert!(admit_pair(&(RequestId::Number(1), alias)).is_err());
    assert!(admit_pair(&(RequestId::Number(1), RequestId::String("1".to_owned()))).is_ok());
    let client = client();
    assert!(client.prepare_tool_submission(RequestId::Number(1), RequestId::Number(1),
        "compute".to_owned(), None, ClientCredentialsTaskSubmissionPolicy::default()).is_err());
    assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
}

#[test]
fn partial_continuations_preserve_original_authority_and_do_not_accumulate_answers() {
    let mut submission = submission(ClientCredentialsTaskSubmissionPolicy::default());
    admit_input(&mut submission, challenge(Some("  opaque\0  ")));
    let progress = submission.progress.as_mut().unwrap();
    let original = progress.original.encode_params().unwrap().unwrap();
    let (round, count) = progress.prepare_resume(&submission.client, pair(),
        Some(answers(json!({"one":{"roots":[]}}))), InputSelection::Partial).unwrap();
    assert_eq!(count, 1);
    let mut wire: Value = serde_json::from_slice(round.operation.wire.body()).unwrap();
    assert_eq!(wire["params"]["requestState"], "  opaque\0  ");
    assert_eq!(wire["params"]["inputResponses"], json!({"one":{"roots":[]}}));
    wire["params"].as_object_mut().unwrap().remove("requestState");
    wire["params"].as_object_mut().unwrap().remove("inputResponses");
    assert_eq!(wire["params"], original);
    assert!(progress.pending.is_some(), "preparation alone cannot consume the challenge");
    progress.commit_resume(&round.ids, count);
    assert!(progress.pending.is_none());
    assert_eq!((progress.continuations, progress.responses), (1, 1));
    let next = json!({"resultType":"input_required", "inputRequests":{"two":{"method":"roots/list"}}});
    let event = result(progress, next);
    progress.admit(event).unwrap();
    let (round, _) = progress.prepare_resume(&submission.client, (RequestId::Number(5), RequestId::Number(6)),
        Some(answers(json!({"two":{"roots":[]}}))), InputSelection::Complete).unwrap();
    let wire: Value = serde_json::from_slice(round.operation.wire.body()).unwrap();
    assert_eq!(wire["params"]["inputResponses"], json!({"two":{"roots":[]}}));
    assert!(wire["params"].get("requestState").is_none());
    assert_eq!(progress.original.encode_params().unwrap().unwrap(), original);
}

#[test]
fn invalid_answers_and_reused_ids_leave_the_entire_challenge_correctable() {
    let mut submission = submission(ClientCredentialsTaskSubmissionPolicy::default());
    admit_input(&mut submission, challenge(Some("unchanged-state")));
    let progress = submission.progress.as_ref().unwrap();
    let original = progress.original.encode_params().unwrap();
    let ids = progress.used_ids.clone();
    for value in [json!({}), json!({"other":{"roots":[]}}), json!({"one":{"action":"decline"}})] {
        assert!(progress.prepare_resume(&submission.client, pair(), Some(answers(value)), InputSelection::Partial).is_err());
        assert_eq!(progress.pending.as_ref().unwrap().request_state(), Some("unchanged-state"));
        assert_eq!(progress.pending.as_ref().unwrap().input_requests().unwrap().members().len(), 2);
        assert_eq!(progress.used_ids, ids);
        assert_eq!((progress.continuations, progress.responses, progress.records), (0, 0, 1));
        assert_eq!(progress.original.encode_params().unwrap(), original);
    }
    for used in [RequestId::Number(1), serde_json::from_str("2.0").unwrap()] {
        assert!(progress.prepare_resume(&submission.client, (RequestId::Number(3), used),
            Some(answers(json!({"one":{"roots":[]}}))), InputSelection::Partial).is_err());
    }
    assert!(progress.prepare_resume(&submission.client, pair(),
        Some(answers(json!({"one":{"roots":[]},"two":{"roots":[]}}))), InputSelection::Complete).is_ok());
}

#[test]
fn partial_state_absence_and_state_only_rounds_keep_the_shared_mrtr_contract() {
    for state in [None, Some("")] {
        let mut submission = submission(ClientCredentialsTaskSubmissionPolicy::default());
        admit_input(&mut submission, challenge(state));
        let progress = submission.progress.as_ref().unwrap();
        assert!(matches!(progress.prepare_resume(&submission.client, pair(),
            Some(answers(json!({"one":{"roots":[]}}))), InputSelection::Partial),
            Err(ClientCredentialsTaskSubmissionCause::Input(ManagedInteractionError::PartialStateRequired))));
        assert!(progress.prepare_resume(&submission.client, pair(),
            Some(answers(json!({"one":{"roots":[]},"two":{"roots":[]}}))), InputSelection::Complete).is_ok());
    }
    let mut submission = submission(ClientCredentialsTaskSubmissionPolicy::new(1, 0, 2).unwrap());
    admit_input(&mut submission, json!({"resultType":"input_required","requestState":""}));
    let progress = submission.progress.as_ref().unwrap();
    let (round, count) = progress.prepare_resume(&submission.client, pair(), None, InputSelection::Complete).unwrap();
    let wire: Value = serde_json::from_slice(round.operation.wire.body()).unwrap();
    assert_eq!(wire["params"]["requestState"], "");
    assert!(wire["params"].get("inputResponses").is_none());
    assert_eq!(count, 0);
}

#[test]
fn cumulative_record_input_and_continuation_limits_gate_challenge_delivery() {
    for policy in [ClientCredentialsTaskSubmissionPolicy::new(0, 2, 4).unwrap(),
        ClientCredentialsTaskSubmissionPolicy::new(1, 1, 4).unwrap(),
        ClientCredentialsTaskSubmissionPolicy::new(1, 2, 1).unwrap()] {
        let mut submission = submission(policy);
        let progress = submission.progress.as_mut().unwrap();
        let event = result(progress, challenge(Some("state")));
        assert!(progress.admit(event).is_err());
        assert!(progress.pending.is_none());
    }
    for (rounds, inputs, records) in [(65, 1, 1), (1, 1025, 1), (1, 1, 0), (1, 1, 1025)] {
        assert!(ClientCredentialsTaskSubmissionPolicy::new(rounds, inputs, records).is_err());
    }
    let mut submission = submission(ClientCredentialsTaskSubmissionPolicy::new(1, 2, 2).unwrap());
    admit_input(&mut submission, challenge(Some("state")));
    let progress = submission.progress.as_mut().unwrap();
    let event = result(progress, json!({"resultType":"complete","content":[],"isError":true}));
    assert!(matches!(progress.admit(event).unwrap(), ClientCredentialsTaskSubmissionEvent::Result(result)
        if matches!(*result, FinalCoreResult::ToolsCall { .. })));
    assert_eq!(progress.remaining_records(), 0);
}

#[test]
fn unadvertised_input_is_not_exposed_and_task_results_are_not_tool_completions() {
    let mut submission = submission(ClientCredentialsTaskSubmissionPolicy::default());
    let progress = submission.progress.as_mut().unwrap();
    let bad = result(progress, json!({"resultType":"input_required", "inputRequests":{
        "sampling":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":1}}
    }}));
    assert!(matches!(progress.admit(bad), Err(ClientCredentialsTaskSubmissionCause::Input(ManagedInteractionError::CapabilityNotAdvertised))));
    assert!(progress.pending.is_none());
    let event = result(progress, json!({"resultType":"task","taskId":"opaque / ID", "status":"working",
        "createdAt":"2020-01-01T00:00:00Z","lastUpdatedAt":"2020-01-01T00:00:00Z","ttlMs":null}));
    assert!(matches!(progress.admit(event).unwrap(), ClientCredentialsTaskSubmissionEvent::Result(result)
        if matches!(*result, FinalCoreResult::ToolsCallTask { .. })));
}

#[test]
fn cancellation_before_send_consumes_once_and_close_preserves_unknown_delivery() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let mut submission = submission(ClientCredentialsTaskSubmissionPolicy::default());
            let cancellation = McpRequestCancellation::new();
            cancellation.cancel();
            let unpolled = submission.send_with_cancellation(&cx, &cancellation);
            drop(unpolled);
            assert_eq!(submission.state(), TaskSubmissionState::Prepared);
            assert!(matches!(submission.send_with_cancellation(&cx, &cancellation).await,
                Err(ClientCredentialsTaskSubmissionError::NotDispatched(_))));
            assert_eq!(submission.state(), TaskSubmissionState::NotDispatched);
            assert!(matches!(submission.send(&cx).await, Err(ClientCredentialsTaskSubmissionError::InvalidState)));
            assert!(submission.client.client.inner.state.try_lock_owned().unwrap().current.is_none());
            assert!(cx.checkpoint().is_ok());
        });
    for state in [TaskSubmissionState::AwaitingResponse, TaskSubmissionState::DeliveryUnknown] {
        assert_eq!(closed_state(state), TaskSubmissionState::DeliveryUnknown);
    }
    assert_eq!(closed_state(TaskSubmissionState::Resolved), TaskSubmissionState::Resolved);
    assert_eq!(closed_state(TaskSubmissionState::AwaitingInput), TaskSubmissionState::Closed);
}
