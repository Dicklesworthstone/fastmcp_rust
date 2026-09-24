use super::*;
use std::sync::{Arc, atomic::AtomicUsize};
use std::time::{Duration, Instant};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
use serde_json::{Value, json};
use crate::http_auth::{BoundBearerCredential, discovery::client_credentials as machine};

fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }
fn runtime() -> asupersync::runtime::Runtime {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(0, 2).build().unwrap()
}
fn original() -> CoreRequest {
    let mut meta = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    meta[fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY] = json!({"roots":{}});
    meta["com.example/identity"] = json!("untouched");
    CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&json!({
        "_meta":meta,"name":"checkout","arguments":{"quantity":3}
    }))).unwrap()
}
fn answers(value: Value) -> FinalInputResponses { serde_json::from_value(value).unwrap() }
fn contract() -> ContinuationReplayContract {
    ContinuationReplayContract::for_configured_endpoint(url("https://machine.example/mcp"), 2).unwrap()
}
fn awaiting(cx: &Cx) -> ClientCredentialsInteraction {
    let resource = url("https://machine.example/mcp");
    let closed = McpRequestCancellation::new();
    let expires_at = Instant::now() + Duration::from_secs(60);
    let bearer = BoundBearerCredential::bind_with_expiry(resource.clone(), "local-fixture-token", expires_at)
        .unwrap().for_owner(&closed).unwrap();
    // Prevent a test from accidentally reaching an issuer: public send must
    // reject this cached lineage. Successful transport is exercised separately.
    bearer.revoke();
    let client = machine::ClientCredentialsClient { inner: Arc::new(machine::ClientInner {
        resource, token_endpoint: url("https://issuer.example/token"), client_id: "fixture".to_owned(), scopes: vec![],
        authentication: machine::MachineAuthentication::Basic(Arc::new(machine::ClientSecret("test-only".to_owned()))),
        issuer_roots: vec![], resource_tls: None, timeout: Duration::from_secs(5), maximum_lifetime: Duration::from_secs(60),
        leeway: Duration::ZERO, closed, pending: AtomicUsize::new(0),
        state: Arc::new(asupersync::sync::Mutex::new(machine::TokenState {
            current: Some(machine::ServiceToken { bearer, scopes: vec![], expires_at, renew_after: expires_at }), generation: 1,
        })),
    }) };
    let original = original();
    let input = input_required(&original.decode_result(r#"{"resultType":"input_required","requestState":"opaque /+%",
        "inputRequests":{"left":{"method":"roots/list"},"right":{"method":"roots/list"}}}"#).unwrap()).unwrap().clone();
    ClientCredentialsInteraction {
        client, original, step: Some(Step::Awaiting(Box::new(input))), cancellation: McpRequestCancellation::new(),
        deadline: machine::discovery_deadline(cx, Duration::from_secs(5)).unwrap(),
        limits: super::super::ManagedInteractionLimits::default(), used_ids: vec![RequestId::Number(1), RequestId::Number(2)],
        continuations: 0, input_responses: 0, response_bytes: 73, notifications: 0, generation: 1,
    }
}
fn recovery(cx: &Cx) -> RecoverableMachineContinuation {
    awaiting(cx).prepare_recoverable_continuation(cx, Some(answers(json!({"left":{"roots":[]}}))), contract()).unwrap()
}

#[test]
fn public_machine_preparation_preserves_exact_request_and_does_not_acquire() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let owner = recovery(&cx);
        let retained = owner.request.as_ref().unwrap().encode_params().unwrap().unwrap();
        assert_eq!(retained["requestState"], "opaque /+%");
        assert_eq!(retained["inputResponses"], json!({"left":{"roots":[]}}));
        assert_eq!(retained["arguments"], json!({"quantity":3}));
        assert_eq!(retained["_meta"]["com.example/identity"], "untouched");
        assert_eq!(owner.attempts(), 0);
        assert!(owner.snapshot.is_none());
        assert!(owner.interaction.pending_input().is_none());
        assert_eq!(owner.interaction.continuation_count(), 0);
        assert_eq!(owner.interaction.response_bytes, 73);
        assert_eq!(owner.interaction.used_ids.len(), 2);
    });
}

#[test]
fn machine_recovery_contract_refuses_other_paths_queries_and_authorities() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        for resource in ["https://other.example/mcp", "https://machine.example/other", "https://machine.example/mcp?other=1"] {
            let contract = ContinuationReplayContract::for_configured_endpoint(url(resource), 1).unwrap();
            let result = awaiting(&cx).prepare_recoverable_continuation(&cx,
                Some(answers(json!({"left":{"roots":[]}}))), contract);
            assert!(matches!(result, Err(MachineContinuationRecoveryError::Recovery(ContinuationRecoveryError::EndpointMismatch))));
        }
        assert_eq!(recovery(&cx).phase, Phase::Prepared);
    });
}

#[test]
fn machine_recovery_refuses_wrong_answers_and_absent_or_empty_server_state() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        for answer in [json!({}), json!({"foreign":{"roots":[]}}), json!({"left":{"action":"decline"}})] {
            assert!(awaiting(&cx).prepare_recoverable_continuation(&cx, Some(answers(answer)), contract()).is_err());
        }
        for state in [None, Some("")] {
            let mut operation = awaiting(&cx);
            let mut wire = json!({"resultType":"input_required","inputRequests":{"left":{"method":"roots/list"}}});
            if let Some(state) = state { wire["requestState"] = json!(state); }
            let input = input_required(&operation.original.decode_result(&wire.to_string()).unwrap()).unwrap().clone();
            operation.step = Some(Step::Awaiting(Box::new(input)));
            assert!(matches!(operation.prepare_recoverable_continuation(&cx,
                Some(answers(json!({"left":{"roots":[]}}))), contract()),
                Err(MachineContinuationRecoveryError::Recovery(ContinuationRecoveryError::StateRequired))));
        }
    });
}

#[test]
fn machine_recovery_measures_retained_answers_before_returning_custody() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let mut operation = awaiting(&cx);
        operation.limits = super::super::ManagedInteractionLimits::new(
            ManagedCoreLimits::new(1024, 4096, 32768, 1, Duration::from_secs(5)).unwrap(), 2, 4).unwrap();
        let answers = answers(json!({"left":{"roots":[{"uri":"file:///root","name":"x".repeat(2048)}]}}));
        assert!(matches!(operation.prepare_recoverable_continuation(&cx, Some(answers), contract()),
            Err(MachineContinuationRecoveryError::Interaction(ClientCredentialsInteractionError::Core(
                ClientCredentialsCoreError::Protocol(ManagedCoreError::RequestTooLarge))))));
    });
}

#[test]
fn machine_recovery_ids_and_frame_capacity_are_admitted_before_grant_work() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let mut owner = recovery(&cx);
        for (discovery, operation) in [("1e0","4"),("3","2.0"),("3","3.0")] {
            assert!(matches!(owner.send(&cx, serde_json::from_str(discovery).unwrap(), serde_json::from_str(operation).unwrap()).await,
                Err(MachineContinuationRecoveryError::Interaction(ClientCredentialsInteractionError::Interaction(
                    ManagedInteractionError::RepeatedRequestId)))));
            assert_eq!(owner.attempts(), 0);
            assert_eq!(owner.phase, Phase::Prepared);
            assert_eq!(owner.interaction.used_ids.len(), 2);
        }
        let core = owner.interaction.limits.core();
        owner.interaction.response_bytes = core.total_bytes() - core.frame_bytes() + 1;
        assert!(matches!(owner.send(&cx, RequestId::Number(3), RequestId::Number(4)).await,
            Err(MachineContinuationRecoveryError::Interaction(ClientCredentialsInteractionError::Core(
                ClientCredentialsCoreError::Protocol(ManagedCoreError::ResponseByteLimit))))));
        assert_eq!(owner.attempts(), 0);
        assert!(owner.snapshot.is_none());
    });
}

#[test]
fn failed_grant_is_terminal_and_never_becomes_an_operation_recovery() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let mut owner = recovery(&cx);
        assert!(matches!(owner.send(&cx, RequestId::Number(3), RequestId::Number(4)).await,
            Err(MachineContinuationRecoveryError::Interaction(ClientCredentialsInteractionError::Core(
                ClientCredentialsCoreError::Authentication(ClientCredentialsError::Expired))))));
        assert_eq!(owner.attempts(), 1);
        assert_eq!(owner.interaction.continuation_count(), 1);
        assert_eq!(owner.interaction.input_responses, 1);
        assert!(!owner.is_recovery_pending());
        assert!(owner.request.is_none());
        assert!(matches!(owner.recover(&cx, RequestId::Number(5), RequestId::Number(6)).await,
            Err(MachineContinuationRecoveryError::Recovery(ContinuationRecoveryError::WrongPhase))));
    });
}

#[test]
fn revoked_or_expired_recovery_snapshot_cannot_be_replaced_by_a_new_grant() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        for expired in [false, true] {
            let mut owner = recovery(&cx);
            let expires_at = if expired { Instant::now() } else { Instant::now() + Duration::from_secs(60) };
            let bearer = BoundBearerCredential::bind_with_expiry(owner.interaction.client.resource().clone(), "pinned-fixture", expires_at)
                .unwrap().for_owner(&owner.interaction.client.inner.closed).unwrap();
            if !expired { bearer.revoke(); }
            owner.snapshot = Some(ClientCredentialsSnapshot { bearer, scopes: vec![], expires_at, generation: 17 });
            owner.phase = Phase::Recoverable;
            owner.attempts = 1;
            assert!(matches!(owner.recover(&cx, RequestId::Number(3), RequestId::Number(4)).await,
                Err(MachineContinuationRecoveryError::Interaction(ClientCredentialsInteractionError::Core(
                    ClientCredentialsCoreError::Authentication(ClientCredentialsError::Expired))))));
            assert_eq!(owner.attempts(), 1);
            assert_eq!(owner.interaction.client.inner.state.try_lock_owned().unwrap().generation, 1);
            assert!(owner.snapshot.is_none());
        }
    });
}

#[test]
fn machine_owner_close_and_precancellation_retire_answers_before_dispatch() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        for close_owner in [false, true] {
            let mut owner = recovery(&cx);
            if close_owner { owner.interaction.client.close(); } else { owner.interaction.cancellation.cancel(); }
            assert!(owner.send(&cx, RequestId::Number(3), RequestId::Number(4)).await.is_err());
            assert_eq!(owner.attempts(), 0);
            assert!(owner.request.is_none());
            assert!(!owner.is_recovery_pending());
        }
    });
}

#[test]
fn discovery_and_operation_use_one_stamped_metadata_and_separate_fresh_ids() {
    let request = original();
    let source = request.decode_result(r#"{"resultType":"input_required","requestState":"state"}"#).unwrap();
    let request = recovery_request(&request, input_required(&source).unwrap(), None).unwrap();
    let prepared = prepared(&url("https://machine.example/mcp"), &request,
        &RequestId::Number(9), &RequestId::Number(10), ManagedCoreLimits::default()).unwrap();
    let discovery: Value = serde_json::from_slice(prepared.discovery_wire.body()).unwrap();
    let operation: Value = serde_json::from_slice(prepared.wire.body()).unwrap();
    assert_eq!(discovery["id"], 9);
    assert_eq!(operation["id"], 10);
    assert_eq!(discovery["params"]["_meta"], operation["params"]["_meta"]);
    assert_eq!(operation["params"]["_meta"][fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],
        json!({machine::CLIENT_CREDENTIALS_EXTENSION:{}}));
    assert_eq!(operation["params"]["requestState"], "state");
    assert!(operation["params"].get("inputResponses").is_none());
    for wire in [prepared.discovery_wire, prepared.wire] {
        assert!(!wire.headers().iter().any(|(key,_)|key.eq_ignore_ascii_case("authorization")));
    }
}

#[test]
fn only_operation_interruption_is_recoverable_and_diagnostics_do_not_retain_peer_text() {
    use asupersync::http::h1::ClientError;
    let io = || ModernHttpExecutorError::Transport(ClientError::Io(std::io::Error::other("secret peer string")));
    assert!(matches!(operation_http_error(io()), MachineContinuationRecoveryError::Recovery(ContinuationRecoveryError::Interrupted)));
    let discovery = terminal_http_error(io());
    assert!(matches!(discovery, MachineContinuationRecoveryError::Transport));
    assert!(!format!("{discovery:?} {discovery}").contains("secret peer string"));
    for error in [ModernHttpExecutorError::Cancelled, ModernHttpExecutorError::Redirect { status:307 },
        ModernHttpExecutorError::ResponseBodyTooLarge { maximum_bytes:1 },
        ModernHttpExecutorError::Transport(ClientError::TlsError("secret peer string".to_owned()))]
    {
        let result = operation_http_error(error);
        assert!(!matches!(result, MachineContinuationRecoveryError::Recovery(ContinuationRecoveryError::Interrupted)));
        assert!(!format!("{result:?} {result}").contains("secret peer string"));
    }
}
