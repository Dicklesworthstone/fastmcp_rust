use super::*;
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, protocol_policy::ProtocolEra};
use serde_json::{Value, json};

fn original(method: &str) -> CoreRequest {
    let mut params = match method {
        "tools/call" => json!({"name":"checkout","arguments":{"quantity":1}}),
        "resources/read" => json!({"uri":"file:///private/%2F"}),
        "prompts/get" => json!({"name":"summary","arguments":{"topic":"private"}}),
        _ => unreachable!(),
    };
    params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    params["_meta"][fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY]["roots"] = json!({});
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
}
fn challenge(request: &CoreRequest, source: &str) -> InputRequiredResult {
    input_required(&request.decode_result(source).unwrap()).unwrap().clone()
}
fn answers(value: Value) -> FinalInputResponses { serde_json::from_value(value).unwrap() }

#[test]
fn recovery_requires_an_explicit_bounded_https_deployment_contract() {
    for endpoint in ["http://localhost/mcp", "http://service.example/mcp"] {
        assert!(ContinuationReplayContract::for_configured_endpoint(CanonicalHttpUrl::parse(endpoint).unwrap(), 1).is_err());
    }
    for maximum in [0, MAX_RECOVERIES + 1, usize::MAX] {
        assert!(ContinuationReplayContract::for_configured_endpoint(CanonicalHttpUrl::parse("https://service.example/mcp").unwrap(), maximum).is_err());
    }
    let contract = ContinuationReplayContract::for_configured_endpoint(CanonicalHttpUrl::parse("https://service.example/mcp?private=route").unwrap(), MAX_RECOVERIES).unwrap();
    assert!(!format!("{contract:?}").contains("private"));
}

#[test]
fn recovery_never_turns_missing_or_empty_state_into_an_initial_call() {
    let original = original("tools/call");
    for source in [
        r#"{"resultType":"input_required","inputRequests":{"one":{"method":"roots/list"}}}"#,
        r#"{"resultType":"input_required","inputRequests":{"one":{"method":"roots/list"}},"requestState":""}"#,
    ] {
        let input = challenge(&original, source);
        assert!(matches!(recovery_request(&original, &input, Some(answers(json!({"one":{"roots":[]}})))), Err(ContinuationRecoveryError::StateRequired)));
    }
}

#[test]
fn replay_preparation_preserves_exact_state_parameters_and_selected_answer_order() {
    for method in ["tools/call", "resources/read", "prompts/get"] {
        let original = original(method);
        let before = original.encode_params().unwrap().unwrap();
        let input = challenge(&original, r#"{"resultType":"input_required","requestState":" opaque+/%\u0000 ","inputRequests":{"a":{"method":"roots/list"},"m":{"method":"roots/list"},"z":{"method":"roots/list"}}}"#);
        let supplied: FinalInputResponses = serde_json::from_str(r#"{"z":{"roots":[]},"a":{"roots":[]}}"#).unwrap();
        let request = recovery_request(&original, &input, Some(supplied)).unwrap();
        let mut params = request.encode_params().unwrap().unwrap();
        assert_eq!(params["requestState"], " opaque+/%\0 ");
        assert_eq!(params["inputResponses"], json!({"z":{"roots":[]},"a":{"roots":[]}}));
        params.as_object_mut().unwrap().remove("requestState");
        params.as_object_mut().unwrap().remove("inputResponses");
        assert_eq!(params, before);
        assert_eq!(original.encode_params().unwrap(), Some(before));
    }
}

#[test]
fn recovery_preparation_rejects_foreign_and_wrong_kind_answers() {
    let original = original("tools/call");
    let input = challenge(&original, r#"{"resultType":"input_required","requestState":"state","inputRequests":{"one":{"method":"roots/list"}}}"#);
    for response in [json!({}), json!({"other":{"roots":[]}}), json!({"one":{"action":"decline"}})] {
        assert!(recovery_request(&original, &input, Some(answers(response))).is_err());
    }
    assert!(recovery_request(&original, &input, Some(answers(json!({"one":{"roots":[]}})))).is_ok());
}

#[test]
fn recovery_keeps_state_only_and_present_empty_input_maps_distinct() {
    let original = original("tools/call");
    let state = challenge(&original, r#"{"resultType":"input_required","requestState":"state"}"#);
    assert!(recovery_request(&original, &state, None).unwrap().encode_params().unwrap().unwrap().get("inputResponses").is_none());
    assert!(recovery_request(&original, &state, Some(answers(json!({})))).is_err());
    let empty = challenge(&original, r#"{"resultType":"input_required","requestState":"state","inputRequests":{}}"#);
    assert!(recovery_request(&original, &empty, None).is_err());
    assert_eq!(recovery_request(&original, &empty, Some(answers(json!({})))).unwrap().encode_params().unwrap().unwrap()["inputResponses"], json!({}));
}

#[test]
fn unknown_response_reservations_are_bounded_without_integer_wrap() {
    assert_eq!(reserve_frame(100, 200, 300).unwrap(), 300);
    for (used, frame, total) in [(101, 200, 300), (300, 1, 300), (usize::MAX, 1, usize::MAX)] {
        assert!(matches!(reserve_frame(used, frame, total), Err(ManagedCoreError::ResponseByteLimit)));
    }
}

#[test]
fn answers_are_bounded_before_retaining_or_cloning_the_continuation() {
    let responses = answers(json!({"root":{"roots":[{"uri":format!("file:///{}", "x".repeat(256))}]}}));
    let bytes = serde_json::to_vec(&responses).unwrap().len();
    assert!(admit_answer_bytes(Some(&responses), bytes).is_ok());
    assert!(matches!(admit_answer_bytes(Some(&responses), bytes - 1), Err(ManagedCoreError::RequestTooLarge)));
    assert!(admit_answer_bytes(None, 0).is_ok());
}

#[test]
fn protocol_authentication_cancellation_and_redirect_errors_are_not_recovery_signals() {
    for error in [ManagedCoreError::Cancelled, ManagedCoreError::TimedOut, ManagedCoreError::InvalidResponse,
        ManagedCoreError::InvalidResult, ManagedCoreError::ResponseIdMismatch,
        ManagedCoreError::Remote { code: (-32603_i64).into() }, ManagedCoreError::HttpStatus { status: 503 },
        ManagedCoreError::Session(OAuthSessionError::Closed), ManagedCoreError::Session(OAuthSessionError::LoginRequired),
        ManagedCoreError::Session(OAuthSessionError::Http(ModernHttpExecutorError::Redirect { status: 302 })),
        ManagedCoreError::Session(OAuthSessionError::Http(ModernHttpExecutorError::Cancelled)),
        ManagedCoreError::Session(OAuthSessionError::Http(ModernHttpExecutorError::CredentialInPeerError)),
        ManagedCoreError::Session(OAuthSessionError::Http(ModernHttpExecutorError::ResponseBodyTooLarge { maximum_bytes: 1 })),
        ManagedCoreError::Session(OAuthSessionError::Http(ModernHttpExecutorError::Transport(ClientError::DeadlineExceeded))),
        ManagedCoreError::Session(OAuthSessionError::Http(ModernHttpExecutorError::Transport(ClientError::HttpError(HttpError::BadHeader))))]
    {
        assert!(!recoverable_transport_failure(&error));
    }
    assert!(recoverable_transport_failure(&ManagedCoreError::MissingTerminal));
    assert!(recoverable_transport_failure(&ManagedCoreError::Session(OAuthSessionError::Http(ModernHttpExecutorError::ResponseBodyReadFailed))));
    assert!(recoverable_transport_failure(&ManagedCoreError::Session(OAuthSessionError::Http(ModernHttpExecutorError::Transport(
        ClientError::HttpError(HttpError::Io(std::io::ErrorKind::UnexpectedEof.into()))
    )))));
}

#[test]
fn old_numeric_aliases_remain_used_after_recovery_id_selection() {
    let used = vec![RequestId::Number(1), RequestId::String("recovered".to_owned())];
    for wire in ["1.0", "1e0", "\"recovered\""] {
        assert!(admit_fresh_id(&used, &serde_json::from_str(wire).unwrap()).is_err());
    }
    assert!(admit_fresh_id(&used, &RequestId::String("1".to_owned())).is_ok());
}
