//! Shared-codec positive and negative controls for streaming conversation state.

use super::*;
use crate::http_auth::rpc::{ManagedCoreEvent, ManagedCoreLimits};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
use serde_json::{Value, json};

#[cfg(feature = "native-tls-roots")]
mod tls;

const TARGET: &str = "https://mcp.example/mcp?tenant=one";
const CHANGE: &[u8] = br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;

fn original(method: &str) -> CoreRequest {
    let mut params = match method {
        "tools/call" => json!({"name":"echo","arguments":{"fixed":42}}),
        "resources/read" => json!({"uri":"file:///owned"}),
        "prompts/get" => json!({"name":"greeting","arguments":{"name":"Ada"}}),
        _ => json!({}),
    };
    params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    params["_meta"][fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY] = json!({"roots":{}});
    params["_meta"]["com.example/identity"] = json!("fixed");
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
}

fn limits(bytes: usize, notifications: usize, continuations: usize) -> ManagedInteractionLimits {
    let core = ManagedCoreLimits::new(
        8192, bytes.min(8192), bytes, notifications, Duration::from_secs(60),
    ).unwrap();
    ManagedInteractionLimits::new(core, continuations, 16).unwrap()
}

fn challenge(state: &str) -> Value {
    json!({"resultType":"input_required", "requestState":state,
        "inputRequests":{"r":{"method":"roots/list"}}})
}

fn terminal(method: &str) -> Value {
    match method {
        "tools/call" => json!({"resultType":"complete","content":[{"type":"text","text":"done"}],"isError":false}),
        "resources/read" => json!({"resultType":"complete","contents":[],"ttlMs":0,"cacheScope":"private"}),
        "prompts/get" => json!({"resultType":"complete","messages":[],"ttlMs":0,"cacheScope":"private"}),
        _ => unreachable!(),
    }
}

fn response(id: &RequestId, result: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result})).unwrap()
}

fn receive(
    conversation: &Conversation,
    result: Value,
    notify: bool,
) -> (ModernHttpRequest, CompletedStream, usize) {
    let (wire, mut decoder) = conversation.prepare(TARGET, 8192, None).unwrap();
    if notify {
        assert!(matches!(decoder.admit(CHANGE, true).unwrap(), ManagedCoreEvent::Notification(_)));
    }
    let frame = response(&conversation.request_id, result);
    let ManagedCoreEvent::Result(result) = decoder.admit(&frame, true).unwrap() else {
        panic!("terminal envelope must decode as a result");
    };
    (wire, CompletedStream { result: *result, usage: decoder.usage() }, frame.len())
}

fn answer(id: RequestId) -> ManagedInputReply {
    ManagedInputReply {
        request_id: id,
        input_responses: Some(serde_json::from_value(json!({"r":{"roots":[]}})).unwrap()),
    }
}

#[test]
fn streamed_rounds_retain_original_operation_state_and_cumulative_usage() {
    for method in ["tools/call", "resources/read", "prompts/get"] {
        let original = original(method);
        let before = original.encode_params().unwrap().unwrap();
        let mut conversation = Conversation::new(
            original, request_id("exchange", 0).unwrap(), limits(32768, 2, 2),
        ).unwrap();
        let mut expected_bytes = 0;
        for round in 0..2 {
            let opaque = format!(" private-state-{round}\0 /% ");
            let (wire, received, frame_bytes) = receive(&conversation, challenge(&opaque), true);
            expected_bytes += wire.body().len() + CHANGE.len() + frame_bytes;
            assert_eq!(received.usage, (expected_bytes, round + 1));
            let Step::Input(input) = conversation.accept(received).unwrap() else {
                panic!("input-required must stay distinct from complete");
            };
            let next_id = request_id("exchange", round + 1).unwrap();
            conversation.resume(&input, answer(next_id.clone())).unwrap();
            let (next, decoder) = conversation.prepare(TARGET, 8192, None).unwrap();
            let body: Value = serde_json::from_slice(next.body()).unwrap();
            assert_eq!(body["method"], method);
            assert_eq!(body["id"], serde_json::to_value(next_id).unwrap());
            assert_eq!(body["params"]["_meta"], before["_meta"]);
            for field in ["name", "arguments", "uri"] {
                assert_eq!(body["params"].get(field), before.get(field));
            }
            assert_eq!(body["params"]["requestState"], opaque);
            assert_eq!(body["params"]["inputResponses"], json!({"r":{"roots":[]}}));
            assert_eq!(decoder.usage(), (expected_bytes + next.body().len(), round + 1));
        }
        let (wire, received, frame_bytes) = receive(&conversation, terminal(method), false);
        expected_bytes += wire.body().len() + frame_bytes;
        assert_eq!(received.usage, (expected_bytes, 2));
        let Step::Complete(result) = conversation.accept(received).unwrap() else {
            panic!("complete must be published rather than invoke another host round");
        };
        assert!(input_required(&result).is_none());
        assert_eq!(conversation.continuations, 2);
        assert_eq!(conversation.input_responses, 2);
        assert_eq!(conversation.usage, (expected_bytes, 2));
        assert_eq!(conversation.original.encode_params().unwrap().unwrap(), before);
    }
}

#[test]
fn notification_quota_survives_a_new_request_id_before_another_observer_effect() {
    let mut conversation = Conversation::new(
        original("tools/call"), request_id("notes", 0).unwrap(), limits(32768, 1, 2),
    ).unwrap();
    let (_, received, _) = receive(&conversation, challenge("state"), true);
    let Step::Input(input) = conversation.accept(received).unwrap() else { panic!("input") };
    conversation.resume(&input, answer(request_id("notes", 1).unwrap())).unwrap();
    let (_, mut decoder) = conversation.prepare(TARGET, 8192, None).unwrap();
    let before = decoder.usage();
    assert!(matches!(decoder.admit(CHANGE, true), Err(ManagedCoreError::NotificationLimit)));
    assert_eq!(decoder.usage(), before, "a refused notification cannot commit usage or reach an observer");
    let frame = response(&conversation.request_id, terminal("tools/call"));
    assert!(matches!(decoder.admit(&frame, false).unwrap(), ManagedCoreEvent::Result(_)));
}

#[test]
fn exact_combined_request_and_response_budget_completes_but_one_byte_less_refuses() {
    let first_id = request_id("bytes", 0).unwrap();
    let generous = Conversation::new(original("tools/call"), first_id.clone(), limits(32768, 0, 0)).unwrap();
    let (wire, _) = generous.prepare(TARGET, 8192, None).unwrap();
    let frame = response(&first_id, terminal("tools/call"));
    let exact = wire.body().len() + frame.len();
    for extra in [0, 1] {
        let conversation = Conversation::new(
            original("tools/call"), first_id.clone(), limits(exact - extra, 0, 0),
        ).unwrap();
        let (_, mut decoder) = conversation.prepare(TARGET, 8192, None).unwrap();
        let before = decoder.usage();
        let result = decoder.admit(&frame, false);
        if extra == 0 {
            assert!(matches!(result, Ok(ManagedCoreEvent::Result(_))));
            assert_eq!(decoder.usage(), (exact, 0));
        } else {
            assert!(matches!(result, Err(ManagedCoreError::ResponseByteLimit)));
            assert_eq!(decoder.usage(), before);
        }
    }
    let exhausted = Conversation::new(
        original("tools/call"), first_id, limits(wire.body().len(), 0, 0),
    ).unwrap();
    assert!(matches!(exhausted.prepare(TARGET, 8192, None), Err(DpopStreamHostError::Stream(
        DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit))
    ))));
}

#[test]
fn invalid_or_reused_answers_leave_private_continuation_state_unchanged() {
    let mut conversation = Conversation::new(
        original("tools/call"), request_id("answers", 0).unwrap(), limits(32768, 0, 2),
    ).unwrap();
    let (_, received, _) = receive(&conversation, challenge("state-never-in-diagnostics"), false);
    let Step::Input(input) = conversation.accept(received).unwrap() else { panic!("input") };
    let before = conversation.current.encode_params().unwrap();
    let usage = conversation.usage;
    for reply in [
        answer(request_id("answers", 0).unwrap()),
        ManagedInputReply {
            request_id: request_id("answers", 1).unwrap(),
            input_responses: Some(serde_json::from_value(json!({"foreign":{"roots":[]}})).unwrap()),
        },
    ] {
        let error = conversation.resume(&input, reply).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("state-never-in-diagnostics"));
        assert_eq!(conversation.current.encode_params().unwrap(), before);
        assert_eq!(conversation.used_ids, [request_id("answers", 0).unwrap()]);
        assert_eq!(conversation.continuations, 0);
        assert_eq!(conversation.input_responses, 0);
        assert_eq!(conversation.usage, usage);
    }
    conversation.resume(&input, answer(request_id("answers", 1).unwrap())).unwrap();
    assert_eq!(conversation.continuations, 1);
}

#[test]
fn continuation_limit_refuses_a_challenge_before_input_resolution() {
    let mut conversation = Conversation::new(
        original("tools/call"), request_id("no-resume", 0).unwrap(), limits(32768, 0, 0),
    ).unwrap();
    let (_, received, _) = receive(&conversation, challenge("not-a-retry"), false);
    assert!(matches!(conversation.accept(received), Err(DpopStreamHostError::Host(
        DpopHostError::Interaction(crate::http_auth::dpop::native::core::interaction::DpopInteractionError::Input(
            ManagedInteractionError::ContinuationLimit
        ))
    ))));
    assert_eq!(conversation.continuations, 0);
}

#[test]
fn streaming_host_configuration_and_ids_fail_before_execution() {
    for prefix in ["", "bad\nname", &"x".repeat(129)] {
        assert!(request_id(prefix, 0).is_err());
    }
    assert_ne!(request_id("owned", 0).unwrap(), request_id("owned", 1).unwrap());
    let interaction = limits(8192, 0, 1);
    assert!(DpopStreamHostLimits::new(interaction, CoreInputLimits::default(), 64, Duration::from_secs(60)).is_ok());
    assert!(DpopStreamHostLimits::new(interaction, CoreInputLimits::default(), 65, Duration::from_secs(60)).is_err());
    assert!(DpopStreamHostLimits::new(interaction, CoreInputLimits::default(), 1, Duration::ZERO).is_err());
    assert!(Conversation::new(original("tools/list"), RequestId::Number(7), interaction).is_err());
}

fn with_arguments(arguments: Value) -> CoreRequest {
    let mut params = original("tools/call").encode_params().unwrap().unwrap();
    params["arguments"] = arguments;
    CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap()
}

fn review(target: &str, tool: &str) -> ReviewedToolHeaders {
    ReviewedToolHeaders::new(
        fastmcp_core::CanonicalHttpUrl::parse(target).unwrap(), tool,
        json!({"type":"object","properties":{
            "region":{"type":"string","x-mcp-header":"Region"},
            "private":{"type":"string","writeOnly":true}
        }}),
        |binding| binding.header_name() == "Mcp-Param-Region",
    ).unwrap()
}

fn projected(wire: &ModernHttpRequest) -> Vec<(String, String)> {
    wire.headers().into_iter().filter(|(name, _)| name.starts_with("Mcp-Param-")).collect()
}

#[test]
fn every_streaming_continuation_projects_only_immutable_original_arguments() {
    let original = with_arguments(json!({"region":"eu 雪","private":"body-private"}));
    let before = original.encode_params().unwrap().unwrap();
    let mut conversation = Conversation::new(original, request_id("headers", 0).unwrap(), limits(32768, 0, 2)).unwrap();
    let review = review(TARGET, "echo");
    for round in 0..=2 {
        let (plain, plain_decoder) = conversation.prepare(TARGET, 8192, None).unwrap();
        let (wire, decoder) = conversation.prepare(TARGET, 8192, Some(&review)).unwrap();
        assert_eq!(wire.body(), plain.body());
        assert_eq!(decoder.usage(), plain_decoder.usage());
        assert!(projected(&plain).is_empty());
        assert_eq!(projected(&wire), vec![(
            "Mcp-Param-Region".to_owned(),
            fastmcp_protocol::http_headers::encode_mcp_header_value("eu 雪").unwrap(),
        )]);
        assert!(!wire.headers().iter().any(|(_, value)| value.contains("body-private") || value.contains("host-only")));
        let body: Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(body["params"]["arguments"], before["arguments"]);
        assert_eq!(body["params"]["_meta"], before["_meta"]);
        if round == 2 { break; }
        let (_, received, _) = receive(&conversation, challenge("private-state"), false);
        let Step::Input(input) = conversation.accept(received).unwrap() else { panic!("input") };
        let reply = ManagedInputReply {
            request_id: request_id("headers", round + 1).unwrap(),
            input_responses: Some(serde_json::from_value(json!({"r":{"roots":[{"uri":"file:///host-only"}]}})).unwrap()),
        };
        conversation.resume(&input, reply).unwrap();
    }
}

#[test]
fn failed_header_admission_never_falls_back_or_mutates_conversation_state() {
    let conversation = Conversation::new(
        with_arguments(json!({"region":"eu"})), request_id("binding", 0).unwrap(), limits(32768, 0, 1),
    ).unwrap();
    let before = conversation.current.encode_params().unwrap();
    for reviewed in [review("https://mcp.example/mcp?tenant=two", "echo"), review(TARGET, "other")] {
        assert!(matches!(conversation.prepare(TARGET, 8192, Some(&reviewed)), Err(DpopStreamHostError::Headers(_))));
        assert_eq!(conversation.current.encode_params().unwrap(), before);
        assert_eq!(conversation.usage, (0, 0));
        assert_eq!(conversation.continuations, 0);
    }
    let wrong_type = Conversation::new(
        with_arguments(json!({"region":42})), request_id("binding", 0).unwrap(), limits(32768, 0, 1),
    ).unwrap();
    assert!(matches!(wrong_type.prepare(TARGET, 8192, Some(&review(TARGET, "echo"))), Err(DpopStreamHostError::Headers(
        ToolHeaderDispatchError::Projection(fastmcp_protocol::http_headers::McpHeaderError::InvalidParameter)
    ))));
    let resource = Conversation::new(original("resources/read"), request_id("binding", 0).unwrap(), limits(32768, 0, 1)).unwrap();
    assert!(matches!(resource.prepare(TARGET, 8192, Some(&review(TARGET, "echo"))), Err(DpopStreamHostError::Headers(
        ToolHeaderDispatchError::OperationMismatch
    ))));
}
