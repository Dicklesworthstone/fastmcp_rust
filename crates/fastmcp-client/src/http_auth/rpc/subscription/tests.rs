use super::*;
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
use serde_json::json;

fn params(filter: Value) -> FinalSubscriptionsListenParams {
    serde_json::from_value(json!({
        "_meta": FinalRequestMeta::new(ClientCapabilities::default()),
        "notifications": filter,
    }))
    .expect("typed subscription parameters")
}

fn decoder(filter: Value) -> SubscriptionDecoder {
    prepare(
        "https://mcp.example/mcp",
        params(filter),
        RequestId::Number(7),
        ManagedCoreLimits::default(),
    )
    .expect("admitted listen request")
    .1
}

fn notification(id: Value, method: &str, mut params: Value) -> Vec<u8> {
    params["_meta"] = json!({});
    params["_meta"][FINAL_SUBSCRIPTION_ID_META_KEY] = id;
    serde_json::to_vec(&json!({"jsonrpc":"2.0", "method":method, "params":params})).unwrap()
}

fn ack(id: Value, filter: Value) -> Vec<u8> {
    notification(id, "notifications/subscriptions/acknowledged", json!({"notifications":filter}))
}

fn changed(id: Value, category: &str) -> Vec<u8> {
    notification(id, &format!("notifications/{category}/list_changed"), json!({}))
}

fn updated(id: Value, uri: &str) -> Vec<u8> {
    notification(id, "notifications/resources/updated", json!({"uri":uri}))
}

fn complete(id: Value, subscription_id: Value) -> Vec<u8> {
    let mut result = json!({"resultType":"complete", "_meta":{}});
    result["_meta"][FINAL_SUBSCRIPTION_ID_META_KEY] = subscription_id;
    serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":id, "result":result})).unwrap()
}

fn snapshot(state: &SubscriptionDecoder) -> (usize, usize, bool, Option<SubscriptionFilter>) {
    (state.bytes, state.notifications, state.terminal, state.accepted.clone())
}

#[test]
fn preparation_preserves_filter_presence_metadata_and_owned_id() {
    let filter = json!({
        "toolsListChanged":true, "promptsListChanged":false,
        "resourceSubscriptions":[],
    });
    let (wire, state) = prepare(
        "https://mcp.example/mcp", params(filter.clone()),
        RequestId::String("owned-stream".to_owned()), ManagedCoreLimits::default(),
    ).unwrap();
    let body: Value = serde_json::from_slice(wire.body()).unwrap();
    assert_eq!(body["id"], "owned-stream");
    assert_eq!(body["method"], "subscriptions/listen");
    assert_eq!(body["params"]["notifications"], filter);
    assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], FINAL_PROTOCOL_VERSION);
    assert!(wire.headers().iter().any(|(name, value)| name.eq_ignore_ascii_case("mcp-method") && value == "subscriptions/listen"));
    assert!(!wire.headers().iter().any(|(name, _)| name.eq_ignore_ascii_case("authorization")));
    assert!(state.accepted.is_none());
}

#[test]
fn acknowledgement_changes_and_terminal_are_delivered_in_order() {
    let filter = json!({"toolsListChanged":true,"resourceSubscriptions":["file:///a"]});
    let mut state = decoder(filter.clone());
    assert!(matches!(state.admit(&ack(json!(7), filter)),
        Ok(ManagedCoreEvent::Notification(notification))
            if matches!(notification.as_ref(), ServerNotification::SubscriptionsAcknowledged(_))));
    assert!(state.admit(&changed(json!(7), "tools")).is_ok());
    assert!(state.admit(&updated(json!(7), "file:///a")).is_ok());
    assert!(matches!(state.admit(&complete(json!(7), json!(7))),
        Ok(ManagedCoreEvent::Result(result))
            if matches!(result.as_ref(), CoreResult::Final(FinalCoreResult::SubscriptionsListen { .. }))));
    assert!(state.terminal);
    assert_eq!(state.notifications, 3);
    let before = snapshot(&state);
    assert!(state.admit(&complete(json!(7), json!(7))).is_err());
    assert_eq!(snapshot(&state), before);
}

#[test]
fn notification_or_success_before_acknowledgement_cannot_advance_state() {
    let mut state = decoder(json!({"toolsListChanged":true}));
    for frame in [changed(json!(7), "tools"), complete(json!(7), json!(7))] {
        let before = snapshot(&state);
        assert!(matches!(state.admit(&frame), Err(ManagedCoreError::UnexpectedNotification)));
        assert_eq!(snapshot(&state), before);
    }
    assert!(state.admit(&ack(json!(7), json!({"toolsListChanged":true}))).is_ok());
}

#[test]
fn acknowledgement_may_narrow_but_cannot_widen_any_core_filter() {
    let requested = json!({
        "toolsListChanged":true,"resourceSubscriptions":["file:///a","file:///b"],
    });
    for accepted in [
        json!({"toolsListChanged":true,"resourceSubscriptions":["file:///a"]}),
        json!({"toolsListChanged":false,"resourceSubscriptions":[]}),
        json!({}),
    ] {
        assert!(decoder(requested.clone()).admit(&ack(json!(7), accepted)).is_ok());
    }
    for widened in [
        json!({"promptsListChanged":true}),
        json!({"resourcesListChanged":true}),
        json!({"resourceSubscriptions":["file:///c"]}),
        json!({"resourceSubscriptions":["file:///a","file:///a"]}),
        json!({"taskIds":["unnegotiated-task"]}),
    ] {
        let mut state = decoder(requested.clone());
        let before = snapshot(&state);
        assert!(state.admit(&ack(json!(7), widened)).is_err());
        assert_eq!(snapshot(&state), before);
    }
}

#[test]
fn accepted_filter_not_original_request_controls_notification_delivery() {
    let mut state = decoder(json!({
        "toolsListChanged":true,"promptsListChanged":true,
        "resourceSubscriptions":["file:///a","file:///b"],
    }));
    state.admit(&ack(json!(7), json!({"promptsListChanged":true,"resourceSubscriptions":["file:///a"]}))).unwrap();
    for frame in [changed(json!(7), "tools"), updated(json!(7), "file:///b")] {
        let before = snapshot(&state);
        assert!(matches!(state.admit(&frame), Err(ManagedCoreError::UnexpectedNotification)));
        assert_eq!(snapshot(&state), before);
    }
    assert!(state.admit(&changed(json!(7), "prompts")).is_ok());
    assert!(state.admit(&updated(json!(7), "file:///a")).is_ok());
}

#[test]
fn resource_selectors_use_exact_spelling_without_percent_or_query_normalization() {
    let uri = "https://resource.example/a%2Fb?q=one";
    let filter = json!({"resourceSubscriptions":[uri]});
    let mut state = decoder(filter.clone());
    state.admit(&ack(json!(7), filter)).unwrap();
    for other in ["https://resource.example/a/b?q=one", "https://resource.example/a%2Fb?q=two"] {
        assert!(state.admit(&updated(json!(7), other)).is_err());
    }
    assert!(state.admit(&updated(json!(7), uri)).is_ok());
}

#[test]
fn foreign_missing_and_type_confused_subscription_ids_are_refused() {
    let filter = json!({"toolsListChanged":true});
    let mut state = decoder(filter.clone());
    for id in [json!(8), json!("7"), Value::Null] {
        assert!(matches!(state.admit(&ack(id, filter.clone())), Err(ManagedCoreError::ResponseIdMismatch)));
        assert!(state.accepted.is_none());
    }
    let absent = br#"{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"notifications":{"toolsListChanged":true}}}"#;
    assert!(state.admit(absent).is_err());
    state.admit(&ack(json!(7), filter)).unwrap();
    for id in [json!(8), json!("7"), Value::Null] {
        let before = snapshot(&state);
        assert!(state.admit(&changed(id, "tools")).is_err());
        assert_eq!(snapshot(&state), before);
    }
    assert!(state.admit(&changed(json!(7), "tools")).is_ok());
}

#[test]
fn duplicate_acknowledgements_do_not_replace_the_accepted_filter() {
    let filter = json!({"toolsListChanged":true,"promptsListChanged":true});
    let mut state = decoder(filter.clone());
    state.admit(&ack(json!(7), json!({"toolsListChanged":true}))).unwrap();
    let before = snapshot(&state);
    assert!(state.admit(&ack(json!(7), filter)).is_err());
    assert_eq!(snapshot(&state), before);
    assert!(state.admit(&changed(json!(7), "prompts")).is_err());
}

#[test]
fn terminal_requires_both_owning_response_id_and_subscription_metadata_id() {
    for (id, subscription_id) in [(json!(8), json!(7)), (json!(7), json!(8)), (json!("7"), json!(7)), (json!(7), json!("7"))] {
        let mut state = decoder(json!({}));
        state.admit(&ack(json!(7), json!({}))).unwrap();
        let before = snapshot(&state);
        assert!(state.admit(&complete(id, subscription_id)).is_err());
        assert_eq!(snapshot(&state), before);
        assert!(state.admit(&complete(json!(7), json!(7))).is_ok());
    }
}

#[test]
fn reverse_requests_batches_duplicate_members_and_noncore_events_are_refused() {
    let mut state = decoder(json!({"toolsListChanged":true}));
    state.admit(&ack(json!(7), json!({"toolsListChanged":true}))).unwrap();
    for frame in [
        br#"{"jsonrpc":"2.0","id":9,"method":"roots/list"}"#.to_vec(),
        br#"[{"jsonrpc":"2.0","id":7,"result":{}}]"#.to_vec(),
        br#"{"jsonrpc":"2.0","id":7,"id":7,"result":{}}"#.to_vec(),
        vec![0xff],
        notification(json!(7), "notifications/progress", json!({"progressToken":"unowned","progress":1})),
        notification(json!(7), "notifications/cancelled", json!({"requestId":7})),
    ] {
        let before = snapshot(&state);
        assert!(state.admit(&frame).is_err());
        assert_eq!(snapshot(&state), before);
    }
}

#[test]
fn frame_total_byte_and_notification_limits_are_transactional() {
    let acknowledgement = ack(json!(7), json!({"toolsListChanged":true}));
    let change = changed(json!(7), "tools");
    let mut state = decoder(json!({"toolsListChanged":true}));
    state.limits.frame_bytes = acknowledgement.len() - 1;
    assert!(matches!(state.admit(&acknowledgement), Err(ManagedCoreError::ResponseByteLimit)));
    assert_eq!(snapshot(&state), (0, 0, false, None));
    state.limits.frame_bytes = acknowledgement.len();
    state.limits.total_bytes = acknowledgement.len() + change.len();
    state.admit(&acknowledgement).unwrap();
    state.admit(&change).unwrap();
    let before = snapshot(&state);
    assert!(matches!(state.admit(&change), Err(ManagedCoreError::ResponseByteLimit)));
    assert_eq!(snapshot(&state), before);

    let mut state = decoder(json!({"toolsListChanged":true}));
    state.limits.notifications = 1;
    state.admit(&acknowledgement).unwrap();
    let before = snapshot(&state);
    assert!(matches!(state.admit(&change), Err(ManagedCoreError::NotificationLimit)));
    assert_eq!(snapshot(&state), before);
    assert!(state.admit(&complete(json!(7), json!(7))).is_ok());
}

#[test]
fn preflight_refuses_unnegotiated_filters_duplicate_resources_and_oversized_requests() {
    for filter in [
        json!({"taskIds":["task"]}),
        json!({"toolsListChange":true}),
        json!({"resourceSubscriptions":["file:///a","file:///a"]}),
        json!({"resourceSubscriptions":["x".repeat(MAX_MANAGED_SUBSCRIPTION_RESOURCE_BYTES + 1)]}),
        json!({"resourceSubscriptions": (0..=MAX_MANAGED_SUBSCRIPTION_RESOURCES).map(|i| format!("file:///{i}")).collect::<Vec<_>>()}),
    ] {
        assert!(prepare("https://mcp.example/mcp", params(filter), RequestId::Number(7), ManagedCoreLimits::default()).is_err());
    }
    let mut limits = ManagedCoreLimits::default();
    limits.notifications = 0;
    assert!(matches!(prepare("https://mcp.example/mcp", params(json!({})), RequestId::Number(7), limits), Err(ManagedCoreError::InvalidLimits)));
    limits.notifications = 1;
    limits.request_bytes = 1;
    assert!(matches!(prepare("https://mcp.example/mcp", params(json!({})), RequestId::Number(7), limits), Err(ManagedCoreError::RequestTooLarge)));
}

#[test]
fn extension_capability_advertisements_are_refused_before_dispatch() {
    let mut value = serde_json::to_value(params(json!({}))).unwrap();
    value["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"] = json!({"io.modelcontextprotocol/tasks":{}});
    let params = serde_json::from_value(value).unwrap();
    assert!(prepare("https://mcp.example/mcp", params, RequestId::Number(7), ManagedCoreLimits::default()).is_err());
}

#[test]
fn peer_error_text_is_not_retained_even_before_acknowledgement() {
    let mut state = decoder(json!({}));
    let error = state.admit(br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32603,"message":"secret-canary","data":{"token":"secret-canary"}}}"#).err().unwrap();
    assert!(matches!(&error, ManagedCoreError::Remote { .. }));
    assert!(!format!("{error:?} {error}").contains("secret-canary"));
    assert_eq!(snapshot(&state), (0, 0, false, None));
}
