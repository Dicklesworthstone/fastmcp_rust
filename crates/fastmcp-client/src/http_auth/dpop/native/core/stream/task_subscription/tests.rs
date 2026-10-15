use super::*;
use std::sync::Arc;
use std::time::{Duration, Instant};

use asupersync::runtime::RuntimeBuilder;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::ClientCapabilities;
use fastmcp_protocol::dpop::DpopKey;
use super::super::{DpopCoreError, DpopSession, ModernHttpResponseKind, Reader};

const TARGET: &str = "https://mcp.example/mcp?tenant=one";
const COMPLETE: &str = r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":2},"x-exact":{"z":900719925474099312345,"a":1.20e+4,"text":"雪"}}}"#;

fn limits(notifications: usize) -> DpopStreamLimits {
    DpopStreamLimits::new(
        ManagedCoreLimits::new(8192, 8192, 32768, notifications, Duration::from_secs(60)).unwrap(),
        Duration::from_secs(10),
    ).unwrap()
}

fn selection(ids: &[&str]) -> DpopTaskSubscription {
    DpopTaskSubscription::new(
        RequestId::Number(1), RequestId::Number(2),
        FinalRequestMeta::new(ClientCapabilities::default()),
        ids.iter().map(|id| TaskId::parse(*id).unwrap()).collect(),
    ).unwrap()
}

fn discovery_result() -> Value {
    json!({"resultType":"complete", "supportedVersions":[FINAL_PROTOCOL_VERSION],
        "capabilities":{"extensions":{TASKS_EXTENSION:{}}},
        "ttlMs":0,"cacheScope":"private",
        "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"task-peer","version":"1"}}})
}

fn discovery(result: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":result})).unwrap()
}

fn response(body: Vec<u8>) -> DpopHttpResponse {
    DpopHttpResponse { status: 200, headers: vec![], body }
}

fn prepared(selected: DpopStreamLimits) -> Prepared {
    Prepared::new(TARGET, selection(&["task-one", "task-two", "task-one"]), selected.core, 8192).unwrap()
}

fn decoder(selected: DpopStreamLimits) -> TaskSubscriptionDecoder {
    prepared(selected).admit(response(discovery(discovery_result()))).unwrap().1
}

fn notification(id: Value, method: &str, mut params: Value) -> Vec<u8> {
    params["_meta"] = json!({FINAL_SUBSCRIPTION_ID_META_KEY:id});
    serde_json::to_vec(&json!({"jsonrpc":"2.0","method":method,"params":params})).unwrap()
}

fn ack(id: Value, filter: Value) -> Vec<u8> {
    notification(id, "notifications/subscriptions/acknowledged", json!({"notifications":filter}))
}

fn status(id: Value, task_id: &str) -> Vec<u8> {
    notification(id, TASK_STATUS_NOTIFICATION, json!({
        "taskId":task_id,"status":"cancelled","createdAt":"2026-09-16T00:00:00Z",
        "lastUpdatedAt":"2026-09-16T00:00:00Z","ttlMs":60000
    }))
}

fn event(bytes: &[u8]) -> Vec<u8> {
    [b"data: ".as_slice(), bytes, b"\r\n\r\n"].concat()
}

fn snapshot(decoder: &TaskSubscriptionDecoder) -> (usize, usize, bool, Option<Vec<TaskId>>) {
    (decoder.bytes, decoder.notifications, decoder.terminal, decoder.accepted.clone())
}

#[test]
fn both_requests_are_exact_bounded_and_tasks_only_before_discovery() {
    let prepared = prepared(limits(3));
    for wire in [&prepared.discovery_wire, &prepared.wire] {
        let body: Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(body["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],
            json!({TASKS_EXTENSION:{}}));
        assert!(wire.headers().iter().any(|(name, value)| name == "Mcp-Method"
            && value == body["method"].as_str().unwrap()));
        assert!(!wire.headers().iter().any(|(name, _)|
            name == "Authorization" || name == "DPoP" || name == "Mcp-Name"));
    }
    let body: Value = serde_json::from_slice(prepared.wire.body()).unwrap();
    assert_eq!(body["id"], 2);
    assert_eq!(body["params"]["notifications"], json!({"taskIds":["task-one","task-two","task-one"]}));
    let exact = prepared.wire.body().len().max(prepared.discovery_wire.body().len());
    for native in [false, true] {
        for short in [false, true] {
            let cap = exact - usize::from(short);
            let core = ManagedCoreLimits::new(
                if native { 8192 } else { cap }, 8192, 32768, 3, Duration::from_secs(60),
            ).unwrap();
            let result = Prepared::new(TARGET, selection(&["task-one","task-two","task-one"]),
                core, if native { cap } else { 8192 });
            if short {
                assert!(matches!(result, Err(DpopStreamError::Core(DpopCoreError::Protocol(
                    ManagedCoreError::RequestTooLarge)))));
            } else { assert!(result.is_ok()); }
        }
    }
}

#[test]
fn invalid_selection_and_unnegotiated_metadata_never_prepare_a_listen() {
    for count in [0, MAX_TASK_SUBSCRIPTION_IDS + 1] {
        assert!(DpopTaskSubscription::new(RequestId::Number(1), RequestId::Number(2),
            FinalRequestMeta::new(ClientCapabilities::default()),
            vec![TaskId::parse("task-one").unwrap(); count]).is_err());
    }
    assert!(DpopTaskSubscription::new(RequestId::Number(1), RequestId::Number(1),
        FinalRequestMeta::new(ClientCapabilities::default()),
        vec![TaskId::parse("task-one").unwrap()]).is_err());
    let mut selected = selection(&["task-one"]);
    let mut metadata = serde_json::to_value(selected.metadata).unwrap();
    metadata[FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"] = json!({TASKS_EXTENSION:{}});
    selected.metadata = serde_json::from_value(metadata).unwrap();
    assert!(matches!(Prepared::new(TARGET, selected, limits(2).core, 8192),
        Err(DpopStreamError::Task(DpopTasksError::Task(ManagedTasksError::Negotiation)))));
    assert!(matches!(Prepared::new(TARGET, selection(&["task-one"]), limits(0).core, 8192),
        Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidLimits)))));
    // Adding the Tasks listener must not grant its extension to core-only APIs.
    let params = serde_json::from_value(json!({
        "_meta":FinalRequestMeta::new(ClientCapabilities::default()),
        "notifications":{"taskIds":["task-one"]},
    })).unwrap();
    assert!(crate::http_auth::rpc::subscription::prepare_bounded(
        TARGET, params, RequestId::Number(2), limits(2).core, 8192,
    ).is_err());
}

#[test]
fn authenticated_discovery_is_required_and_charged_to_the_same_budget() {
    let bytes = discovery(discovery_result());
    assert_eq!(decoder(limits(2)).usage(), (bytes.len(), 0));
    let mut absent = discovery_result();
    absent["capabilities"] = json!({});
    assert!(prepared(limits(2)).admit(response(discovery(absent))).is_err());
    let mut wrong_id: Value = serde_json::from_slice(&bytes).unwrap();
    wrong_id["id"] = json!("1");
    assert!(prepared(limits(2)).admit(response(serde_json::to_vec(&wrong_id).unwrap())).is_err());
    let core = ManagedCoreLimits::new(8192, bytes.len(), bytes.len(), 2, Duration::from_secs(60)).unwrap();
    assert!(matches!(Prepared::new(TARGET, selection(&["task-one"]), core, 8192).unwrap()
        .admit(response(bytes)),
        Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit)))));
}

#[test]
fn only_acknowledged_exact_ids_reach_the_typed_status_observer() {
    let mut decoder = decoder(limits(4));
    let before = snapshot(&decoder);
    for invalid in [
        status(json!(2), "task-one"),
        ack(json!("2"), json!({"taskIds":["task-one"]})),
        ack(json!(2), json!({"taskIds":["task-three"]})),
        ack(json!(2), json!({"taskIds":["task-one","task-one"]})),
        ack(json!(2), json!({"taskIds":["task-one"],"toolsListChanged":true})),
        ack(json!(2), json!({"taskIds":["task-one"],"x-unnegotiated":{}})),
        COMPLETE.as_bytes().to_vec(),
    ] {
        assert!(decoder.admit(&invalid, true).is_err());
        assert_eq!(snapshot(&decoder), before, "refusal cannot mutate admission state");
    }
    assert!(matches!(decoder.admit(&ack(json!(2), json!({"taskIds":["task-one"]})), true).unwrap(),
        StreamEvent::Notification(event) if matches!(*event, DpopTaskSubscriptionEvent::Acknowledged(_))));
    let before = snapshot(&decoder);
    for invalid in [
        status(json!(3), "task-one"),
        status(json!(2), "task-two"),
        status(json!(2), "TASK-one"),
        ack(json!(2), json!({"taskIds":["task-one"]})),
        notification(json!(2), "notifications/tools/list_changed", json!({})),
        notification(json!(2), "notifications/progress", json!({"progressToken":"x","progress":1})),
        br#"[{"jsonrpc":"2.0","method":"notifications/tasks","params":{}}]"#.to_vec(),
    ] {
        assert!(decoder.admit(&invalid, true).is_err());
        assert_eq!(snapshot(&decoder), before);
    }
    let StreamEvent::Notification(observed) = decoder.admit(&status(json!(2), "task-one"), true).unwrap() else {
        panic!("expected a live Task status");
    };
    assert!(matches!(*observed, DpopTaskSubscriptionEvent::Task(ref value)
        if value.params.task.base().task_id.as_str() == "task-one"));
    assert!(!observed.is_progress());
    let StreamEvent::Result(result) = decoder.admit(COMPLETE.as_bytes(), true).unwrap() else {
        panic!("expected the listen's separate completion");
    };
    let encoded = result.encode().unwrap();
    assert!(encoded.contains("900719925474099312345"));
    assert!(encoded.contains("1.20e+4"));
    let before = snapshot(&decoder);
    assert!(decoder.admit(COMPLETE.as_bytes(), true).is_err());
    assert_eq!(snapshot(&decoder), before);
}

#[test]
fn an_empty_accepted_subset_can_complete_but_cannot_publish_task_statuses() {
    for filter in [json!({}), json!({"taskIds":[]})] {
        let mut decoder = decoder(limits(2));
        decoder.admit(&ack(json!(2), filter), true).unwrap();
        assert!(decoder.admit(&status(json!(2), "task-one"), true).is_err());
        assert!(matches!(decoder.admit(COMPLETE.as_bytes(), true).unwrap(), StreamEvent::Result(_)));
    }
}

#[test]
fn discovery_ack_status_and_completion_share_exact_byte_and_notification_bounds() {
    let discovery = discovery(discovery_result());
    let ack = ack(json!(2), json!({"taskIds":["task-one"]}));
    let status = status(json!(2), "task-one");
    let frames = [&discovery[..], &ack[..], &status[..], COMPLETE.as_bytes()];
    let total: usize = frames.iter().map(|frame| frame.len()).sum();
    let maximum = frames.iter().map(|frame| frame.len()).max().unwrap();
    for short in [0, 1, 2] {
        let core = ManagedCoreLimits::new(8192, maximum, total - usize::from(short == 1),
            if short == 2 { 1 } else { 2 }, Duration::from_secs(60)).unwrap();
        let (_, mut decoder) = Prepared::new(TARGET, selection(&["task-one"]), core, 8192).unwrap()
            .admit(response(discovery.clone())).unwrap();
        decoder.admit(&ack, true).unwrap();
        if short == 2 {
            let before = snapshot(&decoder);
            assert!(matches!(decoder.admit(&status, true),
                Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::NotificationLimit)))));
            assert_eq!(snapshot(&decoder), before);
            // Exhausted notification count must still permit completion.
            decoder.admit(COMPLETE.as_bytes(), true).unwrap();
        } else {
            decoder.admit(&status, true).unwrap();
            let result = decoder.admit(COMPLETE.as_bytes(), true);
            if short == 1 {
                assert!(matches!(result,
                    Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit)))));
            } else {
                assert!(result.is_ok());
                assert_eq!(decoder.usage(), (total, 2));
            }
        }
    }
}

fn fixture(f: impl FnOnce(&Lifetime<'_>)) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(clock);
    let runtime = RuntimeBuilder::current_thread().blocking_threads(0, 0)
        .with_timer_driver(timer.clone()).build().unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
    let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(),
        CanonicalHttpUrl::parse(TARGET).unwrap()).unwrap();
    let credential = session.admit_token_response(&issuer, 200,
        br#"{"access_token":"task-subscription-token","token_type":"DPoP","expires_in":300}"#,
        Instant::now(), Duration::from_secs(300)).unwrap();
    let cancellation = McpRequestCancellation::new();
    let bounds = WaitBounds::new(&cx, Duration::from_secs(60), &credential).unwrap();
    let life = Lifetime { cx: &cx, cancellation: &cancellation, session: &session, credential: &credential, bounds };
    with_caller(&cx, || f(&life));
    assert_eq!(timer.pending_count(), 0);
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

fn reader(kind: ModernHttpResponseKind) -> Reader<TaskSubscriptionDecoder, DpopTaskSubscriptionEvent> {
    Reader::new(kind, decoder(limits(8)), limits(8), 32768).unwrap()
}

#[test]
fn shared_reader_delivers_live_events_at_every_byte_split_and_waits_for_clean_eof() {
    fixture(|life| {
        let acknowledgement = event(&ack(json!(2), json!({"taskIds":["task-one"]})));
        let changed = event(&status(json!(2), "task-one"));
        let wire = [acknowledgement.as_slice(), &changed, &event(COMPLETE.as_bytes())].concat();
        for split in 0..=wire.len() {
            let mut reader = reader(ModernHttpResponseKind::Sse);
            let mut idle = Idle::new(life.cx.now(), limits(8).idle);
            let initial_idle = idle.deadline;
            let mut seen = Vec::new();
            let mut observer = |event: &DpopTaskSubscriptionEvent| {
                seen.push(matches!(event, DpopTaskSubscriptionEvent::Acknowledged(_))); true
            };
            reader.push(&wire[..split], life, &mut idle, &mut observer).unwrap();
            reader.push(&wire[split..], life, &mut idle, &mut observer).unwrap();
            assert_eq!(seen, [true, false]);
            assert_eq!(idle.deadline, initial_idle, "Task events are not progress");
            assert!(reader.terminal.is_some());
            assert!(reader.finish(life, &idle).is_ok());
        }
        let mut reader = reader(ModernHttpResponseKind::Sse);
        let mut idle = Idle::new(life.cx.now(), limits(8).idle);
        let mut seen = 0;
        reader.push(&acknowledgement, life, &mut idle, &mut |_| { seen += 1; true }).unwrap();
        assert_eq!(seen, 1, "acknowledgement is visible while the stream is live");
        assert!(reader.terminal.is_none());
    });
}

#[test]
fn shared_reader_withholds_provisional_completion_after_bad_tail_or_premature_eof() {
    fixture(|life| {
        let acknowledgement = event(&ack(json!(2), json!({"taskIds":["task-one"]})));
        let complete = event(COMPLETE.as_bytes());
        for tail in [b"data: unfinished".to_vec(), complete.clone(), event(&status(json!(2), "task-one"))] {
            let mut reader = reader(ModernHttpResponseKind::Sse);
            let mut idle = Idle::new(life.cx.now(), limits(8).idle);
            reader.push(&acknowledgement, life, &mut idle, &mut |_| true).unwrap();
            reader.push(&complete, life, &mut idle, &mut |_| true).unwrap();
            let pushed = reader.push(&tail, life, &mut idle, &mut |_| panic!("post-terminal event escaped"));
            assert!(pushed.is_err() || reader.finish(life, &idle).is_err());
        }
        let mut reader = reader(ModernHttpResponseKind::Sse);
        let mut idle = Idle::new(life.cx.now(), limits(8).idle);
        reader.push(&acknowledgement, life, &mut idle, &mut |_| true).unwrap();
        assert!(matches!(reader.finish(life, &idle),
            Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::MissingTerminal)))));
    });
}

#[test]
fn finite_json_only_reports_redacted_correlated_refusal_never_subscription_success() {
    let refusal = br#"{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"secret-peer-message","data":"secret-peer-data"}}"#;
    let mut decoder = decoder(limits(2));
    let before = snapshot(&decoder);
    let error = decoder.admit(refusal, false).err().unwrap();
    assert!(matches!(&error, DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::Remote { .. }))));
    assert!(!format!("{error:?} {error}").contains("secret-peer"));
    assert_eq!(snapshot(&decoder), before);
    assert!(decoder.admit(COMPLETE.as_bytes(), false).is_err());
    assert_eq!(snapshot(&decoder), before);
}

#[test]
fn cancellation_and_revocation_win_over_coalesced_events_and_observer_refusal() {
    for revoked in [false, true] {
        fixture(|life| {
            let mut reader = reader(ModernHttpResponseKind::Sse);
            let mut idle = Idle::new(life.cx.now(), limits(8).idle);
            let wire = [event(&ack(json!(2), json!({"taskIds":["task-one"]}))),
                event(&status(json!(2), "task-one")), event(COMPLETE.as_bytes())].concat();
            let mut calls = 0;
            let result = reader.push(&wire, life, &mut idle, &mut |_| {
                calls += 1;
                if revoked { life.credential.revoke(); } else { life.cancellation.cancel(); }
                false
            });
            assert_eq!(calls, 1);
            assert!(matches!(result, Err(DpopStreamError::Core(DpopCoreError::Transport(_)))));
            assert!(life.cx.checkpoint().is_ok());
        });
    }
}
