//! Driver state and real Task-codec regression tests. Network cases are separate.

mod stream;

use super::*;
use std::collections::HashSet;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::ClientCapabilities;
use fastmcp_protocol::dpop::DpopKey;
use fastmcp_protocol::tasks_extension::TaskInputResponses;
use serde_json::{Value, json};

use crate::http_auth::dpop::DpopSession;
use crate::http_auth::dpop::native::DpopHttpPolicy;
use crate::http_auth::dpop::native::core::DpopCoreError;

const TARGET: &str = "https://mcp.example/mcp?tenant=one";

fn metadata() -> FinalRequestMeta {
    FinalRequestMeta::new(ClientCapabilities::default())
}

fn task(status: &str) -> Task {
    let mut value = json!({
        "taskId":"task-one", "status":status,
        "createdAt":"2026-09-17T00:00:00Z", "lastUpdatedAt":"2026-09-17T00:00:00Z",
        "ttlMs":null,
    });
    if status == "input_required" {
        value["inputRequests"] = json!({
            "one":{"method":"roots/list"}, "two":{"method":"roots/list"},
        });
    }
    serde_json::from_value(value).unwrap()
}

fn get() -> ManagedTaskRequest {
    ManagedTaskRequest::Get(TaskId::parse("task-one").unwrap())
}

fn update() -> ManagedTaskRequest {
    ManagedTaskRequest::Update {
        task: Box::new(task("input_required")),
        input_responses: serde_json::from_value(json!({"one":{"roots":[]}})).unwrap(),
    }
}

fn prepare(run: &mut Run, request: ManagedTaskRequest, limits: ManagedCoreLimits) -> Prepared {
    run.prepare(TARGET, metadata(), request, limits, 8 * 1024 * 1024).unwrap()
}

fn response(id: &RequestId, result: Value) -> DpopHttpResponse {
    DpopHttpResponse {
        status: 200,
        headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
        body: serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result})).unwrap(),
    }
}

fn discovery(prepared: &Prepared) -> DpopHttpResponse {
    let wire: Value = serde_json::from_slice(prepared.discovery_wire.body()).unwrap();
    response(&serde_json::from_value(wire["id"].clone()).unwrap(), json!({
        "resultType":"complete", "supportedVersions":[super::super::FINAL_PROTOCOL_VERSION],
        "capabilities":{"tools":{},"extensions":{super::super::TASKS_EXTENSION:{}}},
        "ttlMs":0,"cacheScope":"private",
        "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"driver-peer","version":"1"}},
    }))
}

fn snapshot(admitted: &Admitted, value: Task) -> DpopHttpResponse {
    let mut value = serde_json::to_value(value).unwrap();
    value["resultType"] = json!("complete");
    response(&admitted.id, value)
}

fn admit(run: &mut Run, prepared: Prepared) -> Admitted {
    let response = discovery(&prepared);
    run.admit(prepared, response).unwrap()
}

#[test]
fn generated_ids_are_distinct_across_discovery_poll_and_update() {
    let limits = ManagedCoreLimits::default();
    let mut run = Run::new("run", ManagedTaskDriverPolicy::default(), limits).unwrap();
    let mut identities = HashSet::new();
    for (round, request) in [get(), update(), get()].into_iter().enumerate() {
        let prepared = prepare(&mut run, request, limits);
        for (wire, suffix) in [
            (&prepared.discovery_wire, "discover"), (&prepared.operation_wire, "task"),
        ] {
            let body: Value = serde_json::from_slice(wire.body()).unwrap();
            let id = body["id"].as_str().unwrap();
            assert_eq!(id, format!("run.{round}.{suffix}"));
            assert!(identities.insert(id.to_owned()));
            assert_eq!(wire.target(), TARGET);
            assert_eq!(body["params"]["_meta"][super::super::FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],
                json!({super::super::TASKS_EXTENSION:{}}));
        }
    }
    assert_eq!((run.polls, run.updates, run.sequence), (2, 1, 3));
}

#[test]
fn poll_update_and_state_limits_refuse_before_admitting_another_pair() {
    let limits = ManagedCoreLimits::default();
    let policy = ManagedTaskDriverPolicy::new(Duration::from_millis(1), Duration::from_secs(10),
        1, 1, 16, 8192).unwrap();
    let mut run = Run::new("bounded", policy, limits).unwrap();
    prepare(&mut run, get(), limits);
    assert!(matches!(run.prepare(TARGET, metadata(), get(), limits, 8192),
        Err(DpopTaskDriverError::Driver(ManagedTaskDriverError::PollLimit))));
    prepare(&mut run, update(), limits);
    assert!(matches!(run.prepare(TARGET, metadata(), update(), limits, 8192),
        Err(DpopTaskDriverError::Driver(ManagedTaskDriverError::UpdateLimit))));
    assert_eq!((run.polls, run.updates, run.sequence), (1, 1, 2));
    assert!(run.prepare(TARGET, metadata(), ManagedTaskRequest::Cancel(TaskId::parse("task-one").unwrap()),
        limits, 8192).is_err());
    assert_eq!(run.sequence, 2);
    let policy = ManagedTaskDriverPolicy::new(Duration::from_millis(1), Duration::from_secs(10),
        1, 0, 0, 1).unwrap();
    let mut tiny = Run::new("bounded", policy, limits).unwrap();
    assert!(matches!(tiny.prepare(TARGET, metadata(), get(), limits, 8192),
        Err(DpopTaskDriverError::Driver(ManagedTaskDriverError::StateByteLimit))));
    assert_eq!((tiny.polls, tiny.updates, tiny.sequence), (0, 0, 0));
}

fn pair_sizes() -> (usize, usize) {
    let limits = ManagedCoreLimits::default();
    let mut run = Run::new("run", ManagedTaskDriverPolicy::default(), limits).unwrap();
    let prepared = prepare(&mut run, get(), limits);
    let first = discovery(&prepared).body.len();
    let admitted = admit(&mut run, prepared);
    (first, snapshot(&admitted, task("working")).body.len())
}

#[test]
fn all_discovery_and_snapshot_bytes_share_the_whole_run_limit() {
    let (first, last) = pair_sizes();
    for exact in [false, true] {
        let total = 2 * (first + last) - usize::from(!exact);
        let limits = ManagedCoreLimits::new(8192, first.max(last), total, 0,
            Duration::from_secs(10)).unwrap();
        let mut run = Run::new("run", ManagedTaskDriverPolicy::default(), limits).unwrap();
        let prepared = prepare(&mut run, get(), limits);
        let admitted = admit(&mut run, prepared);
        let response = snapshot(&admitted, task("working"));
        assert!(matches!(run.finish(admitted, response).unwrap(), ManagedTaskEvent::Snapshot(_)));
        assert_eq!(run.remaining_bytes, total - first - last);
        let prepared = prepare(&mut run, get(), limits);
        let admitted = admit(&mut run, prepared);
        assert_eq!(admitted.maximum, last - usize::from(!exact));
        let response = snapshot(&admitted, task("working"));
        let result = run.finish(admitted, response);
        if exact {
            assert!(matches!(result.unwrap(), ManagedTaskEvent::Snapshot(_)));
            assert_eq!(run.remaining_bytes, 0);
            assert!(matches!(run.prepare(TARGET, metadata(), get(), limits, 8192),
                Err(DpopTaskDriverError::Task(DpopTasksError::Core(DpopCoreError::Protocol(
                    ManagedCoreError::ResponseByteLimit))))));
        } else {
            assert!(matches!(result,
                Err(DpopTaskDriverError::Task(DpopTasksError::Core(DpopCoreError::Protocol(
                    ManagedCoreError::ResponseByteLimit))))));
            assert_eq!(run.remaining_bytes, last - 1);
        }
    }
}

#[test]
fn exhausted_discovery_cannot_release_a_second_operation_request() {
    let (first, last) = pair_sizes();
    let limits = ManagedCoreLimits::new(8192, first.max(last), 2 * first + last, 0,
        Duration::from_secs(10)).unwrap();
    let mut run = Run::new("run", ManagedTaskDriverPolicy::default(), limits).unwrap();
    let prepared = prepare(&mut run, get(), limits);
    let admitted = admit(&mut run, prepared);
    let response = snapshot(&admitted, task("working"));
    run.finish(admitted, response).unwrap();
    let prepared = prepare(&mut run, get(), limits);
    let response = discovery(&prepared);
    assert_eq!(run.remaining_bytes, response.body.len());
    assert!(matches!(run.admit(prepared, response),
        Err(DpopTaskDriverError::Task(DpopTasksError::Core(DpopCoreError::Protocol(
            ManagedCoreError::ResponseByteLimit))))));
    assert_eq!(run.remaining_bytes, 0);
}

#[test]
fn acknowledged_inputs_are_not_resolved_again_but_changed_descriptors_fail() {
    let limits = ManagedCoreLimits::default();
    let policy = ManagedTaskDriverPolicy::default();
    let mut run = Run::new("run", policy, limits).unwrap();
    let Task::InputRequired { input_requests, .. } = task("input_required") else { unreachable!() };
    let (pending, prints) = run.state.unanswered(&input_requests, policy).unwrap();
    let replies: TaskInputResponses = serde_json::from_value(json!({"one":{"roots":[]}})).unwrap();
    validate_answers(&pending, &replies).unwrap();
    let keys = vec!["one".to_owned()];
    let prepared = prepare(&mut run, update(), limits);
    run.state.answer_bytes(&keys, &prints, policy.maximum_state_bytes).unwrap();
    // Preparing an update alone cannot suppress future input resolution.
    assert_eq!(run.state.unanswered(&input_requests, policy).unwrap().0.len(), 2);
    let admitted = admit(&mut run, prepared);
    let ack = response(&admitted.id, json!({"resultType":"complete"}));
    assert!(matches!(run.finish(admitted, ack).unwrap(), ManagedTaskEvent::Updated(_)));
    run.state.record_answers(&keys, &prints, policy.maximum_state_bytes).unwrap();
    let pending = run.state.unanswered(&input_requests, policy).unwrap().0;
    assert_eq!(pending.keys().map(String::as_str).collect::<Vec<_>>(), vec!["two"]);
    let changed: TaskInputRequests = serde_json::from_value(json!({
        "one":{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":1}},
    })).unwrap();
    assert!(matches!(run.state.unanswered(&changed, policy), Err(ManagedTaskDriverError::InputKeyReused)));
    assert_eq!(run.state.unanswered(&input_requests, policy).unwrap().0.len(), 1);
}

#[test]
fn failed_update_reply_does_not_claim_answer_acknowledgement() {
    let limits = ManagedCoreLimits::default();
    let policy = ManagedTaskDriverPolicy::default();
    let mut run = Run::new("run", policy, limits).unwrap();
    let prepared = prepare(&mut run, update(), limits);
    let admitted = admit(&mut run, prepared);
    let mut response = response(&admitted.id, json!({"resultType":"complete"}));
    response.status = 401;
    assert!(matches!(run.finish(admitted, response),
        Err(DpopTaskDriverError::Task(DpopTasksError::Task(ManagedTasksError::HttpStatus { status: 401 })))));
    let Task::InputRequired { input_requests, .. } = task("input_required") else { unreachable!() };
    assert_eq!(run.state.unanswered(&input_requests, policy).unwrap().0.len(), 2);
}

#[test]
fn invalid_metadata_or_wire_size_does_not_spend_an_identity() {
    let limits = ManagedCoreLimits::default();
    let mut run = Run::new("run", ManagedTaskDriverPolicy::default(), limits).unwrap();
    let mut other = metadata();
    other.client_capabilities = serde_json::from_value(json!({"extensions":{"com.example/other":{}}})).unwrap();
    assert!(run.prepare(TARGET, other, get(), limits, 8192).is_err());
    assert!(run.prepare(TARGET, metadata(), get(), limits, 1).is_err());
    assert_eq!((run.polls, run.sequence), (0, 0));
    let prepared = prepare(&mut run, get(), limits);
    let wire: Value = serde_json::from_slice(prepared.discovery_wire.body()).unwrap();
    assert_eq!(wire["id"], "run.0.discover");
}

#[test]
fn prefixes_are_bounded_and_identity_overflow_does_not_wrap() {
    let policy = ManagedTaskDriverPolicy::default();
    let limits = ManagedCoreLimits::default();
    for prefix in ["".to_owned(), "x".repeat(129), "private\nvalue".to_owned(), "雪".to_owned()] {
        let error = Run::new(&prefix, policy, limits).err().unwrap();
        assert!(matches!(error, DpopTaskDriverError::InvalidIdPrefix));
        assert!(!format!("{error:?} {error}").contains("private"));
    }
    let mut run = Run::new(&"x".repeat(128), policy, limits).unwrap();
    run.sequence = usize::MAX;
    assert!(matches!(run.prepare(TARGET, metadata(), get(), limits, 8192),
        Err(DpopTaskDriverError::IdentityExhausted)));
    assert_eq!((run.polls, run.updates, run.sequence), (0, 0, usize::MAX));
}

fn client() -> (DpopHttpClient, DpopCredential) {
    let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
    let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(),
        CanonicalHttpUrl::parse(TARGET).unwrap()).unwrap();
    let credential = session.admit_token_response(&issuer, 200,
        br#"{"access_token":"driver-token","token_type":"DPoP","expires_in":60}"#,
        Instant::now(), Duration::from_secs(60)).unwrap();
    (DpopHttpClient::new(session, DpopHttpPolicy::default()).unwrap(), credential)
}

#[test]
fn precancelled_public_driver_never_needs_network_or_invokes_host_code() {
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let (mut client, credential) = client();
    let mut drive = Box::pin(client.drive_task(&cx, &credential, metadata(),
        TaskId::parse("task-one").unwrap(), "run", ManagedTaskDriverPolicy::default(),
        ManagedCoreLimits::default(),
        |_| { panic!("cancelled driver invoked resolver"); #[allow(unreachable_code)]
            std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller)) },
        |_| panic!("cancelled driver invoked observer")));
    assert!(matches!(drive.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(DpopTaskDriverError::Task(DpopTasksError::Core(DpopCoreError::Transport(
            DpopHttpError::Cancelled)))))));
}
