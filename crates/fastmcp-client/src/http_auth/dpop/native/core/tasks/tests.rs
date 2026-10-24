//! Protocol and public-entrypoint regressions for explicit DPoP Tasks.

use super::*;
use std::future::Future;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::ClientCapabilities;
use fastmcp_protocol::dpop::DpopKey;
use crate::http_auth::dpop::DpopSession;
use crate::http_auth::dpop::native::DpopHttpPolicy;

#[cfg(feature = "native-tls-roots")]
mod tls;

const TARGET: &str = "https://mcp.example/mcp?tenant=one";
const TASK_FIELDS: &str = r#""taskId":"task-one","status":"working","createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z","ttlMs":60000"#;

fn metadata() -> FinalRequestMeta {
    FinalRequestMeta::new(ClientCapabilities::default())
}
fn id() -> TaskId { TaskId::parse("task-one").unwrap() }
fn operation(request: ManagedTaskRequest) -> DpopTaskOperation {
    DpopTaskOperation::new(RequestId::Number(1), RequestId::Number(2), request).unwrap()
}
fn prepared(request: ManagedTaskRequest) -> Prepared {
    Prepared::new(TARGET, metadata(), operation(request), ManagedCoreLimits::default(), 8 * 1024 * 1024).unwrap()
}
fn tool() -> ManagedTaskRequest {
    ManagedTaskRequest::CallTool { name: "echo".to_owned(), arguments: Some(json!({"exact":[1,"雪",true]})) }
}
fn input_task() -> Task {
    serde_json::from_value(json!({
        "taskId":"task-one","status":"input_required","createdAt":"2026-09-16T00:00:00Z",
        "lastUpdatedAt":"2026-09-16T00:00:00Z","ttlMs":60000,
        "inputRequests":{"roots":{"method":"roots/list"}},
    })).unwrap()
}
fn update() -> ManagedTaskRequest {
    ManagedTaskRequest::Update { task: Box::new(input_task()),
        input_responses: serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap() }
}
fn response(status: u16, body: Vec<u8>) -> DpopHttpResponse {
    DpopHttpResponse { status, headers: vec![("Content-Type".to_owned(),"application/json".to_owned())], body }
}
fn envelope(id: &RequestId, result: &str) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":{},"result":{result}}}"#, serde_json::to_string(id).unwrap()).into_bytes()
}
fn discovery_result() -> Value {
    json!({"resultType":"complete","supportedVersions":[FINAL_PROTOCOL_VERSION],
        "capabilities":{"tools":{},"extensions":{TASKS_EXTENSION:{}}},
        "ttlMs":0,"cacheScope":"private",
        "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"task-peer","version":"1"}}})
}
fn discovery() -> DpopHttpResponse {
    response(200, envelope(&RequestId::Number(1), &discovery_result().to_string()))
}
fn terminal(result: &str) -> DpopHttpResponse {
    response(200, envelope(&RequestId::Number(2), result))
}
fn task_result(kind: &str) -> String {
    format!(r#"{{"resultType":"{kind}",{TASK_FIELDS}}}"#)
}

#[test]
fn request_ids_validate_numeric_aliases_without_conflating_strings() {
    for alias in ["1", "1.0", "1e0"] {
        let other: RequestId = serde_json::from_str(alias).unwrap();
        assert!(DpopTaskOperation::new(RequestId::Number(1), other, tool()).is_err());
    }
    assert!(DpopTaskOperation::new(RequestId::Number(1), RequestId::String("1".to_owned()), tool()).is_ok());
    let request = prepared(tool());
    let first: Value = serde_json::from_slice(request.discovery_wire.body()).unwrap();
    let second: Value = serde_json::from_slice(request.operation_wire.body()).unwrap();
    assert_eq!(first["id"], 1);
    assert_eq!(second["id"], 2);
}

#[test]
fn preparation_stamps_both_requests_and_preserves_method_owned_arguments() {
    for (request, method) in [
        (tool(), "tools/call"), (ManagedTaskRequest::Get(id()), TASK_GET),
        (update(), TASK_UPDATE), (ManagedTaskRequest::Cancel(id()), TASK_CANCEL),
    ] {
        let prepared = prepared(request);
        for wire in [&prepared.discovery_wire, &prepared.operation_wire] {
            assert_eq!(wire.target(), TARGET);
            let body: Value = serde_json::from_slice(wire.body()).unwrap();
            assert_eq!(body["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"], json!({TASKS_EXTENSION:{}}));
            assert!(!wire.headers().iter().any(|(name, _)| name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("dpop")));
        }
        let body: Value = serde_json::from_slice(prepared.operation_wire.body()).unwrap();
        assert_eq!(body["method"], method);
        if method == "tools/call" {
            assert_eq!(body["params"]["arguments"], json!({"exact":[1,"雪",true]}));
            assert!(prepared.operation_wire.headers().iter().any(|(name, value)| name == "Mcp-Name" && value == "echo"));
        } else {
            assert_eq!(body["params"]["taskId"], "task-one");
        }
    }
    let mut other = metadata();
    other.client_capabilities = serde_json::from_value(json!({"extensions":{"com.example/other":{}}})).unwrap();
    assert!(matches!(Prepared::new(TARGET, other, operation(tool()), ManagedCoreLimits::default(), 8192),
        Err(DpopTasksError::Task(ManagedTasksError::Negotiation))));
}

#[test]
fn input_answers_require_the_observed_ledger_before_discovery() {
    assert!(Prepared::new(TARGET, metadata(), operation(update()), ManagedCoreLimits::default(), 8192).is_ok());
    for answers in [json!({"other":{"roots":[]}}), json!({"roots":{"action":"accept"}})] {
        let request = ManagedTaskRequest::Update { task: Box::new(input_task()),
            input_responses: serde_json::from_value(answers).unwrap() };
        assert!(matches!(Prepared::new(TARGET, metadata(), operation(request), ManagedCoreLimits::default(), 8192),
            Err(DpopTasksError::Task(ManagedTasksError::InvalidInputResponses))));
    }
    let working: Task = serde_json::from_str(&format!("{{{TASK_FIELDS}}}")).unwrap();
    let request = ManagedTaskRequest::Update { task: Box::new(working),
        input_responses: serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap() };
    assert!(matches!(Prepared::new(TARGET, metadata(), operation(request), ManagedCoreLimits::default(), 8192),
        Err(DpopTasksError::Task(ManagedTasksError::UpdateRequiresInput))));
}

#[test]
fn discovery_requires_the_exact_offer_not_a_tasks_shaped_response() {
    for request in [tool(), ManagedTaskRequest::Get(id()), update(), ManagedTaskRequest::Cancel(id())] {
        assert!(prepared(request).admit(discovery()).is_ok());
    }
    for changed in 0..4 {
        let mut result = discovery_result();
        match changed {
            0 => { result["capabilities"]["extensions"] = json!({}); }
            1 => { result["capabilities"]["extensions"][TASKS_EXTENSION] = json!({"unreviewed":true}); }
            2 => { result["supportedVersions"] = json!(["2025-11-25"]); }
            _ => { result["capabilities"]["extensions"] = json!({"com.example/tasks":{}}); }
        }
        assert!(prepared(ManagedTaskRequest::Get(id())).admit(response(200,
            envelope(&RequestId::Number(1), &result.to_string()))).is_err());
    }
    let wrong_id = response(200, envelope(&RequestId::String("1".to_owned()), &discovery_result().to_string()));
    assert!(matches!(prepared(tool()).admit(wrong_id),
        Err(DpopTasksError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseIdMismatch)))));
    for status in [202, 307, 401, 500] {
        let mut denied = discovery();
        denied.status = status;
        assert!(matches!(prepared(tool()).admit(denied),
            Err(DpopTasksError::Core(DpopCoreError::Protocol(ManagedCoreError::HttpStatus { .. })))));
    }
}

#[test]
fn tool_results_do_not_force_task_creation_and_mutation_acks_do_not_invent_snapshots() {
    for (source, kind) in [
        (r#"{"resultType":"complete","content":[],"x-exact":{"z":900719925474099312345,"a":1.20e+4}}"#.to_owned(), 0),
        (task_result("task"), 1),
        (r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"opaque-state"}"#.to_owned(), 2),
    ] {
        let result = prepared(tool()).admit(discovery()).unwrap().finish(terminal(&source)).unwrap();
        let ManagedTaskEvent::ToolResult(result) = result else { panic!("expected typed tool result"); };
        assert!(matches!(
            (kind, *result),
            (0, FinalCoreResult::ToolsCall { .. })
                | (1, FinalCoreResult::ToolsCallTask { .. })
                | (2, FinalCoreResult::ToolsCallInputRequired { .. })
        ));
    }
    assert!(matches!(prepared(update()).admit(discovery()).unwrap()
        .finish(terminal(r#"{"resultType":"complete"}"#)), Ok(ManagedTaskEvent::Updated(_))));
    assert!(matches!(prepared(ManagedTaskRequest::Cancel(id())).admit(discovery()).unwrap()
        .finish(terminal(r#"{"resultType":"complete"}"#)), Ok(ManagedTaskEvent::Cancelled(_))));
}

#[test]
fn task_identity_and_raw_input_shape_are_checked_after_response_correlation() {
    assert!(matches!(prepared(ManagedTaskRequest::Get(id())).admit(discovery()).unwrap()
        .finish(terminal(&task_result("complete"))), Ok(ManagedTaskEvent::Snapshot(_))));
    let changed = task_result("complete").replace("task-one", "task-two");
    assert!(matches!(prepared(ManagedTaskRequest::Get(id())).admit(discovery()).unwrap()
        .finish(terminal(&changed)), Err(DpopTasksError::Task(ManagedTasksError::TaskIdMismatch))));
    let mut invalid = serde_json::to_value(input_task()).unwrap();
    invalid["resultType"] = json!("complete");
    invalid["inputRequests"]["roots"]["params"] = json!([]);
    assert!(matches!(prepared(ManagedTaskRequest::Get(id())).admit(discovery()).unwrap()
        .finish(terminal(&invalid.to_string())), Err(DpopTasksError::Task(ManagedTasksError::InvalidResponse))));
    let bytes = envelope(&RequestId::String("2".to_owned()), &invalid.to_string());
    assert!(matches!(prepared(ManagedTaskRequest::Get(id())).admit(discovery()).unwrap()
        .finish(response(200, bytes)), Err(DpopTasksError::Task(ManagedTasksError::ResponseIdMismatch))));
}

#[test]
fn terminal_admission_rejects_batches_duplicates_trailing_data_and_redacts_peer_errors() {
    for bytes in [
        br#"[{"jsonrpc":"2.0","id":2,"result":{}}]"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":2,"id":2,"result":{}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":2,"result":{}}{}"#.as_slice(),
        br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#.as_slice(),
    ] {
        assert!(prepared(tool()).admit(discovery()).unwrap().finish(response(200, bytes.to_vec())).is_err());
    }
    let error = prepared(tool()).admit(discovery()).unwrap().finish(response(200,
        br#"{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"private-token","data":{"proof":"private-proof"}}}"#.to_vec())).err().unwrap();
    assert!(matches!(&error, DpopTasksError::Task(ManagedTasksError::Remote { .. })));
    assert!(!format!("{error:?} {error}").contains("private"));
    let mut challenge = terminal(&task_result("task"));
    challenge.status = 401;
    assert!(matches!(prepared(tool()).admit(discovery()).unwrap().finish(challenge),
        Err(DpopTasksError::Task(ManagedTasksError::HttpStatus { status:401 }))));
}

#[test]
fn response_budget_is_cumulative_across_discovery_and_operation() {
    let first = discovery().body.len();
    let last = terminal(&task_result("task")).body.len();
    for exact in [false, true] {
        let limits = ManagedCoreLimits::new(8192, first.max(last), first + last - usize::from(!exact), 0, Duration::from_secs(10)).unwrap();
        let prepared = Prepared::new(TARGET, metadata(), operation(tool()), limits, 8192).unwrap();
        let result = prepared.admit(discovery()).unwrap().finish(terminal(&task_result("task")));
        if exact {
            assert!(matches!(result, Ok(ManagedTaskEvent::ToolResult(_))));
        } else {
            assert!(matches!(result, Err(DpopTasksError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit)))));
        }
    }
    let limits = ManagedCoreLimits::new(8192, first, first, 0, Duration::from_secs(10)).unwrap();
    assert!(matches!(Prepared::new(TARGET, metadata(), operation(tool()), limits, 8192).unwrap().admit(discovery()),
        Err(DpopTasksError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit)))));
}

#[test]
fn both_requests_are_byte_bounded_before_any_discovery() {
    let ordinary = prepared(tool());
    let needed = ordinary.discovery_wire.body().len().max(ordinary.operation_wire.body().len());
    for native in [false, true] {
        for exact in [false, true] {
            let limit = needed - usize::from(!exact);
            let limits = ManagedCoreLimits::new(if native {8192} else {limit}, 8192, 16384, 0, Duration::from_secs(10)).unwrap();
            let result = Prepared::new(TARGET, metadata(), operation(tool()), limits, if native {limit} else {8192});
            assert_eq!(result.is_ok(), exact);
        }
    }
}

fn client() -> (DpopHttpClient, DpopCredential) {
    let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
    let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(), CanonicalHttpUrl::parse(TARGET).unwrap()).unwrap();
    let credential = session.admit_token_response(&issuer, 200,
        br#"{"access_token":"tasks-token","token_type":"DPoP","expires_in":60}"#,
        Instant::now(), Duration::from_secs(60)).unwrap();
    (DpopHttpClient::new(session, DpopHttpPolicy::default()).unwrap(), credential)
}

#[test]
fn precancelled_public_task_operation_never_needs_a_network_runtime() {
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let (mut client, credential) = client();
    let mut call = Box::pin(client.request_task(&cx, &credential, metadata(), operation(tool()), ManagedCoreLimits::default()));
    assert!(matches!(call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(DpopTasksError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled))))));
}
