//! Local admission uses the real request codec and retained identity ledger.

use super::*;
use crate::http_auth::dpop::DpopSession;
use crate::http_auth::dpop::native::DpopHttpPolicy;
use crate::http_auth::dpop::native::core::DpopCoreError;
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::ClientCapabilities;
use fastmcp_protocol::dpop::DpopKey;
use serde_json::{Value, json};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

const TARGET: &str = "https://mcp.example/mcp?tenant=one";

fn metadata() -> FinalRequestMeta {
    FinalRequestMeta::new(ClientCapabilities::default())
}

fn operation(discovery: RequestId, tool: RequestId) -> DpopTaskOperation {
    DpopTaskOperation::new(discovery, tool, ManagedTaskRequest::CallTool {
        name: "echo".to_owned(), arguments: Some(json!({"private":"body-only"})),
    }).unwrap()
}

fn policy() -> ManagedTaskDriverPolicy {
    ManagedTaskDriverPolicy::new(Duration::from_millis(1), Duration::from_secs(10),
        2, 1, 1, 8192).unwrap()
}

fn prepare(run: &mut Run, operation: DpopTaskOperation) -> Result<Prepared, DpopTaskDriverError> {
    run.prepare_initial(TARGET, metadata(), operation, ManagedCoreLimits::default(), 8192)
}

#[test]
fn initial_ids_cannot_collide_with_any_later_poll_or_update_pair() {
    for sequence in 0..3 {
        for suffix in ["discover", "task"] {
            for collision_is_discovery in [false, true] {
                let mut run = Run::new("run", policy(), ManagedCoreLimits::default()).unwrap();
                let collision = RequestId::String(format!("run.{sequence}.{suffix}"));
                let other = RequestId::String("initial".to_owned());
                let (discovery, tool) = if collision_is_discovery {
                    (collision, other)
                } else { (other, collision) };
                let rejected = prepare(&mut run, operation(discovery, tool));
                assert!(matches!(rejected, Err(DpopTaskDriverError::Driver(
                    ManagedTaskDriverError::RepeatedRequestId,
                ))));
                assert_eq!((run.sequence, run.polls, run.updates, run.notifications), (0, 0, 0, 0));
                assert_eq!(run.remaining_bytes, ManagedCoreLimits::default().total_bytes());
                // A refused initial pair must not reserve even its non-colliding ID.
                prepare(&mut run, operation(RequestId::String("initial".to_owned()),
                    RequestId::Number(7))).unwrap();
            }
        }
    }
    // Same spelling just beyond the finite generated namespace is not a collision.
    let mut run = Run::new("run", policy(), ManagedCoreLimits::default()).unwrap();
    prepare(&mut run, operation(RequestId::String("run.3.task".to_owned()),
        RequestId::Number(7))).unwrap();
}

#[test]
fn initial_tool_admission_reserves_ids_without_spending_a_poll_or_update() {
    let limits = ManagedCoreLimits::default();
    let mut run = Run::new("run", policy(), limits).unwrap();
    let prepared = prepare(&mut run, operation(RequestId::Number(7), RequestId::Number(8))).unwrap();
    let discovery: Value = serde_json::from_slice(prepared.discovery_wire.body()).unwrap();
    let tool: Value = serde_json::from_slice(prepared.operation_wire.body()).unwrap();
    assert_eq!(discovery["id"], 7);
    assert_eq!(discovery["method"], "server/discover");
    assert!(discovery["params"].get("arguments").is_none());
    assert_eq!(tool["id"], 8);
    assert_eq!(tool["method"], "tools/call");
    assert_eq!(tool["params"]["arguments"], json!({"private":"body-only"}));
    assert_eq!(prepared.operation_wire.target(), TARGET);
    assert_eq!((run.sequence, run.polls, run.updates), (0, 0, 0));
    let repeated = ManagedTaskRequestIds::new(
        serde_json::from_str("7e0").unwrap(), RequestId::Number(9),
    ).unwrap();
    assert!(matches!(run.state.reserve_ids(&repeated, policy().maximum_state_bytes),
        Err(ManagedTaskDriverError::RepeatedRequestId)));
    let get = run.prepare(TARGET, metadata(), ManagedTaskRequest::Get(
        TaskId::parse("task-one").unwrap()), limits, 8192).unwrap();
    let wire: Value = serde_json::from_slice(get.operation_wire.body()).unwrap();
    assert_eq!(wire["id"], "run.0.task");
    assert_eq!(wire["method"], "tasks/get");
    assert_eq!((run.sequence, run.polls, run.updates), (1, 1, 0));
}

#[test]
fn wrong_initial_method_and_oversized_request_leave_identity_custody_unchanged() {
    for cancel in [false, true] {
        let mut run = Run::new("run", policy(), ManagedCoreLimits::default()).unwrap();
        let id = TaskId::parse("task-one").unwrap();
        let request = if cancel { ManagedTaskRequest::Cancel(id) } else { ManagedTaskRequest::Get(id) };
        let refused = prepare(&mut run,
            DpopTaskOperation::new(RequestId::Number(1), RequestId::Number(2), request).unwrap());
        assert!(matches!(refused, Err(DpopTaskDriverError::Driver(
            ManagedTaskDriverError::UnexpectedResponse,
        ))));
        assert!(run.prepare_initial(TARGET, metadata(),
            operation(RequestId::Number(1), RequestId::Number(2)),
            ManagedCoreLimits::default(), 1).is_err());
        // Neither refusal makes those IDs unavailable to a valid tool call.
        prepare(&mut run, operation(RequestId::Number(1), RequestId::Number(2))).unwrap();
        assert_eq!((run.sequence, run.polls, run.updates), (0, 0, 0));
    }
}

fn client() -> (DpopHttpClient, DpopCredential) {
    let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
    let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(),
        CanonicalHttpUrl::parse(TARGET).unwrap()).unwrap();
    let credential = session.admit_token_response(&issuer, 200,
        br#"{"access_token":"preflight-token","token_type":"DPoP","expires_in":60}"#,
        Instant::now(), Duration::from_secs(60)).unwrap();
    (DpopHttpClient::new(session, DpopHttpPolicy::default()).unwrap(), credential)
}

fn no_input(_: TaskInputRequests) -> std::future::Ready<Result<ManagedTaskInputAction, ManagedTaskDriverError>> {
    panic!("preflight cannot invoke input resolution")
}

fn first_poll(client: &mut DpopHttpClient, credential: &DpopCredential, cx: &Cx,
    cancellation: &McpRequestCancellation, events: bool) -> DpopHttpError
{
    let op = operation(RequestId::Number(1), RequestId::Number(2));
    let mut future: Pin<Box<dyn Future<Output = Result<DpopTaskExecutionOutcome, DpopTaskDriverError>> + '_>> =
        if events {
            Box::pin(client.start_and_drive_task_with_events(cx, cancellation, credential,
                metadata(), op, "run", policy(), DpopStreamLimits::default(), no_input,
                |_| panic!("preflight cannot publish a Task"),
                |_| panic!("preflight cannot publish a notification")))
        } else {
            Box::pin(client.start_and_drive_task(cx, cancellation, credential,
                metadata(), op, "run", policy(), ManagedCoreLimits::default(), no_input,
                |_| panic!("preflight cannot publish a Task")))
        };
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(Err(DpopTaskDriverError::Task(DpopTasksError::Core(
            DpopCoreError::Transport(error),
        )))) => error,
        _ => panic!("preflight must return the exact transport disposition"),
    }
}

#[test]
fn cancelled_creation_needs_no_runtime_and_does_not_revoke_siblings() {
    for events in [false, true] {
        for cancel_cx in [false, true] {
            let (mut client, credential) = client();
            let cx = Cx::for_testing();
            let cancellation = McpRequestCancellation::new();
            if cancel_cx { cx.set_cancel_requested(true); } else { cancellation.cancel(); }
            assert_eq!(first_poll(&mut client, &credential, &cx, &cancellation, events),
                DpopHttpError::Cancelled);
            assert!(!client.revocation_handle().is_revoked());
            assert_eq!(cx.checkpoint().is_err(), cancel_cx);
            assert_eq!(first_poll(&mut client, &credential, &Cx::for_testing(),
                &McpRequestCancellation::new(), events), DpopHttpError::RuntimeUnavailable);
        }
    }
}
