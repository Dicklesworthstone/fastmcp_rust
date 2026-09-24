//! Public machine tool submission over the existing loopback TLS fixture.
//! The transport, both-profile discovery, codecs and submission are production
//! code. The token is pre-acquired: these cases do not qualify issuer grants,
//! durable persistence, server idempotency or process-crash execution.

use super::*;
use std::pin::Pin;
use asupersync::time::Sleep;
use fastmcp_protocol::{CoreResult, FinalCoreResult, FinalInputResponses, RequestId};
use crate::http_auth::discovery::client_credentials::{ClientCredentialsError, OAuthDiscoveryError};
use crate::http_auth::discovery::client_credentials::tasks::ClientCredentialsTasksError;
use crate::http_auth::discovery::client_credentials::tasks::submission::{
    ClientCredentialsTaskSubmission, ClientCredentialsTaskSubmissionCause,
    ClientCredentialsTaskSubmissionError, ClientCredentialsTaskSubmissionEvent,
    ClientCredentialsTaskSubmissionPolicy, TaskSubmissionState,
};
use crate::http_auth::rpc::interaction::ManagedInteractionError;

#[derive(Clone, Copy, Debug)]
enum SubmissionCase {
    Ordinary, Task, Complete, Partial, StateOnly, Correctable, Stream, BadProgress,
    RecordLimit, ContinuationLimit, InputLimit, Unadvertised, RefusedDiscovery,
    MissingExtension, LostHead, LostBody, WrongId, LostContinuation, RefusedContinuation,
    DropDiscovery, CancelDiscovery, DropDispatch, CancelDispatch, DropRead, CancelRead,
    ExpiredInput, DeadlineInput, ClosedInput,
}
impl SubmissionCase {
    fn interrupted(self) -> bool {
        matches!(self, Self::DropDiscovery | Self::CancelDiscovery | Self::DropDispatch
            | Self::CancelDispatch | Self::DropRead | Self::CancelRead)
    }
    fn discovery_wait(self) -> bool { matches!(self, Self::DropDiscovery | Self::CancelDiscovery) }
    fn read_wait(self) -> bool { matches!(self, Self::DropRead | Self::CancelRead) }
    fn cancels(self) -> bool { matches!(self, Self::CancelDiscovery | Self::CancelDispatch | Self::CancelRead) }
    fn refuses_input(self) -> bool {
        matches!(self, Self::RecordLimit | Self::ContinuationLimit | Self::InputLimit | Self::Unadvertised)
    }
    fn host_pause(self) -> bool { matches!(self, Self::ExpiredInput | Self::DeadlineInput | Self::ClosedInput) }
    fn has_input(self) -> bool {
        matches!(self, Self::Complete | Self::Partial | Self::StateOnly | Self::Correctable
            | Self::Stream | Self::LostContinuation | Self::RefusedContinuation)
            || self.refuses_input() || self.host_pause()
    }
    fn requests(self) -> usize {
        if self.discovery_wait() || matches!(self, Self::RefusedDiscovery | Self::MissingExtension) { 1 }
        else if matches!(self, Self::Partial) { 6 }
        else if matches!(self, Self::RefusedContinuation) { 3 }
        else if self.has_input() && !self.refuses_input() && !self.host_pause() { 4 }
        else { 2 }
    }
}
fn isolated_submission(name: &str, case: SubmissionCase) {
    isolated_run(&format!("tool_submission::{name}"), || run_submission(case));
}
fn id(number: usize) -> RequestId { RequestId::String(format!("submit:{number}")) }
fn supplied(value: serde_json::Value) -> FinalInputResponses { serde_json::from_value(value).unwrap() }
fn arguments() -> serde_json::Value { json!({"payload":"PRIVATE-ARGUMENT","idempotency":"application-key"}) }
fn task_result() -> serde_json::Value {
    json!({"resultType":"task","taskId":"opaque / task-é","status":"working",
        "createdAt":"2020-01-01T00:00:00Z","lastUpdatedAt":"2020-01-01T00:00:00Z","ttlMs":null})
}
fn input(partial: bool) -> serde_json::Value {
    if partial {
        json!({"resultType":"input_required","requestState":"  opaque\u{0} +/%  ",
            "inputRequests":{"one":{"method":"roots/list"},"two":{"method":"roots/list"}}})
    } else {
        json!({"resultType":"input_required","inputRequests":{"one":{"method":"roots/list"}}})
    }
}
async fn tool(peer: &Peer, round: usize, metadata: &serde_json::Value,
    responses: Option<serde_json::Value>, state: Option<&str>,
) -> (TlsStream<TcpStream>, serde_json::Value) {
    let (socket, request) = peer.rpc("tools/call").await;
    assert_eq!(request["id"], format!("submit:{}", round * 2 + 1));
    assert_eq!(request["params"]["name"], "compute");
    assert_eq!(request["params"]["arguments"], arguments());
    assert_eq!(&request["params"]["_meta"], metadata);
    assert!(!request["params"].as_object().unwrap().contains_key("task"));
    assert_eq!(request["params"].get("inputResponses"), responses.as_ref());
    assert_eq!(request["params"].get("requestState"), state.map(|text| json!(text)).as_ref());
    (socket, request)
}
async fn result_reply(socket: &mut TlsStream<TcpStream>, request: &serde_json::Value, result: serde_json::Value) {
    reply(socket, json!({"jsonrpc":"2.0","id":request["id"],"result":result})).await;
    closed(socket).await;
}
async fn refused_discovery(peer: &Peer, round: usize) {
    let (mut socket, request) = peer.rpc("server/discover").await;
    assert_eq!(request["id"], format!("submit:{}", round * 2));
    socket.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    socket.shutdown().await.unwrap();
    closed(&mut socket).await;
}
async fn lost_body(socket: &mut TlsStream<TcpStream>) {
    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{\"jsonrpc\":").await.unwrap();
    socket.shutdown().await.unwrap();
    closed(socket).await;
}
async fn server(peer: &Peer, metadata: &serde_json::Value, case: SubmissionCase) {
    if matches!(case, SubmissionCase::RefusedDiscovery) { refused_discovery(peer, 0).await; return; }
    if matches!(case, SubmissionCase::MissingExtension) {
        let (mut socket, request) = peer.rpc("server/discover").await;
        result_reply(&mut socket, &request, json!({"resultType":"complete","supportedVersions":["2026-07-28"],
            "ttlMs":0,"cacheScope":"private","capabilities":{"extensions":{CLIENT_CREDENTIALS_EXTENSION:{}}}})).await;
        return;
    }
    peer.discover().await;
    let (mut socket, request) = tool(peer, 0, metadata, None, None).await;
    if matches!(case, SubmissionCase::LostHead) {
        socket.shutdown().await.unwrap(); closed(&mut socket).await; return;
    }
    if matches!(case, SubmissionCase::LostBody) { lost_body(&mut socket).await; return; }
    if matches!(case, SubmissionCase::WrongId) {
        reply(&mut socket, json!({"jsonrpc":"2.0","id":"other:1","result":task_result()})).await;
        closed(&mut socket).await; return;
    }
    if matches!(case, SubmissionCase::Stream | SubmissionCase::BadProgress | SubmissionCase::RecordLimit) {
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
        event(&mut socket, json!({"jsonrpc":"2.0","method":"notifications/progress",
            "params":{"progressToken":"submission-progress","progress":1}})).await;
        if matches!(case, SubmissionCase::BadProgress) {
            event(&mut socket, json!({"jsonrpc":"2.0","method":"notifications/progress",
                "params":{"progressToken":"submission-progress","progress":1}})).await;
        } else { event(&mut socket, json!({"jsonrpc":"2.0","id":request["id"],"result":input(false)})).await; }
        closed(&mut socket).await;
        if !matches!(case, SubmissionCase::Stream) { return; }
    } else {
        let first = match case {
            SubmissionCase::Ordinary => json!({"resultType":"complete","content":[],"isError":true}),
            SubmissionCase::StateOnly => json!({"resultType":"input_required","requestState":""}),
            SubmissionCase::Partial => input(true),
            _ if case.has_input() => input(false),
            _ => task_result(),
        };
        result_reply(&mut socket, &request, first).await;
    }
    if !case.has_input() || case.refuses_input() || case.host_pause() { return; }
    if matches!(case, SubmissionCase::RefusedContinuation) { refused_discovery(peer, 1).await; return; }
    peer.discover().await;
    let (responses, state) = match case {
        SubmissionCase::StateOnly => (None, Some("")),
        SubmissionCase::Partial => (Some(json!({"one":{"roots":[]}})), Some("  opaque\u{0} +/%  ")),
        _ => (Some(json!({"one":{"roots":[]}})), None),
    };
    let (mut socket, request) = tool(peer, 1, metadata, responses, state).await;
    if matches!(case, SubmissionCase::LostContinuation) { lost_body(&mut socket).await; return; }
    if matches!(case, SubmissionCase::Partial) {
        result_reply(&mut socket, &request, json!({"resultType":"input_required","inputRequests":{"two":{"method":"roots/list"}}})).await;
        peer.discover().await;
        let (mut socket, request) = tool(peer, 2, metadata, Some(json!({"two":{"roots":[]}})), None).await;
        result_reply(&mut socket, &request, task_result()).await;
    } else { result_reply(&mut socket, &request, task_result()).await; }
}
fn unknown(error: ClientCredentialsTaskSubmissionError) {
    assert!(matches!(&error, ClientCredentialsTaskSubmissionError::TaskCreationDeliveryUnknown(_)), "{error:?}");
    assert!(error.cause().is_some());
    assert!(!format!("{error:?} {error}").contains("PRIVATE-ARGUMENT"));
}
fn refused(error: &ClientCredentialsTaskSubmissionError) {
    assert!(matches!(error, ClientCredentialsTaskSubmissionError::NotDispatched(_)));
    assert!(matches!(error.cause(), Some(ClientCredentialsTaskSubmissionCause::Task(
        ClientCredentialsTasksError::Protocol(ManagedTasksError::HttpStatus { status: 403 })))));
}
fn cancelled(error: &ClientCredentialsTaskSubmissionError) {
    assert!(matches!(error.cause(), Some(ClientCredentialsTaskSubmissionCause::Task(
        ClientCredentialsTasksError::Authentication(ClientCredentialsError::Discovery(OAuthDiscoveryError::Cancelled))))));
}
async fn assert_retired(owner: &mut ClientCredentialsTaskSubmission, cx: &Cx, state: TaskSubmissionState) {
    assert_eq!(owner.state(), state);
    assert!(owner.pending_input().is_none());
    let send = owner.send(cx).await.unwrap_err();
    if state == TaskSubmissionState::DeliveryUnknown { unknown(send); }
    else { assert!(matches!(send, ClientCredentialsTaskSubmissionError::InvalidState)); }
    assert!(owner.resume(cx, id(10), id(11), None).await.is_err());
    owner.close();
    assert_eq!(owner.state(), state);
}
async fn application(machine: &ClientCredentialsTasksClient, owner: &mut ClientCredentialsTaskSubmission,
    cx: &Cx, case: SubmissionCase, expiry: Option<Instant>,
) {
    let sent = owner.send(cx).await;
    if matches!(case, SubmissionCase::RefusedDiscovery | SubmissionCase::MissingExtension | SubmissionCase::LostHead) {
        let error = sent.unwrap_err();
        let state = if matches!(case, SubmissionCase::LostHead) {
            unknown(error); TaskSubmissionState::DeliveryUnknown
        } else {
            assert!(matches!(error, ClientCredentialsTaskSubmissionError::NotDispatched(_)));
            if matches!(case, SubmissionCase::RefusedDiscovery) { refused(&error); }
            else {
                assert!(matches!(error.cause(), Some(ClientCredentialsTaskSubmissionCause::Task(
                    ClientCredentialsTasksError::Protocol(ManagedTasksError::Negotiation)))));
            }
            TaskSubmissionState::NotDispatched
        };
        assert_retired(owner, cx, state).await; return;
    }
    sent.unwrap();
    assert_eq!(owner.state(), TaskSubmissionState::AwaitingResponse);
    // The normal client would now renew; continuation MUST keep the original
    // bearer and must not contact the fixture's deliberately unserved issuer.
    machine.client.inner.state.try_lock_owned().unwrap().current.as_mut().unwrap().renew_after = Instant::now();
    if matches!(case, SubmissionCase::Stream | SubmissionCase::BadProgress | SubmissionCase::RecordLimit) {
        assert!(matches!(owner.next_event(cx).await.unwrap(), Some(ClientCredentialsTaskSubmissionEvent::Notification(_))));
        assert_eq!(owner.state(), TaskSubmissionState::AwaitingResponse);
    }
    let first = owner.next_event(cx).await;
    if matches!(case, SubmissionCase::LostBody | SubmissionCase::WrongId | SubmissionCase::BadProgress) || case.refuses_input() {
        let error = first.err().expect("invalid result must fail, not manufacture a Task");
        match (case, error.cause().unwrap()) {
            (SubmissionCase::ContinuationLimit, ClientCredentialsTaskSubmissionCause::Input(ManagedInteractionError::ContinuationLimit)) => {},
            (SubmissionCase::InputLimit, ClientCredentialsTaskSubmissionCause::Input(ManagedInteractionError::InputLimit)) => {},
            (SubmissionCase::Unadvertised, ClientCredentialsTaskSubmissionCause::Input(ManagedInteractionError::CapabilityNotAdvertised)) => {},
            (SubmissionCase::RecordLimit, ClientCredentialsTaskSubmissionCause::RecordLimit) => {},
            (SubmissionCase::LostBody, ClientCredentialsTaskSubmissionCause::Task(
                ClientCredentialsTasksError::Protocol(ManagedTasksError::InvalidResponse))) => {},
            (SubmissionCase::WrongId, ClientCredentialsTaskSubmissionCause::Task(
                ClientCredentialsTasksError::Protocol(ManagedTasksError::ResponseIdMismatch))) => {},
            (SubmissionCase::BadProgress, ClientCredentialsTaskSubmissionCause::Task(
                ClientCredentialsTasksError::Protocol(ManagedTasksError::InvalidProgress))) => {},
            (_, cause) => panic!("unexpected boundary for {case:?}: {cause:?}"),
        }
        unknown(error);
        assert_retired(owner, cx, TaskSubmissionState::DeliveryUnknown).await; return;
    }
    let mut outcome = first.unwrap().unwrap();
    if case.has_input() {
        assert!(matches!(&outcome, ClientCredentialsTaskSubmissionEvent::InputRequired(_)));
        assert_eq!(owner.state(), TaskSubmissionState::AwaitingInput);
        assert!(matches!(owner.next_event(cx).await, Err(ClientCredentialsTaskSubmissionError::InputPending)));
        if case.host_pause() {
            if matches!(case, SubmissionCase::ClosedInput) { machine.client.inner.closed.cancel(); }
            else {
                let delay = expiry.map_or(Duration::from_secs(3), |time|
                    time.saturating_duration_since(Instant::now()) + Duration::from_millis(100));
                Sleep::new(cx.now().saturating_add_nanos(u64::try_from(delay.as_nanos()).unwrap())).await;
            }
            let error = owner.resume(cx, id(2), id(3), Some(supplied(json!({"one":{"roots":[]}})))).await.unwrap_err();
            assert!(matches!(&error, ClientCredentialsTaskSubmissionError::NotDispatched(_)));
            match (case, error.cause().unwrap()) {
                (SubmissionCase::ExpiredInput, ClientCredentialsTaskSubmissionCause::Task(
                    ClientCredentialsTasksError::Authentication(ClientCredentialsError::Expired))) => {},
                (SubmissionCase::DeadlineInput, ClientCredentialsTaskSubmissionCause::Task(
                    ClientCredentialsTasksError::Authentication(ClientCredentialsError::Discovery(OAuthDiscoveryError::TimedOut)))) => {},
                (SubmissionCase::ClosedInput, ClientCredentialsTaskSubmissionCause::Task(
                    ClientCredentialsTasksError::Authentication(ClientCredentialsError::Closed))) => {},
                (_, cause) => panic!("unexpected pause failure for {case:?}: {cause:?}"),
            }
            assert_eq!(owner.request_id(), &id(1));
            assert_retired(owner, cx, TaskSubmissionState::Closed).await; return;
        }
        if matches!(case, SubmissionCase::Correctable) {
            // Three local rejections differ only in answer/identity. They must
            // neither spend IDs nor contact discovery before the valid answer.
            for (discovery, operation, answers) in [
                (id(2), id(3), json!({"other":{"roots":[]}})),
                (id(2), id(3), json!({"one":{"action":"decline"}})),
                (id(0), id(3), json!({"one":{"roots":[]}})),
            ] {
                assert!(matches!(owner.resume(cx, discovery, operation, Some(supplied(answers))).await,
                    Err(ClientCredentialsTaskSubmissionError::NotDispatched(_))));
                assert_eq!(owner.state(), TaskSubmissionState::AwaitingInput);
                assert_eq!(owner.request_id(), &id(1));
                assert_eq!(owner.pending_input().unwrap().input_requests().unwrap().members().len(), 1);
            }
        }
        let resumed = match case {
            SubmissionCase::Partial => owner.resume_partial(cx, id(2), id(3), supplied(json!({"one":{"roots":[]}}))).await,
            SubmissionCase::StateOnly => owner.resume(cx, id(2), id(3), None).await,
            _ => owner.resume(cx, id(2), id(3), Some(supplied(json!({"one":{"roots":[]}})))).await,
        };
        if matches!(case, SubmissionCase::RefusedContinuation) {
            refused(&resumed.unwrap_err());
            assert_eq!(owner.request_id(), &id(3));
            assert_retired(owner, cx, TaskSubmissionState::NotDispatched).await; return;
        }
        resumed.unwrap();
        let next = owner.next_event(cx).await;
        if matches!(case, SubmissionCase::LostContinuation) {
            unknown(next.err().unwrap());
            assert_eq!(owner.request_id(), &id(3));
            assert_retired(owner, cx, TaskSubmissionState::DeliveryUnknown).await; return;
        }
        outcome = next.unwrap().unwrap();
        if matches!(case, SubmissionCase::Partial) {
            assert!(matches!(&outcome, ClientCredentialsTaskSubmissionEvent::InputRequired(_)));
            let pending = owner.pending_input().unwrap();
            assert!(pending.request_state().is_none());
            assert_eq!(pending.input_requests().unwrap().members().len(), 1);
            owner.resume(cx, id(4), id(5), Some(supplied(json!({"two":{"roots":[]}})))).await.unwrap();
            outcome = owner.next_event(cx).await.unwrap().unwrap();
        }
    }
    let ClientCredentialsTaskSubmissionEvent::Result(result) = outcome else { panic!("final result required"); };
    assert_eq!(matches!(&*result, FinalCoreResult::ToolsCall { .. }), matches!(case, SubmissionCase::Ordinary));
    let wire: serde_json::Value = serde_json::from_str(&CoreResult::Final(*result).encode().unwrap()).unwrap();
    if matches!(case, SubmissionCase::Ordinary) { assert_eq!(wire["isError"], true); }
    else { assert_eq!(wire["taskId"], "opaque / task-é"); assert_eq!(wire["resultType"], "task"); }
    assert_eq!(owner.state(), TaskSubmissionState::Resolved);
    assert!(owner.next_event(cx).await.unwrap().is_none());
    assert!(owner.pending_input().is_none());
    owner.close();
    assert_eq!(owner.state(), TaskSubmissionState::Resolved);
    assert!(owner.send(cx).await.is_err());
}

async fn entered_while_pending<F: Future>(mut future: Pin<&mut F>, entered: &McpRequestCancellation) {
    let mut signal = std::pin::pin!(entered.cancelled());
    poll_fn(|task| {
        assert!(future.as_mut().poll(task).is_pending(), "fixture response must remain suspended");
        if signal.as_mut().poll(task).is_ready() { Poll::Ready(()) } else { Poll::Pending }
    }).await;
}
async fn interrupt(peer: &Peer, metadata: &serde_json::Value, owner: &mut ClientCredentialsTaskSubmission,
    cx: &Cx, case: SubmissionCase,
) {
    let entered = McpRequestCancellation::new();
    let cancellation = McpRequestCancellation::new();
    let server = async {
        let mut socket = if case.discovery_wait() {
            let (socket, request) = peer.rpc("server/discover").await;
            assert_eq!(request["id"], "submit:0"); socket
        } else {
            peer.discover().await;
            tool(peer, 0, metadata, None, None).await.0
        };
        if case.read_wait() {
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\nConnection: close\r\n\r\n").await.unwrap();
            socket.flush().await.unwrap();
        }
        entered.cancel();
        closed(&mut socket).await;
    };
    let application = async {
        if case.read_wait() {
            owner.send_with_cancellation(cx, &cancellation).await.unwrap();
            let mut read = Box::pin(owner.next_event(cx));
            entered_while_pending(read.as_mut(), &entered).await;
            if case.cancels() {
                cancellation.cancel();
                let error = read.await.err().unwrap();
                cancelled(&error); unknown(error);
            }
            else { drop(read); }
        } else {
            let mut send = Box::pin(owner.send_with_cancellation(cx, &cancellation));
            entered_while_pending(send.as_mut(), &entered).await;
            if case.cancels() {
                cancellation.cancel();
                let error = send.await.unwrap_err();
                cancelled(&error);
                if case.discovery_wait() { assert!(matches!(error, ClientCredentialsTaskSubmissionError::NotDispatched(_))); }
                else { unknown(error); }
            } else { drop(send); }
        }
        assert_retired(owner, cx, if case.discovery_wait() { TaskSubmissionState::NotDispatched }
            else { TaskSubmissionState::DeliveryUnknown }).await;
        assert!(!cancellation.is_cancel_requested() || case.cancels());
    };
    Box::pin(pair(server, application)).await;
}

fn run_submission(case: SubmissionCase) {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let scenario = async {
            let peer = Peer::new().await;
            let mut machine = peer.client();
            let mut expiry = None;
            if matches!(case, SubmissionCase::ExpiredInput) {
                let inner = Arc::get_mut(&mut machine.client.inner).unwrap();
                let expires_at = Instant::now() + Duration::from_secs(2);
                let bearer = BoundBearerCredential::bind_with_expiry(inner.resource.clone(), "watched-access", expires_at)
                    .unwrap().for_owner(&inner.closed).unwrap();
                inner.state.try_lock_owned().unwrap().current = Some(ServiceToken {
                    bearer, scopes: vec![], expires_at, renew_after: expires_at,
                });
                expiry = Some(expires_at);
            }
            if matches!(case, SubmissionCase::DeadlineInput) {
                Arc::get_mut(&mut machine.client.inner).unwrap().timeout = Duration::from_secs(2);
            }
            if matches!(case, SubmissionCase::Unadvertised) {
                machine.metadata[FINAL_CLIENT_CAPABILITIES_META_KEY].as_object_mut().unwrap().remove("roots");
            }
            machine.metadata["progressToken"] = json!("submission-progress");
            let policy = ClientCredentialsTaskSubmissionPolicy::new(
                if matches!(case, SubmissionCase::ContinuationLimit) { 0 } else { 2 },
                if matches!(case, SubmissionCase::InputLimit) { 0 } else { 4 },
                if matches!(case, SubmissionCase::RecordLimit) { 2 } else { 3 },
            ).unwrap();
            let mut owner = machine.prepare_tool_submission(id(0), id(1), "compute".to_owned(), Some(arguments()), policy).unwrap();
            assert_eq!(owner.state(), TaskSubmissionState::Prepared);
            peer.quiet();
            let unpolled = owner.send(&cx); drop(unpolled);
            assert_eq!(owner.state(), TaskSubmissionState::Prepared);
            peer.quiet();
            if case.interrupted() { interrupt(&peer, &machine.metadata, &mut owner, &cx, case).await; }
            else { Box::pin(pair(server(&peer, &machine.metadata, case), application(&machine, &mut owner, &cx, case, expiry))).await; }
            let expected: BTreeSet<_> = (0..case.requests()).map(|n| format!("submit:{n}")).collect();
            assert_eq!(*peer.seen.lock().unwrap(), expected, "no hidden discovery, renewal, continuation or mutation");
            assert_eq!(peer.updates.load(Ordering::SeqCst), 0);
            assert!(cx.checkpoint().is_ok(), "request-local cancellation must not cancel the ambient context");
            if !matches!(case, SubmissionCase::ClosedInput) { assert!(!machine.client.inner.closed.is_cancel_requested()); }
            peer.quiet();
        };
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(15_000_000_000), Box::pin(scenario)).await.unwrap();
    });
}

#[test]
fn ordinary_tool_error_is_not_a_task_creation() { isolated_submission("ordinary_tool_error_is_not_a_task_creation", SubmissionCase::Ordinary); }
#[test]
fn actual_task_result_resolves_once_without_polling_or_persistence() { isolated_submission("actual_task_result_resolves_once_without_polling_or_persistence", SubmissionCase::Task); }
#[test]
fn complete_inputs_continue_to_task_under_original_credential() { isolated_submission("complete_inputs_continue_to_task_under_original_credential", SubmissionCase::Complete); }
#[test]
fn partial_inputs_preserve_opaque_state_and_only_current_answers() { isolated_submission("partial_inputs_preserve_opaque_state_and_only_current_answers", SubmissionCase::Partial); }
#[test]
fn empty_state_only_continuation_keeps_answers_absent() { isolated_submission("empty_state_only_continuation_keeps_answers_absent", SubmissionCase::StateOnly); }
#[test]
fn invalid_answers_and_reused_identity_remain_locally_correctable() { isolated_submission("invalid_answers_and_reused_identity_remain_locally_correctable", SubmissionCase::Correctable); }
#[test]
fn streaming_progress_and_input_share_one_cumulative_budget() { isolated_submission("streaming_progress_and_input_share_one_cumulative_budget", SubmissionCase::Stream); }
#[test]
fn repeated_progress_cannot_authorize_another_tool_attempt() { isolated_submission("repeated_progress_cannot_authorize_another_tool_attempt", SubmissionCase::BadProgress); }
#[test]
fn exhausted_record_budget_cannot_publish_resumable_input() { isolated_submission("exhausted_record_budget_cannot_publish_resumable_input", SubmissionCase::RecordLimit); }
#[test]
fn zero_continuations_refuses_input_without_sending_it() { isolated_submission("zero_continuations_refuses_input_without_sending_it", SubmissionCase::ContinuationLimit); }
#[test]
fn zero_input_budget_refuses_input_without_sending_it() { isolated_submission("zero_input_budget_refuses_input_without_sending_it", SubmissionCase::InputLimit); }
#[test]
fn unadvertised_roots_are_not_exposed_to_the_host() { isolated_submission("unadvertised_roots_are_not_exposed_to_the_host", SubmissionCase::Unadvertised); }
#[test]
fn refused_discovery_never_dispatches_the_tool() { isolated_submission("refused_discovery_never_dispatches_the_tool", SubmissionCase::RefusedDiscovery); }
#[test]
fn missing_tasks_negotiation_never_dispatches_the_tool() { isolated_submission("missing_tasks_negotiation_never_dispatches_the_tool", SubmissionCase::MissingExtension); }
#[test]
fn lost_response_head_retains_unknown_tool_delivery() { isolated_submission("lost_response_head_retains_unknown_tool_delivery", SubmissionCase::LostHead); }
#[test]
fn lost_result_body_retains_unknown_task_creation() { isolated_submission("lost_result_body_retains_unknown_task_creation", SubmissionCase::LostBody); }
#[test]
fn foreign_result_identity_never_resolves_the_submission() { isolated_submission("foreign_result_identity_never_resolves_the_submission", SubmissionCase::WrongId); }
#[test]
fn lost_continuation_reply_cannot_restore_old_input() { isolated_submission("lost_continuation_reply_cannot_restore_old_input", SubmissionCase::LostContinuation); }
#[test]
fn refused_continuation_discovery_consumes_only_that_attempt() { isolated_submission("refused_continuation_discovery_consumes_only_that_attempt", SubmissionCase::RefusedContinuation); }
#[test]
fn abandoned_discovery_is_not_dispatched_and_not_resendable() { isolated_submission("abandoned_discovery_is_not_dispatched_and_not_resendable", SubmissionCase::DropDiscovery); }
#[test]
fn cancelled_discovery_is_not_dispatched_and_not_resendable() { isolated_submission("cancelled_discovery_is_not_dispatched_and_not_resendable", SubmissionCase::CancelDiscovery); }
#[test]
fn abandoned_dispatch_retains_unknown_delivery_and_releases_socket() { isolated_submission("abandoned_dispatch_retains_unknown_delivery_and_releases_socket", SubmissionCase::DropDispatch); }
#[test]
fn cancelled_dispatch_retains_unknown_delivery_and_releases_socket() { isolated_submission("cancelled_dispatch_retains_unknown_delivery_and_releases_socket", SubmissionCase::CancelDispatch); }
#[test]
fn abandoned_result_read_retains_unknown_delivery_and_releases_socket() { isolated_submission("abandoned_result_read_retains_unknown_delivery_and_releases_socket", SubmissionCase::DropRead); }
#[test]
fn cancelled_result_read_retains_unknown_delivery_and_releases_socket() { isolated_submission("cancelled_result_read_retains_unknown_delivery_and_releases_socket", SubmissionCase::CancelRead); }
#[test]
fn expired_input_authority_never_renews_or_posts_a_continuation() { isolated_submission("expired_input_authority_never_renews_or_posts_a_continuation", SubmissionCase::ExpiredInput); }
#[test]
fn host_pause_cannot_reset_the_original_submission_deadline() { isolated_submission("host_pause_cannot_reset_the_original_submission_deadline", SubmissionCase::DeadlineInput); }
#[test]
fn closed_machine_owner_prevents_pending_input_dispatch() { isolated_submission("closed_machine_owner_prevents_pending_input_dispatch", SubmissionCase::ClosedInput); }
