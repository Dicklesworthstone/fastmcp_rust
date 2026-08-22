//! Exact-name public-surface harness for the frozen CLT-01 runners.
//!
//! These functions deliberately live at the integration-harness root so the
//! frozen `cargo test … clt_01_* -- --exact` commands discover one test with
//! the literal required ID. The scripted transport is a transport conformance
//! probe; all behavior under test flows through the shipped public API.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::{Duration, Instant};

use asupersync::Cx;
use fastmcp_client::{
    ExecutionTerminalReason, ExecutionTerminalState, OpaquePagination, PaginationBounds,
    ProtocolEra, Request, RequestExecutor, RequestTimeoutPolicy, clt_01_a_manifest_digest,
    clt_01_b_manifest_digest,
};
use fastmcp_core::McpErrorCode;
use fastmcp_protocol::{DecodedResult, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId};
use fastmcp_transport::{Transport, TransportError};

#[derive(Debug, Default)]
struct ProbeState {
    received: VecDeque<Result<JsonRpcMessage, TransportError>>,
    sent: Vec<JsonRpcMessage>,
    send_error: Option<std::io::ErrorKind>,
    closed: bool,
}

struct ScriptedTransport {
    state: Rc<RefCell<ProbeState>>,
}

#[derive(Clone)]
struct Probe(Rc<RefCell<ProbeState>>);

impl ScriptedTransport {
    fn new(
        received: impl IntoIterator<Item = Result<JsonRpcMessage, TransportError>>,
    ) -> (Self, Probe) {
        let state = Rc::new(RefCell::new(ProbeState {
            received: received.into_iter().collect(),
            ..ProbeState::default()
        }));
        (
            Self {
                state: state.clone(),
            },
            Probe(state),
        )
    }

    fn backpressured() -> (Self, Probe) {
        let state = Rc::new(RefCell::new(ProbeState {
            send_error: Some(std::io::ErrorKind::WouldBlock),
            ..ProbeState::default()
        }));
        (
            Self {
                state: state.clone(),
            },
            Probe(state),
        )
    }
}

impl Probe {
    fn sent_len(&self) -> usize {
        self.0.borrow().sent.len()
    }

    fn sent(&self) -> Vec<JsonRpcMessage> {
        self.0.borrow().sent.clone()
    }

    fn closed(&self) -> bool {
        self.0.borrow().closed
    }
}

impl Transport for ScriptedTransport {
    fn send(&mut self, _cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
        if let Some(kind) = self.state.borrow().send_error {
            return Err(TransportError::Io(std::io::Error::from(kind)));
        }
        self.state.borrow_mut().sent.push(message.clone());
        Ok(())
    }

    fn recv(&mut self, _cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
        self.state
            .borrow_mut()
            .received
            .pop_front()
            .unwrap_or(Err(TransportError::Closed))
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.state.borrow_mut().closed = true;
        Ok(())
    }
}

fn request(id: i64) -> Request {
    request_with_progress_marker(id, serde_json::json!(id))
}

fn request_with_progress_marker(id: i64, progress_marker: serde_json::Value) -> Request {
    JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "id": id,
            "_meta": {"progressToken": progress_marker},
        })),
        id,
    )
}

fn request_without_progress_marker(id: i64) -> Request {
    JsonRpcRequest::new("tools/call", Some(serde_json::json!({"id": id})), id)
}

fn response(id: i64, result: serde_json::Value) -> JsonRpcMessage {
    JsonRpcMessage::Response(JsonRpcResponse::success(RequestId::Number(id), result))
}

fn modern_progress_and_final(
    id: i64,
    progress_marker: serde_json::Value,
) -> [Result<JsonRpcMessage, TransportError>; 2] {
    [
        Ok(JsonRpcMessage::Request(JsonRpcRequest::notification(
            "notifications/progress",
            Some(serde_json::json!({"progressToken": progress_marker, "progress": 0.5})),
        ))),
        Ok(response(
            id,
            serde_json::json!({
                "resultType": "complete",
                "content": [],
                "isError": false,
                "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"},
            }),
        )),
    ]
}

#[test]
fn clt_01_custom_transport_selected_modern_uses_typed_correlation_and_progress() {
    let cx = Cx::for_testing();
    let (transport, probe) =
        ScriptedTransport::new(modern_progress_and_final(151, serde_json::json!(151)));
    let executor = RequestExecutor::with_protocol_era(transport, ProtocolEra::Modern2026);
    let mut execution = executor
        .execute(&cx, request(151))
        .expect("the modern custom transport commits one correlated request");

    let (result, diagnostic, progress) = executor
        .wait_decoded_with_stream(&cx, &mut execution)
        .expect("the selected modern transport retains typed final and progress paths");
    assert!(matches!(result, DecodedResult::Complete(_)));
    assert!(diagnostic.is_none());
    assert_eq!(progress.len(), 1);
    assert_eq!(progress[0].method, "notifications/progress");
    assert_eq!(executor.protocol_era(), ProtocolEra::Modern2026);
    assert_eq!(probe.sent_len(), 1);
}

#[test]
fn clt_01_custom_transport_accepts_exact_string_advertised_progress_token() {
    let cx = Cx::for_testing();
    let marker = serde_json::json!("public-string-progress-token");
    let (transport, probe) = ScriptedTransport::new(modern_progress_and_final(152, marker.clone()));
    let executor = RequestExecutor::with_protocol_era(transport, ProtocolEra::Modern2026);
    let mut execution = executor
        .execute(&cx, request_with_progress_marker(152, marker))
        .expect("the string-marker request commits before progress arrives");

    let (_, _, progress) = executor
        .wait_decoded_with_stream(&cx, &mut execution)
        .expect("an exactly repeated string marker owns modern progress");
    assert_eq!(progress.len(), 1);
    assert_eq!(probe.sent_len(), 1);
}

#[test]
fn clt_01_custom_transport_rejects_progress_without_an_advertised_marker() {
    let cx = Cx::for_testing();
    let (transport, probe) =
        ScriptedTransport::new(modern_progress_and_final(153, serde_json::json!(153)));
    let executor = RequestExecutor::with_protocol_era(transport, ProtocolEra::Modern2026);
    let mut execution = executor
        .execute(&cx, request_without_progress_marker(153))
        .expect("the marker-free request commits before the peer notification");

    let (_, _, progress) = executor
        .wait_decoded_with_stream(&cx, &mut execution)
        .expect("unowned progress must not reject the correlated final response");
    assert!(progress.is_empty());
    assert_eq!(probe.sent_len(), 1);
}

#[test]
fn clt_01_custom_transport_rejects_one_changed_advertised_progress_token() {
    let cx = Cx::for_testing();
    let marker = serde_json::json!("public-string-progress-token");
    // Only the peer's advertised marker differs from the paired positive.
    let (transport, probe) = ScriptedTransport::new(modern_progress_and_final(
        152,
        serde_json::json!("other-token"),
    ));
    let executor = RequestExecutor::with_protocol_era(transport, ProtocolEra::Modern2026);
    let mut execution = executor
        .execute(&cx, request_with_progress_marker(152, marker))
        .expect("the same request still commits before foreign progress arrives");

    let (_, _, progress) = executor
        .wait_decoded_with_stream(&cx, &mut execution)
        .expect("a foreign progress marker must not fail the correlated final response");
    assert!(progress.is_empty());
    assert_eq!(probe.sent_len(), 1);
}

#[test]
fn clt_01_custom_transport_rejects_final_result_under_one_changed_selected_era() {
    let cx = Cx::for_testing();
    let (transport, probe) =
        ScriptedTransport::new(modern_progress_and_final(151, serde_json::json!(151)));
    // Only the already-negotiated era differs from the accepted modern path.
    // A custom transport must not decode final-only metadata through the
    // unary exact-2024 compatibility path.
    let executor = RequestExecutor::with_protocol_era(transport, ProtocolEra::Legacy2024);
    let mut execution = executor
        .execute(&cx, request(151))
        .expect("the same request still commits before peer result admission");

    let error = executor
        .wait_decoded_with_stream(&cx, &mut execution)
        .expect_err("final-only metadata cannot be projected onto exact legacy decoding");
    assert_eq!(error.code, McpErrorCode::InvalidRequest);
    assert_eq!(executor.protocol_era(), ProtocolEra::Legacy2024);
    assert_eq!(probe.sent_len(), 1);
}

#[test]
fn legacy_multiplexed_executor_retains_sampling_and_roots_callbacks() {
    let cx = Cx::for_testing();
    let (transport, probe) = ScriptedTransport::new([
        Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
            "sampling/createMessage",
            Some(serde_json::json!({"messages": [], "maxTokens": 9})),
            701,
        ))),
        Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
            "roots/list",
            Some(serde_json::json!({})),
            702,
        ))),
    ]);
    let executor = RequestExecutor::with_protocol_era(transport, ProtocolEra::Legacy2024);

    executor
        .drive(&cx)
        .expect("legacy sampling callback is retained");
    executor
        .drive(&cx)
        .expect("legacy roots callback is retained");
    let reverse = executor.take_reverse_requests();
    assert_eq!(reverse.len(), 2);
    assert_eq!(reverse[0].request().method, "sampling/createMessage");
    assert_eq!(reverse[1].request().method, "roots/list");

    executor
        .respond_to_reverse_request(&cx, &reverse[0], serde_json::json!({"model": "test"}))
        .expect("sampling reply preserves its callback ownership");
    executor
        .respond_to_reverse_request(&cx, &reverse[1], serde_json::json!({"roots": []}))
        .expect("roots reply preserves its callback ownership");

    let sent = probe.sent();
    assert!(matches!(
        &sent[0],
        JsonRpcMessage::Response(response)
            if response.id == Some(RequestId::Number(701))
                && response.result == Some(serde_json::json!({"model": "test"}))
    ));
    assert!(matches!(
        &sent[1],
        JsonRpcMessage::Response(response)
            if response.id == Some(RequestId::Number(702))
                && response.result == Some(serde_json::json!({"roots": []}))
    ));
}

#[test]
fn legacy_multiplexed_executor_rejects_sampling_without_only_required_max_tokens() {
    let cx = Cx::for_testing();
    let (transport, probe) = ScriptedTransport::new([
        Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
            "sampling/createMessage",
            Some(serde_json::json!({"messages": [], "maxTokens": 9})),
            701,
        ))),
        // Only mandatory `maxTokens` differs from the admitted callback above.
        Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
            "sampling/createMessage",
            Some(serde_json::json!({"messages": []})),
            702,
        ))),
    ]);
    let executor = RequestExecutor::with_protocol_era(transport, ProtocolEra::Legacy2024);

    executor
        .drive(&cx)
        .expect("baseline exact legacy sampling callback is retained");
    let retained = executor.take_reverse_requests();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].request_id(), &RequestId::Number(701));

    executor
        .drive(&cx)
        .expect("missing maxTokens receives a correlated local rejection");
    assert!(executor.take_reverse_requests().is_empty());
    let sent = probe.sent();
    assert!(matches!(
        &sent[0],
        JsonRpcMessage::Response(response)
            if response.id == Some(RequestId::Number(702))
                && response
                    .error
                    .as_ref()
                    .is_some_and(|error| error.code.as_i32() == Some(i32::from(McpErrorCode::InvalidParams)))
    ));

    executor
        .respond_to_reverse_request(&cx, &retained[0], serde_json::json!({"model": "test"}))
        .expect("the malformed callback leaves the retained callback ownership unchanged");
    assert!(matches!(
        &probe.sent()[1],
        JsonRpcMessage::Response(response)
            if response.id == Some(RequestId::Number(701))
                && response.result == Some(serde_json::json!({"model": "test"}))
    ));
}

#[test]
fn legacy_multiplexed_executor_rejects_client_direction_and_absent_era_reverse_requests() {
    let cx = Cx::for_testing();
    let (transport, probe) = ScriptedTransport::new([
        Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
            "completion/complete",
            Some(serde_json::json!({})),
            703,
        ))),
        Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
            "elicitation/create",
            Some(serde_json::json!({})),
            704,
        ))),
    ]);
    let executor = RequestExecutor::with_protocol_era(transport, ProtocolEra::Legacy2024);

    executor
        .drive(&cx)
        .expect("wrong-direction completion receives a local rejection");
    executor
        .drive(&cx)
        .expect("elicitation absent from legacy receives a local rejection");

    assert!(executor.take_reverse_requests().is_empty());
    let sent = probe.sent();
    assert!(matches!(
        &sent[0],
        JsonRpcMessage::Response(response)
            if response.id == Some(RequestId::Number(703)) && response.error.is_some()
    ));
    assert!(matches!(
        &sent[1],
        JsonRpcMessage::Response(response)
            if response.id == Some(RequestId::Number(704)) && response.error.is_some()
    ));
}

#[test]
fn reverse_sampling_is_rejected_when_only_selected_era_changes() {
    let cx = Cx::for_testing();
    let (transport, probe) =
        ScriptedTransport::new([Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
            "sampling/createMessage",
            Some(serde_json::json!({"messages": [], "maxTokens": 9})),
            701,
        )))]);
    // Only the selected era differs from the accepted legacy callback path.
    let executor = RequestExecutor::with_protocol_era(transport, ProtocolEra::Modern2026);

    executor
        .drive(&cx)
        .expect("final-era ingress rejects historical reverse callbacks");
    assert!(executor.take_reverse_requests().is_empty());
    assert!(matches!(
        &probe.sent()[0],
        JsonRpcMessage::Response(response)
            if response.id == Some(RequestId::Number(701)) && response.error.is_some()
    ));
}

#[test]
fn legacy_reverse_cancellation_ignores_one_changed_request_envelope() {
    let cx = Cx::for_testing();
    let (transport, probe) = ScriptedTransport::new([
        Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
            "sampling/createMessage",
            Some(serde_json::json!({"messages": [], "maxTokens": 9})),
            705,
        ))),
        // Only the notification envelope changes from the accepted paired
        // cancellation path: it incorrectly carries a JSON-RPC request ID.
        Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
            "notifications/cancelled",
            Some(serde_json::json!({"requestId": 705})),
            706,
        ))),
    ]);
    let executor = RequestExecutor::with_protocol_era(transport, ProtocolEra::Legacy2024);

    executor
        .drive(&cx)
        .expect("legacy sampling callback is retained before cancellation");
    let reverse = executor
        .take_reverse_requests()
        .pop()
        .expect("callback reaches the public boundary");
    executor
        .drive(&cx)
        .expect("wrong-envelope cancellation is inert without connection failure");

    assert!(
        !reverse.cancellation().is_cancel_requested(),
        "a request-shaped cancellation cannot cancel a live callback"
    );
    assert_eq!(
        probe.sent_len(),
        0,
        "malformed cancellation receives no reply"
    );

    executor
        .respond_to_reverse_request(&cx, &reverse, serde_json::json!({"model": "test"}))
        .expect("the inert cancellation leaves the retained callback response-capable");
    assert!(matches!(
        &probe.sent()[0],
        JsonRpcMessage::Response(response)
            if response.id == Some(RequestId::Number(705))
                && response.result == Some(serde_json::json!({"model": "test"}))
    ));
}

#[test]
fn clt_01_a_positive() {
    assert_eq!(
        clt_01_a_manifest_digest().as_bytes(),
        &[
            0x52, 0x7c, 0x4b, 0xdb, 0x5b, 0xdd, 0xff, 0x10, 0x95, 0xb3, 0x27, 0xf7, 0x92, 0x5b,
            0xcf, 0x73, 0xba, 0x6e, 0xd0, 0x05, 0x22, 0x5b, 0x8b, 0x59, 0x91, 0x6b, 0x0b, 0x7e,
            0xe3, 0x88, 0x62, 0xb7,
        ],
    );
    let cx = Cx::for_testing();
    let (transport, probe) = ScriptedTransport::new([
        Ok(response(999, serde_json::json!({"unknown": true}))),
        Ok(response(2, serde_json::json!({"kind": "input-required"}))),
        Ok(JsonRpcMessage::Request(JsonRpcRequest::notification(
            "notifications/message",
            Some(serde_json::json!({"level": "info"})),
        ))),
        Ok(response(
            1,
            serde_json::json!({"kind": "complete", "extra": [1, 2]}),
        )),
    ]);
    let executor = RequestExecutor::new(transport);
    let mut first = executor
        .execute(&cx, request(1))
        .expect("first request commits");
    let mut second = executor
        .execute(&cx, request(2))
        .expect("second request commits");

    let records = executor.pending_records();
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| {
        record.correlation_key
            == record
                .request_id
                .correlation_key()
                .expect("committed request IDs remain canonicalizable")
            && record.request_state == ExecutionTerminalState::Pending
            && record.send_committed
            && record.idle_deadline <= record.absolute_deadline
            && !record.cancellation_committed
    }));
    assert_eq!(
        executor
            .wait(&cx, &mut first)
            .expect("reordered first final")
            .id,
        Some(RequestId::Number(1))
    );
    assert_eq!(
        executor
            .wait(&cx, &mut second)
            .expect("stored second final")
            .id,
        Some(RequestId::Number(2))
    );
    assert_eq!(executor.take_notifications().len(), 1);
    let uncorrelated = executor.take_uncorrelated_responses();
    assert_eq!(uncorrelated.len(), 1);
    assert_eq!(uncorrelated[0].id, Some(RequestId::Number(999)));
    assert_eq!(executor.pending_records(), [] as [fastmcp_client::PendingRequestRecord; 0]);
    assert_eq!(probe.sent_len(), 2);

    let (duplicate_transport, duplicate_probe) = ScriptedTransport::new([
        Ok(response(4, serde_json::json!({"kind": "complete"}))),
        Ok(response(4, serde_json::json!({"kind": "late-duplicate"}))),
    ]);
    let duplicate = RequestExecutor::new(duplicate_transport);
    let mut duplicate_owner = duplicate
        .execute(&cx, request(4))
        .expect("duplicate-response owner request commits");
    assert_eq!(
        duplicate
            .wait(&cx, &mut duplicate_owner)
            .expect("first final response is delivered")
            .id,
        Some(RequestId::Number(4))
    );
    duplicate
        .drive(&cx)
        .expect("duplicate final is retained rather than reassigned");
    let duplicate_response = duplicate.take_uncorrelated_responses();
    assert_eq!(duplicate_response.len(), 1);
    assert_eq!(duplicate_response[0].id, Some(RequestId::Number(4)));
    assert_eq!(duplicate_probe.sent_len(), 1);

    let (abandoned_transport, abandoned_probe) = ScriptedTransport::new([
        Ok(response(31, serde_json::json!({"late": true}))),
        Ok(response(32, serde_json::json!({"current": true}))),
    ]);
    let abandoned = RequestExecutor::new(abandoned_transport);
    let dropped = abandoned
        .execute(&cx, request(31))
        .expect("owner request commits before its handle is dropped");
    drop(dropped);
    let mut current = abandoned
        .execute(&cx, request(32))
        .expect("next request drains the dropped owner");
    assert_eq!(
        abandoned
            .wait(&cx, &mut current)
            .expect("late tombstone response cannot poison the current owner")
            .id,
        Some(RequestId::Number(32))
    );
    assert_eq!(abandoned.take_uncorrelated_responses(), [] as [fastmcp_protocol::JsonRpcResponse; 0]);
    assert_eq!(abandoned_probe.sent_len(), 3);

    let (malformed_transport, malformed_probe) = ScriptedTransport::new([Err(
        TransportError::Codec(fastmcp_transport::CodecError::Json(
            serde_json::from_str::<serde_json::Value>("{")
                .expect_err("the transport probe supplies malformed JSON"),
        )),
    )]);
    let malformed = RequestExecutor::new(malformed_transport);
    let mut malformed_first = malformed
        .execute(&cx, request(11))
        .expect("first malformed-ingress owner request commits");
    let mut malformed_second = malformed
        .execute(&cx, request(12))
        .expect("second malformed-ingress owner request commits");
    assert_eq!(
        malformed
            .drive(&cx)
            .expect_err("malformed ingress selects only local terminal outcomes")
            .code,
        McpErrorCode::InternalError
    );
    assert_eq!(
        malformed
            .wait(&cx, &mut malformed_first)
            .expect_err("malformed ingress fans out to the first owner")
            .code,
        McpErrorCode::InternalError
    );
    assert_eq!(
        malformed
            .wait(&cx, &mut malformed_second)
            .expect_err("malformed ingress fans out to the second owner")
            .code,
        McpErrorCode::InternalError
    );
    assert_eq!(malformed.pending_records(), [] as [fastmcp_client::PendingRequestRecord; 0]);
    assert_eq!(malformed_probe.sent_len(), 2);

    let (backpressured_transport, backpressured_probe) = ScriptedTransport::backpressured();
    let backpressured = RequestExecutor::new(backpressured_transport);
    let backpressure_error = match backpressured.execute(&cx, request(21)) {
        Ok(_) => panic!("would-block send must not create an execution"),
        Err(error) => error,
    };
    assert_eq!(backpressure_error.code, McpErrorCode::InternalError);
    assert_eq!(backpressured.pending_records(), [] as [fastmcp_client::PendingRequestRecord; 0]);
    assert_eq!(backpressured.terminal_records(), [] as [fastmcp_client::ExecutionTerminalRecord; 0]);
    assert_eq!(backpressured_probe.sent_len(), 0);

    let (closed_transport, closed_probe) = ScriptedTransport::new([Err(TransportError::Closed)]);
    let closed = RequestExecutor::new(closed_transport);
    let mut first_closed_owner = closed
        .execute(&cx, request(3))
        .expect("first connection-loss owner request commits");
    let mut second_closed_owner = closed
        .execute(&cx, request(5))
        .expect("second connection-loss owner request commits");
    assert_eq!(
        closed
            .drive(&cx)
            .expect_err("connection loss fans out to every owner")
            .code,
        McpErrorCode::InternalError
    );
    assert_eq!(
        closed
            .wait(&cx, &mut first_closed_owner)
            .expect_err("first connection-loss waiter receives the fanout outcome")
            .code,
        McpErrorCode::InternalError
    );
    assert_eq!(
        closed
            .wait(&cx, &mut second_closed_owner)
            .expect_err("second connection-loss waiter receives the fanout outcome")
            .code,
        McpErrorCode::InternalError
    );
    assert_eq!(closed.pending_records(), [] as [fastmcp_client::PendingRequestRecord; 0]);
    assert_eq!(closed_probe.sent_len(), 2);
}

#[test]
fn clt_01_a_planted_negative() {
    let cx = Cx::for_testing();
    let (transport, probe) = ScriptedTransport::new(std::iter::empty());
    let executor = RequestExecutor::new(transport);
    let _first = executor
        .execute(&cx, request(7))
        .expect("baseline request commits");
    let before = executor.pending_records();

    // One variable changes: the second request reuses the exact correlation ID.
    let error = match executor.execute(&cx, request(7)) {
        Ok(_) => panic!("duplicate in-flight ID must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code, McpErrorCode::InvalidRequest);
    assert_eq!(executor.pending_records(), before);
    assert_eq!(executor.terminal_records(), [] as [fastmcp_client::ExecutionTerminalRecord; 0]);
    assert_eq!(probe.sent_len(), 1);
    assert!(executor.take_notifications().is_empty());
    assert_eq!(executor.take_uncorrelated_responses(), [] as [fastmcp_protocol::JsonRpcResponse; 0]);
    assert_eq!(executor.take_cancellation_events(), [] as [fastmcp_client::CancellationRequested; 0]);
}

#[test]
fn canonical_terminal_id_tombstone_prevents_reuse_and_late_duplicate_aba() {
    let cx = Cx::for_testing();
    let (transport, probe) = ScriptedTransport::new(std::iter::empty());
    let executor = RequestExecutor::new(transport);
    let mut completed = executor
        .execute(&cx, request(301))
        .expect("baseline request commits");
    executor
        .route_response_with_raw_result(
            &cx,
            JsonRpcResponse::success(
                RequestId::Integer("301e0".to_owned()),
                serde_json::json!({"kind": "complete"}),
            ),
            Some(r#"{"kind":"complete"}"#.to_owned()),
        )
        .expect("a numeric response alias completes the baseline owner");

    let same_canonical_request = || {
        JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({"id": "same-canonical-id"})),
            RequestId::Integer("301e0".to_owned()),
        )
    };
    let unconsumed_error = match executor.execute(&cx, same_canonical_request()) {
        Err(error) => error,
        Ok(_) => panic!("unconsumed terminal outcome retains its canonical ID"),
    };
    assert_eq!(unconsumed_error.code, McpErrorCode::InvalidRequest);
    assert_eq!(
        executor
            .wait(&cx, &mut completed)
            .expect("baseline owner consumes its final response")
            .id,
        Some(RequestId::Integer("301e0".to_owned())),
    );
    let consumed_error = match executor.execute(&cx, same_canonical_request()) {
        Err(error) => error,
        Ok(_) => panic!("consumption cannot reopen the canonical ID before expiry"),
    };
    assert_eq!(consumed_error.code, McpErrorCode::InvalidRequest);

    let mut adjacent = executor
        .execute(&cx, request(302))
        .expect("an unrelated request remains admissible");
    let pending_before_late_duplicate = executor.pending_records();
    executor
        .route_response_with_raw_result(
            &cx,
            JsonRpcResponse::success(
                RequestId::Number(301),
                serde_json::json!({"kind": "complete"}),
            ),
            Some(r#"{"kind":"complete"}"#.to_owned()),
        )
        .expect("changing only the late final ID targets the retired owner");
    assert_eq!(executor.pending_records(), pending_before_late_duplicate);
    executor
        .route_response_with_raw_result(
            &cx,
            JsonRpcResponse::success(
                RequestId::Number(302),
                serde_json::json!({"kind": "complete"}),
            ),
            Some(r#"{"kind":"complete"}"#.to_owned()),
        )
        .expect("only the adjacent owner's final may complete it");
    assert_eq!(
        executor
            .wait(&cx, &mut adjacent)
            .expect("late duplicate cannot complete the adjacent owner")
            .id,
        Some(RequestId::Number(302)),
    );
    assert_eq!(probe.sent_len(), 2);
    let late_duplicates = executor.take_uncorrelated_responses();
    assert_eq!(late_duplicates.len(), 1);
    assert_eq!(late_duplicates[0].id, Some(RequestId::Number(301)));
}

#[test]
fn multiplexed_executor_returns_the_exact_admitted_raw_completion_result() {
    let cx = Cx::for_testing();
    let (transport, probe) = ScriptedTransport::new(std::iter::empty());
    let executor = RequestExecutor::with_protocol_era(transport, ProtocolEra::Legacy2024);
    let mut execution = executor
        .execute(
            &cx,
            JsonRpcRequest::new(
                "completion/complete",
                Some(serde_json::json!({
                    "ref": {"type": "ref/prompt", "name": "deploy"},
                    "argument": {"name": "environment", "value": "sta"},
                })),
                711,
            ),
        )
        .expect("client-originated completion commits through the multiplexed executor");
    let raw_result = r#"{"completion":{"values":["staging"],"total":1,"hasMore":false}}"#;
    executor
        .route_response_with_raw_result(
            &cx,
            JsonRpcResponse::success(
                RequestId::Number(711),
                serde_json::from_str(raw_result).expect("exact raw result is valid JSON"),
            ),
            Some(raw_result.to_owned()),
        )
        .expect("exact completion result is routed to its request owner");

    let (response, retained_raw_result) = executor
        .try_take_response_with_raw_result(&mut execution)
        .expect("terminal owner is available without a second ingress reader")
        .expect("the routed terminal response wakes its owner");
    assert_eq!(response.id, Some(RequestId::Number(711)));
    assert_eq!(retained_raw_result.as_deref(), Some(raw_result));
    assert_eq!(probe.sent_len(), 1);
}

#[test]
fn clt_01_b_positive() {
    assert_eq!(
        clt_01_b_manifest_digest().as_bytes(),
        &[
            0x8f, 0xae, 0x58, 0xf3, 0x7a, 0xe8, 0x54, 0xb1, 0x89, 0xc7, 0x42, 0x9a, 0x75, 0xd8,
            0xf7, 0x4b, 0x4b, 0x88, 0xda, 0x1e, 0x1d, 0xd7, 0xd5, 0x9a, 0x8d, 0x88, 0x0e, 0xd1,
            0x97, 0xa5, 0x78, 0xc6,
        ],
    );
    let cx = Cx::for_testing();
    let (transport, probe) = ScriptedTransport::new([
        Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
            "sampling/createMessage",
            Some(serde_json::json!({"messages": [], "maxTokens": 9})),
            700,
        ))),
        Ok(JsonRpcMessage::Request(JsonRpcRequest::notification(
            "notifications/progress",
            Some(serde_json::json!({"progressToken": 42, "progress": 0.5})),
        ))),
        Ok(response(42, serde_json::json!({"kind": "complete"}))),
    ]);
    let executor = RequestExecutor::new(transport);
    let mut execution = executor.execute(&cx, request(42)).expect("request commits");
    executor.drive(&cx).expect("reverse request is queued");
    let reverse = executor.take_reverse_requests();
    assert_eq!(reverse[0].request_id(), &RequestId::Number(700));
    executor
        .respond_to_reverse_request(&cx, &reverse[0], serde_json::json!({"ok": true}))
        .expect("reverse final is sent");
    executor.drive(&cx).expect("exact progress is streamed");
    assert_eq!(
        execution.take_stream_notifications().expect("stream").len(),
        1
    );
    assert_eq!(
        executor
            .wait(&cx, &mut execution)
            .expect("final follows stream")
            .id,
        Some(RequestId::Number(42))
    );

    let (cancel_transport, _) = ScriptedTransport::new(std::iter::empty());
    let cancelled = RequestExecutor::new(cancel_transport);
    let mut owner = cancelled
        .execute(&cx, request(43))
        .expect("request commits");
    let cancelled_cx = Cx::for_testing();
    cancelled_cx.set_cancel_requested(true);
    assert_eq!(
        cancelled
            .wait(&cancelled_cx, &mut owner)
            .expect_err("caller cancellation wins")
            .code,
        McpErrorCode::RequestCancelled
    );
    assert_eq!(
        cancelled.take_cancellation_events()[0].reason,
        ExecutionTerminalReason::CallerCancelled
    );

    let (timeout_transport, _) = ScriptedTransport::new(std::iter::empty());
    let timed = RequestExecutor::new(timeout_transport);
    let policy = RequestTimeoutPolicy::new(Duration::from_millis(1), Duration::from_millis(2))
        .expect("bounded policy");
    let mut timeout_owner = timed
        .execute_with_timeout_policy(&cx, request(44), policy)
        .expect("request commits");
    timed
        .poll_timeouts_at(&cx, timed.pending_records()[0].idle_deadline)
        .expect("idle timeout selects one terminal outcome");
    assert_eq!(
        timed
            .wait(&cx, &mut timeout_owner)
            .expect_err("timeout releases owner")
            .code,
        McpErrorCode::RequestCancelled
    );

    let mut pagination = OpaquePagination::new(PaginationBounds::default(), Instant::now());
    assert!(
        pagination
            .accept_page(Some(String::new()), 0, 0, Instant::now())
            .expect("empty cursor")
    );
    assert!(
        pagination
            .accept_page(Some(String::new()), 0, 0, Instant::now())
            .expect("repeat cursor")
    );
    assert!(
        !pagination
            .accept_page(None, 0, 0, Instant::now())
            .expect("absent cursor")
    );

    let (shutdown_transport, shutdown_probe) = ScriptedTransport::new(std::iter::empty());
    let shutdown = RequestExecutor::new(shutdown_transport);
    let mut closing = shutdown.execute(&cx, request(45)).expect("request commits");
    shutdown.shutdown(&cx).expect("shutdown completes");
    assert!(shutdown_probe.closed());
    assert_eq!(
        shutdown
            .wait(&cx, &mut closing)
            .expect_err("shutdown releases waiter")
            .code,
        McpErrorCode::RequestCancelled
    );
    assert_eq!(probe.sent_len(), 2);
}

#[test]
fn reverse_callback_cancellation_rejects_stale_owner_after_same_id_reuse() {
    let cx = Cx::for_testing();
    let (transport, probe) = ScriptedTransport::new([
        Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
            "sampling/createMessage",
            Some(serde_json::json!({"messages": [], "maxTokens": 9})),
            700,
        ))),
        Ok(JsonRpcMessage::Request(JsonRpcRequest::notification(
            "notifications/cancelled",
            Some(serde_json::json!({"requestId": 700})),
        ))),
        Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
            "sampling/createMessage",
            Some(serde_json::json!({"messages": [], "maxTokens": 9})),
            700,
        ))),
    ]);
    let executor = RequestExecutor::new(transport);

    executor
        .drive(&cx)
        .expect("first reverse request is retained");
    let stale = executor
        .take_reverse_requests()
        .pop()
        .expect("first request crosses the public handler boundary");
    executor
        .drive(&cx)
        .expect("matching cancellation is accepted for the retained owner");
    assert!(
        stale.cancellation().is_cancel_requested(),
        "the first callback observes its exact cancellation"
    );

    executor
        .drive(&cx)
        .expect("a later request may reuse the cancelled JSON-RPC ID");
    let current = executor
        .take_reverse_requests()
        .pop()
        .expect("reused ID receives a fresh public owner");
    assert!(
        !current.cancellation().is_cancel_requested(),
        "cancellation must not replay into the new request incarnation"
    );

    let error = executor
        .respond_to_reverse_request(&cx, &stale, serde_json::json!({"stale": true}))
        .expect_err("a cancelled callback cannot answer a later request with the same ID");
    assert_eq!(error.code, McpErrorCode::InvalidRequest);
    assert_eq!(probe.sent_len(), 0, "stale refusal writes no peer frame");

    executor
        .respond_to_reverse_request(&cx, &current, serde_json::json!({"current": true}))
        .expect("the current request owner remains response-capable");
    assert_eq!(probe.sent_len(), 1);
}

#[test]
fn reverse_callback_owner_cannot_cross_connection_boundaries() {
    let cx = Cx::for_testing();
    let reverse_request = || {
        Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
            "sampling/createMessage",
            Some(serde_json::json!({"messages": [], "maxTokens": 9})),
            700,
        )))
    };
    let (first_transport, _) = ScriptedTransport::new([reverse_request()]);
    let (second_transport, second_probe) = ScriptedTransport::new([reverse_request()]);
    let first = RequestExecutor::new(first_transport);
    let second = RequestExecutor::new(second_transport);

    first
        .drive(&cx)
        .expect("first connection retains its request");
    second
        .drive(&cx)
        .expect("second connection retains its equal-ID request");
    let foreign = first
        .take_reverse_requests()
        .pop()
        .expect("first connection exposes its owner");
    let local = second
        .take_reverse_requests()
        .pop()
        .expect("second connection exposes its owner");

    let error = second
        .respond_to_reverse_request(&cx, &foreign, serde_json::json!({"foreign": true}))
        .expect_err("an equal request ID from another connection is not an owner");
    assert_eq!(error.code, McpErrorCode::InvalidRequest);
    assert_eq!(
        second_probe.sent_len(),
        0,
        "foreign refusal writes no peer frame"
    );

    second
        .respond_to_reverse_request(&cx, &local, serde_json::json!({"local": true}))
        .expect("the local owner can answer its own connection");
    assert_eq!(second_probe.sent_len(), 1);
}

#[test]
fn reverse_callback_connection_shutdown_cancels_taken_owner() {
    let cx = Cx::for_testing();
    let (transport, probe) =
        ScriptedTransport::new([Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
            "sampling/createMessage",
            Some(serde_json::json!({"messages": [], "maxTokens": 9})),
            700,
        )))]);
    let executor = RequestExecutor::new(transport);
    executor.drive(&cx).expect("reverse request is retained");
    let reverse = executor
        .take_reverse_requests()
        .pop()
        .expect("request crosses the public handler boundary");

    executor
        .shutdown(&cx)
        .expect("connection shutdown completes");
    assert!(
        reverse.cancellation().is_cancel_requested(),
        "a callback cannot remain live after its connection closes"
    );
    let error = executor
        .respond_to_reverse_request(&cx, &reverse, serde_json::json!({"late": true}))
        .expect_err("a closed connection cannot accept a reverse response");
    assert_eq!(error.code, McpErrorCode::InternalError);
    assert_eq!(
        probe.sent_len(),
        0,
        "shutdown leaves no late response frame"
    );
}

#[test]
fn clt_01_b_planted_negative() {
    let cx = Cx::for_testing();
    let (transport, probe) =
        ScriptedTransport::new([Ok(JsonRpcMessage::Request(JsonRpcRequest::notification(
            "notifications/progress",
            Some(serde_json::json!({"progressToken": 101, "progress": 0.5})),
        )))]);
    let executor = RequestExecutor::new(transport);
    let mut owner = executor
        .execute(&cx, request(100))
        .expect("baseline request commits");
    let before = executor.pending_records();

    // One variable changes: the progress token is not the live request ID.
    executor
        .drive(&cx)
        .expect("unrelated progress is peer activity");
    assert_eq!(executor.pending_records(), before);
    assert!(
        owner
            .take_stream_notifications()
            .expect("stream remains empty")
            .is_empty()
    );
    assert_eq!(executor.take_notifications().len(), 1);
    assert_eq!(executor.take_cancellation_events(), [] as [fastmcp_client::CancellationRequested; 0]);
    assert_eq!(probe.sent_len(), 1);
}
