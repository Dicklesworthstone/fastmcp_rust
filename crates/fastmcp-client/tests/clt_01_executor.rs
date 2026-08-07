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
    ExecutionTerminalReason, ExecutionTerminalState, OpaquePagination, PaginationBounds, Request,
    RequestExecutor, RequestTimeoutPolicy, clt_01_a_manifest_digest, clt_01_b_manifest_digest,
};
use fastmcp_core::McpErrorCode;
use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId};
use fastmcp_transport::{Transport, TransportError};

#[derive(Default)]
struct ProbeState {
    received: VecDeque<Result<JsonRpcMessage, TransportError>>,
    sent: Vec<JsonRpcMessage>,
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
}

impl Probe {
    fn sent_len(&self) -> usize {
        self.0.borrow().sent.len()
    }

    fn closed(&self) -> bool {
        self.0.borrow().closed
    }
}

impl Transport for ScriptedTransport {
    fn send(&mut self, _cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
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
    JsonRpcRequest::new("tools/call", Some(serde_json::json!({"id": id})), id)
}

fn response(id: i64, result: serde_json::Value) -> JsonRpcMessage {
    JsonRpcMessage::Response(JsonRpcResponse::success(RequestId::Number(id), result))
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
        record.correlation_key == record.request_id
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
    assert_eq!(executor.take_uncorrelated_responses().len(), 1);
    assert!(executor.pending_records().is_empty());
    assert_eq!(probe.sent_len(), 2);

    let (closed_transport, _) = ScriptedTransport::new([Err(TransportError::Closed)]);
    let closed = RequestExecutor::new(closed_transport);
    let mut owner = closed.execute(&cx, request(3)).expect("request commits");
    assert_eq!(
        closed
            .drive(&cx)
            .expect_err("connection loss fails the owner")
            .code,
        McpErrorCode::InternalError
    );
    assert_eq!(
        closed
            .wait(&cx, &mut owner)
            .expect_err("waiter fanout outcome")
            .code,
        McpErrorCode::InternalError
    );
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
    let error = executor
        .execute(&cx, request(7))
        .expect_err("duplicate in-flight ID is rejected");
    assert_eq!(error.code, McpErrorCode::InvalidRequest);
    assert_eq!(executor.pending_records(), before);
    assert_eq!(probe.sent_len(), 1);
    assert!(executor.take_notifications().is_empty());
    assert!(executor.take_uncorrelated_responses().is_empty());
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
            Some(serde_json::json!({"messages": []})),
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
    assert_eq!(reverse[0].id, Some(RequestId::Number(700)));
    executor
        .respond_to_reverse_request(&cx, RequestId::Number(700), serde_json::json!({"ok": true}))
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
    assert!(executor.take_cancellation_events().is_empty());
    assert_eq!(probe.sent_len(), 1);
}
