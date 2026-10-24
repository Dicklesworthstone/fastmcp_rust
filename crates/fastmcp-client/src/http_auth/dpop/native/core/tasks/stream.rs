//! Incremental, negotiated Task operations on the existing DPoP stream owner.
//!
//! Discovery remains a finite JSON exchange. The subsequent tool/get/update/
//! cancel reply may be JSON or SSE, but neither its media type nor resultType
//! chooses its method authority. The same Reply decoder serves both transports;
//! the common DPoP reader owns TLS, nonce/proof handling, observers and EOF.

/// Task-capable tool conversations with explicit typed host input.
pub mod interaction;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::common_types::ExactNonNegativeJsonNumber;
use fastmcp_protocol::{
    FinalRequestMeta, JsonRpcMessage, ProgressMarker, RequestId, ServerNotification,
    decode_strict_jsonrpc_message,
};

use super::{
    Admitted, DpopCredential, DpopHttpClient, DpopTaskOperation,
    ManagedCoreError, ManagedCoreLimits, ManagedTaskEvent,
    ModernHttpRequest, Prepared, Reply, WaitBounds, check_live,
};
use super::super::stream::{
    CompletedStream, DpopStreamError, DpopStreamLimits, Idle, PreparedStream, StreamDecoder,
    StreamEvent,
};
use super::super::stream::budget::{Budgeted, SharedStreamBudget};
use crate::http_auth::rpc::admit_http_notification;

pub(super) struct TaskStreamDecoder {
    id: RequestId,
    reply: Reply,
    limits: ManagedCoreLimits,
    maximum_frame: usize,
    bytes: usize,
    notifications: usize,
    progress: Option<ProgressMarker>,
    last_progress: Option<ExactNonNegativeJsonNumber>,
    terminal: bool,
}

impl TaskStreamDecoder {
    fn from_admitted(
        admitted: Admitted,
        limits: ManagedCoreLimits,
        discovery_bytes: usize,
        progress: Option<ProgressMarker>,
    ) -> Result<(ModernHttpRequest, Self), DpopStreamError> {
        Self::with_usage(admitted, limits, (discovery_bytes, 0), progress)
    }

    // Private continuation seam: only the lifecycle owner may seed cumulative
    // payload/notification usage. Per-request correlation and progress history
    // start afresh, but quotas never do. A terminal is still permitted when the
    // notification count is exactly exhausted and payload capacity remains.
    pub(super) fn with_usage(
        admitted: Admitted,
        limits: ManagedCoreLimits,
        usage: (usize, usize),
        progress: Option<ProgressMarker>,
    ) -> Result<(ModernHttpRequest, Self), DpopStreamError> {
        if usage.1 > limits.notifications() {
            return Err(ManagedCoreError::NotificationLimit.into());
        }
        let remaining = limits.total_bytes().checked_sub(usage.0)
            .filter(|remaining| *remaining > 0)
            .ok_or(ManagedCoreError::ResponseByteLimit)?;
        let Admitted { wire, id, reply, maximum } = admitted;
        Ok((wire, Self {
            id,
            reply,
            limits,
            maximum_frame: maximum.min(limits.frame_bytes()).min(remaining),
            bytes: usage.0,
            notifications: usage.1,
            progress,
            last_progress: None,
            terminal: false,
        }))
    }
}

impl StreamDecoder for TaskStreamDecoder {
    type Terminal = ManagedTaskEvent;

    fn admit(
        &mut self,
        frame: &[u8],
        allow_notification: bool,
    ) -> Result<StreamEvent<ManagedTaskEvent>, DpopStreamError> {
        if self.terminal {
            return Err(ManagedCoreError::InvalidResponse.into());
        }
        let maximum = self.maximum_frame.min(
            self.limits.total_bytes().saturating_sub(self.bytes),
        );
        if frame.len() > maximum {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        // Raw duplicate/batch admission precedes both method decoding and any
        // progress/quota mutation. No rejected frame can spend or rewind state.
        let message = decode_strict_jsonrpc_message(frame, maximum)
            .map_err(|_| ManagedCoreError::InvalidResponse)?;
        let event = match message {
            JsonRpcMessage::Response(_) => {
                let result = self.reply.decode(&self.id, frame, maximum)?;
                self.terminal = true;
                StreamEvent::Result(result)
            }
            JsonRpcMessage::Request(request) => {
                if !allow_notification || request.id.is_some() {
                    return Err(ManagedCoreError::UnexpectedNotification.into());
                }
                if self.notifications >= self.limits.notifications() {
                    return Err(ManagedCoreError::NotificationLimit.into());
                }
                let notification = admit_http_notification(
                    frame,
                    &request,
                    self.progress.as_ref(),
                    self.last_progress.as_ref(),
                )?;
                if let ServerNotification::Progress(progress) = &notification {
                    self.last_progress = Some(progress.progress.clone());
                }
                self.notifications += 1;
                StreamEvent::Notification(Box::new(notification))
            }
        };
        self.bytes += frame.len();
        Ok(event)
    }

    fn usage(&self) -> (usize, usize) {
        (self.bytes, self.notifications)
    }
}

// Capture progress identity from the already-admitted, actual operation body,
// never from the discovery ID or an unrelated synthetic core request. This
// bounded preflight runs before discovery/proof signing and retains no inputs.
pub(super) fn progress_marker(
    wire: &ModernHttpRequest,
    maximum: usize,
) -> Result<Option<ProgressMarker>, DpopStreamError> {
    let message = decode_strict_jsonrpc_message(wire.body(), maximum)
        .map_err(|_| ManagedCoreError::InvalidRequest)?;
    let JsonRpcMessage::Request(request) = message else {
        return Err(ManagedCoreError::InvalidRequest.into());
    };
    request.params.as_ref()
        .and_then(|params| params.get("_meta"))
        .and_then(|meta| meta.get("progressToken"))
        .map(|value| serde_json::from_value(value.clone())
            .map_err(|_| ManagedCoreError::InvalidRequest.into()))
        .transpose()
}

impl DpopHttpClient {
    /// Executes fresh authenticated Tasks discovery, then one Task operation
    /// with incremental notifications and a method-owned JSON or SSE result.
    ///
    /// This explicitly selected Tasks API supports tool calls, get, update and
    /// cancel. Tool completion, input-required and task results remain distinct;
    /// get returns its requested Task, while update/cancel return acknowledgements,
    /// never invented snapshots. Ordinary core calls remain core-only. Metadata,
    /// both request bodies and an update's input ledger are checked before I/O.
    /// Other extension offers are not silently replaced or negotiated here.
    ///
    /// Discovery is JSON-only and must admit the exact official Tasks surface.
    /// Operation notifications are delivered as they arrive. A terminal remains
    /// provisional until clean HTTP EOF; extra records, unfinished tails and
    /// missing completion fail. JSON replies cannot smuggle a notification.
    /// No input-required result, failed mutation or challenge triggers replay.
    ///
    /// One original credential, resource and absolute deadline own both POSTs,
    /// including preparation, decoding and observer work. The idle budget also
    /// starts before discovery; only valid, matching, strictly increasing progress
    /// can extend idle time, never the absolute or token deadline. The core total
    /// payload limit includes discovery and every operation payload, and its
    /// notification limit spans the operation. Native raw-body and SSE syntax
    /// limits remain independent. Zero notifications requires terminal-only data.
    ///
    /// `observer` returns true to continue or false to stop. It must be brief,
    /// nonblocking and apply local disclosure policy. Already-delivered events
    /// and committed remote effects cannot be recalled. Cancellation, revocation,
    /// expiry, observer refusal/panic or drop retires this owned request without
    /// closing the caller's context. There is no background worker, automatic
    /// refresh, bearer downgrade, polling, reconnect or cancellation POST.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_task_with_events<N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        operation: DpopTaskOperation,
        limits: DpopStreamLimits,
        mut observer: N,
    ) -> Result<ManagedTaskEvent, DpopStreamError>
    where
        N: FnMut(&ServerNotification) -> bool,
    {
        let bounds = WaitBounds::new(cx, self.policy.timeout.min(limits.core.timeout()), credential)?;
        self.request_task_stream_with_bounds(
            cx, cancellation, credential, metadata, operation, limits, bounds, &mut observer,
        ).await.map(|completed| completed.result)
    }

    // Polling, input-driving and subscription-watch consumers retain their
    // ORIGINAL bounds and charge actual payload/notification usage. Visibility
    // stops at the private core integration; no public retry capability is added.
    #[allow(clippy::too_many_arguments)]
    pub(in super::super) async fn request_task_stream_with_bounds<N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        operation: DpopTaskOperation,
        limits: DpopStreamLimits,
        bounds: WaitBounds,
        observer: &mut N,
    ) -> Result<CompletedStream<ManagedTaskEvent>, DpopStreamError>
    where
        N: FnMut(&ServerNotification) -> bool,
    {
        self.request_task_stream_with_budget(
            cx, cancellation, credential, metadata, operation, limits, bounds, observer, None,
        ).await
    }

    // Only a live watch supplies the aggregate ledger. Its discovery and
    // method frames are charged before publication, alongside listen frames.
    #[allow(clippy::too_many_arguments)]
    pub(in super::super) async fn request_task_stream_with_budget<N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        operation: DpopTaskOperation,
        limits: DpopStreamLimits,
        bounds: WaitBounds,
        observer: &mut N,
        budget: Option<SharedStreamBudget>,
    ) -> Result<CompletedStream<ManagedTaskEvent>, DpopStreamError>
    where
        N: FnMut(&ServerNotification) -> bool,
    {
        let idle = Idle::new(cx.now(), limits.idle);
        check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
        let prepared = Prepared::new(
            self.resource().as_str(), metadata, operation, limits.core, self.policy.max_body_bytes,
        );
        check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
        let prepared = prepared?;
        let progress = progress_marker(&prepared.operation_wire, limits.core.request_bytes())?;
        check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
        let response = self.post_resource_with_bounds(
            cx, cancellation, credential, &prepared.discovery_wire, idle.bounds(bounds),
        ).await?;
        check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
        let discovery_bytes = response.body().len();
        let admitted = prepared.admit(response);
        check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
        let (wire, decoder) = TaskStreamDecoder::from_admitted(
            admitted?, limits.core, discovery_bytes, progress,
        )?;
        if let Some(budget) = &budget {
            budget.charge((discovery_bytes, 0))?;
        }
        let decoder = Budgeted::new(decoder, budget);
        self.execute_prepared_core_stream(
            cx, cancellation, credential,
            PreparedStream { wire, decoder, limits, bounds, idle }, observer,
        ).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};
    use fastmcp_core::CanonicalHttpUrl;
    use fastmcp_protocol::{ClientCapabilities, CoreResult, FinalCoreResult};
    use fastmcp_protocol::dpop::DpopKey;
    use fastmcp_protocol::tasks_extension::{Task, TaskId, TASKS_EXTENSION};
    use serde_json::{Value, json};
    use crate::http_auth::dpop::DpopSession;
    use crate::http_auth::dpop::native::{DpopHttpPolicy, DpopHttpResponse};
    use super::super::{
        DpopCoreError, DpopHttpError, DpopTasksError, ManagedTaskRequest, ManagedTasksError,
    };

    #[cfg(feature = "native-tls-roots")]
    mod tls;

    const TARGET: &str = "https://mcp.example/mcp?tenant=one";
    const TASK_FIELDS: &str = r#""taskId":"task-one","status":"working","createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z","ttlMs":60000"#;

    fn limits(notifications: usize) -> DpopStreamLimits {
        DpopStreamLimits::new(
            ManagedCoreLimits::new(8192, 8192, 32768, notifications, Duration::from_secs(60)).unwrap(),
            Duration::from_secs(30),
        ).unwrap()
    }

    fn metadata() -> FinalRequestMeta {
        let mut meta = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        meta["progressToken"] = json!("work");
        serde_json::from_value(meta).unwrap()
    }

    fn request(kind: usize) -> ManagedTaskRequest {
        let id = TaskId::parse("task-one").unwrap();
        match kind {
            0 => ManagedTaskRequest::CallTool {
                name: "echo".to_owned(), arguments: Some(json!({"private":"body-only","x":17})),
            },
            1 => {
                ManagedTaskRequest::Get(id)
            }
            2 => {
                let task: Task = serde_json::from_value(json!({
                    "taskId":"task-one", "status":"input_required",
                    "createdAt":"2026-09-16T00:00:00Z", "lastUpdatedAt":"2026-09-16T00:00:00Z",
                    "ttlMs":60000, "inputRequests":{"roots":{"method":"roots/list"}}
                })).unwrap();
                ManagedTaskRequest::Update {
                    task: Box::new(task),
                    input_responses: serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap(),
                }
            }
            _ => ManagedTaskRequest::Cancel(id),
        }
    }

    fn operation(kind: usize, first: i64) -> DpopTaskOperation {
        DpopTaskOperation::new(RequestId::Number(first), RequestId::Number(first + 1), request(kind)).unwrap()
    }

    fn discovery_result() -> Value {
        json!({"resultType":"complete", "supportedVersions":[super::super::FINAL_PROTOCOL_VERSION],
            "capabilities":{"tools":{},"extensions":{TASKS_EXTENSION:{}}},
            "ttlMs":0,"cacheScope":"private",
            "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"task-peer","version":"1"}}})
    }

    fn frame(id: i64, result: &str) -> Vec<u8> {
        format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#).into_bytes()
    }

    fn response(bytes: Vec<u8>) -> DpopHttpResponse {
        DpopHttpResponse { status: 200, headers: vec![], body: bytes }
    }

    fn terminal(kind: usize) -> String {
        match kind {
            0 => format!(r#"{{"resultType":"task",{TASK_FIELDS}}}"#),
            1 => format!(r#"{{"resultType":"complete",{TASK_FIELDS}}}"#),
            _ => r#"{"resultType":"complete"}"#.to_owned(),
        }
    }

    fn prepared(kind: usize, limits: DpopStreamLimits) -> Prepared {
        Prepared::new(TARGET, metadata(), operation(kind, 1), limits.core, 8192).unwrap()
    }

    fn decoder(kind: usize, limits: DpopStreamLimits) -> TaskStreamDecoder {
        let prepared = prepared(kind, limits);
        let progress = progress_marker(&prepared.operation_wire, limits.core.request_bytes()).unwrap();
        let discovery = frame(1, &discovery_result().to_string());
        let bytes = discovery.len();
        TaskStreamDecoder::from_admitted(prepared.admit(response(discovery)).unwrap(), limits.core, bytes, progress)
            .unwrap().1
    }

    fn progress(token: Value, value: &str) -> Vec<u8> {
        format!(r#"{{"jsonrpc":"2.0","method":"notifications/progress","params":{{"progressToken":{token},"progress":{value}}}}}"#).into_bytes()
    }

    fn snapshot(decoder: &TaskStreamDecoder) -> (usize, usize, bool, Option<ExactNonNegativeJsonNumber>) {
        (decoder.bytes, decoder.notifications, decoder.terminal, decoder.last_progress.clone())
    }

    fn assert_result(kind: usize, event: ManagedTaskEvent) {
        assert!(match (kind, event) {
            (0, ManagedTaskEvent::ToolResult(result)) => matches!(*result, FinalCoreResult::ToolsCallTask { .. }),
            (1, ManagedTaskEvent::Snapshot(result)) => result.task.base().task_id.as_str() == "task-one",
            (2, ManagedTaskEvent::Updated(_)) | (3, ManagedTaskEvent::Cancelled(_)) => true,
            _ => false,
        });
    }

    #[test]
    fn json_and_streamed_task_results_share_method_and_identity_admission() {
        for kind in 0..4 {
            for sse in [false, true] {
                let mut decoder = decoder(kind, limits(4));
                let before = snapshot(&decoder);
                assert!(matches!(decoder.admit(&frame(3, &terminal(kind)), sse),
                    Err(DpopStreamError::Task(DpopTasksError::Task(ManagedTasksError::ResponseIdMismatch)))));
                assert_eq!(snapshot(&decoder), before);
                let StreamEvent::Result(event) = decoder.admit(&frame(2, &terminal(kind)), sse).unwrap() else {
                    panic!("expected the method-owned terminal");
                };
                assert_result(kind, event);
                let completed = snapshot(&decoder);
                assert!(decoder.admit(&frame(2, &terminal(kind)), sse).is_err());
                assert_eq!(snapshot(&decoder), completed);
            }
        }
        let mut get = decoder(1, limits(0));
        let before = snapshot(&get);
        assert!(matches!(get.admit(&frame(2, &terminal(1).replace("task-one", "task-two")), false),
            Err(DpopStreamError::Task(DpopTasksError::Task(ManagedTasksError::TaskIdMismatch)))));
        assert_eq!(snapshot(&get), before);
    }

    #[test]
    fn tool_complete_input_required_and_task_are_not_coerced_into_one_result_family() {
        for (source, kind) in [
            (r#"{"resultType":"complete","content":[],"x-exact":{"z":900719925474099312345,"a":1.20e+4}}"#.to_owned(), 0),
            (r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"opaque-state"}"#.to_owned(), 1),
            (terminal(0), 2),
        ] {
            let mut decoder = decoder(0, limits(0));
            let StreamEvent::Result(ManagedTaskEvent::ToolResult(result)) = decoder.admit(&frame(2, &source), true).unwrap() else {
                panic!("tool outcome must remain typed");
            };
            assert!(matches!((kind, &*result),
                (0, FinalCoreResult::ToolsCall { .. })
                | (1, FinalCoreResult::ToolsCallInputRequired { .. })
                | (2, FinalCoreResult::ToolsCallTask { .. })));
            if kind == 0 {
                let encoded = CoreResult::Final(*result).encode().unwrap();
                assert!(encoded.contains("900719925474099312345"));
                assert!(encoded.contains("1.20e+4"));
            }
        }
    }

    #[test]
    fn discovery_and_all_streamed_payloads_spend_one_exact_byte_budget() {
        let discovery = frame(1, &discovery_result().to_string()).len();
        let notification = progress(json!("work"), "1");
        let final_frame = frame(2, &terminal(1));
        let maximum = discovery.max(notification.len()).max(final_frame.len());
        let exact = discovery + notification.len() + final_frame.len();
        for subtract in [0, 1] {
            let bounded = DpopStreamLimits::new(ManagedCoreLimits::new(
                8192, maximum, exact - subtract, 1, Duration::from_secs(60),
            ).unwrap(), Duration::from_secs(30)).unwrap();
            let mut decoder = decoder(1, bounded);
            assert_eq!(decoder.usage(), (discovery, 0));
            assert!(matches!(decoder.admit(&notification, true), Ok(StreamEvent::Notification(_))));
            let before = snapshot(&decoder);
            let result = decoder.admit(&final_frame, true);
            if subtract == 0 {
                assert!(matches!(result, Ok(StreamEvent::Result(_))));
                assert_eq!(decoder.usage(), (exact, 1));
            } else {
                assert!(matches!(result, Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit)))));
                assert_eq!(snapshot(&decoder), before);
            }
        }
        let exhausted = ManagedCoreLimits::new(8192, discovery, discovery, 0, Duration::from_secs(60)).unwrap();
        let prepared = Prepared::new(TARGET, metadata(), operation(1, 1), exhausted, 8192).unwrap();
        assert!(prepared.admit(response(frame(1, &discovery_result().to_string()))).is_err());
    }

    #[test]
    fn progress_is_exact_request_owned_and_refused_frames_leave_state_unchanged() {
        for kind in 0..4 {
            let mut decoder = decoder(kind, limits(2));
            let first = "900719925474099312345";
            assert!(matches!(decoder.admit(&progress(json!("work"), first), true), Ok(StreamEvent::Notification(_))));
            let before = snapshot(&decoder);
            for (token, value) in [(json!(2), "1e400"), (json!("other"), "1e400"),
                (json!("work"), first), (json!("work"), "900719925474099312344")] {
                assert!(matches!(decoder.admit(&progress(token, value), true),
                    Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidProgress)))));
                assert_eq!(snapshot(&decoder), before);
            }
            assert!(decoder.admit(&progress(json!("work"), "900719925474099312346"), true).is_ok());
            let before = snapshot(&decoder);
            assert!(matches!(decoder.admit(&progress(json!("work"), "1e400"), true),
                Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::NotificationLimit)))));
            assert_eq!(snapshot(&decoder), before);
            assert!(decoder.admit(&frame(2, &terminal(kind)), true).is_ok());
        }
        let mut decoder = decoder(1, limits(0));
        let before = snapshot(&decoder);
        assert!(decoder.admit(&progress(json!("work"), "1"), true).is_err());
        assert_eq!(snapshot(&decoder), before);
        assert!(decoder.admit(&frame(2, &terminal(1)), true).is_ok());
    }

    #[test]
    fn malformed_control_and_json_notifications_cannot_advance_a_task_stream() {
        let mut decoder = decoder(1, limits(8));
        for frame in [
            br#"[{"jsonrpc":"2.0","id":2,"result":{}}]"#.to_vec(),
            br#"{"jsonrpc":"2.0","id":2,"id":2,"result":{}}"#.to_vec(),
            br#"{"jsonrpc":"2.0","id":9,"method":"roots/list"}"#.to_vec(),
            br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}"#.to_vec(),
            br#"{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"notifications":{}}}"#.to_vec(),
            br#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"work","progress":1,"progress":2}}"#.to_vec(),
        ] {
            let before = snapshot(&decoder);
            assert!(decoder.admit(&frame, true).is_err());
            assert_eq!(snapshot(&decoder), before);
        }
        let before = snapshot(&decoder);
        assert!(decoder.admit(&progress(json!("work"), "1"), false).is_err());
        assert_eq!(snapshot(&decoder), before);
        let peer_error = br#"{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"private-peer-canary","data":"private-input-canary"}}"#;
        let error = decoder.admit(peer_error, true).err().unwrap();
        assert!(matches!(&error, DpopStreamError::Task(DpopTasksError::Task(ManagedTasksError::Remote { .. }))));
        assert!(!format!("{error:?} {error}").contains("canary"));
        assert_eq!(snapshot(&decoder), before);
        assert!(decoder.admit(&frame(2, &terminal(1)), true).is_ok());
    }

    #[test]
    fn progress_preflight_reads_the_exact_operation_and_precancelled_calls_do_not_dispatch() {
        for kind in 0..4 {
            let prepared = prepared(kind, limits(4));
            assert_eq!(progress_marker(&prepared.operation_wire, 8192).unwrap(), Some(ProgressMarker::String("work".to_owned())));
            assert!(progress_marker(&prepared.operation_wire, prepared.operation_wire.body().len() - 1).is_err());
        }
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
        let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(), CanonicalHttpUrl::parse(TARGET).unwrap()).unwrap();
        let credential = session.admit_token_response(&issuer, 200,
            br#"{"access_token":"test-token","token_type":"DPoP","expires_in":60}"#,
            Instant::now(), Duration::from_secs(60)).unwrap();
        let mut client = DpopHttpClient::new(session, DpopHttpPolicy::default()).unwrap();
        let cancellation = McpRequestCancellation::new();
        let mut calls = 0;
        let mut future = Box::pin(client.request_task_with_events(
            &cx, &cancellation, &credential, metadata(), operation(1, 1), limits(4),
            |_| { calls += 1; true },
        ));
        assert!(matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled))))));
        drop(future);
        assert_eq!(calls, 0);
        assert!(!cancellation.is_cancel_requested());
    }
}
