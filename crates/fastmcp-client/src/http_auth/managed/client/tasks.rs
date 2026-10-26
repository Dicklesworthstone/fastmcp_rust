//! Official Tasks operations under the managed credential boundary.
//!
//! Returned values contain no connection, token, or running response owner.
//! Task identity is opaque data; the upstream must authorize every later action.

use std::time::Duration;

use asupersync::Cx;
use asupersync::time::Sleep;
use fastmcp_core::{McpError, McpErrorCode, McpRequestCancellation};
use fastmcp_protocol::tasks_extension::TaskInputLedger;
use fastmcp_protocol::FinalCoreResult;
use serde_json::Value;

use super::{Call, CallResult, ManagedHttpClient, ManagedHttpClientError};
use crate::{
    ClientHttpConnectionError, FinalCancelTaskResult, FinalGetTaskResult, FinalTask, FinalTaskId,
    FinalTaskInputResponses, FinalToolCallOutcome, FinalUpdateTaskResult, HttpClient,
    HttpClientError, ModernHttpSubscriptionTermination,
};

mod listen;
mod resolve;
mod tool_events;

const MAX_TASK_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TASK_WAIT_POLLS: usize = 1_024;

// Tool outcomes, direct subscriptions, and watches share the same native
// framing policy. Application payload budgets count decoded typed values,
// not JSON-RPC envelopes or SSE fields, and must not shrink these limits.
// Conversely a small wire document can still contain excessive data fields:
// the byte ceiling is not a substitute for the explicit per-event line cap.
fn task_sse_limits() -> Result<crate::sse::SseLimits, HttpClientError> {
    crate::sse::SseLimits::with_data_lines(
        MAX_TASK_RESPONSE_BYTES + 8,
        MAX_TASK_RESPONSE_BYTES,
        64,
        4_096,
    )
    .ok_or_else(|| {
        HttpClientError::CoreResult(McpError::internal_error(
            "Invalid managed Tasks response limits",
        ))
    })
}

pub(super) enum TaskCall<'a> {
    Tool {
        name: &'a str,
        arguments: Value,
    },
    ToolEvents(tool_events::ToolEventRequest<'a>),
    Get(FinalTaskId),
    Update {
        task: &'a FinalTask,
        responses: FinalTaskInputResponses,
    },
    Cancel(FinalTaskId),
    Wait {
        task_id: FinalTaskId,
        minimum_interval: Duration,
        max_polls: usize,
    },
    Listen(listen::ListenRequest<'a>),
    Watch(listen::watch::WatchRequest),
    Resolve {
        task_id: FinalTaskId,
        max_inputs: usize,
        max_payload_bytes: usize,
    },
}

pub(super) enum TaskResult {
    Tool(Box<FinalToolCallOutcome>),
    Get(Box<FinalGetTaskResult>),
    Update(FinalUpdateTaskResult),
    Cancel(FinalCancelTaskResult),
    Listen(Option<Box<ModernHttpSubscriptionTermination>>),
}

fn invalid_input() -> ManagedHttpClientError {
    ManagedHttpClientError::Request {
        code: Some(McpErrorCode::InvalidParams),
    }
}

fn admit_input(
    task: &FinalTask,
    responses: &FinalTaskInputResponses,
) -> Result<(), ManagedHttpClientError> {
    let FinalTask::InputRequired { input_requests, .. } = task else {
        return Err(invalid_input());
    };
    TaskInputLedger::from_requests(input_requests)
        .map_err(|_| invalid_input())?
        .validate_responses(responses)
        .map_err(|_| invalid_input())
}

fn admit_wait(minimum_interval: Duration, max_polls: usize) -> Result<(), ManagedHttpClientError> {
    if !(1..=MAX_TASK_WAIT_POLLS).contains(&max_polls)
        || minimum_interval < Duration::from_millis(1)
        || minimum_interval > Duration::from_secs(60)
    {
        return Err(ManagedHttpClientError::InvalidPolicy);
    }
    Ok(())
}

fn checkpoint(cx: &Cx, cancellation: &McpRequestCancellation) -> Result<(), HttpClientError> {
    if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
        return Err(HttpClientError::CoreResult(McpError::request_cancelled()));
    }
    Ok(())
}

fn poll_interval(task: &FinalTask, minimum: Duration) -> Result<Duration, HttpClientError> {
    let Some(interval) = &task.base().poll_interval_ms else {
        return Ok(minimum);
    };
    let millis = interval.try_as_millis().map_err(|_| {
        HttpClientError::CoreResult(McpError::invalid_request("Invalid task polling interval"))
    })?;
    // Never shorten a peer interval to make it fit the local operation timeout.
    // The enclosing managed deadline/credential guard wins a longer wait instead.
    Ok(minimum.max(Duration::from_millis(millis)))
}

impl TaskCall<'_> {
    pub(super) async fn dispatch(
        self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        client: &mut HttpClient,
    ) -> Result<TaskResult, HttpClientError> {
        checkpoint(cx, cancellation)?;
        // All verbs use the ordinary client's one monotonic ID allocator. The
        // native methods retain bilateral Tasks admission and raw correlation.
        let id = client.next_request_id()?;
        match self {
            Self::Tool { name, arguments } => {
                let limits = task_sse_limits()?;
                let listener = client
                    .connection
                    .open_final_tasks_tool_call_listener(cx, id, name, arguments, limits)
                    .await
                    .map_err(HttpClientError::Connection)?;
                // JSON and finite SSE are both collected INSIDE the outer
                // managed session/credential guards. No stream may escape them.
                let collected = listener.collect(cx).await.map_err(|error| {
                    HttpClientError::Connection(ClientHttpConnectionError::FinalCoreListen(error))
                })?;
                let outcome = match collected.terminal {
                    FinalCoreResult::ToolsCall { result, .. } => {
                        FinalToolCallOutcome::Complete(result)
                    }
                    FinalCoreResult::ToolsCallTask { result } => FinalToolCallOutcome::Task(result),
                    FinalCoreResult::ToolsCallInputRequired { result, .. } => {
                        FinalToolCallOutcome::InputRequired(result)
                    }
                    _ => {
                        return Err(HttpClientError::CoreResult(McpError::invalid_request(
                            "Unexpected managed Tasks tool outcome",
                        )));
                    }
                };
                Ok(TaskResult::Tool(Box::new(outcome)))
            }
            Self::ToolEvents(request) => {
                Box::pin(request.dispatch(cx, cancellation, client, id)).await
            }
            Self::Get(task_id) => client
                .connection
                .get_task_final(cx, id, task_id, MAX_TASK_RESPONSE_BYTES)
                .await
                .map(|result| TaskResult::Get(Box::new(result)))
                .map_err(HttpClientError::Connection),
            Self::Update { task, responses } => client
                .connection
                .update_task_final(cx, id, task, responses, MAX_TASK_RESPONSE_BYTES)
                .await
                .map(TaskResult::Update)
                .map_err(HttpClientError::Connection),
            Self::Cancel(task_id) => client
                .connection
                .cancel_task_final(cx, id, task_id, MAX_TASK_RESPONSE_BYTES)
                .await
                .map(TaskResult::Cancel)
                .map_err(HttpClientError::Connection),
            Self::Wait {
                task_id,
                minimum_interval,
                max_polls,
            } => {
                let mut request_id = id;
                for poll in 0..max_polls {
                    checkpoint(cx, cancellation)?;
                    let result = client
                        .connection
                        .get_task_final(cx, request_id, task_id.clone(), MAX_TASK_RESPONSE_BYTES)
                        .await
                        .map_err(HttpClientError::Connection)?;
                    checkpoint(cx, cancellation)?;
                    if !matches!(&result.task, FinalTask::Working(_)) || poll + 1 == max_polls {
                        return Ok(TaskResult::Get(Box::new(result)));
                    }
                    let interval = poll_interval(&result.task, minimum_interval)?;
                    // Retain no history or response body while idle. Peer delays
                    // outside the clock's range saturate, never wrap into a hot loop.
                    drop(result);
                    let at = cx.now().saturating_add_nanos(
                        u64::try_from(interval.as_nanos()).unwrap_or(u64::MAX),
                    );
                    Sleep::new(at).await;
                    checkpoint(cx, cancellation)?;
                    request_id = client.next_request_id()?;
                }
                // The public entrypoint admits a nonzero bounded count. Keep an
                // internal misuse a typed failure rather than an unbounded loop.
                Err(HttpClientError::CoreResult(McpError::invalid_params(
                    "Task wait requires a nonzero poll count",
                )))
            }
            Self::Listen(request) => request.dispatch(cx, cancellation, client, id).await,
            Self::Watch(request) => Box::pin(request.dispatch(cx, cancellation, client, id)).await,
            Self::Resolve {
                task_id,
                max_inputs,
                max_payload_bytes,
            } => {
                Box::pin(resolve::dispatch(
                    cx,
                    cancellation,
                    client,
                    id,
                    task_id,
                    max_inputs,
                    max_payload_bytes,
                ))
                .await
            }
        }
    }
}

impl ManagedHttpClient {
    /// Explicitly enables completed official Tasks operations on this client.
    ///
    /// The `tasks` feature must be compiled in and upstream discovery must
    /// independently admit the official extension with exact empty settings.
    /// No credential or HTTP request is acquired here. Changing this local
    /// policy retires any earlier connection and its catalog cursors. Repeating
    /// the selection is a no-op; it never reopens a closed client or session.
    #[must_use]
    pub fn with_tasks(mut self) -> Self {
        if !self.tasks_enabled {
            self.connection = None;
            self.tasks_enabled = true;
        }
        self
    }

    fn admit_tasks(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> Result<(), ManagedHttpClientError> {
        if self.closed {
            return Err(ManagedHttpClientError::Closed);
        }
        self.session.check(cx, cancellation)?;
        if !self.tasks_enabled {
            return Err(ManagedHttpClientError::InvalidPolicy);
        }
        Ok(())
    }

    async fn perform_task(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        call: TaskCall<'_>,
    ) -> Result<TaskResult, ManagedHttpClientError> {
        self.admit_tasks(cx, cancellation)?;
        match self.perform_any(cx, cancellation, Call::Task(call)).await? {
            CallResult::Task(value) => Ok(*value),
            CallResult::Core(_) | CallResult::Catalog(_) | CallResult::CoreListen(_) => {
                Err(ManagedHttpClientError::InvalidPolicy)
            }
        }
    }

    /// Invokes a Tasks-capable tool, retaining complete, task and input-required
    /// outcomes exactly. Requires `with_tasks`; never follows reverse handlers,
    /// resumes MRTR, polls a created task, or retries an uncertain tool execution.
    /// The finite operation timeout covers credential acquisition, discovery and
    /// the entire JSON/SSE response. Dropping the call retires its connection,
    /// not an already-created remote task; cancel that task explicitly by ID.
    pub async fn call_tool_final_outcome(
        &mut self,
        cx: &Cx,
        name: &str,
        arguments: Value,
    ) -> Result<FinalToolCallOutcome, ManagedHttpClientError> {
        self.call_tool_final_outcome_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            name,
            arguments,
        )
        .await
    }

    /// The exact tool-outcome operation with an independent cancellation domain.
    pub async fn call_tool_final_outcome_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        name: &str,
        arguments: Value,
    ) -> Result<FinalToolCallOutcome, ManagedHttpClientError> {
        match self
            .perform_task(cx, cancellation, TaskCall::Tool { name, arguments })
            .await?
        {
            TaskResult::Tool(result) => Ok(*result),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }

    /// Fetches one authorized task snapshot. Every operation obtains a current
    /// credential; renewal invalidates discovery and caches before the GET-like
    /// MCP POST. The peer's returned task ID must match the requested ID.
    pub async fn get_task_final(
        &mut self,
        cx: &Cx,
        task_id: FinalTaskId,
    ) -> Result<FinalGetTaskResult, ManagedHttpClientError> {
        self.get_task_final_with_cancellation(cx, &McpRequestCancellation::new(), task_id)
            .await
    }

    /// Fetches a snapshot under the supplied cancellation domain.
    pub async fn get_task_final_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> Result<FinalGetTaskResult, ManagedHttpClientError> {
        match self
            .perform_task(cx, cancellation, TaskCall::Get(task_id))
            .await?
        {
            TaskResult::Get(result) => Ok(*result),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }

    /// Waits for a task to need input, complete, fail or be cancelled.
    ///
    /// Fetches immediately, then polls only while the task is `Working`. Each
    /// delay is at least both `minimum_interval` and the latest peer-provided
    /// `pollIntervalMs`. At most `max_polls` requests are sent. Exhausting that
    /// count returns the last exact `Working` snapshot: callers MUST inspect
    /// `result.task`, not equate a successful wait with successful task completion.
    /// Input-required and failed results likewise retain their original variants.
    ///
    /// One operation deadline covers acquisition, discovery, all HTTP responses
    /// and all delays. One credential generation authorizes the entire wait;
    /// renewal is considered only before it starts and never extends a running
    /// wait's authority. Cancellation, session closure and original credential
    /// expiry interrupt an idle delay as well as an active HTTP request. A failed
    /// request is not retried. Explicitly start another wait to continue later.
    ///
    /// No history, subscription stream or live response owner is returned. No
    /// input-required task is automatically resumed. Dropping this future drops
    /// its connection and timer, not the remote task; remote cancellation remains
    /// an explicit `cancel_task_final` operation.
    ///
    /// Requires `with_tasks`, 1..=1024 polls and a local minimum interval from
    /// 1ms through 60s. An even longer peer interval is respected until the
    /// enclosing operation deadline wins. Invalid bounds refuse before I/O.
    pub async fn wait_task_final(
        &mut self,
        cx: &Cx,
        task_id: FinalTaskId,
        minimum_interval: Duration,
        max_polls: usize,
    ) -> Result<FinalGetTaskResult, ManagedHttpClientError> {
        self.wait_task_final_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            task_id,
            minimum_interval,
            max_polls,
        )
        .await
    }

    /// Waits under an independent cancellation domain without cancelling the
    /// shared OAuth login or the remote task. See `wait_task_final` for bounds
    /// and the distinction between an actionable result and poll-count exhaustion.
    pub async fn wait_task_final_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
        minimum_interval: Duration,
        max_polls: usize,
    ) -> Result<FinalGetTaskResult, ManagedHttpClientError> {
        self.admit_tasks(cx, cancellation)?;
        admit_wait(minimum_interval, max_polls)?;
        match self
            .perform_task(
                cx,
                cancellation,
                TaskCall::Wait {
                    task_id,
                    minimum_interval,
                    max_polls,
                },
            )
            .await?
        {
            TaskResult::Get(result) => Ok(*result),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }

    /// Supplies responses matching a retained input-required snapshot. Invalid
    /// phase or mismatched outstanding response kinds refuse before acquiring
    /// credentials or taking connection custody. Partial updates and unknown or
    /// already-satisfied keys retain the shared protocol ledger's semantics.
    /// The upstream remains responsible for current ownership and state
    /// authorization. The acknowledgement is not a new task snapshot, and a
    /// failed or abandoned update is never automatically replayed.
    pub async fn update_task_final(
        &mut self,
        cx: &Cx,
        task: &FinalTask,
        responses: FinalTaskInputResponses,
    ) -> Result<FinalUpdateTaskResult, ManagedHttpClientError> {
        self.update_task_final_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            task,
            responses,
        )
        .await
    }

    /// Submits task inputs under an independent cancellation domain.
    pub async fn update_task_final_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task: &FinalTask,
        responses: FinalTaskInputResponses,
    ) -> Result<FinalUpdateTaskResult, ManagedHttpClientError> {
        self.admit_tasks(cx, cancellation)?;
        admit_input(task, &responses)?;
        match self
            .perform_task(cx, cancellation, TaskCall::Update { task, responses })
            .await?
        {
            TaskResult::Update(result) => Ok(result),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }

    /// Requests cancellation of the remote task, not the shared OAuth login.
    /// Returns the exact complete acknowledgement without inventing a terminal
    /// snapshot. Explicitly fetch the task again to observe its current state.
    pub async fn cancel_task_final(
        &mut self,
        cx: &Cx,
        task_id: FinalTaskId,
    ) -> Result<FinalCancelTaskResult, ManagedHttpClientError> {
        self.cancel_task_final_with_cancellation(cx, &McpRequestCancellation::new(), task_id)
            .await
    }

    /// Cancels the remote task under the supplied request-cancellation domain.
    pub async fn cancel_task_final_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> Result<FinalCancelTaskResult, ManagedHttpClientError> {
        match self
            .perform_task(cx, cancellation, TaskCall::Cancel(task_id))
            .await?
        {
            TaskResult::Cancel(result) => Ok(result),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod framing_tests {
    use super::task_sse_limits;
    use crate::sse::{BoundedSseParser, SseParseError};

    #[test]
    fn native_task_frames_accept_4096_data_lines_but_refuse_one_more() {
        let payload = r#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","content":[]}}"#;
        for lines in [4_096, 4_097] {
            let wire = format!("data: {payload}\n{}\n", "data:\n".repeat(lines - 1));
            let mut parser = BoundedSseParser::new(task_sse_limits().unwrap());
            if lines == 4_096 {
                let frames = parser.push(wire.as_bytes()).unwrap();
                assert_eq!(frames.len(), 1);
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&frames[0]).unwrap(),
                    serde_json::from_str::<serde_json::Value>(payload).unwrap()
                );
                assert!(!parser.finish().unwrap().discarded_pending_event);
            } else {
                assert!(matches!(
                    parser.push(wire.as_bytes()),
                    Err(SseParseError::TooManyDataLines { limit_lines: 4_096 })
                ));
                assert_eq!(parser.buffered_bytes(), 0);
                assert!(matches!(parser.push(b"\n"), Err(SseParseError::Poisoned)));
            }
        }
    }

    #[test]
    fn data_line_accounting_survives_chunk_boundaries_and_resets_per_event() {
        let mut parser = BoundedSseParser::new(task_sse_limits().unwrap());
        for _ in 0..2 {
            for _ in 0..4_096 {
                assert!(parser.push(b"dat").unwrap().is_empty());
                assert!(parser.push(b"a:\n").unwrap().is_empty());
            }
            let frames = parser.push(b"\n").unwrap();
            assert_eq!(frames, ["\n".repeat(4_095)]);
            assert_eq!(parser.buffered_bytes(), 0);
        }
    }

    #[test]
    fn task_framing_still_refuses_oversized_lines_and_keepalive_floods() {
        let limits = task_sse_limits().unwrap();
        let mut parser = BoundedSseParser::new(limits);
        let oversized = vec![b'x'; limits.max_line_bytes() + 1];
        assert!(matches!(
            parser.push(&oversized),
            Err(SseParseError::LineTooLong { .. })
        ));
        assert_eq!(parser.buffered_bytes(), 0);
        let mut parser = BoundedSseParser::new(limits);
        assert!(parser.push(&b":alive\n".repeat(64)).unwrap().is_empty());
        assert!(matches!(
            parser.push(b":alive\n"),
            Err(SseParseError::KeepaliveFlood { limit_lines: 64 })
        ));
        assert_eq!(parser.buffered_bytes(), 0);
    }
}
