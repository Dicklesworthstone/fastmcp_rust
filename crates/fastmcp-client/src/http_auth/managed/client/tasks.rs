//! Completed official Tasks operations under the managed credential boundary.
//!
//! The returned values contain no connection, token, or running response owner.
//! Task identity is opaque data; the upstream must authorize every later action.

use asupersync::Cx;
use fastmcp_core::{McpError, McpErrorCode, McpRequestCancellation};
use fastmcp_protocol::FinalCoreResult;
use fastmcp_protocol::tasks_extension::TaskInputLedger;
use serde_json::Value;

use super::{Call, CallResult, ManagedHttpClient, ManagedHttpClientError};
use crate::{
    ClientHttpConnectionError, FinalCancelTaskResult, FinalGetTaskResult, FinalTask,
    FinalTaskId, FinalTaskInputResponses, FinalToolCallOutcome, FinalUpdateTaskResult,
    HttpClient, HttpClientError,
};

const MAX_TASK_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(super) enum TaskCall<'a> {
    Tool { name: &'a str, arguments: Value },
    Get(FinalTaskId),
    Update { task: &'a FinalTask, responses: FinalTaskInputResponses },
    Cancel(FinalTaskId),
}

pub(super) enum TaskResult {
    Tool(Box<FinalToolCallOutcome>),
    Get(Box<FinalGetTaskResult>),
    Update(FinalUpdateTaskResult),
    Cancel(FinalCancelTaskResult),
}

fn invalid_input() -> ManagedHttpClientError {
    ManagedHttpClientError::Request { code: Some(McpErrorCode::InvalidParams) }
}

fn admit_input(task: &FinalTask, responses: &FinalTaskInputResponses) -> Result<(), ManagedHttpClientError> {
    let FinalTask::InputRequired { input_requests, .. } = task else {
        return Err(invalid_input());
    };
    TaskInputLedger::from_requests(input_requests)
        .map_err(|_| invalid_input())?
        .validate_responses(responses)
        .map_err(|_| invalid_input())
}

impl TaskCall<'_> {
    pub(super) async fn dispatch(
        self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        client: &mut HttpClient,
    ) -> Result<TaskResult, HttpClientError> {
        if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
            return Err(HttpClientError::CoreResult(McpError::request_cancelled()));
        }
        // All verbs use the ordinary client's one monotonic ID allocator. The
        // native methods retain bilateral Tasks admission and raw correlation.
        let id = client.next_request_id()?;
        match self {
            Self::Tool { name, arguments } => {
                let limits = crate::sse::SseLimits::new(
                    MAX_TASK_RESPONSE_BYTES + 8,
                    MAX_TASK_RESPONSE_BYTES,
                    64,
                ).ok_or_else(|| HttpClientError::CoreResult(
                    McpError::internal_error("Invalid managed Tasks response limits"),
                ))?;
                let listener = client.connection
                    .open_final_tasks_tool_call_listener(cx, id, name, arguments, limits)
                    .await
                    .map_err(HttpClientError::Connection)?;
                // JSON and finite SSE are both collected INSIDE the outer
                // managed session/credential guards. No stream may escape them.
                let collected = listener.collect(cx).await.map_err(|error| {
                    HttpClientError::Connection(ClientHttpConnectionError::FinalCoreListen(error))
                })?;
                let outcome = match collected.terminal {
                    FinalCoreResult::ToolsCall { result, .. } => FinalToolCallOutcome::Complete(result),
                    FinalCoreResult::ToolsCallTask { result } => FinalToolCallOutcome::Task(result),
                    FinalCoreResult::ToolsCallInputRequired { result, .. } => FinalToolCallOutcome::InputRequired(result),
                    _ => return Err(HttpClientError::CoreResult(McpError::invalid_request(
                        "Unexpected managed Tasks tool outcome",
                    ))),
                };
                Ok(TaskResult::Tool(Box::new(outcome)))
            }
            Self::Get(task_id) => client.connection
                .get_task_final(cx, id, task_id, MAX_TASK_RESPONSE_BYTES)
                .await
                .map(|result| TaskResult::Get(Box::new(result)))
                .map_err(HttpClientError::Connection),
            Self::Update { task, responses } => client.connection
                .update_task_final(cx, id, task, responses, MAX_TASK_RESPONSE_BYTES)
                .await
                .map(TaskResult::Update)
                .map_err(HttpClientError::Connection),
            Self::Cancel(task_id) => client.connection
                .cancel_task_final(cx, id, task_id, MAX_TASK_RESPONSE_BYTES)
                .await
                .map(TaskResult::Cancel)
                .map_err(HttpClientError::Connection),
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

    fn admit_tasks(&self, cx: &Cx, cancellation: &McpRequestCancellation) -> Result<(), ManagedHttpClientError> {
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
            CallResult::Core(_) => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }

    /// Invokes a Tasks-capable tool, retaining complete, task and input-required
    /// outcomes exactly. Requires `with_tasks`; never follows reverse handlers,
    /// resumes MRTR, polls a created task, or retries an uncertain tool execution.
    /// The finite operation timeout covers credential acquisition, discovery and
    /// the entire JSON/SSE response. Dropping the call retires its connection,
    /// not an already-created remote task; cancel that task explicitly by ID.
    pub async fn call_tool_final_outcome(
        &mut self, cx: &Cx, name: &str, arguments: Value,
    ) -> Result<FinalToolCallOutcome, ManagedHttpClientError> {
        self.call_tool_final_outcome_with_cancellation(cx, &McpRequestCancellation::new(), name, arguments).await
    }

    /// The exact tool-outcome operation with an independent cancellation domain.
    pub async fn call_tool_final_outcome_with_cancellation(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation, name: &str, arguments: Value,
    ) -> Result<FinalToolCallOutcome, ManagedHttpClientError> {
        match self.perform_task(cx, cancellation, TaskCall::Tool { name, arguments }).await? {
            TaskResult::Tool(result) => Ok(*result),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }

    /// Fetches one authorized task snapshot. Every operation obtains a current
    /// credential; renewal invalidates discovery and caches before the GET-like
    /// MCP POST. The peer's returned task ID must match the requested ID.
    pub async fn get_task_final(
        &mut self, cx: &Cx, task_id: FinalTaskId,
    ) -> Result<FinalGetTaskResult, ManagedHttpClientError> {
        self.get_task_final_with_cancellation(cx, &McpRequestCancellation::new(), task_id).await
    }

    /// Fetches a snapshot under the supplied cancellation domain.
    pub async fn get_task_final_with_cancellation(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation, task_id: FinalTaskId,
    ) -> Result<FinalGetTaskResult, ManagedHttpClientError> {
        match self.perform_task(cx, cancellation, TaskCall::Get(task_id)).await? {
            TaskResult::Get(result) => Ok(*result),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }

    /// Supplies responses matching a retained input-required snapshot. Invalid
    /// phase, keys or response kinds refuse before acquiring/renewing credentials
    /// or taking connection custody. The upstream remains responsible for current
    /// ownership and state authorization. The acknowledgement is not a new task
    /// snapshot, and a failed/abandoned update is never automatically replayed.
    pub async fn update_task_final(
        &mut self, cx: &Cx, task: &FinalTask, responses: FinalTaskInputResponses,
    ) -> Result<FinalUpdateTaskResult, ManagedHttpClientError> {
        self.update_task_final_with_cancellation(cx, &McpRequestCancellation::new(), task, responses).await
    }

    /// Submits task inputs under an independent cancellation domain.
    pub async fn update_task_final_with_cancellation(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation,
        task: &FinalTask, responses: FinalTaskInputResponses,
    ) -> Result<FinalUpdateTaskResult, ManagedHttpClientError> {
        self.admit_tasks(cx, cancellation)?;
        admit_input(task, &responses)?;
        match self.perform_task(cx, cancellation, TaskCall::Update { task, responses }).await? {
            TaskResult::Update(result) => Ok(result),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }

    /// Requests cancellation of the remote task, not the shared OAuth login.
    /// Returns the exact complete acknowledgement without inventing a terminal
    /// snapshot. Explicitly fetch the task again to observe its current state.
    pub async fn cancel_task_final(
        &mut self, cx: &Cx, task_id: FinalTaskId,
    ) -> Result<FinalCancelTaskResult, ManagedHttpClientError> {
        self.cancel_task_final_with_cancellation(cx, &McpRequestCancellation::new(), task_id).await
    }

    /// Cancels the remote task under the supplied request-cancellation domain.
    pub async fn cancel_task_final_with_cancellation(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation, task_id: FinalTaskId,
    ) -> Result<FinalCancelTaskResult, ManagedHttpClientError> {
        match self.perform_task(cx, cancellation, TaskCall::Cancel(task_id)).await? {
            TaskResult::Cancel(result) => Ok(result),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }
}

#[cfg(test)]
mod tests;
