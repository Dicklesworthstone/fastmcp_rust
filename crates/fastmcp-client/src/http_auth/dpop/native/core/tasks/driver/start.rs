//! One task-capable tool call joined to the existing bounded Task lifecycle.
//!
//! Only a fully admitted creation snapshot can enter the driver. The original
//! tool request is consumed once and never appears in its get/update loop.

use fastmcp_protocol::FinalCoreResult;

use super::*;

/// The original method result remains intact, including metadata and tool
/// errors. An immediate input-required result is a host handoff, not success.
/// A Task outcome is likewise not necessarily a successful remote execution.
/// Debug deliberately excludes arguments, Task IDs, results and input data.
pub enum DpopTaskExecutionOutcome {
    /// Immediate complete or request-level input-required; no Task was driven.
    Tool(Box<FinalCoreResult>),
    /// Creation followed by terminal state or an explicit Task-input pause.
    Task {
        initial: Box<FinalCoreResult>,
        outcome: ManagedTaskRunOutcome,
    },
}

impl fmt::Debug for DpopTaskExecutionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tool(_) => "DpopTaskExecutionOutcome::Tool(..)",
            Self::Task { .. } => "DpopTaskExecutionOutcome::Task(..)",
        })
    }
}

impl Run {
    fn prepare_initial(
        &mut self,
        target: &str,
        metadata: FinalRequestMeta,
        operation: DpopTaskOperation,
        limits: ManagedCoreLimits,
        native_maximum: usize,
    ) -> Result<Prepared, DpopTaskDriverError> {
        if !matches!(&operation.request, ManagedTaskRequest::CallTool { .. }) {
            return Err(ManagedTaskDriverError::UnexpectedResponse.into());
        }
        // Reject a collision anywhere in the bounded future namespace BEFORE
        // creating remote work, not halfway through driving an already-created
        // Task. These are correlation IDs, never replay or idempotency keys.
        let pairs = self.policy.maximum_polls + self.policy.maximum_updates;
        for sequence in 0..pairs {
            for suffix in ["discover", "task"] {
                let future = RequestId::String(format!("{}.{sequence}.{suffix}", self.prefix));
                if operation.discovery_id.correlates_with(&future)
                    || operation.operation_id.correlates_with(&future)
                {
                    return Err(ManagedTaskDriverError::RepeatedRequestId.into());
                }
            }
        }
        let ids = ManagedTaskRequestIds::new(
            operation.discovery_id.clone(), operation.operation_id.clone(),
        )?;
        // Retain the caller's reviewed headers and both exact request IDs.
        // No state is reserved until actual request/header admission succeeds.
        let prepared = Prepared::new(target, metadata, operation, limits, native_maximum)?;
        self.state.reserve_ids(&ids, self.policy.maximum_state_bytes)?;
        Ok(prepared)
    }
}

impl DpopHttpClient {
    /// Sends one task-capable tool call and drives any returned Task.
    ///
    /// JSON and finite request-scoped SSE replies use the same decoder and
    /// guards as `drive_task`. Notifications are admitted and discarded but
    /// still consume run-wide quotas. Use [`Self::start_and_drive_task_with_events`]
    /// for notifications and explicit parser/idle bounds.
    ///
    /// This operation creates remote work; abandoning it is not an undo.
    /// Consult the event variant's lifetime, handoff and recovery contract.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_and_drive_task<R, F, O>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        operation: DpopTaskOperation,
        id_prefix: &str,
        policy: ManagedTaskDriverPolicy,
        limits: ManagedCoreLimits,
        resolve: R,
        observe: O,
    ) -> Result<DpopTaskExecutionOutcome, DpopTaskDriverError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
    {
        self.start_and_drive_task_with_events(
            cx, cancellation, credential, metadata, operation, id_prefix, policy,
            DpopStreamLimits::new(limits, limits.timeout())?, resolve, observe, |_| true,
        ).await
    }

    /// Creates at most one Task, then reuses the ordinary get/input/update driver.
    ///
    /// The initial operation MUST be CallTool. Its reviewed header policy and
    /// exact IDs are preserved; a collision with any future generated ID is
    /// refused before discovery or signing. Poll/update limits apply to the
    /// subsequent lifecycle. The initial pair also consumes retained-ID space,
    /// response bytes and notifications; the handoff replenishes NONE of them.
    ///
    /// One original credential and the earliest native/core/driver/caller/token
    /// deadline cover preparation, tool execution, all polls, host work and
    /// input updates. Every pair performs authenticated Tasks discovery. A new
    /// network pair resets only its idle allowance. No refresh, retry, bearer
    /// fallback, reconnect, remote cancellation or detached work is introduced.
    ///
    /// Clean HTTP EOF is required before a creation result becomes actionable.
    /// An immediate tool completion or request-level input-required result is
    /// returned unchanged as Tool, without invoking Task callbacks or replaying
    /// tools/call. Request-level continuation belongs to the explicit input-host
    /// API, not this Task resolver. A Task result enters the shared lifecycle:
    /// terminal creation needs no get; input-required can be resolved directly;
    /// Working honors its polling hint before the first get. A stale acknowledged
    /// input cannot cause repeated host work or a repeated update.
    ///
    /// observe receives the admitted creation Task BEFORE any successor POST.
    /// Hosts needing recovery should retain that ID there. A later failure
    /// never retries the initial tool, returns stale success, or claims rollback:
    /// the Task may still exist. Reconciliation after uncertainty is explicit.
    /// Observers/resolvers use the same caller/lifetime guards as drive_task;
    /// they must cooperate, and previously committed effects cannot be undone.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_and_drive_task_with_events<R, F, O, N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        operation: DpopTaskOperation,
        id_prefix: &str,
        policy: ManagedTaskDriverPolicy,
        limits: DpopStreamLimits,
        resolve: R,
        observe: O,
        mut notify: N,
    ) -> Result<DpopTaskExecutionOutcome, DpopTaskDriverError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
        N: FnMut(&ServerNotification) -> bool,
    {
        if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
            return Err(DpopHttpError::Cancelled.into());
        }
        let timeout = policy.timeout.min(limits.core.timeout()).min(self.policy.timeout);
        let bounds = WaitBounds::new(cx, timeout, credential)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let mut run = Run::new(id_prefix, policy, limits.core)?;
        let prepared = run.prepare_initial(
            self.resource().as_str(), metadata.clone(), operation,
            limits.core, self.policy.max_body_bytes,
        )?;
        let event = self.drive_task_selected_pair(
            cx, cancellation, credential, bounds, &mut run, prepared,
            ReplyMode::Stream(limits), &mut notify,
        ).await?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let ManagedTaskEvent::ToolResult(initial) = event else {
            return Err(ManagedTaskDriverError::UnexpectedResponse.into());
        };
        let task = match initial.as_ref() {
            FinalCoreResult::ToolsCallTask { result } => result.task.clone(),
            FinalCoreResult::ToolsCall { .. }
            | FinalCoreResult::ToolsCallInputRequired { .. } => {
                return Ok(DpopTaskExecutionOutcome::Tool(initial));
            }
            _ => return Err(ManagedTaskDriverError::UnexpectedResponse.into()),
        };
        let task_id = task.base().task_id.clone();
        // Never call the public driver here: that would create a fresh run,
        // deadline and ID/input ledger, losing the creating pair's accounting.
        let outcome = self.drive_task_run(
            cx, cancellation, credential, metadata, task_id, run, bounds,
            limits.core, ReplyMode::Stream(limits), Some(task), resolve, observe, notify,
        ).await?;
        Ok(DpopTaskExecutionOutcome::Task { initial, outcome })
    }
}

#[cfg(test)]
mod tests;
