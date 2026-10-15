//! One creating call followed by subscription-driven Task input handling.
//!
//! Creation consumes the same credential, deadline and response quotas as its
//! continuation. No error, partial response or restart repeats tools/call.

use std::fmt;

use fastmcp_protocol::FinalCoreResult;

use super::*;

/// Original tool result plus, when needed, an authoritative Task observation.
/// Neither a terminal Task nor a complete tool result implies tool success.
/// Debug omits arguments, identifiers, peer results and host input.
pub enum DpopTaskSubscriptionExecutionOutcome {
    /// Immediate tool completion, request-level input handoff, or a Task
    /// already terminal at creation. No subsequent get or listen was sent.
    Initial(Box<FinalCoreResult>),
    /// A nonterminal creation followed by the same bounded subscription/input
    /// lifecycle. The full creation and get metadata remain available.
    Observed {
        initial: Box<FinalCoreResult>,
        outcome: DpopTaskWaitOutcome,
    },
}

impl fmt::Debug for DpopTaskSubscriptionExecutionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Initial(_) => "DpopTaskSubscriptionExecutionOutcome::Initial(..)",
            Self::Observed { .. } => "DpopTaskSubscriptionExecutionOutcome::Observed(..)",
        })
    }
}

fn creation_operation(
    prefix: &str,
    request: ManagedTaskRequest,
) -> Result<DpopTaskOperation, DpopTaskWatchError> {
    if !matches!(&request, ManagedTaskRequest::CallTool { .. }) {
        return Err(DpopTaskWatchError::UnexpectedResponse);
    }
    // "create" is disjoint from numbered gets, "input" updates and "listen".
    // The host chooses only the already-validated prefix, so there is no
    // arbitrary creating ID which can collide with a later generated request.
    Ok(DpopTaskOperation::new(
        RequestId::String(format!("{prefix}.create.discover")),
        RequestId::String(format!("{prefix}.create.call")),
        request,
    )?)
}

impl DpopHttpClient {
    /// Create once, then drive a returned Task without periodic polling.
    ///
    /// `request` must be `ManagedTaskRequest::CallTool`; get/update/cancel are
    /// refused before signing or I/O. This convenience is body-only: it does
    /// not mirror arguments into headers. Generated creating IDs use the
    /// disjoint `id_prefix.create` namespace. Select a fresh prefix per run.
    /// Both request bodies and advertised capabilities pass the existing Task
    /// preparation, discovery and negotiated JSON/SSE response decoders.
    ///
    /// Creation must reach clean HTTP EOF before any Task callback or successor
    /// request. An immediate tool completion or request-level input-required
    /// result returns unchanged; the latter is not a Task-input continuation.
    /// A terminal creation also returns its original tool result without a
    /// redundant get. For a nonterminal Task, `observe` first sees its admitted
    /// creation BEFORE another POST, allowing the host to retain the ID for
    /// recovery. A fresh get then reconciles the Task before resolving input
    /// or subscribing; no get result is synthesized from a creation snapshot.
    ///
    /// The continuation uses the ordinary acknowledged listen, post-ACK get,
    /// capability-gated input resolver and clean-ACK input ledger. Creation's
    /// response bytes and notifications are charged to the SAME cumulative
    /// limits. The SAME original credential and earliest native/core/input/
    /// caller/token deadline cover creation, observation, host work and every
    /// update. Snapshot limits count gets, not the creating call. Progress on
    /// creation is admitted and charged but does not escape as a Task snapshot.
    ///
    /// No failed or uncertain creating call is replayed. Failure after creation
    /// may leave a running remote Task: the host must reconcile the saved ID,
    /// never retry this creating helper as recovery. Cancellation, panic or
    /// observer refusal stops local work, not remote execution or the login.
    /// No automatic renewal, reconnect, remote cancellation, detached worker or
    /// persistence is introduced. Checkpoints remain observation-only.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_and_drive_task_with_subscription<R, F, O>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        request: ManagedTaskRequest,
        id_prefix: &str,
        policy: DpopTaskWatchDriverPolicy,
        limits: DpopStreamLimits,
        resolve: R,
        observe: O,
    ) -> Result<DpopTaskSubscriptionExecutionOutcome, DpopTaskWatchError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
    {
        if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
            return Err(DpopHttpError::Cancelled.into());
        }
        let timeout = self.policy.timeout.min(limits.core.timeout()).min(policy.input.timeout);
        let bounds = WaitBounds::new(cx, timeout, credential)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        // Prefix and callback metadata admission precede creation. The later
        // private watch constructor reuses these limits, not a new deadline.
        WatchState::new(id_prefix, policy.watch, limits)?;
        let operation = creation_operation(id_prefix, request)?;
        let mut input = InputDriver::new(policy.input, &metadata, resolve, observe)?;
        let completed = self.request_task_stream_with_bounds(
            cx, cancellation, credential, metadata.clone(), operation, limits,
            bounds, &mut |_| true,
        ).await?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let ManagedTaskEvent::ToolResult(initial) = completed.result else {
            return Err(DpopTaskWatchError::UnexpectedResponse);
        };
        let task = match initial.as_ref() {
            FinalCoreResult::ToolsCall { .. } | FinalCoreResult::ToolsCallInputRequired { .. } => {
                return Ok(DpopTaskSubscriptionExecutionOutcome::Initial(initial));
            }
            FinalCoreResult::ToolsCallTask { result } => result.task.clone(),
            _ => return Err(DpopTaskWatchError::UnexpectedResponse),
        };
        let life = Lifetime { cx, cancellation, session: &self.session, credential, bounds };
        callback(&life, || (input.observe)(&task))??;
        if matches!(&task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_)) {
            return Ok(DpopTaskSubscriptionExecutionOutcome::Initial(initial));
        }
        let task_id = task.base().task_id.clone();
        // Never call the public watcher/driver here: it would reset response
        // quotas and create a new absolute deadline after remote work began.
        let outcome = self.watch_task_using(
            cx, cancellation, credential, metadata, task_id, id_prefix,
            policy.watch, limits, bounds, completed.usage, Some(input),
        ).await?;
        Ok(DpopTaskSubscriptionExecutionOutcome::Observed { initial, outcome })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_creating_entrypoint_cannot_dispatch_an_existing_task_operation() {
        let id = TaskId::parse("task-one").unwrap();
        for request in [ManagedTaskRequest::Get(id.clone()), ManagedTaskRequest::Cancel(id)] {
            assert!(matches!(creation_operation("run", request), Err(DpopTaskWatchError::UnexpectedResponse)));
        }
        assert!(creation_operation("run", ManagedTaskRequest::CallTool {
            name: "work".to_owned(), arguments: None,
        }).is_ok());
    }

    #[test]
    fn creation_usage_reduces_both_continuation_quotas_atomically() {
        let mut state = WatchState::new("run", DpopTaskWatchPolicy::default(),
            DpopStreamLimits::default()).unwrap();
        let initial = state.remaining_limits().unwrap().core;
        state.charge((17, 1)).unwrap();
        let remaining = state.remaining_limits().unwrap().core;
        assert_eq!(remaining.total_bytes(), initial.total_bytes() - 17);
        assert_eq!(remaining.notifications(), initial.notifications() - 1);
        let before = state.usage;
        assert!(state.charge((initial.total_bytes(), 0)).is_err());
        assert_eq!(state.usage, before);
        assert!(state.charge((0, initial.notifications())).is_err());
        assert_eq!(state.usage, before);
    }
}
