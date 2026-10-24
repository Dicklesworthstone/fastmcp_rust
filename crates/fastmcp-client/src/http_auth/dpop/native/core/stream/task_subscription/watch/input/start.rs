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


fn admit_creation_operation(
    prefix: &str,
    operation: &DpopTaskOperation,
    policy: DpopTaskWatchDriverPolicy,
) -> Result<(), DpopTaskWatchError> {
    if !matches!(&operation.request, ManagedTaskRequest::CallTool { .. }) {
        return Err(DpopTaskWatchError::UnexpectedResponse);
    }
    let collides = |candidate: &RequestId| {
        operation.discovery_id.correlates_with(candidate)
            || operation.operation_id.correlates_with(candidate)
    };
    for index in 0..policy.watch.maximum_snapshots {
        for suffix in ["discover", "get"] {
            if collides(&RequestId::String(format!("{prefix}.{index}.{suffix}"))) {
                return Err(ManagedTaskDriverError::RepeatedRequestId.into());
            }
        }
    }
    for index in 0..policy.input.maximum_updates {
        for suffix in ["discover", "update"] {
            if collides(&RequestId::String(format!("{prefix}.input.{index}.{suffix}"))) {
                return Err(ManagedTaskDriverError::RepeatedRequestId.into());
            }
        }
    }
    for suffix in ["listen.discover", "listen"] {
        if collides(&RequestId::String(format!("{prefix}.{suffix}"))) {
            return Err(ManagedTaskDriverError::RepeatedRequestId.into());
        }
    }
    Ok(())
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
        let operation = creation_operation(id_prefix, request)?;
        self.start_and_drive_task_operation_with_subscription(
            cx, cancellation, credential, metadata, operation, id_prefix,
            policy, limits, resolve, observe,
        ).await
    }

    /// Create once from an already-reviewed DPoP Task operation, then continue
    /// through the subscription/input lifecycle without losing its tool headers.
    ///
    /// The operation must be CallTool. Its exact discovery/tool IDs and optional
    /// ReviewedToolHeaders are retained. Before signing or I/O, both IDs are
    /// checked against every generated get, input-update, and listen identity
    /// permitted by the selected policy; a collision fails closed.
    ///
    /// All creation EOF, observer, quota, deadline, no-replay, recovery and
    /// teardown rules are identical to start_and_drive_task_with_subscription.
    /// Reviewed headers apply only to the creating tool POST. They never appear
    /// on Tasks discovery, get, update or subscription requests.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_and_drive_task_operation_with_subscription<R, F, O>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        operation: DpopTaskOperation,
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
        // Prefix, future-ID namespace and callback metadata admission all
        // precede creation. No collision may surface after remote work exists.
        WatchState::new(id_prefix, policy.watch, limits)?;
        admit_creation_operation(id_prefix, &operation, policy)?;
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
    fn arbitrary_creation_ids_are_checked_against_the_entire_future_namespace() {
        let policy = DpopTaskWatchDriverPolicy::new(
            3, 2, 4, 8192, std::time::Duration::from_secs(10),
        ).unwrap();
        let call = || ManagedTaskRequest::CallTool {
            name: "work".to_owned(), arguments: None,
        };
        for id in [
            "run.0.discover", "run.2.get", "run.input.0.discover",
            "run.input.1.update", "run.listen.discover", "run.listen",
        ] {
            let operation = DpopTaskOperation::new(
                RequestId::String(id.to_owned()),
                RequestId::String("initial-call".to_owned()),
                call(),
            ).unwrap();
            assert!(matches!(
                admit_creation_operation("run", &operation, policy),
                Err(DpopTaskWatchError::Driver(ManagedTaskDriverError::RepeatedRequestId))
            ));
        }
        let operation = DpopTaskOperation::new(
            RequestId::String("run.3.get".to_owned()),
            RequestId::String("run.input.2.update".to_owned()),
            call(),
        ).unwrap();
        assert!(admit_creation_operation("run", &operation, policy).is_ok());
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
