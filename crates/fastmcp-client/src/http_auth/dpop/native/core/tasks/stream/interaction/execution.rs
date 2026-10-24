//! One bounded execution from request-level host input to subscribed Task input.
//!
//! Request-level continuations and Task updates are different protocol actions.
//! This owner composes their existing engines, never translates one into the
//! other and never restarts a creating request after an uncertain response.

use std::future::Future;

use fastmcp_protocol::tasks_extension::{Task, TaskInputRequests};

use super::*;
use crate::http_auth::dpop::native::core::stream::task_subscription::watch::{
    DpopTaskWatchError,
    input::{DpopTaskWatchDriverPolicy, ManagedTaskDriverError, ManagedTaskInputAction},
};
use crate::http_auth::dpop::native::core::tasks::wait::DpopTaskWaitOutcome;

/// Retains the original method result and request-level host accounting.
/// A terminal Task or tool result with isError is not promoted to tool success.
/// Debug deliberately omits peer results, Task IDs, arguments and host answers.
pub enum DpopTaskHostedExecutionOutcome {
    /// The conversation completed without a nonterminal Task. This includes
    /// an already-terminal Task creation; no extra get or listen was issued.
    Initial(DpopTaskHostResult),
    /// The conversation produced a Task and continued to an authoritative
    /// terminal or explicit Task-input handoff under the original lifetime.
    Observed {
        initial: DpopTaskHostResult,
        outcome: DpopTaskWaitOutcome,
    },
}

impl fmt::Debug for DpopTaskHostedExecutionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Initial(_) => "DpopTaskHostedExecutionOutcome::Initial(..)",
            Self::Observed { .. } => "DpopTaskHostedExecutionOutcome::Observed(..)",
        })
    }
}

/// Preserve typed, sanitized errors from each existing owner. No failed stage
/// yields a reusable continuation or permission to replay a previous stage.
#[derive(Debug)]
pub enum DpopTaskHostedExecutionError {
    Conversation(DpopTaskHostError),
    Watch(DpopTaskWatchError),
}

impl fmt::Display for DpopTaskHostedExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conversation(error) => error.fmt(f),
            Self::Watch(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DpopTaskHostedExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Conversation(error) => error,
            Self::Watch(error) => error,
        })
    }
}

impl From<DpopTaskHostError> for DpopTaskHostedExecutionError {
    fn from(error: DpopTaskHostError) -> Self { Self::Conversation(error) }
}
impl From<DpopTaskWatchError> for DpopTaskHostedExecutionError {
    fn from(error: DpopTaskWatchError) -> Self { Self::Watch(error) }
}
impl From<DpopHttpError> for DpopTaskHostedExecutionError {
    fn from(error: DpopHttpError) -> Self { Self::Conversation(error.into()) }
}

fn admit_initial(
    operation: &DpopTaskOperation,
    prefix: &str,
    limits: &DpopTaskHostLimits,
    policy: DpopTaskWatchDriverPolicy,
) -> Result<(), DpopTaskHostedExecutionError> {
    validate_prefix(prefix)?;
    if !matches!(&operation.request, ManagedTaskRequest::CallTool { .. }) {
        return Err(DpopTaskHostError::from(ManagedInteractionError::InvalidInitialRequest).into());
    }
    let ids = [&operation.discovery_id, &operation.operation_id];
    policy.admit_creation_ids(prefix, ids)?;
    // A collision on even the LAST permitted continuation must fail before
    // remote creation, not after earlier host work. Prefix syntax forbids ':',
    // so these IDs are also disjoint from every dot-separated watch/input ID.
    for ordinal in 1..=limits.resolutions {
        for suffix in ["discover", "tool"] {
            let next = RequestId::String(format!("{prefix}:{ordinal}:{suffix}"));
            if ids.iter().any(|id| id.correlates_with(&next)) {
                return Err(DpopTaskHostError::from(ManagedInteractionError::RepeatedRequestId).into());
            }
        }
    }
    Ok(())
}

impl DpopHttpClient {
    /// Resolve request-level tool input, then drive a returned Task by subscription.
    ///
    /// The original CallTool selection and any reviewed parameter headers pass
    /// unchanged into [`Self::execute_task_with_input_host`]'s internal engine.
    /// A fully admitted input_required result authorizes only its validated
    /// continuation: exact requestState and typed host answers accompany the
    /// original tool arguments. No failed POST, lost EOF or host refusal permits
    /// replay. On a Task result the tool conversation ends permanently.
    ///
    /// The guarded Task observer receives that creation before any successor
    /// POST, allowing explicit host-owned checkpointing. Already-terminal Tasks
    /// return the original result without a get. Other Tasks enter the ordinary
    /// get/acknowledge/reconcile subscription driver. Only authoritative gets
    /// can invoke task_resolve, using the SAME capability and clean-ACK ledger
    /// as [`Self::drive_task_with_subscription`]. RequestState and request-level
    /// answers are never sent in Task discovery, gets, listen or updates.
    ///
    /// One credential and one earliest native/core/Task-policy/caller/token
    /// deadline span ALL stages. The request-host session's pre-network deadline
    /// may shorten this lifetime; its exact deadline also survives Task handoff.
    /// Conversation usage (including both outgoing JSON bodies per round) is
    /// retained, then Task response payloads/notifications spend the remaining
    /// shared stream quotas. Request/frame, raw-body and SSE caps remain in force.
    /// Each network pair uses the existing idle policy; after subscription setup
    /// the fixed listen-idle bound also owns Task input and reconciliation.
    ///
    /// `host` and limits.inputs bound request-level roots/sampling/elicitation.
    /// `task_resolve` is separately and explicitly authorized by the Task policy;
    /// its model/tool costs remain the application's responsibility. Returned
    /// CoreInputUsage covers ONLY request-level host work. No fresh host budget
    /// is secretly created for Task inputs. `notify` sees tool-conversation
    /// notifications; `observe` sees Task creation and authoritative snapshots.
    /// Task-operation notifications are admitted and charged, not forwarded.
    ///
    /// Every result/challenge and update ACK requires clean response EOF.
    /// Local cancellation, revocation, observer/host refusal and drop release
    /// owned work without remote cancellation, refresh or background retries.
    /// Failure after creation may leave a running Task: reconcile its saved ID,
    /// never repeat this creating API as recovery. Input after listen teardown
    /// returns to the caller without another automatic update.
    ///
    /// Use a fresh 1..=128 ASCII alphanumeric/underscore/dot/dash id_prefix.
    /// Both initial IDs are checked against every possible continuation/get/
    /// update/listen identity BEFORE I/O. IDs are not idempotency keys.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_and_drive_task_with_input_host<H, R, F, O, N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        operation: DpopTaskOperation,
        id_prefix: &str,
        limits: &DpopTaskHostLimits,
        task_policy: DpopTaskWatchDriverPolicy,
        host: &mut H,
        task_resolve: R,
        observe: O,
        notify: N,
    ) -> Result<DpopTaskHostedExecutionOutcome, DpopTaskHostedExecutionError>
    where
        H: CoreInputHost + ?Sized,
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
        N: FnMut(&ServerNotification) -> bool,
    {
        if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
            return Err(DpopHttpError::Cancelled.into());
        }
        admit_initial(&operation, id_prefix, limits, task_policy)?;
        let timeout = self.policy.timeout.min(limits.stream.core.timeout()).min(task_policy.timeout());
        let bounds = WaitBounds::new(cx, timeout, credential)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let completed = self.execute_task_conversation_with_bounds(
            cx, cancellation, credential, metadata.clone(), operation, id_prefix,
            limits, bounds, host, notify,
        ).await?;
        check_live(cx, cancellation, &self.session, credential, completed.bounds)?;
        let task = match completed.result.result.as_ref() {
            FinalCoreResult::ToolsCall { .. } => {
                return Ok(DpopTaskHostedExecutionOutcome::Initial(completed.result));
            }
            FinalCoreResult::ToolsCallTask { result } => result.task.clone(),
            _ => return Err(DpopTaskHostError::from(ManagedCoreError::InvalidResult).into()),
        };
        // Never enter a public watcher here: that would forget conversation
        // charges and its host deadline at the point remote work first exists.
        let outcome = self.drive_created_task_with_subscription(
            cx, cancellation, credential, metadata, task, id_prefix, task_policy,
            limits.stream, completed.bounds, completed.usage, task_resolve, observe,
        ).await?;
        match outcome {
            None => Ok(DpopTaskHostedExecutionOutcome::Initial(completed.result)),
            Some(outcome) => Ok(DpopTaskHostedExecutionOutcome::Observed {
                initial: completed.result, outcome,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn policy() -> DpopTaskWatchDriverPolicy {
        DpopTaskWatchDriverPolicy::new(3, 2, 4, 8192, Duration::from_secs(10)).unwrap()
    }

    fn operation(first: RequestId, second: RequestId) -> DpopTaskOperation {
        DpopTaskOperation::new(first, second, ManagedTaskRequest::CallTool {
            name: "work".to_owned(), arguments: Some(json!({"secret":"body-only"})),
        }).unwrap()
    }

    fn limits() -> DpopTaskHostLimits {
        DpopTaskHostLimits::new(DpopStreamLimits::default(), CoreInputLimits::default(), 2, 4).unwrap()
    }

    #[test]
    fn every_future_namespace_is_reserved_before_creation_in_either_initial_slot() {
        for name in ["run:1:discover", "run:2:tool", "run.0.discover", "run.2.get",
            "run.input.0.discover", "run.input.1.update", "run.listen", "run.listen.discover"]
        {
            for first in [false, true] {
                let collision = RequestId::String(name.to_owned());
                let initial = if first { operation(collision, RequestId::Number(9)) }
                    else { operation(RequestId::Number(9), collision) };
                let before = (initial.discovery_id.clone(), initial.operation_id.clone());
                assert!(admit_initial(&initial, "run", &limits(), policy()).is_err());
                assert_eq!((initial.discovery_id.clone(), initial.operation_id.clone()), before);
            }
        }
    }

    #[test]
    fn valid_nearby_ids_and_prefix_boundaries_do_not_gain_false_collisions() {
        for name in ["run:0:tool", "run:3:tool", "run.3.get", "run.input.2.update",
            "run.listen.other", "run.0.tool", "other.0.get"]
        {
            let initial = operation(RequestId::String(name.to_owned()), RequestId::Number(9));
            admit_initial(&initial, "run", &limits(), policy()).unwrap();
        }
        let initial = operation(RequestId::Number(1), serde_json::from_str("2e0").unwrap());
        for prefix in ["a".to_owned(), "_.-".to_owned(), "z".repeat(128)] {
            admit_initial(&initial, &prefix, &limits(), policy()).unwrap();
        }
        for prefix in [String::new(), "a:b".to_owned(), "a/b".to_owned(), "雪".to_owned(), "z".repeat(129)] {
            assert!(matches!(admit_initial(&initial, &prefix, &limits(), policy()),
                Err(DpopTaskHostedExecutionError::Conversation(DpopTaskHostError::InvalidIdPrefix))));
        }
    }

    #[test]
    fn existing_task_operations_cannot_be_reinterpreted_as_creating_conversations() {
        let id = fastmcp_protocol::tasks_extension::TaskId::parse("task-one").unwrap();
        for request in [ManagedTaskRequest::Get(id.clone()), ManagedTaskRequest::Cancel(id)] {
            let initial = DpopTaskOperation::new(RequestId::Number(1), RequestId::Number(2), request).unwrap();
            assert!(matches!(admit_initial(&initial, "run", &limits(), policy()),
                Err(DpopTaskHostedExecutionError::Conversation(DpopTaskHostError::Interaction(
                    ManagedInteractionError::InvalidInitialRequest)))));
        }
        let error = admit_initial(&operation(RequestId::String("run.2.get".to_owned()), RequestId::Number(9)),
            "run", &limits(), policy()).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("run.2.get"));
        assert!(!format!("{error:?} {error}").contains("body-only"));
    }
}
