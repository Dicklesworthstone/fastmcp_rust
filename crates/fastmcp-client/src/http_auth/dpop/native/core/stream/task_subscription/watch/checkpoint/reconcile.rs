//! Fresh authoritative snapshots for a bounded set of saved Task selections.
//!
//! This is a startup observation pass, not a worker, retry loop or executor.
//! One credential, deadline and cumulative response budget own the whole pass.
//! Each Task receives one fresh discovery/get pair; no saved completion ledger
//! can suppress that read, and no creating request or input answer is replayed.

use std::panic::{AssertUnwindSafe, catch_unwind};

use fastmcp_protocol::ServerNotification;
use fastmcp_protocol::tasks_extension::GetTaskResult;

use super::*;
use super::super::WatchState;
use crate::http_auth::caller::with_caller;
use crate::http_auth::dpop::native::{WaitBounds, check_live};
use crate::http_auth::dpop::native::core::stream::DpopStreamError;
use crate::http_auth::dpop::native::core::tasks::{
    DpopTaskOperation, DpopTasksError, ManagedTaskEvent, ManagedTasksError,
};

/// Maximum number of independently saved Tasks in one explicit startup pass.
pub const MAX_DPOP_TASK_RECONCILIATION_TASKS: usize = 128;

struct Reconciliation<'a> {
    checkpoints: &'a [DpopTaskWatchCheckpoint],
    state: WatchState,
    next: usize,
}

impl<'a> Reconciliation<'a> {
    fn new(
        resource: &CanonicalHttpUrl,
        checkpoints: &'a [DpopTaskWatchCheckpoint],
        prefix: &str,
        limits: DpopStreamLimits,
    ) -> Result<Self, DpopTaskCheckpointError> {
        if !(1..=MAX_DPOP_TASK_RECONCILIATION_TASKS).contains(&checkpoints.len()) {
            return Err(DpopTaskCheckpointError::InvalidSelection);
        }
        // Admit the ENTIRE selection before any runtime, proof or network
        // operation. A foreign endpoint later in the slice must not cause an
        // earlier Task to be queried or published. Duplicate reads spend no I/O.
        for (index, checkpoint) in checkpoints.iter().enumerate() {
            checkpoint.admit_resource(resource)?;
            if checkpoints[..index].iter().any(|other| other.task_id == checkpoint.task_id) {
                return Err(DpopTaskCheckpointError::InvalidSelection);
            }
        }
        let policy = DpopTaskWatchPolicy::new(checkpoints.len())?;
        let state = WatchState::new(prefix, policy, limits)?;
        Ok(Self { checkpoints, state, next: 0 })
    }

    fn next_request(&mut self) -> Result<(DpopTaskOperation, DpopStreamLimits), DpopTaskCheckpointError> {
        let checkpoint = self.checkpoints.get(self.next)
            .ok_or(DpopTaskCheckpointError::InvalidSelection)?;
        Ok(self.state.snapshot_request(&checkpoint.task_id)?)
    }

    fn admit(
        &mut self,
        event: ManagedTaskEvent,
        usage: (usize, usize),
    ) -> Result<Box<GetTaskResult>, DpopTaskCheckpointError> {
        let checkpoint = self.checkpoints.get(self.next)
            .ok_or(DpopTaskCheckpointError::InvalidSelection)?;
        let ManagedTaskEvent::Snapshot(snapshot) = event else {
            return Err(DpopTaskWatchError::UnexpectedResponse.into());
        };
        if snapshot.task.base().task_id != checkpoint.task_id {
            let error = DpopTasksError::Task(ManagedTasksError::TaskIdMismatch);
            return Err(DpopTaskWatchError::from(DpopStreamError::from(error)).into());
        }
        // The shared decoder already checked method/ID/raw result/clean EOF.
        // Charge before advancing or publishing; a rejected snapshot cannot
        // partially advance the checkpoint cursor or either resource budget.
        self.state.charge(usage)?;
        self.next += 1;
        Ok(snapshot)
    }
}

fn observe_snapshot<O>(
    snapshot: &GetTaskResult,
    observer: &mut O,
) -> Result<(), DpopTaskCheckpointError>
where
    O: FnMut(&GetTaskResult) -> bool,
{
    let result = catch_unwind(AssertUnwindSafe(|| observer(snapshot)));
    let error = match result {
        Ok(true) => return Ok(()),
        Ok(false) => DpopStreamError::ObserverStopped,
        Err(_) => DpopStreamError::ObserverPanicked,
    };
    Err(DpopTaskWatchError::from(error).into())
}

impl DpopHttpClient {
    /// Reconcile 1..=128 unique saved Tasks in their supplied order, delivering
    /// one fresh GetTaskResult per Task. Returns the number delivered only after
    /// the entire pass succeeds. Working/input-required/failed/cancelled states
    /// remain their exact server snapshots, not fabricated successful execution.
    ///
    /// Notifications are validated and counted but discarded. This operation
    /// never opens a subscription or polls a Working Task again. Use a restored
    /// single-Task watch for continued observation after the startup pass.
    /// No failed request, even a read, is automatically retried.
    #[allow(clippy::too_many_arguments)]
    pub async fn reconcile_task_checkpoints<O>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        checkpoints: &[DpopTaskWatchCheckpoint],
        id_prefix: &str,
        limits: DpopStreamLimits,
        observe: O,
    ) -> Result<usize, DpopTaskCheckpointError>
    where
        O: FnMut(&GetTaskResult) -> bool,
    {
        self.reconcile_task_checkpoints_with_events(
            cx, cancellation, credential, metadata, checkpoints, id_prefix,
            limits, observe, |_| true,
        ).await
    }

    /// Reconcile saved Tasks while incrementally delivering validated progress
    /// and other request-scoped notifications from each discovery/get exchange.
    ///
    /// All saved endpoints and Task uniqueness are checked before any proof or
    /// I/O. Each operation performs fresh authenticated Tasks discovery against
    /// THIS client's exact resource with the SAME original credential. Saved
    /// data never chooses transport roots, login, metadata or endpoint routing.
    ///
    /// One native/core/caller/token deadline and cumulative payload/notification
    /// budget span the entire pass, including all discovery envelopes. Each
    /// successive decoder receives only the remaining budget. No changing ID,
    /// Task, response representation or callback replenishes it. Native raw-body
    /// and SSE syntax limits still apply independently to each response. Request
    /// IDs are generated from a fresh bounded prefix, not an idempotency key.
    ///
    /// JSON or finite SSE snapshots require clean HTTP EOF before observation.
    /// Callbacks are synchronous and must be brief, nonblocking and apply host
    /// disclosure policy. Returning false or panicking stops the pass; lifetime
    /// is checked before and after each callback. Previously delivered events
    /// cannot be recalled if a later Task fails, expires, disappears or becomes
    /// forbidden. An explicit new pass may redeliver them; exactly-once host
    /// effects are not implied. No snapshot list or result history is retained.
    ///
    /// Cancellation, revocation, callback failure, transport/protocol error or
    /// dropping the future stops observation. Nothing continues detached; no
    /// login, refresh, reconnect, creation, update or remote cancel is performed.
    #[allow(clippy::too_many_arguments)]
    pub async fn reconcile_task_checkpoints_with_events<O, N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        checkpoints: &[DpopTaskWatchCheckpoint],
        id_prefix: &str,
        limits: DpopStreamLimits,
        mut observe: O,
        mut notify: N,
    ) -> Result<usize, DpopTaskCheckpointError>
    where
        O: FnMut(&GetTaskResult) -> bool,
        N: FnMut(&ServerNotification) -> bool,
    {
        if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
            return Err(DpopTaskWatchError::from(DpopHttpError::Cancelled).into());
        }
        let mut reconciliation = Reconciliation::new(
            self.resource(), checkpoints, id_prefix, limits,
        )?;
        let bounds = WaitBounds::new(cx, self.policy.timeout.min(limits.core.timeout()), credential)
            .map_err(DpopTaskWatchError::from)?;
        while reconciliation.next < checkpoints.len() {
            check_live(cx, cancellation, &self.session, credential, bounds)
                .map_err(DpopTaskWatchError::from)?;
            let (operation, remaining) = reconciliation.next_request()?;
            let completed = self.request_task_stream_with_bounds(
                cx, cancellation, credential, metadata.clone(), operation,
                remaining, bounds, &mut notify,
            ).await.map_err(DpopTaskWatchError::from)?;
            check_live(cx, cancellation, &self.session, credential, bounds)
                .map_err(DpopTaskWatchError::from)?;
            let snapshot = reconciliation.admit(completed.result, completed.usage)?;
            check_live(cx, cancellation, &self.session, credential, bounds)
                .map_err(DpopTaskWatchError::from)?;
            let observed = with_caller(cx, || observe_snapshot(&snapshot, &mut observe));
            // Cancellation/revocation/deadline wins even if an observer also
            // refuses or panics. No successor request starts after that event.
            check_live(cx, cancellation, &self.session, credential, bounds)
                .map_err(DpopTaskWatchError::from)?;
            observed?;
        }
        Ok(reconciliation.next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;
    use fastmcp_protocol::ClientCapabilities;
    use fastmcp_protocol::tasks_extension::Task;
    use serde_json::json;
    use crate::http_auth::dpop::native::core::DpopCoreError;
    use crate::http_auth::rpc::ManagedCoreLimits;

    fn saved(id: &str) -> DpopTaskWatchCheckpoint {
        DpopTaskWatchCheckpoint::new(
            &CanonicalHttpUrl::parse("https://mcp.example/mcp?tenant=one").unwrap(),
            TaskId::parse(id).unwrap(),
        ).unwrap()
    }

    fn limits(notifications: usize) -> DpopStreamLimits {
        DpopStreamLimits::new(
            ManagedCoreLimits::new(4096, 4096, 8192, notifications, Duration::from_secs(60)).unwrap(),
            Duration::from_secs(10),
        ).unwrap()
    }

    fn snapshot(id: &str, status: &str) -> ManagedTaskEvent {
        let value = json!({
            "resultType":"complete", "taskId":id, "status":status,
            "createdAt":"2026-10-15T00:00:00Z", "lastUpdatedAt":"2026-10-15T00:00:00Z",
            "ttlMs":null, "_meta":{"hostMarker":"preserve-me"},
        });
        ManagedTaskEvent::Snapshot(Box::new(serde_json::from_value(value).unwrap()))
    }

    #[test]
    fn complete_selection_is_admitted_before_any_request_and_never_mutates_checkpoints() {
        let first = saved("one");
        let original = first.encode().unwrap();
        let duplicate = vec![first.clone(), first.clone()];
        assert!(matches!(Reconciliation::new(first.resource(), &duplicate, "restart", limits(1)),
            Err(DpopTaskCheckpointError::InvalidSelection)));
        let mut foreign = saved("two");
        foreign.resource = CanonicalHttpUrl::parse("https://mcp.example/mcp?tenant=two").unwrap();
        let mixed = vec![first.clone(), foreign];
        assert!(matches!(Reconciliation::new(first.resource(), &mixed, "restart", limits(1)),
            Err(DpopTaskCheckpointError::ResourceMismatch)));
        assert!(matches!(Reconciliation::new(first.resource(), &[], "restart", limits(1)),
            Err(DpopTaskCheckpointError::InvalidSelection)));
        let too_many = (0..=MAX_DPOP_TASK_RECONCILIATION_TASKS)
            .map(|n| saved(&format!("task-{n}"))).collect::<Vec<_>>();
        assert!(matches!(Reconciliation::new(first.resource(), &too_many, "restart", limits(1)),
            Err(DpopTaskCheckpointError::InvalidSelection)));
        let at_limit = &too_many[..MAX_DPOP_TASK_RECONCILIATION_TASKS];
        assert!(Reconciliation::new(first.resource(), at_limit, "restart", limits(1)).is_ok());

        let valid = vec![first.clone(), saved("two")];
        let state = Reconciliation::new(first.resource(), &valid, "restart", limits(1)).unwrap();
        assert_eq!((state.next, state.state.snapshots, state.state.usage), (0, 0, (0, 0)));
        assert_eq!(first.encode().unwrap(), original);
    }

    #[test]
    fn startup_reads_each_checkpoint_once_under_cumulative_limits() {
        let checkpoints = vec![saved("one"), saved("two")];
        let mut state = Reconciliation::new(checkpoints[0].resource(), &checkpoints, "restart", limits(1)).unwrap();
        let (_, first_limits) = state.next_request().unwrap();
        assert_eq!(state.state.snapshots, 1);
        let first = state.admit(snapshot("one", "working"), (4000, 1)).unwrap();
        assert_eq!(&first.task.base().task_id, checkpoints[0].task_id());
        let (_, second_limits) = state.next_request().unwrap();
        assert_eq!(state.state.snapshots, 2);
        assert_eq!(second_limits.core.total_bytes(), 4192);
        assert_eq!(second_limits.core.frame_bytes(), 4096);
        assert_eq!(second_limits.core.notifications(), 0);
        assert_eq!(second_limits.core.timeout(), first_limits.core.timeout());
        let final_snapshot = state.admit(snapshot("two", "cancelled"), (4192, 0)).unwrap();
        assert_eq!(&final_snapshot.task.base().task_id, checkpoints[1].task_id());
        assert!(matches!(final_snapshot.task, Task::Cancelled(_)));
        assert_eq!(state.state.usage, (8192, 1));
        assert_eq!(state.next, 2);
        let before = (state.next, state.state.snapshots, state.state.usage);
        assert!(state.next_request().is_err());
        assert_eq!((state.next, state.state.snapshots, state.state.usage), before);
    }

    #[test]
    fn wrong_task_and_either_budget_overflow_cannot_advance_or_publish() {
        let checkpoints = vec![saved("one"), saved("two")];
        let mut state = Reconciliation::new(checkpoints[0].resource(), &checkpoints, "restart", limits(1)).unwrap();
        state.next_request().unwrap();
        let before = (state.next, state.state.snapshots, state.state.usage);
        assert!(state.admit(snapshot("two", "working"), (1, 0)).is_err());
        assert_eq!((state.next, state.state.snapshots, state.state.usage), before);
        for usage in [(1, 2), (8193, 1), (usize::MAX, 0)] {
            assert!(state.admit(snapshot("one", "working"), usage).is_err());
            assert_eq!((state.next, state.state.snapshots, state.state.usage), before);
        }
        let admitted = state.admit(snapshot("one", "working"), (8191, 1)).unwrap();
        assert!(matches!(admitted.task, Task::Working(_)));
        let (_, remaining) = state.next_request().unwrap();
        assert_eq!(remaining.core.frame_bytes(), 1);
        assert_eq!(remaining.core.total_bytes(), 1);
        assert_eq!(remaining.core.notifications(), 0);
    }

    #[test]
    fn snapshot_observer_retains_metadata_and_refusal_or_panic_is_sanitized() {
        let ManagedTaskEvent::Snapshot(snapshot) = snapshot("one", "working") else { unreachable!() };
        let mut calls = 0;
        observe_snapshot(&snapshot, &mut |value| {
            calls += 1;
            assert_eq!(serde_json::to_value(value).unwrap()["_meta"]["hostMarker"], "preserve-me");
            true
        }).unwrap();
        assert_eq!(calls, 1);
        assert!(matches!(observe_snapshot(&snapshot, &mut |_| false),
            Err(DpopTaskCheckpointError::Watch(DpopTaskWatchError::Stream(DpopStreamError::ObserverStopped)))));
        let error = observe_snapshot(&snapshot, &mut |_| panic!("private-observer-payload")).unwrap_err();
        assert!(matches!(error,
            DpopTaskCheckpointError::Watch(DpopTaskWatchError::Stream(DpopStreamError::ObserverPanicked))));
        assert!(!format!("{error:?} {error}").contains("private-observer-payload"));
    }

    #[test]
    fn public_startup_rejects_late_foreign_endpoint_without_callbacks_then_admits_local_control() {
        let (mut client, credential) = super::super::tests::client();
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        for matches in [false, true] {
            let first = saved("one");
            let mut second = saved("two");
            if !matches {
                second.resource = CanonicalHttpUrl::parse("https://mcp.example/mcp?tenant=two").unwrap();
            }
            let checkpoints = [first, second];
            let mut snapshots = 0;
            let mut notifications = 0;
            let mut future = Box::pin(client.reconcile_task_checkpoints_with_events(
                &cx, &cancellation, &credential, FinalRequestMeta::new(ClientCapabilities::default()),
                &checkpoints, "startup", limits(2),
                |_| { snapshots += 1; true }, |_| { notifications += 1; true },
            ));
            let result = future.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            if matches {
                assert!(matches!(result, Poll::Ready(Err(DpopTaskCheckpointError::Watch(
                    DpopTaskWatchError::Stream(DpopStreamError::Core(DpopCoreError::Transport(
                        DpopHttpError::RuntimeUnavailable))))))));
            } else {
                assert!(matches!(result, Poll::Ready(Err(DpopTaskCheckpointError::ResourceMismatch))));
            }
            drop(future);
            assert_eq!((snapshots, notifications), (0, 0));
            assert!(!client.revocation_handle().is_revoked());
        }
    }

    #[test]
    fn public_startup_precancellation_wins_over_invalid_selection_and_prefix() {
        for cancel_caller in [false, true] {
            let (mut client, credential) = super::super::tests::client();
            let cx = Cx::for_testing();
            let cancellation = McpRequestCancellation::new();
            if cancel_caller { cx.set_cancel_requested(true); } else { cancellation.cancel(); }
            let mut future = Box::pin(client.reconcile_task_checkpoints(
                &cx, &cancellation, &credential, FinalRequestMeta::new(ClientCapabilities::default()),
                &[], "", limits(0), |_| panic!("must not observe"),
            ));
            assert!(matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(DpopTaskCheckpointError::Watch(DpopTaskWatchError::Stream(
                    DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled))))))));
            drop(future);
            assert!(!client.revocation_handle().is_revoked());
        }
    }
}
