//! Caller-owned asynchronous discovery and claiming of recoverable Task work.
//!
//! Claims remain owner-bound leases. A known claim is held behind restoration
//! custody while its current snapshot is checked; it cannot reach application
//! code during that check. An abandoned provider whose claim outcome is unknown
//! must retain its payload and lease for ordinary backend expiry recovery.

#[allow(clippy::wildcard_imports)]
use super::*;
use std::task::Poll;

const RECOVERY_CHECKPOINT_INTERVAL: StdDuration = StdDuration::from_millis(25);

/// One outstanding renewal, shared by the application-poll and maintenance
/// paths. The owned future carries the original caller and exact lease identity;
/// it does not borrow a mutable guard across unrelated storage or worker polls.
#[derive(Default)]
pub(super) struct FinalTaskLeaseRenewal {
    operation: Option<FinalTaskStoreFuture<'static, bool>>,
    checkpoint: Option<Pin<Box<asupersync::time::Sleep>>>,
}

impl FinalTaskLeaseRenewal {
    pub(super) fn poll(
        &mut self,
        cx: &Cx,
        guard: &FinalTaskExecutionGuard,
        task: &mut std::task::Context<'_>,
    ) -> Poll<McpResult<bool>> {
        let result = self.poll_renewal(cx, guard, task);
        if result.is_ready() {
            // Also drop an abandoned provider before its guard can restore
            // the lease. A completed provider is never polled a second time.
            self.operation = None;
            self.checkpoint = None;
        }
        result
    }

    fn poll_renewal(
        &mut self,
        cx: &Cx,
        guard: &FinalTaskExecutionGuard,
        task: &mut std::task::Context<'_>,
    ) -> Poll<McpResult<bool>> {
        let caller = match final_task_service_caller(cx) {
            Ok(caller) => caller,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if Self::expired(guard) {
            return Poll::Ready(Ok(false));
        }
        if let Err(error) = guard.ensure_execution_authorized() {
            return Poll::Ready(Err(error));
        }
        // Only this attempt's private commit receipt permits its bounded
        // cleanup after the transition has consumed the dispatch lease.
        if guard
            .transition_committed
            .load(TaskServiceOrdering::Acquire)
        {
            return Poll::Ready(Ok(true));
        }
        let Some(fence) = guard.dispatch_fence else {
            return Poll::Ready(Ok(false));
        };
        let operation = self.operation.get_or_insert_with(|| {
            let store = Arc::clone(&guard.runtime.store);
            let task_id = guard.task_id.clone();
            let generation = guard.generation;
            let owner = guard.owner_id.clone();
            Box::pin(async move {
                CallerContextFuture::new(&caller, async {
                    store
                        .renew_handoff_dispatch_if_current_with_cx(
                            &caller, &task_id, generation, &owner, fence,
                        )
                        .await
                })
                .await
            })
        });
        if let Poll::Ready(result) = operation.as_mut().poll(task) {
            // A receipt can arrive with cancellation, expiry or revocation.
            // It may describe a committed extension but grants no application
            // poll after the original caller or execution bound has expired.
            if let Err(error) = final_task_service_caller(cx) {
                return Poll::Ready(Err(error));
            }
            if Self::expired(guard) {
                return Poll::Ready(Ok(false));
            }
            if let Err(error) = guard.ensure_execution_authorized() {
                return Poll::Ready(Err(error));
            }
            return Poll::Ready(result);
        }
        if let Err(error) = final_task_service_caller(cx) {
            return Poll::Ready(Err(error));
        }
        if Self::expired(guard) {
            return Poll::Ready(Ok(false));
        }
        if let Err(error) = guard.ensure_execution_authorized() {
            return Poll::Ready(Err(error));
        }
        // A silent provider cannot hide caller cancellation or the original
        // backend execution/retention deadline. This timer only checks those
        // bounds; it never renews a lease or resets an execution budget.
        let checkpoint = self.checkpoint.get_or_insert_with(|| {
            Box::pin(asupersync::time::sleep(
                cx.now(),
                RECOVERY_CHECKPOINT_INTERVAL,
            ))
        });
        if checkpoint.as_mut().poll(task).is_ready() {
            checkpoint.set(asupersync::time::sleep(
                cx.now(),
                RECOVERY_CHECKPOINT_INTERVAL,
            ));
            task.waker().wake_by_ref();
        }
        Poll::Pending
    }

    fn expired(guard: &FinalTaskExecutionGuard) -> bool {
        let now = guard.runtime.retention_clock_now();
        guard.is_authoritatively_expired()
            || guard.execution_budget.is_some_and(|budget| {
                now >= budget.total_deadline
                    || budget
                        .attempt_deadline
                        .is_some_and(|deadline| now >= deadline)
            })
    }
}

/// Hold a validated claim across the asynchronous post-claim read. Successful
/// transfer performs no synchronous storage access. Abandonment uses exactly
/// the existing owner-bound execution guard's restoration rules.
struct PendingRecoveryHandoff<'a> {
    runtime: &'a FinalTaskRuntime,
    owner_id: &'a str,
    handoff: Option<FinalTaskSupervisorHandoff>,
}

impl Drop for PendingRecoveryHandoff<'_> {
    fn drop(&mut self) {
        if let Some(handoff) = self.handoff.take() {
            drop(FinalTaskExecutionGuard::new(
                self.runtime,
                self.owner_id,
                &handoff,
            ));
        }
    }
}

/// A receipt-producing operation is checked before each poll, but a returned
/// receipt reaches its owner before another cancellation check. This allows
/// the owner to establish restoration custody or publish an expiry commit.
async fn await_recovery_store<T>(
    cx: &Cx,
    operation: impl Future<Output = McpResult<T>>,
    committed_receipt: bool,
) -> McpResult<T> {
    await_recovery_store_while(cx, operation, committed_receipt, || Ok(())).await
}

/// Dispatch admission has a service-owned stop signal in addition to caller
/// cancellation. Preserve the same receipt-before-checkpoint rule while making
/// that stop observable even when a storage provider never wakes.
async fn await_recovery_store_while<T>(
    cx: &Cx,
    operation: impl Future<Output = McpResult<T>>,
    committed_receipt: bool,
    additional_checkpoint: impl Fn() -> McpResult<()>,
) -> McpResult<T> {
    let checkpoint = || {
        final_task_service_caller(cx)?;
        additional_checkpoint()
    };
    let mut operation = std::pin::pin!(operation);
    let mut wake = None;
    std::future::poll_fn(|task| {
        if let Err(error) = checkpoint() {
            return Poll::Ready(Err(error));
        }
        match operation.as_mut().poll(task) {
            Poll::Ready(result) => {
                if !committed_receipt {
                    if let Err(error) = checkpoint() {
                        return Poll::Ready(Err(error));
                    }
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                // A provider may neither wake nor cooperate with cancellation.
                // Keep cancellation, deadline and effect checks independent of
                // its wakeups, using only the admitted caller's timer driver.
                if let Err(error) = checkpoint() {
                    return Poll::Ready(Err(error));
                }
                let wake = wake.get_or_insert_with(|| {
                    Box::pin(asupersync::time::sleep(
                        cx.now(),
                        RECOVERY_CHECKPOINT_INTERVAL,
                    ))
                });
                if wake.as_mut().poll(task).is_ready() {
                    wake.set(asupersync::time::sleep(
                        cx.now(),
                        RECOVERY_CHECKPOINT_INTERVAL,
                    ));
                    task.waker().wake_by_ref();
                }
                Poll::Pending
            }
        }
    })
    .await
}

impl FinalTaskRuntime {
    /// Reads a Task for a trusted embedding application using its caller's storage hooks.
    ///
    /// Like [`Self::get_task`], this may read protected Tasks and does not
    /// authorize an incoming request. The application needs neither an entered
    /// Task service nor a blocking pool. The snapshot and any execution expiry
    /// come from the store on the supplied caller. Cancellation stops the read
    /// without returning a late payload; an atomic expiry already recorded by
    /// the store remains effective.
    pub fn get_task_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        task_id: &'a FinalTaskId,
    ) -> impl Future<Output = McpResult<FinalGetTaskResult>> + Send + 'a {
        CallerContextFuture::new(cx, async move {
            let caller = Cx::current()
                .ok_or_else(|| McpError::internal_error("Task read has no installed caller"))?;
            let ctx = McpContext::new(caller, 0);
            ctx.checkpoint()?;
            let live = || ctx.ensure_live().map_err(|_| McpError::request_cancelled());
            let stored = control::await_control_read(
                &ctx,
                self.store.get_task_snapshot_with_cx(ctx.cx(), task_id),
                live,
            )
            .await?
            .ok_or_else(|| McpError::invalid_params("Task not found"))?;
            let mut snapshot = self.validate_loaded_task_snapshot(stored, Some(task_id))?;
            if matches!(snapshot.task(), FinalTask::Working(_) | FinalTask::InputRequired { .. }) {
                live()?;
                let expired = control::await_control_read(
                    &ctx,
                    self.store.expire_task_execution_if_current_with_cx(ctx.cx(), &snapshot),
                    live,
                )
                .await?;
                if let Some(committed) = expired {
                    snapshot = self.validate_execution_expiry_receipt(&snapshot, committed)?;
                    self.emit_recovery_commit(ctx.cx(), &snapshot).await;
                }
            }
            live()?;
            Ok(fastmcp_protocol::CompleteTaskResult {
                task: snapshot.into_task(),
                meta: None,
                additional: BTreeMap::new(),
            })
        })
    }

    pub(super) fn recover_initial_work_excluding_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        owner_id: &'a str,
        recovery_cursor: &'a mut Option<FinalTaskId>,
        excluded_task_ids: &'a BTreeSet<FinalTaskId>,
    ) -> impl Future<Output = McpResult<Option<FinalTaskInitialWork>>> + Send + 'a {
        CallerContextFuture::new(cx, async move {
            match self
                .recover_handoff_excluding_with_cx(
                    cx,
                    owner_id,
                    recovery_cursor,
                    excluded_task_ids,
                    FinalTaskRecoveryKind::Initial,
                )
                .await?
            {
                Some(FinalTaskSupervisorHandoff::Initial(handoff)) => Ok(Some(handoff)),
                None => Ok(None),
                Some(FinalTaskSupervisorHandoff::Resumed(_)) => unreachable!(),
            }
        })
    }

    pub(super) fn recover_accepted_input_excluding_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        owner_id: &'a str,
        recovery_cursor: &'a mut Option<FinalTaskId>,
        excluded_task_ids: &'a BTreeSet<FinalTaskId>,
    ) -> impl Future<Output = McpResult<Option<FinalTaskAcceptedInput>>> + Send + 'a {
        CallerContextFuture::new(cx, async move {
            match self
                .recover_handoff_excluding_with_cx(
                    cx,
                    owner_id,
                    recovery_cursor,
                    excluded_task_ids,
                    FinalTaskRecoveryKind::Resumed,
                )
                .await?
            {
                Some(FinalTaskSupervisorHandoff::Resumed(handoff)) => Ok(Some(handoff)),
                None => Ok(None),
                Some(FinalTaskSupervisorHandoff::Initial(_)) => unreachable!(),
            }
        })
    }

    async fn recover_handoff_excluding_with_cx(
        &self,
        cx: &Cx,
        owner_id: &str,
        recovery_cursor: &mut Option<FinalTaskId>,
        excluded_task_ids: &BTreeSet<FinalTaskId>,
        kind: FinalTaskRecoveryKind,
    ) -> McpResult<Option<FinalTaskSupervisorHandoff>> {
        let mut skipped = BTreeSet::new();
        let mut lost_comparisons = 0;
        let mut work_steps = 0;
        for _ in 0..MAX_FINAL_TASK_RECOVERY_CAS_RETRIES + excluded_task_ids.len() {
            final_task_service_caller(cx)?;
            let operation = match kind {
                FinalTaskRecoveryKind::Initial => self
                    .store
                    .next_initial_work_snapshot_after_with_cx(cx, recovery_cursor.as_ref()),
                FinalTaskRecoveryKind::Resumed => self
                    .store
                    .next_accepted_input_snapshot_after_with_cx(cx, recovery_cursor.as_ref()),
            };
            let Some(candidate) = await_recovery_store(cx, operation, false).await? else {
                return Ok(None);
            };
            let candidate = self.validate_loaded_task_snapshot(candidate, None)?;
            let task_id = candidate.task().base().task_id.clone();
            if excluded_task_ids.contains(&task_id) {
                if !skipped.insert(task_id.clone()) {
                    return Ok(None);
                }
                *recovery_cursor = Some(task_id);
                continue;
            }
            work_steps += 1;
            if self
                .expire_execution_snapshot_with_cx(cx, &candidate)
                .await?
                .is_some()
            {
                *recovery_cursor = Some(task_id);
                if work_steps == MAX_FINAL_TASK_RECOVERY_CAS_RETRIES {
                    break;
                }
                continue;
            }
            if !matches!(candidate.task(), FinalTask::Working(_)) {
                return Err(McpError::internal_error(
                    "Final task store returned a non-working recovery candidate",
                ));
            }
            if let Some(handoff) = self
                .claim_recovery_handoff_with_cx(cx, &candidate, owner_id, kind)
                .await?
            {
                return Ok(Some(handoff));
            }
            lost_comparisons += 1;
            if work_steps == MAX_FINAL_TASK_RECOVERY_CAS_RETRIES {
                break;
            }
        }
        if lost_comparisons < MAX_FINAL_TASK_RECOVERY_CAS_RETRIES {
            if let Some(task_id) = recovery_cursor.as_ref() {
                self.signal_task_service(task_id.clone());
            }
            return Ok(None);
        }
        Err(McpError::internal_error(
            "Task recovery exceeded bounded lost-CAS retries",
        ))
    }

    pub(super) fn take_initial_work_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        task_id: &'a FinalTaskId,
        owner_id: &'a str,
    ) -> impl Future<Output = McpResult<Option<FinalTaskInitialWork>>> + Send + 'a {
        CallerContextFuture::new(cx, async move {
            match self
                .take_recovery_handoff_with_cx(
                    cx,
                    task_id,
                    owner_id,
                    FinalTaskRecoveryKind::Initial,
                )
                .await?
            {
                Some(FinalTaskSupervisorHandoff::Initial(handoff)) => Ok(Some(handoff)),
                None => Ok(None),
                Some(FinalTaskSupervisorHandoff::Resumed(_)) => unreachable!(),
            }
        })
    }

    pub(super) fn take_accepted_input_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        task_id: &'a FinalTaskId,
        owner_id: &'a str,
    ) -> impl Future<Output = McpResult<Option<FinalTaskAcceptedInput>>> + Send + 'a {
        CallerContextFuture::new(cx, async move {
            match self
                .take_recovery_handoff_with_cx(
                    cx,
                    task_id,
                    owner_id,
                    FinalTaskRecoveryKind::Resumed,
                )
                .await?
            {
                Some(FinalTaskSupervisorHandoff::Resumed(handoff)) => Ok(Some(handoff)),
                None => Ok(None),
                Some(FinalTaskSupervisorHandoff::Initial(_)) => unreachable!(),
            }
        })
    }

    async fn take_recovery_handoff_with_cx(
        &self,
        cx: &Cx,
        task_id: &FinalTaskId,
        owner_id: &str,
        kind: FinalTaskRecoveryKind,
    ) -> McpResult<Option<FinalTaskSupervisorHandoff>> {
        final_task_service_caller(cx)?;
        // Signals are advisory: a reclaimed Task must not stop other work.
        let Some(current) =
            await_recovery_store(cx, self.store.get_task_snapshot_with_cx(cx, task_id), false)
                .await?
        else {
            return Ok(None);
        };
        let current = self.validate_loaded_task_snapshot(current, Some(task_id))?;
        let current = self
            .expire_execution_snapshot_with_cx(cx, &current)
            .await?
            .unwrap_or(current);
        self.claim_recovery_handoff_with_cx(cx, &current, owner_id, kind)
            .await
    }

    async fn claim_recovery_handoff_with_cx(
        &self,
        cx: &Cx,
        expected: &FinalTaskSnapshot,
        owner_id: &str,
        kind: FinalTaskRecoveryKind,
    ) -> McpResult<Option<FinalTaskSupervisorHandoff>> {
        final_task_service_caller(cx)?;
        let authorization = FinalTaskAccessMetadata::new(
            expected.task().base().task_id.clone(),
            expected.generation(),
            expected.creation_generation(),
            expected.authenticated_principal(),
            expected.original_operation().cloned(),
        );
        let handoff = match kind {
            FinalTaskRecoveryKind::Initial => {
                let Some(claim) = await_recovery_store(
                    cx,
                    self.store
                        .take_initial_work_handoff_for_owner_if_current_with_cx(
                            cx, expected, owner_id,
                        ),
                    true,
                )
                .await?
                else {
                    return Ok(None);
                };
                validate_final_task_handoff_binding(
                    expected,
                    owner_id,
                    &claim.task_id,
                    claim.generation,
                    &claim.owner_id,
                    "initial-work",
                )?;
                validate_final_task_work_descriptor(&claim.work_descriptor)?;
                FinalTaskSupervisorHandoff::Initial(FinalTaskInitialWork {
                    task_id: claim.task_id,
                    generation: claim.generation,
                    work_descriptor: claim.work_descriptor,
                    authority: None,
                    execution_permit: claim.execution_permit,
                    execution_authorization: authorization,
                })
            }
            FinalTaskRecoveryKind::Resumed => {
                let Some(claim) = await_recovery_store(
                    cx,
                    self.store
                        .take_input_handoff_for_owner_if_current_with_cx(cx, expected, owner_id),
                    true,
                )
                .await?
                else {
                    return Ok(None);
                };
                validate_final_task_handoff_binding(
                    expected,
                    owner_id,
                    &claim.task_id,
                    claim.generation,
                    &claim.owner_id,
                    "accepted-input",
                )?;
                validate_final_task_work_descriptor(&claim.work_descriptor)?;
                if claim.input_responses.is_empty() {
                    return Err(McpError::internal_error(
                        "Final task store returned an empty accepted-input handoff",
                    ));
                }
                FinalTaskSupervisorHandoff::Resumed(FinalTaskAcceptedInput {
                    task_id: claim.task_id,
                    generation: claim.generation,
                    work_descriptor: claim.work_descriptor,
                    input_responses: claim.input_responses,
                    authority: None,
                    execution_permit: claim.execution_permit,
                    execution_authorization: authorization,
                })
            }
        };
        let mut pending = PendingRecoveryHandoff {
            runtime: self,
            owner_id,
            handoff: Some(handoff),
        };
        // Establish custody before any further cancellation check or await.
        // A late cancellation restores the exact known claim instead of
        // losing it between the provider receipt and application dispatch.
        let task_id = &expected.task().base().task_id;
        final_task_service_caller(cx)?;
        let current =
            await_recovery_store(cx, self.store.get_task_snapshot_with_cx(cx, task_id), false)
                .await?
                .ok_or_else(|| McpError::invalid_params("Task not found"))?;
        let current = self.validate_loaded_task_snapshot(current, Some(task_id))?;
        if current.generation() != expected.generation()
            || current.creation_generation() != expected.creation_generation()
            || current.authenticated_principal() != expected.authenticated_principal()
            || current.original_operation() != expected.original_operation()
            || !final_tasks_match_exactly(current.task(), expected.task())?
        {
            return Err(McpError::internal_error(
                "Final task store changed the claimed task before application handoff",
            ));
        }
        final_task_service_caller(cx)?;
        Ok(pending.handoff.take())
    }

    async fn expire_execution_snapshot_with_cx(
        &self,
        cx: &Cx,
        expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        if !matches!(
            expected.task(),
            FinalTask::Working(_) | FinalTask::InputRequired { .. }
        ) {
            return Ok(None);
        }
        final_task_service_caller(cx)?;
        let Some(committed) = await_recovery_store(
            cx,
            self.store
                .expire_task_execution_if_current_with_cx(cx, expected),
            true,
        )
        .await?
        else {
            return Ok(None);
        };
        let committed = self.validate_execution_expiry_receipt(expected, committed)?;
        self.emit_recovery_commit(cx, &committed).await;
        Ok(Some(committed))
    }

    pub(super) fn validate_execution_expiry_receipt(
        &self,
        expected: &FinalTaskSnapshot,
        committed: FinalTaskSnapshot,
    ) -> McpResult<FinalTaskSnapshot> {
        let committed =
            self.validate_loaded_task_snapshot(committed, Some(&expected.task().base().task_id))?;
        if !matches!(committed.task(), FinalTask::Failed { .. })
            || committed.generation() <= expected.generation()
            || committed.authenticated_principal() != expected.authenticated_principal()
            || committed.original_operation() != expected.original_operation()
            || committed.creation_generation() != expected.creation_generation()
        {
            return Err(McpError::internal_error(
                "Final task store returned an invalid execution-expiry commit",
            ));
        }
        validate_final_task_transition(expected.task(), committed.task())?;
        Ok(committed)
    }

    pub(super) async fn emit_recovery_commit(&self, cx: &Cx, committed: &FinalTaskSnapshot) {
        if final_task_service_caller(cx).is_err() {
            return;
        }
        let task_id = &committed.task().base().task_id;
        let Ok(Some(current)) =
            await_recovery_store(cx, self.store.get_task_snapshot_with_cx(cx, task_id), false)
                .await
        else {
            return;
        };
        let Ok(current) = self.validate_loaded_task_snapshot(current, Some(task_id)) else {
            return;
        };
        if current.generation() != committed.generation()
            || current.creation_generation() != committed.creation_generation()
            || current.authenticated_principal() != committed.authenticated_principal()
            || current.original_operation() != committed.original_operation()
            || !final_tasks_match_exactly(current.task(), committed.task()).unwrap_or(false)
        {
            return;
        }
        let emitters = {
            let mut registered = self
                .notification_emitters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registered.retain(|emitter| emitter.strong_count() != 0);
            registered.clone()
        };
        let notification = final_task_notification(committed.task());
        let principal = committed.authenticated_principal();
        let mut panicked_emitter_count = 0usize;
        if catch_unwind(AssertUnwindSafe(|| {
            (self.application_notification_emitter)(notification.clone(), principal);
        }))
        .is_err()
        {
            panicked_emitter_count += 1;
        }
        for weak in &emitters {
            if final_task_service_caller(cx).is_err() {
                break;
            }
            let current = await_recovery_store(
                cx,
                self.store.get_task_access_metadata_with_cx(cx, task_id),
                false,
            )
            .await;
            if !current.is_ok_and(|current| {
                current.is_some_and(|current| {
                    current.task_id() == task_id
                        && current.generation() == committed.generation()
                        && current.creation_generation() == committed.creation_generation()
                        && current.authenticated_principal() == principal
                        && current.original_operation() == committed.original_operation()
                })
            }) {
                continue;
            }
            // Keep only a weak reference while its asynchronous fence waits;
            // dropping a subscription must release its callback immediately.
            let Some(emitter) = weak.upgrade() else {
                continue;
            };
            if catch_unwind(AssertUnwindSafe(|| {
                emitter(notification.clone(), principal);
            }))
            .is_err()
            {
                panicked_emitter_count += 1;
            }
        }
        if panicked_emitter_count != 0 {
            log::error!(
                target: "fastmcp_rust::server",
                "Final Task notification delivery degraded after durable mutation; panicked_emitter_count={}",
                panicked_emitter_count
            );
        }
    }

    pub(super) fn expire_pending_execution_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
    ) -> impl Future<Output = McpResult<()>> + Send + 'a {
        CallerContextFuture::new(cx, async move {
            for turn in 0..MAX_FINAL_TASK_RECOVERY_HANDOFFS_PER_SCAN {
                final_task_service_caller(cx)?;
                let Some(candidate) = await_recovery_store(
                    cx,
                    self.store.next_expired_execution_snapshot_with_cx(cx),
                    false,
                )
                .await?
                else {
                    break;
                };
                let candidate = self.validate_loaded_task_snapshot(candidate, None)?;
                self.expire_execution_snapshot_with_cx(cx, &candidate)
                    .await?;
                if turn + 1 == MAX_FINAL_TASK_RECOVERY_HANDOFFS_PER_SCAN {
                    self.signal_task_service(candidate.task().base().task_id.clone());
                }
            }
            Ok(())
        })
    }
}

impl FinalTaskExecutionGuard {
    /// Transfer the known elected fence to one final store operation. Before
    /// admission Drop owns restoration. After admission a lost receipt leaves
    /// reconciliation to the backend's finite lease.
    pub(super) async fn settle_dispatch_with_cx(
        &mut self,
        cx: &Cx,
        settlement: FinalTaskDispatchSettlement,
    ) -> McpResult<bool> {
        let caller = final_task_service_caller(cx)?;
        let Some(fence) = self.dispatch_fence else {
            return Ok(false);
        };
        if FinalTaskLeaseRenewal::expired(self) {
            return Ok(false);
        }
        let Some(restoration) = self.restoration.take() else {
            return Ok(false);
        };
        // The factory itself may commit. Disarm the guard before constructing
        // it, and keep factory, polls and destruction inside the caller's Cx.
        CallerContextFuture::new(&caller, async {
            let store = &self.runtime.store;
            let operation = match (settlement, restoration) {
                (FinalTaskDispatchSettlement::Finish, _) => {
                    store.finish_handoff_dispatch_for_owner_if_current_with_cx(
                        &caller,
                        &self.task_id,
                        self.generation,
                        &self.owner_id,
                        fence,
                    )
                }
                (FinalTaskDispatchSettlement::Restore, FinalTaskHandoffRestoration::Initial(work)) => {
                    store.restore_initial_work_for_owner_if_current_with_cx(
                        &caller,
                        &self.task_id,
                        self.generation,
                        &self.owner_id,
                        fence,
                        work,
                    )
                }
                (FinalTaskDispatchSettlement::Restore, FinalTaskHandoffRestoration::Resumed(inputs)) => {
                    store.restore_input_for_owner_if_current_with_cx(
                        &caller,
                        &self.task_id,
                        self.generation,
                        &self.owner_id,
                        fence,
                        inputs,
                    )
                }
            };
            await_recovery_store_while(&caller, operation, true, || {
                if FinalTaskLeaseRenewal::expired(self) {
                    Err(McpError::request_cancelled())
                } else {
                    Ok(())
                }
            })
            .await
        })
        .await
    }

    /// Keeps a claimed handoff in restoration custody while its dispatch
    /// preflight awaits storage. An uncertain election instead retains the
    /// backend's finite lease; only an actual receipt supplies a restore fence.
    pub(super) fn elect_with_cx<'a>(
        &'a mut self,
        cx: &'a Cx,
        stop: &'a AtomicBool,
    ) -> impl Future<Output = McpResult<bool>> + Send + 'a {
        CallerContextFuture::new(cx, async move {
            let checkpoint = || {
                if stop.load(TaskServiceOrdering::Acquire) {
                    Err(McpError::request_cancelled())
                } else {
                    Ok(())
                }
            };
            final_task_service_caller(cx)?;
            checkpoint()?;
            if self.execution_admission_lost {
                return Ok(false);
            }
            let Some(current) = await_recovery_store_while(
                cx,
                self.runtime
                    .store
                    .get_task_snapshot_with_cx(cx, &self.task_id),
                false,
                &checkpoint,
            )
            .await?
            else {
                return Ok(false);
            };
            let current = self
                .runtime
                .validate_loaded_task_snapshot(current, Some(&self.task_id))?;
            final_task_service_caller(cx)?;
            checkpoint()?;
            let current = await_recovery_store_while(
                cx,
                self.runtime.expire_execution_snapshot_with_cx(cx, &current),
                true,
                &checkpoint,
            )
            .await?
            .unwrap_or(current);
            if current.generation() != self.generation
                || !matches!(current.task(), FinalTask::Working(_))
                || self
                    .execution_authorization
                    .as_ref()
                    .is_none_or(|expected| !expected.admits_snapshot(&current))
            {
                return Ok(false);
            }
            final_task_service_caller(cx)?;
            checkpoint()?;
            let Some(budget) = await_recovery_store_while(
                cx,
                self.runtime
                    .store
                    .task_execution_budget_if_current_with_cx(cx, &current),
                false,
                &checkpoint,
            )
            .await?
            else {
                return Ok(false);
            };
            let Some(attempt_deadline) = budget.attempt_deadline else {
                return Err(McpError::internal_error(
                    "Final task store did not bound the claimed execution attempt",
                ));
            };
            if budget.attempts == 0 {
                return Err(McpError::internal_error(
                    "Final task store did not bound the claimed execution attempt",
                ));
            }
            self.execution_budget = Some(budget);
            final_task_service_caller(cx)?;
            checkpoint()?;
            let Some(deadline) = await_recovery_store_while(
                cx,
                self.runtime
                    .store
                    .task_retention_deadline_if_current_with_cx(cx, &self.task_id, self.generation),
                false,
                &checkpoint,
            )
            .await?
            else {
                return Ok(false);
            };
            let expired = |now| {
                now >= budget.total_deadline
                    || now >= attempt_deadline
                    || matches!(
                        deadline,
                        FinalTaskRetentionDeadline::Finite(retention) if now >= retention
                    )
            };
            final_task_service_caller(cx)?;
            checkpoint()?;
            if expired(self.runtime.retention_clock_now()) {
                return Ok(false);
            }

            // Set this before constructing the provider future: even its
            // factory may perform admission or commit work. If its outcome is
            // lost, Drop must not restore a pre-dispatch claim over a possible
            // elected owner or replay the original application invocation.
            self.dispatch_election_uncertain = true;
            let elected = await_recovery_store_while(
                cx,
                self.runtime
                    .store
                    .begin_handoff_dispatch_for_owner_if_current_with_cx(
                        cx,
                        &self.task_id,
                        self.generation,
                        &self.owner_id,
                    ),
                true,
                &checkpoint,
            )
            .await?;
            let Some(fence) = elected else {
                self.dispatch_election_uncertain = false;
                return Ok(false);
            };
            if fence == 0 {
                // A malformed receipt cannot authorize restoration. Retain
                // uncertainty rather than passing an invented fence to Drop.
                return Err(McpError::internal_error(
                    "Final task store returned a zero dispatch fencing token",
                ));
            }
            // Adopt the exact committed fence before any subsequent check.
            // Late cancellation or a sibling service error can now restore
            // only this known election; it cannot invent an unelected claim.
            self.retention_deadline = Some(deadline);
            self.dispatch_fence = Some(fence);
            self.dispatch_election_uncertain = false;
            final_task_service_caller(cx)?;
            checkpoint()?;
            if expired(self.runtime.retention_clock_now()) {
                return Err(McpError::request_cancelled());
            }
            Ok(true)
        })
    }
}

impl FinalTaskHandoffExecutor {
    /// Keeps this attempt's lease live while bulk expiry waits on storage.
    /// Task cancellation returns to the supervisor's existing grace path;
    /// maintenance never polls or terminalizes the application callback.
    pub(super) fn expire_pending_execution_with_lease_heartbeat<'a>(
        &'a self,
        cx: &'a Cx,
        guard: &'a mut FinalTaskExecutionGuard,
        cancellation_wake: &'a FinalTaskCancellationWakeRegistration,
    ) -> impl Future<Output = McpResult<()>> + Send + 'a {
        CallerContextFuture::new(cx, async move {
            let mut maintenance = None;
            let mut completed = None;
            let mut heartbeat = None;
            let mut renewal = FinalTaskLeaseRenewal::default();
            std::future::poll_fn(|task| {
                match std::task::ready!(Self::poll_maintenance_checkpoint(
                    cx,
                    guard,
                    cancellation_wake,
                    task,
                )) {
                    Ok(true) => {}
                    Ok(false) => return Poll::Ready(Ok(())),
                    Err(error) => return Poll::Ready(Err(error)),
                }
                if heartbeat.is_none() {
                    let interval = match std::task::ready!(Self::poll_renew_maintenance_lease(
                        cx,
                        guard,
                        &mut renewal,
                        task,
                    )) {
                        Ok(Some(interval)) => interval,
                        Ok(None) => return Poll::Ready(Ok(())),
                        Err(error) => return Poll::Ready(Err(error)),
                    };
                    heartbeat = Some(Box::pin(asupersync::time::sleep(cx.now(), interval)));
                }
                if completed.is_none() {
                    // Check before constructing the provider future too: a
                    // factory may perform synchronous admission work.
                    if let Err(error) = final_task_service_caller(cx) {
                        return Poll::Ready(Err(error));
                    }
                    let operation = maintenance.get_or_insert_with(|| {
                        Box::pin(self.runtime.expire_pending_execution_with_cx(cx))
                    });
                    if let Poll::Ready(result) = operation.as_mut().poll(task) {
                        // Settlement can suspend below. Preserve Ready rather
                        // than polling a completed provider a second time.
                        completed = Some(result);
                    }
                }
                match std::task::ready!(Self::poll_maintenance_checkpoint(
                    cx,
                    guard,
                    cancellation_wake,
                    task,
                )) {
                    Ok(true) => {}
                    Ok(false) => return Poll::Ready(Ok(())),
                    Err(error) => return Poll::Ready(Err(error)),
                }
                if let Some(result) = completed.take() {
                    return Poll::Ready(result);
                }
                // The checkpoint above admits this caller before Sleep can
                // register a wake; a narrowed host cannot borrow a timer.
                if let Err(error) = final_task_service_caller(cx) {
                    return Poll::Ready(Err(error));
                }
                let heartbeat = heartbeat.as_mut().expect("maintenance heartbeat is armed");
                if heartbeat.as_mut().poll(task).is_ready() {
                    let interval = match std::task::ready!(Self::poll_renew_maintenance_lease(
                        cx,
                        guard,
                        &mut renewal,
                        task,
                    )) {
                        Ok(Some(interval)) => interval,
                        Ok(None) => return Poll::Ready(Ok(())),
                        Err(error) => return Poll::Ready(Err(error)),
                    };
                    heartbeat.set(asupersync::time::sleep(cx.now(), interval));
                    // Register the replacement on a later poll rather than
                    // spinning through a ready or zero-duration deadline.
                    task.waker().wake_by_ref();
                }
                Poll::Pending
            })
            .await
        })
    }

    /// Returns false when the ordinary supervisor monitor should regain
    /// control. In particular, durable task cancellation does not revoke its
    /// cooperative cleanup opportunity.
    fn poll_maintenance_checkpoint(
        cx: &Cx,
        guard: &mut FinalTaskExecutionGuard,
        cancellation_wake: &FinalTaskCancellationWakeRegistration,
        task: &mut std::task::Context<'_>,
    ) -> Poll<McpResult<bool>> {
        // A committed worker mutation may be waiting to deliver its receipt.
        // Settle it before inspecting the lease that commit may have consumed.
        if guard
            .pending_write
            .poll_settlement(task, false)
            .is_pending()
        {
            return Poll::Pending;
        }
        if guard.pending_write.outcome_uncertain() {
            return Poll::Ready(Err(worker::worker_outcome_unknown()));
        }
        if guard.pending_write.application_closed() {
            return Poll::Ready(Err(McpError::request_cancelled()));
        }
        cancellation_wake.register_waker(task.waker());
        if let Err(error) = final_task_service_caller(cx) {
            return Poll::Ready(Err(error));
        }
        if guard
            .transition_committed
            .load(TaskServiceOrdering::Acquire)
        {
            // The private commit receipt permits bounded application cleanup,
            // not further maintenance under a now-consumed dispatch lease.
            return Poll::Ready(Ok(false));
        }
        match guard.retire_if_execution_expired() {
            Ok(true) => return Poll::Ready(Ok(false)),
            Ok(false) => {}
            Err(error) => return Poll::Ready(Err(error)),
        }
        if guard.is_authoritatively_expired() {
            return Poll::Ready(Ok(false));
        }
        match guard.retire_if_execution_authorization_lost() {
            Ok(true) => return Poll::Ready(Ok(false)),
            Ok(false) => {}
            Err(error) => return Poll::Ready(Err(error)),
        }
        match guard.is_cancellation_requested() {
            Ok(requested) => Poll::Ready(Ok(!requested)),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    /// Renews only the guard's exact owner/fence and returns its next bounded
    /// heartbeat. A false renewal never authorizes reconstructing a lease.
    fn poll_renew_maintenance_lease(
        cx: &Cx,
        guard: &mut FinalTaskExecutionGuard,
        renewal: &mut FinalTaskLeaseRenewal,
        task: &mut std::task::Context<'_>,
    ) -> Poll<McpResult<Option<StdDuration>>> {
        let renewed = match std::task::ready!(renewal.poll(cx, guard, task)) {
            Ok(renewed) => renewed,
            Err(error) => return Poll::Ready(Err(error)),
        };
        Poll::Ready(Self::maintenance_interval_after_renewal(cx, guard, renewed))
    }

    fn maintenance_interval_after_renewal(
        cx: &Cx,
        guard: &mut FinalTaskExecutionGuard,
        renewed: bool,
    ) -> McpResult<Option<StdDuration>> {
        final_task_service_caller(cx)?;
        if !renewed {
            if guard
                .transition_committed
                .load(TaskServiceOrdering::Acquire)
                || guard.retire_if_execution_expired()?
                || guard.is_authoritatively_expired()
            {
                return Ok(None);
            }
            return Err(McpError::internal_error(
                "Final task dispatch lease was lost while application work was running",
            ));
        }
        if guard
            .transition_committed
            .load(TaskServiceOrdering::Acquire)
        {
            return Ok(None);
        }
        let backend_interval = guard.bounded_heartbeat_interval()?;
        final_task_service_caller(cx)?;
        let interval = cx.budget().deadline.map_or(backend_interval, |deadline| {
            backend_interval.min(StdDuration::from_nanos(deadline.duration_since(cx.now())))
        });
        Ok(Some(interval))
    }
}

#[cfg(test)]
mod tests;
