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
    let mut operation = std::pin::pin!(operation);
    let mut wake = None;
    std::future::poll_fn(|task| {
        if let Err(error) = final_task_service_caller(cx) {
            return Poll::Ready(Err(error));
        }
        match operation.as_mut().poll(task) {
            Poll::Ready(result) => {
                if !committed_receipt {
                    if let Err(error) = final_task_service_caller(cx) {
                        return Poll::Ready(Err(error));
                    }
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                // A provider may neither wake nor cooperate with cancellation.
                // Keep cancellation, deadline and effect checks independent of
                // its wakeups, using only the admitted caller's timer driver.
                if let Err(error) = final_task_service_caller(cx) {
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
        self.emit_recovery_commit(cx, &committed).await;
        Ok(Some(committed))
    }

    async fn emit_recovery_commit(&self, cx: &Cx, committed: &FinalTaskSnapshot) {
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

#[cfg(test)]
mod tests;
