//! Caller-owned asynchronous control requests for the final Tasks profile.
//!
//! A provider may suspend any control operation without blocking unrelated
//! requests. Reads remain subject to live request authority on every poll;
//! once an atomic write starts, its provider owns settling the commit receipt.

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::extensions::TaskControlReceipt;
use std::task::Poll;

/// Request-owned authority for one exact terminal Task reclamation.
///
/// The framework creates this admission only after authorizing the current
/// administrator and binding the inspected target to its originating runtime.
/// An asynchronous store uses [`Self::context`] for I/O and calls
/// [`Self::checkpoint_before_write`] immediately before its first irreversible
/// write, including after a suspension. Once a write may have committed, the
/// backend must settle that original receipt instead of reporting cancellation
/// as proof that nothing changed. This value cannot be cloned or constructed
/// by application code.
pub struct FinalTaskRetentionAdmission<'a> {
    runtime: &'a FinalTaskRuntime,
    ctx: &'a McpContext,
    target: &'a TaskRetentionTarget,
    reason: TaskRetentionReason,
}

impl<'a> FinalTaskRetentionAdmission<'a> {
    /// Returns the original caller's context and cancellation authority.
    #[must_use]
    pub fn context(&self) -> &'a McpContext {
        self.ctx
    }

    /// Returns the exact inspected Task identifier.
    #[must_use]
    pub fn task_id(&self) -> &'a FinalTaskId {
        &self.target.task_id
    }

    /// Returns the generation that the backend must compare atomically.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.target.generation
    }

    /// Returns the closed administrative reason bound to this operation.
    #[must_use]
    pub const fn reason(&self) -> TaskRetentionReason {
        self.reason
    }

    /// Revalidates current administrative authority before the first write.
    pub fn checkpoint_before_write(&self) -> McpResult<()> {
        self.runtime.authorize_task_retention(
            self.ctx,
            &TaskRetentionAuthorization::Reclaim {
                task_id: &self.target.task_id,
                generation: self.target.generation,
                reason: self.reason,
            },
        )?;
        Ok(())
    }
}

impl FinalTaskRuntime {
    /// Inspects one terminal Task through the caller-owned asynchronous store.
    ///
    /// Administrative authority is checked before storage is invoked, on every
    /// poll, and before returning the non-payload comparison target. A suspended
    /// read can be cancelled without waiting for an unrelated storage wakeup.
    pub fn inspect_task_retention_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> impl Future<Output = McpResult<TaskRetentionTarget>> + Send + 'a {
        CallerContextFuture::new(ctx.cx(), async move {
            let authorize = || {
                self.authorize_task_retention(ctx, &TaskRetentionAuthorization::Inspect { task_id })
                    .map(|_| ())
            };
            authorize()?;
            let snapshot = await_control_read(
                ctx,
                self.store.get_task_snapshot_with_context(ctx, task_id),
                authorize,
            )
            .await?
            .ok_or_else(|| {
                McpError::invalid_params("Task has no reclaimable terminal generation")
            })?;
            let snapshot = self.validate_loaded_task_snapshot(snapshot, Some(task_id))?;
            if snapshot.generation() == 0 || !final_task_is_terminal(snapshot.task()) {
                return Err(McpError::invalid_params(
                    "Task has no reclaimable terminal generation",
                ));
            }
            Ok(TaskRetentionTarget {
                task_id: task_id.clone(),
                generation: snapshot.generation(),
                runtime: Arc::clone(&self.retention_administration),
            })
        })
    }

    /// Reclaims an inspected terminal generation without blocking its caller.
    ///
    /// The backend receives a fresh administrative admission and must compare
    /// the exact target within its atomic reclamation transaction. A validated
    /// committed receipt remains successful if cancellation or revocation
    /// arrives after that write; neither can safely imply a rolled-back
    /// reclamation. Repeating a retained receipt preserves its original reason.
    /// These hooks do not establish a persistent backend or durability claim.
    pub fn reclaim_task_retention_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        target: &'a TaskRetentionTarget,
        reason: TaskRetentionReason,
    ) -> impl Future<Output = McpResult<TaskRetentionReclamation>> + Send + 'a {
        CallerContextFuture::new(ctx.cx(), async move {
            let admission = FinalTaskRetentionAdmission {
                runtime: self,
                ctx,
                target,
                reason,
            };
            admission.checkpoint_before_write()?;
            if !Arc::ptr_eq(&target.runtime, &self.retention_administration) {
                return Err(McpError::invalid_params(
                    "Task retention target belongs to another runtime",
                ));
            }
            // The provider owns settling any write it starts. A read-style
            // cancellation guard could abandon an already committed mutation.
            let outcome = self
                .store
                .reclaim_terminal_task_with_context(admission)
                .await
                .map_err(|error| control_write_error(ctx, "Task retention reclamation", error))?;
            if let Some(receipt) = outcome.receipt() {
                if matches!(&outcome, TaskRetentionReclamation::Reclaimed(_))
                    && receipt.reason != reason
                {
                    return Err(McpError::internal_error(
                        "Task retention backend substituted the committed reason",
                    ));
                }
                let expected = TaskRetentionReceipt::new(
                    receipt.sequence,
                    &target.task_id,
                    target.generation,
                    receipt.reason,
                    receipt.released_payload_bytes,
                )?;
                if *receipt != expected {
                    return Err(McpError::internal_error(
                        "Task retention backend returned an unrelated receipt",
                    ));
                }
            }
            Ok(outcome)
        })
    }

    /// Reads a bounded redacted audit page through the asynchronous store.
    ///
    /// Current administrative authority fences every provider poll and the
    /// returned page. The backend cannot widen the requested page, configured
    /// journal limits, or exclusive sequence cursor.
    pub fn task_retention_audit_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        after: Option<u64>,
        limit: usize,
    ) -> impl Future<Output = McpResult<TaskRetentionAuditPage>> + Send + 'a {
        CallerContextFuture::new(ctx.cx(), async move {
            validate_task_retention_page_limit(limit)?;
            let action = TaskRetentionAuthorization::Audit { after, limit };
            let policy = self.authorize_task_retention(ctx, &action)?;
            let page = await_control_read(
                ctx,
                self.store
                    .task_retention_audit_with_context(ctx, after, limit),
                || self.authorize_task_retention(ctx, &action).map(|_| ()),
            )
            .await?;
            if page.records.len() > limit
                || page.retained_records > policy.max_records
                || page.retained_bytes > policy.max_bytes
                || after
                    .is_some_and(|after| page.records.iter().any(|record| record.sequence <= after))
            {
                return Err(McpError::internal_error(
                    "Task retention backend exceeded its audit bounds",
                ));
            }
            Ok(page)
        })
    }

    pub(crate) fn task_for_request_with_cx<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
        action: TaskAccessAction,
    ) -> impl Future<Output = McpResult<FinalTaskSnapshot>> + Send + 'a {
        CallerContextFuture::new(
            ctx.cx(),
            self.task_for_request_on_caller(ctx, task_id, action),
        )
    }

    async fn task_for_request_on_caller(
        &self,
        ctx: &McpContext,
        task_id: &FinalTaskId,
        action: TaskAccessAction,
    ) -> McpResult<FinalTaskSnapshot> {
        authorization::ensure_current_task_authentication(ctx)?;
        let metadata = await_control_read(
            ctx,
            self.store
                .get_task_access_metadata_with_context(ctx, task_id),
            || authorization::ensure_current_task_authentication(ctx),
        )
        .await?
        .ok_or_else(authorization::task_access_denied)?;
        if metadata.task_id() != task_id
            || metadata.generation() == 0
            || metadata.creation_generation() == 0
            || metadata.creation_generation() > metadata.generation()
            || metadata.authenticated_principal() != task_request_principal(ctx)?
        {
            return Err(authorization::task_access_denied());
        }
        self.authorize_original_operation(ctx, action, metadata.original_operation())?;
        authorization::ensure_current_task_authentication(ctx)?;
        let snapshot = await_control_read(
            ctx,
            self.store.get_task_snapshot_with_context(ctx, task_id),
            || self.authorize_original_operation(ctx, action, metadata.original_operation()),
        )
        .await?
        .ok_or_else(authorization::task_access_denied)?;
        if !metadata.admits_snapshot(&snapshot) {
            return Err(authorization::task_access_denied());
        }
        self.authorize_original_operation(ctx, action, snapshot.original_operation())?;
        let snapshot = self.validate_loaded_task_snapshot(snapshot, Some(task_id))?;
        let snapshot = match self.expire_control_snapshot(ctx, &snapshot).await? {
            Some(expired) => {
                self.emit_control_commit(
                    ctx,
                    action,
                    final_task_notification(expired.task()),
                    &expired,
                )
                .await;
                expired
            }
            None => snapshot,
        };
        // Expiry and publication may themselves suspend. A late payload never
        // escapes after the requesting principal or operation loses authority.
        self.authorize_original_operation(ctx, action, snapshot.original_operation())?;
        authorization::ensure_current_task_authentication(ctx)?;
        Ok(snapshot)
    }

    #[cfg(test)]
    pub(crate) fn update_task_for_request_with_cx<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
        input_responses: &'a FinalTaskInputResponses,
    ) -> impl Future<Output = McpResult<UpdateTaskResult>> + Send + 'a {
        self.update_task_for_request_with_receipt(
            ctx,
            task_id,
            input_responses,
            TaskControlReceipt::default(),
        )
    }

    pub(crate) fn update_task_for_request_with_receipt<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
        input_responses: &'a FinalTaskInputResponses,
        receipt: TaskControlReceipt,
    ) -> impl Future<Output = McpResult<UpdateTaskResult>> + Send + 'a {
        CallerContextFuture::new(ctx.cx(), async move {
            let current = self
                .task_for_request_on_caller(ctx, task_id, TaskAccessAction::Update)
                .await?;
            let Some((task, outstanding_responses)) =
                prepare_task_input_update(&current, input_responses)?
            else {
                return Ok(UpdateTaskResult::default());
            };
            let notification = final_task_notification(&task);
            self.validate_task_transition_write(&current, &task, &notification)?;
            self.authorize_original_operation(
                ctx,
                TaskAccessAction::Update,
                current.original_operation(),
            )?;
            authorization::ensure_current_task_authentication(ctx)?;
            // Do not wrap an admitted mutation in the read guard. The provider
            // receives the full request context so it can observe cancellation
            // and settle its own receipt after an earlier Pending poll.
            receipt.admit_write();
            let result = self
                .store
                .replace_task_and_append_input_if_current_with_context(
                    ctx,
                    &current,
                    task.clone(),
                    notification.clone(),
                    outstanding_responses,
                )
                .await;
            if matches!(&result, Ok(None)) {
                receipt.no_commit();
            }
            let result =
                result.map_err(|error| control_write_error(ctx, "Task input update", error));
            if !matches!(&result, Ok(Some(_)))
                && self
                    .authorize_original_operation(
                        ctx,
                        TaskAccessAction::Update,
                        current.original_operation(),
                    )
                    .is_ok()
                && let Some(expired) = self.expire_control_snapshot(ctx, &current).await?
            {
                self.emit_control_commit(
                    ctx,
                    TaskAccessAction::Update,
                    final_task_notification(expired.task()),
                    &expired,
                )
                .await;
            }
            let Some(committed) = result? else {
                return Err(McpError::invalid_params(
                    "Task state changed before the transition could be recorded",
                ));
            };
            let committed = self.validate_committed_transition(&current, &task, committed)?;
            receipt.committed();
            // Wake the worker before fallible notification reads. Neither
            // cancellation nor observer failure can turn accepted input into
            // an ordinary cancelled response that suggests a safe retry.
            if matches!(task, FinalTask::Working(_)) {
                self.signal_task_service(task_id.clone());
            }
            self.emit_control_commit(ctx, TaskAccessAction::Update, notification, &committed)
                .await;
            Ok(UpdateTaskResult::default())
        })
    }

    #[cfg(test)]
    pub(crate) fn cancel_task_for_request_with_cx<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> impl Future<Output = McpResult<FinalCancelTaskResult>> + Send + 'a {
        self.cancel_task_for_request_with_receipt(ctx, task_id, TaskControlReceipt::default())
    }

    pub(crate) fn cancel_task_for_request_with_receipt<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
        receipt: TaskControlReceipt,
    ) -> impl Future<Output = McpResult<FinalCancelTaskResult>> + Send + 'a {
        CallerContextFuture::new(ctx.cx(), async move {
            let current = self
                .task_for_request_on_caller(ctx, task_id, TaskAccessAction::Cancel)
                .await?;
            if matches!(
                current.task(),
                FinalTask::Completed { .. } | FinalTask::Failed { .. } | FinalTask::Cancelled(_)
            ) {
                return Err(McpError::invalid_params(
                    "terminal tasks cannot be cancelled",
                ));
            }
            let cancelled_task = FinalTask::Cancelled(transition_terminal_final_task_base(
                current.task().base().clone(),
                FinalTaskStatus::Cancelled,
                None,
            )?);
            let notification = final_task_notification(&cancelled_task);
            self.validate_task_transition_write(&current, &cancelled_task, &notification)?;
            self.authorize_original_operation(
                ctx,
                TaskAccessAction::Cancel,
                current.original_operation(),
            )?;
            authorization::ensure_current_task_authentication(ctx)?;
            receipt.admit_write();
            let cancellation = self
                .store
                .request_cancellation_and_clear_input_if_current_with_context(
                    ctx,
                    &current,
                    cancelled_task.clone(),
                    notification.clone(),
                )
                .await;
            if matches!(&cancellation, Ok(None)) {
                receipt.no_commit();
            }
            let cancellation = cancellation
                .map_err(|error| control_write_error(ctx, "Task cancellation", error))?
                .ok_or_else(|| {
                    McpError::invalid_params(
                        "Task state changed before cancellation could be recorded",
                    )
                })?;
            let cancellation = self.validate_loaded_task_snapshot(cancellation, Some(task_id))?;
            let terminal =
                validate_control_cancellation_receipt(&current, &cancelled_task, &cancellation)?;
            self.signal_task_service_cancellation(task_id.clone());
            let retained = self
                .verify_control_cancellation(ctx, &current, &cancellation, terminal)
                .await
                .map_err(|error| {
                    if authorization::ensure_current_task_authentication(ctx).is_err()
                        || error.code == McpError::request_cancelled().code
                    {
                        control_outcome_unknown("Task cancellation")
                    } else {
                        error
                    }
                })?;
            receipt.committed();
            if retained {
                self.emit_control_commit(
                    ctx,
                    TaskAccessAction::Cancel,
                    notification,
                    &cancellation,
                )
                .await;
            }
            Ok(FinalCancelTaskResult::default())
        })
    }

    /// Performs only the atomic expiry and receipt validation. Publication is
    /// separate so post-commit readback never recursively awaits itself.
    async fn expire_control_snapshot(
        &self,
        ctx: &McpContext,
        expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        if !matches!(
            expected.task(),
            FinalTask::Working(_) | FinalTask::InputRequired { .. }
        ) {
            return Ok(None);
        }
        authorization::ensure_current_task_authentication(ctx)?;
        let Some(committed) = self
            .store
            .expire_task_execution_if_current_with_context(ctx, expected)
            .await
            .map_err(|error| control_write_error(ctx, "Task execution expiry", error))?
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
        Ok(Some(committed))
    }

    /// Loads current payload only after fresh metadata confirms that the
    /// original committed incarnation still belongs to this request.
    async fn read_control_successor(
        &self,
        ctx: &McpContext,
        action: TaskAccessAction,
        expected: &FinalTaskSnapshot,
    ) -> McpResult<FinalTaskSnapshot> {
        let task_id = &expected.task().base().task_id;
        self.authorize_original_operation(ctx, action, expected.original_operation())?;
        let metadata = await_control_read(
            ctx,
            self.store
                .get_task_access_metadata_with_context(ctx, task_id),
            || self.authorize_original_operation(ctx, action, expected.original_operation()),
        )
        .await?
        .ok_or_else(authorization::task_access_denied)?;
        if metadata.task_id() != task_id
            || metadata.generation() < expected.generation()
            || metadata.creation_generation() != expected.creation_generation()
            || metadata.authenticated_principal() != expected.authenticated_principal()
            || metadata.original_operation() != expected.original_operation()
        {
            return Err(McpError::internal_error(
                "Final task store changed the task principal or creation authority",
            ));
        }
        let current = await_control_read(
            ctx,
            self.store.get_task_snapshot_with_context(ctx, task_id),
            || self.authorize_original_operation(ctx, action, metadata.original_operation()),
        )
        .await?
        .ok_or_else(authorization::task_access_denied)?;
        if !metadata.admits_snapshot(&current) {
            return Err(McpError::internal_error(
                "Final task store changed the task principal or creation authority",
            ));
        }
        self.validate_loaded_task_snapshot(current, Some(task_id))
    }

    async fn verify_control_cancellation(
        &self,
        ctx: &McpContext,
        expected: &FinalTaskSnapshot,
        returned: &FinalTaskSnapshot,
        terminal: bool,
    ) -> McpResult<bool> {
        self.authorize_original_operation(
            ctx,
            TaskAccessAction::Cancel,
            returned.original_operation(),
        )?;
        let task_id = &expected.task().base().task_id;
        // Intent precedes snapshot readback: the elected worker can consume
        // intent only by committing a newer terminal cancellation.
        let cancellation_requested = !terminal
            && await_control_read(
                ctx,
                self.store
                    .is_cancellation_requested_with_context(ctx, task_id),
                || {
                    self.authorize_original_operation(
                        ctx,
                        TaskAccessAction::Cancel,
                        returned.original_operation(),
                    )
                },
            )
            .await?;
        let committed = self
            .read_control_successor(ctx, TaskAccessAction::Cancel, returned)
            .await?;
        let committed = match self.expire_control_snapshot(ctx, &committed).await? {
            Some(expired) => {
                self.emit_control_commit(
                    ctx,
                    TaskAccessAction::Cancel,
                    final_task_notification(expired.task()),
                    &expired,
                )
                .await;
                expired
            }
            None => committed,
        };
        if committed.authenticated_principal() != returned.authenticated_principal()
            || committed.creation_generation() != returned.creation_generation()
            || committed.original_operation() != returned.original_operation()
        {
            return Err(McpError::internal_error(
                "Final task store changed the task principal",
            ));
        }
        if committed.generation() == returned.generation()
            && final_tasks_match_exactly(committed.task(), returned.task())?
        {
            if !terminal && !cancellation_requested {
                return Err(McpError::internal_error(
                    "Final task store did not retain the active cancellation intent",
                ));
            }
            return Ok(terminal);
        }
        if terminal
            || committed.generation() <= returned.generation()
            || !matches!(committed.task(), FinalTask::Cancelled(_))
        {
            return Err(McpError::internal_error(
                "Final task store returned cancellation data that is not durably retained",
            ));
        }
        validate_final_task_transition(returned.task(), committed.task()).map_err(|_| {
            McpError::internal_error(
                "Final task store returned an invalid cooperative cancellation transition",
            )
        })?;
        Ok(false)
    }

    /// Best-effort publication cannot change a committed request's receipt.
    /// Its metadata and payload probes use the asynchronous hooks too.
    pub(super) async fn emit_control_commit(
        &self,
        ctx: &McpContext,
        action: TaskAccessAction,
        notification: FinalTaskStatusNotification,
        committed: &FinalTaskSnapshot,
    ) {
        let Ok(current) = self.read_control_successor(ctx, action, committed).await else {
            return;
        };
        let current = match self.expire_control_snapshot(ctx, &current).await {
            Ok(Some(expired)) => {
                self.emit_control_notification(
                    ctx,
                    action,
                    final_task_notification(expired.task()),
                    &expired,
                )
                .await;
                return;
            }
            Ok(None) => current,
            Err(_) => return,
        };
        if current.generation() != committed.generation()
            || current.creation_generation() != committed.creation_generation()
            || current.authenticated_principal() != committed.authenticated_principal()
            || current.original_operation() != committed.original_operation()
            || !final_tasks_match_exactly(current.task(), committed.task()).unwrap_or(false)
        {
            return;
        }
        self.emit_control_notification(ctx, action, notification, committed)
            .await;
    }

    async fn emit_control_notification(
        &self,
        ctx: &McpContext,
        action: TaskAccessAction,
        notification: FinalTaskStatusNotification,
        committed: &FinalTaskSnapshot,
    ) {
        if self
            .authorize_original_operation(ctx, action, committed.original_operation())
            .is_err()
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
            // Keep only a weak observer while its asynchronous fence is
            // pending. Dropping a subscription must release its callback.
            if self
                .authorize_original_operation(ctx, action, committed.original_operation())
                .is_err()
            {
                break;
            }
            let current = await_control_read(
                ctx,
                self.store.get_task_access_metadata_with_context(
                    ctx,
                    &notification.params.task.base().task_id,
                ),
                || self.authorize_original_operation(ctx, action, committed.original_operation()),
            )
            .await;
            if !current.is_ok_and(|current| {
                current.is_some_and(|current| {
                    current.task_id() == &notification.params.task.base().task_id
                        && current.generation() == committed.generation()
                        && current.creation_generation() == committed.creation_generation()
                        && current.authenticated_principal() == principal
                        && current.original_operation() == committed.original_operation()
                })
            }) {
                continue;
            }
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
}

/// A read may be abandoned when its request loses authority. Arm request-local
/// cancellation before polling the provider so a parked read is actually woken.
async fn await_control_read<T>(
    ctx: &McpContext,
    mut future: FinalTaskStoreFuture<'_, T>,
    admit: impl Fn() -> McpResult<()> + Send,
) -> McpResult<T> {
    let mut cancelled = Box::pin(ctx.request_cancelled());
    std::future::poll_fn(move |poll| {
        if let Err(error) = admit() {
            return Poll::Ready(Err(error));
        }
        if cancelled.as_mut().poll(poll).is_ready() {
            return Poll::Ready(Err(McpError::request_cancelled()));
        }
        let result = future.as_mut().poll(poll);
        if let Err(error) = admit() {
            return Poll::Ready(Err(error));
        }
        result
    })
    .await
}

fn control_outcome_unknown(operation: &str) -> McpError {
    McpError::internal_error(format!(
        "{operation} may have committed; its outcome could not be verified. Reconcile Task state before retrying."
    ))
}

pub(super) fn control_write_error(ctx: &McpContext, operation: &str, error: McpError) -> McpError {
    if ctx.ensure_live().is_err() || error.code == McpError::request_cancelled().code {
        control_outcome_unknown(operation)
    } else {
        error
    }
}

fn validate_control_cancellation_receipt(
    expected: &FinalTaskSnapshot,
    cancelled_task: &FinalTask,
    returned: &FinalTaskSnapshot,
) -> McpResult<bool> {
    if returned.authenticated_principal() != expected.authenticated_principal()
        || returned.original_operation() != expected.original_operation()
        || returned.creation_generation() != expected.creation_generation()
    {
        return Err(McpError::internal_error(
            "Final task store changed the task principal",
        ));
    }
    match returned.task() {
        FinalTask::Cancelled(_) => {
            validate_final_task_transition(expected.task(), returned.task()).map_err(|_| {
                McpError::internal_error(
                    "Final task store returned an invalid terminal cancellation transition",
                )
            })?;
            if returned.generation() <= expected.generation()
                || !final_tasks_match_exactly(returned.task(), cancelled_task)?
            {
                return Err(McpError::internal_error(
                    "Final task store substituted the intended terminal cancellation",
                ));
            }
            Ok(true)
        }
        FinalTask::Working(_) => {
            if returned.generation() != expected.generation()
                || !final_tasks_match_exactly(returned.task(), expected.task())?
            {
                return Err(McpError::internal_error(
                    "Final task store returned a substituted active cancellation snapshot",
                ));
            }
            Ok(false)
        }
        _ => Err(McpError::internal_error(
            "Final task store returned a non-working active cancellation snapshot",
        )),
    }
}

#[cfg(test)]
mod tests;
