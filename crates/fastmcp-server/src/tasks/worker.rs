//! Asynchronous mutations by an already elected application Task worker.
//!
//! The service still owns its existing bounded synchronous recovery, lease,
//! authorization and restoration operations. These APIs let the application's
//! status/result/input transitions await storage without doing synchronous
//! payload reads or notification probes inside that operation. They neither
//! introduce a persistent backend nor make the whole service asynchronous.

#[allow(clippy::wildcard_imports)]
use super::*;
use std::task::Poll;

#[cfg(test)]
mod tests;

/// Sealed authority for one asynchronous mutation by an elected Task worker.
///
/// The framework binds the current record to the original claim, owner and
/// dispatch fence before constructing this admission. A backend must compare
/// those facts, cancellation disposition, deadlines and quotas atomically with
/// its write. Call [`Self::checkpoint_before_write`] immediately before the
/// first irreversible write, including after any suspension. Once admitted,
/// settle the original operation and its exact receipt; cancellation alone
/// cannot establish that nothing committed.
///
/// This value cannot be constructed or cloned by application code. Its context
/// carries the worker's caller-owned `Cx`, not a retained ingress credential.
pub struct FinalTaskWorkerAdmission<'a> {
    authority: &'a FinalTaskHandoffAuthority,
    ctx: &'a McpContext,
    expected: &'a FinalTaskSnapshot,
    metadata: &'a FinalTaskAccessMetadata,
    cancellation_required: bool,
    write_admitted: &'a AtomicBool,
}

impl<'a> FinalTaskWorkerAdmission<'a> {
    /// The caller-owned context used for this operation's storage I/O.
    #[must_use]
    pub fn context(&self) -> &'a McpContext {
        self.ctx
    }

    /// The exact current record that the backend must compare before writing.
    #[must_use]
    pub fn expected(&self) -> &'a FinalTaskSnapshot {
        self.expected
    }

    /// Immutable generation that originally elected this worker's claim.
    #[must_use]
    pub const fn claim_generation(&self) -> u64 {
        self.authority.generation
    }

    /// Exact owner of the elected invocation.
    #[must_use]
    pub fn owner_id(&self) -> &'a str {
        &self.authority.owner_id
    }

    /// Monotonic dispatch fence that the atomic mutation must still own.
    #[must_use]
    pub const fn dispatch_fence(&self) -> u64 {
        self.authority.dispatch_fence
    }

    /// Whether this mutation must consume an already committed cancellation.
    #[must_use]
    pub const fn cancellation_required(&self) -> bool {
        self.cancellation_required
    }

    /// Rechecks caller liveness and current execution policy before writing.
    ///
    /// No storage I/O is performed here. The backend must independently compare
    /// the record, owner, fence, cancellation and budgets in its transaction.
    pub fn checkpoint_before_write(&self) -> McpResult<()> {
        if self
            .authority
            .transition_committed
            .load(TaskServiceOrdering::Acquire)
        {
            return Err(stale_final_task_handoff_error());
        }
        self.authority.authorize_worker(self.ctx, self.metadata)?;
        self.write_admitted
            .store(true, TaskServiceOrdering::Release);
        Ok(())
    }
}

enum WorkerMutation {
    Status(Option<String>),
    Input(FinalTaskInputRequests, Option<String>),
    Complete(FinalTaskCallToolResult, Option<String>),
    Fail(FinalTaskError, Option<String>),
    Cancel(Option<String>),
}

macro_rules! asynchronous_worker_methods {
    () => {
        /// Publishes working status metadata through the asynchronous store.
        ///
        /// The original claim, work, inputs, lease and execution deadline are
        /// retained. The current record generation advances. A lost fence or
        /// cancellation winner refuses the write. Service recovery and lease
        /// maintenance remain bounded synchronous operations.
        pub async fn update_status_message_with_cx(
            &mut self,
            cx: &Cx,
            status_message: Option<String>,
        ) -> McpResult<FinalTask> {
            self.authority()?
                .mutate_with_cx(cx, WorkerMutation::Status(status_message))
                .await
        }

        /// Requests input through the asynchronous store under this exact claim.
        ///
        /// The complete input batch and lifetime key history retain the same
        /// validation as the synchronous method. A committed receipt remains
        /// successful if caller cancellation arrives while storage settles it.
        pub async fn require_input_with_cx(
            &self,
            cx: &Cx,
            input_requests: FinalTaskInputRequests,
            status_message: Option<String>,
        ) -> McpResult<FinalTask> {
            self.authority()?
                .mutate_with_cx(cx, WorkerMutation::Input(input_requests, status_message))
                .await
        }

        /// Completes this Task through the caller-owned asynchronous store.
        ///
        /// Current execution policy is rechecked before writing. The backend
        /// compares the exact generation, owner and dispatch fence atomically;
        /// a validated committed receipt survives late cancellation or policy
        /// revocation. Notification delivery cannot revoke that receipt.
        pub async fn complete_task_with_cx(
            &self,
            cx: &Cx,
            result: FinalTaskCallToolResult,
            status_message: Option<String>,
        ) -> McpResult<FinalTask> {
            self.authority()?
                .mutate_with_cx(cx, WorkerMutation::Complete(result, status_message))
                .await
        }

        /// Fails this Task through the asynchronous store under its exact fence.
        pub async fn fail_task_with_cx(
            &self,
            cx: &Cx,
            error: FinalTaskError,
            status_message: Option<String>,
        ) -> McpResult<FinalTask> {
            self.authority()?
                .mutate_with_cx(cx, WorkerMutation::Fail(error, status_message))
                .await
        }

        /// Reads cancellation intent through asynchronous metadata and storage.
        /// The same admitted Task incarnation is revalidated before returning.
        pub async fn is_cancellation_requested_with_cx(&self, cx: &Cx) -> McpResult<bool> {
            self.authority()?.cancellation_requested_with_cx(cx).await
        }

        /// Records cooperative cancellation through the asynchronous store.
        ///
        /// Task cancellation intent must already have won. This does not grant
        /// permission to write from a cancelled or expired caller context.
        pub async fn honor_cancellation_with_cx(
            &self,
            cx: &Cx,
            status_message: Option<String>,
        ) -> McpResult<FinalTask> {
            self.authority()?
                .mutate_with_cx(cx, WorkerMutation::Cancel(status_message))
                .await
        }
    };
}

impl FinalTaskInitialWork {
    asynchronous_worker_methods!();
}

impl FinalTaskAcceptedInput {
    asynchronous_worker_methods!();
}

impl FinalTaskHandoffAuthority {
    /// A current policy decision is separate from the backend's atomic fence.
    /// Policy callbacks are bounded and synchronous by their public contract.
    fn authorize_worker(
        &self,
        ctx: &McpContext,
        metadata: &FinalTaskAccessMetadata,
    ) -> McpResult<()> {
        ctx.ensure_live()
            .map_err(|_| McpError::request_cancelled())?;
        let now = self.runtime.retention_clock_now();
        if now >= self.execution_budget.total_deadline
            || self
                .execution_budget
                .attempt_deadline
                .is_some_and(|deadline| now >= deadline)
        {
            return Err(McpError::request_cancelled());
        }
        if metadata.task_id() != &self.task_id
            || metadata.generation() < self.generation
            || metadata.creation_generation() != self.execution_authorization.creation_generation()
            || metadata.authenticated_principal()
                != self.execution_authorization.authenticated_principal()
            || metadata.original_operation() != self.execution_authorization.original_operation()
        {
            return Err(stale_final_task_handoff_error());
        }
        if self.execution_revoked.load(TaskServiceOrdering::Acquire) {
            return Err(authorization::task_execution_denied());
        }
        if self.runtime.authorize_task_execution(metadata).is_err() {
            self.execution_revoked
                .store(true, TaskServiceOrdering::Release);
            return Err(authorization::task_execution_denied());
        }
        ctx.ensure_live().map_err(|_| McpError::request_cancelled())
    }

    fn wait_deadline(&self, ctx: &McpContext) -> asupersync::Time {
        let caller_now = ctx.cx().now();
        let backend_now = self.runtime.retention_clock_now();
        let deadline = self
            .execution_budget
            .attempt_deadline
            .unwrap_or(self.execution_budget.total_deadline)
            .min(self.execution_budget.total_deadline);
        let mapped = caller_now + deadline.saturating_duration_since(backend_now);
        ctx.cx()
            .budget()
            .deadline
            .map_or(mapped, |caller| caller.min(mapped))
    }

    async fn load_worker_metadata(&self, ctx: &McpContext) -> McpResult<FinalTaskAccessMetadata> {
        self.authorize_worker(ctx, &self.execution_authorization)?;
        let continuity = await_worker_read(
            ctx,
            self.wait_deadline(ctx),
            self.runtime.store.get_handoff_access_metadata_with_context(
                ctx,
                &self.task_id,
                self.generation,
                &self.owner_id,
                self.dispatch_fence,
            ),
            || self.authorize_worker(ctx, &self.execution_authorization),
        )
        .await?;
        if let Some(metadata) = continuity {
            self.authorize_worker(ctx, &metadata)?;
            return Ok(metadata);
        }

        // The old exact-generation contract remains sufficient only when the
        // backend does not claim continuity across working metadata updates.
        let metadata = await_worker_read(
            ctx,
            self.wait_deadline(ctx),
            self.runtime
                .store
                .get_task_access_metadata_with_context(ctx, &self.task_id),
            || self.authorize_worker(ctx, &self.execution_authorization),
        )
        .await?;
        let metadata = match metadata {
            Some(metadata) => metadata,
            None if self
                .execution_authorization
                .authenticated_principal()
                .is_none()
                && self.execution_authorization.original_operation().is_none()
                && self
                    .runtime
                    .execution_authorizers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_empty() =>
            {
                self.execution_authorization.clone()
            }
            None => return Err(authorization::task_execution_denied()),
        };
        if metadata.generation() != self.generation {
            return Err(stale_final_task_handoff_error());
        }
        self.authorize_worker(ctx, &metadata)?;
        Ok(metadata)
    }

    async fn load_worker_snapshot(
        &self,
        ctx: &McpContext,
    ) -> McpResult<(FinalTaskAccessMetadata, FinalTaskSnapshot)> {
        let metadata = self.load_worker_metadata(ctx).await?;
        let snapshot = await_worker_read(
            ctx,
            self.wait_deadline(ctx),
            self.runtime
                .store
                .get_task_snapshot_with_context(ctx, &self.task_id),
            || self.authorize_worker(ctx, &metadata),
        )
        .await?
        .ok_or_else(stale_final_task_handoff_error)?;
        let snapshot = self
            .runtime
            .validate_loaded_task_snapshot(snapshot, Some(&self.task_id))?;
        if snapshot.generation() != metadata.generation() || !metadata.admits_snapshot(&snapshot) {
            return Err(stale_final_task_handoff_error());
        }
        Ok((metadata, snapshot))
    }

    fn mutate_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        mutation: WorkerMutation,
    ) -> impl Future<Output = McpResult<FinalTask>> + Send + 'a {
        CallerContextFuture::new(cx, async move {
            let ctx = McpContext::new(cx.clone(), 0);
            if self.transition_committed.load(TaskServiceOrdering::Acquire) {
                return Err(stale_final_task_handoff_error());
            }
            let status_only = matches!(&mutation, WorkerMutation::Status(_));
            let cancellation_required = matches!(&mutation, WorkerMutation::Cancel(_));
            let (metadata, current) = self.load_worker_snapshot(&ctx).await?;
            let task = prepare_worker_transition(&current, mutation)?;
            let notification = final_task_notification(&task);
            self.runtime
                .validate_task_transition_write(&current, &task, &notification)?;
            self.authorize_worker(&ctx, &metadata)?;
            let write_admitted = AtomicBool::new(false);
            let admission = FinalTaskWorkerAdmission {
                authority: self,
                ctx: &ctx,
                expected: &current,
                metadata: &metadata,
                cancellation_required,
                write_admitted: &write_admitted,
            };
            let operation = if status_only {
                self.runtime
                    .store
                    .update_working_status_for_handoff_with_context(
                        admission,
                        task.clone(),
                        notification.clone(),
                    )
            } else {
                self.runtime
                    .store
                    .replace_task_and_clear_input_for_handoff_with_context(
                        admission,
                        task.clone(),
                        notification.clone(),
                    )
            };
            let outcome = await_worker_write(
                &ctx,
                self.wait_deadline(&ctx),
                operation,
                &write_admitted,
                || self.authorize_worker(&ctx, &metadata),
            )
            .await;
            let returned = match outcome {
                Ok(Some(committed)) => {
                    if !write_admitted.load(TaskServiceOrdering::Acquire) {
                        return Err(McpError::internal_error(
                            "Task store returned an unadmitted worker mutation",
                        ));
                    }
                    committed
                }
                Ok(None) => {
                    self.authorize_worker(&ctx, &metadata)?;
                    return Err(stale_final_task_handoff_error());
                }
                Err(error) => {
                    if write_admitted.load(TaskServiceOrdering::Acquire)
                        && (ctx.ensure_live().is_err()
                            || self.execution_revoked.load(TaskServiceOrdering::Acquire)
                            || error.code == McpError::request_cancelled().code)
                    {
                        return Err(McpError::internal_error(
                            "Task worker mutation may have committed; reconcile its original Task before retrying",
                        ));
                    }
                    return Err(error);
                }
            };
            let committed = self
                .runtime
                .validate_committed_transition(&current, &task, returned)?;
            if !status_only {
                self.transition_committed
                    .store(true, TaskServiceOrdering::Release);
            }
            // A validated committed receipt is authoritative. Publication is
            // best effort and cannot replace it with a late cancellation.
            self.emit_worker_commit(&ctx, notification, &committed)
                .await;
            Ok(task)
        })
    }

    fn cancellation_requested_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
    ) -> impl Future<Output = McpResult<bool>> + Send + 'a {
        CallerContextFuture::new(cx, async move {
            let ctx = McpContext::new(cx.clone(), 0);
            let (metadata, _) = self.load_worker_snapshot(&ctx).await?;
            let requested = await_worker_read(
                &ctx,
                self.wait_deadline(&ctx),
                self.runtime
                    .store
                    .is_cancellation_requested_with_context(&ctx, &self.task_id),
                || self.authorize_worker(&ctx, &metadata),
            )
            .await?;
            // A successor or reclaimed incarnation cannot lend its cancellation
            // state to the old handoff while the provider was suspended.
            self.load_worker_snapshot(&ctx).await?;
            Ok(requested)
        })
    }

    async fn emit_worker_commit(
        &self,
        ctx: &McpContext,
        notification: FinalTaskStatusNotification,
        committed: &FinalTaskSnapshot,
    ) {
        let metadata = FinalTaskAccessMetadata::new(
            self.task_id.clone(),
            committed.generation(),
            committed.creation_generation(),
            committed.authenticated_principal(),
            committed.original_operation().cloned(),
        );
        if self.authorize_worker(ctx, &metadata).is_err() {
            return;
        }
        // The commit receipt grants access only to its own incarnation. Check
        // fresh payload-free metadata before opening a record that may already
        // have been replaced or reclaimed while the write was settling.
        let current = await_worker_read(
            ctx,
            self.wait_deadline(ctx),
            self.runtime
                .store
                .get_task_access_metadata_with_context(ctx, &self.task_id),
            || self.authorize_worker(ctx, &metadata),
        )
        .await;
        if !current.is_ok_and(|current| {
            current.is_some_and(|current| {
                current.task_id() == &self.task_id
                    && current.generation() == committed.generation()
                    && current.creation_generation() == committed.creation_generation()
                    && current.authenticated_principal() == committed.authenticated_principal()
                    && current.original_operation() == committed.original_operation()
            })
        }) {
            return;
        }
        let current = await_worker_read(
            ctx,
            self.wait_deadline(ctx),
            self.runtime
                .store
                .get_task_snapshot_with_context(ctx, &self.task_id),
            || self.authorize_worker(ctx, &metadata),
        )
        .await;
        if !current.is_ok_and(|current| {
            current.is_some_and(|current| {
                current.generation() == committed.generation()
                    && metadata.admits_snapshot(&current)
                    && final_tasks_match_exactly(current.task(), committed.task()).unwrap_or(false)
            })
        }) {
            return;
        }
        let emitters = {
            let mut registered = self
                .runtime
                .notification_emitters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registered.retain(|emitter| emitter.strong_count() != 0);
            registered.clone()
        };
        let principal = committed.authenticated_principal();
        let mut panicked = 0usize;
        if catch_unwind(AssertUnwindSafe(|| {
            (self.runtime.application_notification_emitter)(notification.clone(), principal);
        }))
        .is_err()
        {
            panicked += 1;
        }
        for weak in emitters {
            if self.authorize_worker(ctx, &metadata).is_err() {
                break;
            }
            let current = await_worker_read(
                ctx,
                self.wait_deadline(ctx),
                self.runtime
                    .store
                    .get_task_access_metadata_with_context(ctx, &self.task_id),
                || self.authorize_worker(ctx, &metadata),
            )
            .await;
            if !current.is_ok_and(|current| {
                current.is_some_and(|current| {
                    current.task_id() == &self.task_id
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
                panicked += 1;
            }
        }
        if panicked != 0 {
            log::error!(
                target: "fastmcp_rust::server",
                "Task worker notification delivery degraded after committed mutation; panicked_emitter_count={}",
                panicked
            );
        }
    }
}

fn prepare_worker_transition(
    current: &FinalTaskSnapshot,
    mutation: WorkerMutation,
) -> McpResult<FinalTask> {
    let base = current.task().base().clone();
    match mutation {
        WorkerMutation::Status(status) => {
            if !matches!(current.task(), FinalTask::Working(_)) {
                return Err(McpError::invalid_params(
                    "only a working task can publish a status message",
                ));
            }
            final_task_payload_bytes(
                &status,
                MAX_FINAL_TASK_METADATA_BYTES - FINAL_TASK_CANCELLATION_METADATA_RESERVE_BYTES,
                "status message",
            )?;
            Ok(FinalTask::Working(transition_final_task_base(
                base,
                FinalTaskStatus::Working,
                status,
            )?))
        }
        WorkerMutation::Input(input_requests, status) => {
            if input_requests.is_empty() {
                return Err(McpError::invalid_params(
                    "input_required tasks require at least one input request",
                ));
            }
            FinalTaskInputLedger::from_requests(&input_requests)
                .map_err(|error| McpError::invalid_params(error.to_string()))?;
            if !matches!(current.task(), FinalTask::Working(_)) {
                return Err(McpError::invalid_params(
                    "only a working task can require client input",
                ));
            }
            Ok(FinalTask::InputRequired {
                base: transition_final_task_base(base, FinalTaskStatus::InputRequired, status)?,
                input_requests,
            })
        }
        WorkerMutation::Complete(result, status) => {
            if !matches!(current.task(), FinalTask::Working(_)) {
                return Err(McpError::invalid_params("only a working task can complete"));
            }
            Ok(FinalTask::Completed {
                base: transition_terminal_final_task_base(
                    base,
                    FinalTaskStatus::Completed,
                    status,
                )?,
                result,
            })
        }
        WorkerMutation::Fail(error, status) => {
            if final_task_is_terminal(current.task()) {
                return Err(McpError::invalid_params("terminal tasks cannot fail"));
            }
            Ok(FinalTask::Failed {
                base: transition_terminal_final_task_base(base, FinalTaskStatus::Failed, status)?,
                error,
            })
        }
        WorkerMutation::Cancel(status) => {
            if final_task_is_terminal(current.task()) {
                return Err(McpError::invalid_params(
                    "terminal tasks cannot be cancelled",
                ));
            }
            Ok(FinalTask::Cancelled(transition_terminal_final_task_base(
                base,
                FinalTaskStatus::Cancelled,
                status,
            )?))
        }
    }
}

fn poll_worker_deadline(
    ctx: &McpContext,
    deadline: asupersync::Time,
    timer: &mut Option<Pin<Box<asupersync::time::Sleep>>>,
    poll: &mut std::task::Context<'_>,
) -> McpResult<bool> {
    let caller = Cx::current().ok_or_else(|| {
        McpError::internal_error("Task worker storage wait has no installed caller")
    })?;
    if !caller.capabilities().time || caller.timer_driver().is_none() {
        return Err(McpError::internal_error(
            "Task worker storage wait requires the caller's timer driver",
        ));
    }
    let now = ctx.cx().now();
    if now >= deadline {
        return Ok(true);
    }
    let timer = timer.get_or_insert_with(|| {
        Box::pin(asupersync::time::sleep(
            now,
            StdDuration::from_nanos(deadline.duration_since(now)),
        ))
    });
    Ok(timer.as_mut().poll(poll).is_ready())
}

async fn await_worker_read<T>(
    ctx: &McpContext,
    deadline: asupersync::Time,
    mut future: FinalTaskStoreFuture<'_, T>,
    admit: impl Fn() -> McpResult<()> + Send,
) -> McpResult<T> {
    let mut cancelled = Box::pin(ctx.cx().cancelled());
    let mut timer = None;
    std::future::poll_fn(move |poll| {
        if let Err(error) = admit() {
            return Poll::Ready(Err(error));
        }
        if cancelled.as_mut().poll(poll).is_ready() {
            return Poll::Ready(Err(McpError::request_cancelled()));
        }
        let outcome = future.as_mut().poll(poll);
        if let Err(error) = admit() {
            return Poll::Ready(Err(error));
        }
        if outcome.is_pending() {
            match poll_worker_deadline(ctx, deadline, &mut timer, poll) {
                Ok(false) => {}
                Ok(true) => return Poll::Ready(Err(McpError::request_cancelled())),
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        outcome
    })
    .await
}

async fn await_worker_write<T>(
    ctx: &McpContext,
    deadline: asupersync::Time,
    mut future: FinalTaskStoreFuture<'_, T>,
    write_admitted: &AtomicBool,
    admit: impl Fn() -> McpResult<()> + Send,
) -> McpResult<T> {
    let mut cancelled = Box::pin(ctx.cx().cancelled());
    let mut timer = None;
    std::future::poll_fn(move |poll| {
        if !write_admitted.load(TaskServiceOrdering::Acquire) {
            if let Err(error) = admit() {
                return Poll::Ready(Err(error));
            }
            if cancelled.as_mut().poll(poll).is_ready() {
                return Poll::Ready(Err(McpError::request_cancelled()));
            }
        }
        let outcome = future.as_mut().poll(poll);
        // A provider may cross the admission boundary and first return Pending
        // in the same poll. Preserve custody before checking cancellation again.
        if !write_admitted.load(TaskServiceOrdering::Acquire) {
            if let Err(error) = admit() {
                return Poll::Ready(Err(error));
            }
            if outcome.is_pending() {
                match poll_worker_deadline(ctx, deadline, &mut timer, poll) {
                    Ok(false) => {}
                    Ok(true) => return Poll::Ready(Err(McpError::request_cancelled())),
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
        }
        outcome
    })
    .await
}
