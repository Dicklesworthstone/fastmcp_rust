//! Asynchronous mutations by an already elected application Task worker.
//!
//! The service still owns its existing bounded synchronous recovery, lease,
//! authorization and restoration operations. These APIs let the application's
//! status/result/input transitions await storage without doing synchronous
//! payload reads or notification probes inside that operation. They neither
//! introduce a persistent backend nor make the whole service asynchronous.

#[allow(clippy::wildcard_imports)]
use super::*;
use std::task::{Context, Poll, Waker};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod custody_tests;

/// Sealed authority for one asynchronous mutation by an elected Task worker.
///
/// The framework binds the current record to the original claim, owner and
/// dispatch fence before constructing this admission. A backend must compare
/// those facts, cancellation disposition, deadlines and quotas atomically with
/// its write. Call [`Self::checkpoint_before_write`] immediately before the
/// first irreversible write, including after any suspension. Once admitted,
/// settle the original operation and its exact receipt; cancellation alone
/// cannot establish that nothing committed. Framework custody retains one
/// admitted provider future independently of the application future and polls
/// only that provider after application execution stops. Providers must settle
/// their original operation without leaving detached writes running.
///
/// This value cannot be constructed or cloned by application code. Its context
/// carries the worker's caller-owned `Cx`, not a retained ingress credential.
pub struct FinalTaskWorkerAdmission<'a> {
    authority: &'a WorkerAuthority,
    ctx: &'a McpContext,
    expected: &'a FinalTaskSnapshot,
    metadata: &'a FinalTaskAccessMetadata,
    cancellation_required: bool,
    write_admitted: &'a AtomicBool,
    abort: &'a AtomicBool,
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
        if self.abort.load(TaskServiceOrdering::Acquire) {
            return Err(McpError::request_cancelled());
        }
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

/// Owned authorization facts only. The provider slot is deliberately excluded
/// so retaining an in-flight provider cannot form an Arc cycle through itself.
struct WorkerAuthority {
    runtime: FinalTaskRuntime,
    task_id: FinalTaskId,
    generation: u64,
    owner_id: String,
    dispatch_fence: u64,
    transition_committed: Arc<AtomicBool>,
    execution_budget: FinalTaskExecutionBudget,
    execution_authorization: FinalTaskAccessMetadata,
    execution_revoked: Arc<AtomicBool>,
    application_closed: Arc<AtomicBool>,
}

impl WorkerAuthority {
    fn capture(authority: &FinalTaskHandoffAuthority) -> Self {
        Self {
            runtime: authority.runtime.clone(),
            task_id: authority.task_id.clone(),
            generation: authority.generation,
            owner_id: authority.owner_id.clone(),
            dispatch_fence: authority.dispatch_fence,
            transition_committed: Arc::clone(&authority.transition_committed),
            execution_budget: authority.execution_budget,
            execution_authorization: authority.execution_authorization.clone(),
            execution_revoked: Arc::clone(&authority.execution_revoked),
            application_closed: Arc::clone(&authority.pending_write.application_closed),
        }
    }

    /// A current policy decision is separate from the backend's atomic fence.
    /// Policy callbacks are bounded and synchronous by their public contract.
    fn authorize_worker(
        &self,
        ctx: &McpContext,
        metadata: &FinalTaskAccessMetadata,
    ) -> McpResult<()> {
        if self.application_closed.load(TaskServiceOrdering::Acquire) {
            return Err(McpError::request_cancelled());
        }
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
}

impl FinalTaskHandoffAuthority {
    fn mutate_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        mutation: WorkerMutation,
    ) -> impl Future<Output = McpResult<FinalTask>> + Send + 'a {
        CallerContextFuture::new(cx, async move {
            // Capture the effective caller after the public wrapper intersects
            // its authority with the polling host, including resumed limits.
            let caller = Cx::current().ok_or_else(|| {
                McpError::internal_error("Task worker has no installed caller")
            })?;
            let ctx = Arc::new(McpContext::new(caller, 0));
            let authority = Arc::new(WorkerAuthority::capture(self));
            if self.transition_committed.load(TaskServiceOrdering::Acquire) {
                return Err(stale_final_task_handoff_error());
            }
            let status_only = matches!(&mutation, WorkerMutation::Status(_));
            let cancellation_required = matches!(&mutation, WorkerMutation::Cancel(_));
            let (metadata, current) = authority.load_worker_snapshot(&ctx).await?;
            let task = prepare_worker_transition(&current, mutation)?;
            let notification = final_task_notification(&task);
            self.runtime
                .validate_task_transition_write(&current, &task, &notification)?;
            authority.authorize_worker(&ctx, &metadata)?;
            // Reserve before invoking a provider factory. This owned future
            // survives the observing application future being dropped.
            let write = self.pending_write.reserve()?;
            let observer = WorkerWriteObserver(Arc::clone(&write));
            let write_admitted = Arc::clone(&write.admitted);
            let abort = Arc::clone(&write.abort);
            let uncertain = Arc::clone(&self.pending_write.uncertain);
            let provider_ctx = Arc::clone(&ctx);
            let provider_authority = Arc::clone(&authority);
            let provider_notification = notification.clone();
            let future = CallerContextFuture::new(ctx.cx(), async move {
                let authorize = || {
                    if abort.load(TaskServiceOrdering::Acquire) {
                        return Err(McpError::request_cancelled());
                    }
                    provider_authority.authorize_worker(&provider_ctx, &metadata)
                };
                authorize()?;
                let admission = FinalTaskWorkerAdmission {
                    authority: &provider_authority,
                    ctx: &provider_ctx,
                    expected: &current,
                    metadata: &metadata,
                    cancellation_required,
                    write_admitted: &write_admitted,
                    abort: &abort,
                };
                let operation = if status_only {
                    provider_authority.runtime.store.update_working_status_for_handoff_with_context(
                        admission, task.clone(), provider_notification,
                    )
                } else {
                    provider_authority.runtime.store.replace_task_and_clear_input_for_handoff_with_context(
                        admission, task.clone(), provider_notification,
                    )
                };
                let outcome = await_worker_write(
                    &provider_ctx,
                    provider_authority.wait_deadline(&provider_ctx),
                    operation,
                    &write_admitted,
                    &authorize,
                ).await;
                let returned = match outcome {
                    Ok(Some(committed)) => {
                        if !write_admitted.load(TaskServiceOrdering::Acquire) {
                            uncertain.store(true, TaskServiceOrdering::Release);
                            return Err(McpError::internal_error(
                                "Task store returned an unadmitted worker mutation",
                            ));
                        }
                        committed
                    }
                    Ok(None) => {
                        // A failed comparison is not a committed receipt and
                        // must still satisfy current caller authority.
                        authorize()?;
                        return Err(stale_final_task_handoff_error());
                    }
                    Err(error) => {
                        if write_admitted.load(TaskServiceOrdering::Acquire) {
                            uncertain.store(true, TaskServiceOrdering::Release);
                            return Err(worker_outcome_unknown());
                        }
                        return Err(error);
                    }
                };
                let committed = match provider_authority.runtime
                    .validate_committed_transition(&current, &task, returned)
                {
                    Ok(committed) => committed,
                    Err(error) => {
                        uncertain.store(true, TaskServiceOrdering::Release);
                        return Err(error);
                    }
                };
                if !status_only {
                    provider_authority.transition_committed.store(true, TaskServiceOrdering::Release);
                }
                Ok(committed)
            });
            *write.future.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::pin(future));
            let committed = std::future::poll_fn(|poll| {
                if write.poll(poll).is_pending() { return Poll::Pending; }
                self.pending_write.clear(&write);
                Poll::Ready(write.result.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take().ok_or_else(|| McpError::internal_error("Task worker receipt was already consumed"))?)
            }).await?;
            drop(observer);
            // A validated committed receipt is authoritative. Publication is
            // best effort and cannot replace it with a late cancellation.
            authority.emit_worker_commit(&ctx, notification, &committed)
                .await;
            Ok(committed.task().clone())
        })
    }

    fn cancellation_requested_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
    ) -> impl Future<Output = McpResult<bool>> + Send + 'a {
        CallerContextFuture::new(cx, async move {
            let caller = Cx::current().ok_or_else(|| {
                McpError::internal_error("Task worker has no installed caller")
            })?;
            let ctx = McpContext::new(caller, 0);
            let authority = WorkerAuthority::capture(self);
            let (metadata, _) = authority.load_worker_snapshot(&ctx).await?;
            let requested = await_worker_read(
                &ctx,
                authority.wait_deadline(&ctx),
                self.runtime
                    .store
                    .is_cancellation_requested_with_context(&ctx, &self.task_id),
                || authority.authorize_worker(&ctx, &metadata),
            )
            .await?;
            // A successor or reclaimed incarnation cannot lend its cancellation
            // state to the old handoff while the provider was suspended.
            authority.load_worker_snapshot(&ctx).await?;
            Ok(requested)
        })
    }
}

impl WorkerAuthority {
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

/// One bounded provider slot per elected handoff. Neither application drop nor
/// an observing future's cancellation releases an admitted provider operation.
#[derive(Default)]
pub(super) struct FinalTaskWorkerWrites {
    current: Mutex<Option<Arc<WorkerWrite>>>,
    uncertain: Arc<AtomicBool>,
    application_closed: Arc<AtomicBool>,
}

impl FinalTaskWorkerWrites {
    fn reserve(&self) -> McpResult<Arc<WorkerWrite>> {
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.application_closed() {
            return Err(McpError::request_cancelled());
        }
        if current
            .as_ref()
            .is_some_and(|write| !write.settled.load(TaskServiceOrdering::Acquire))
        {
            return Err(McpError::invalid_request(
                "An asynchronous Task handoff mutation is already pending",
            ));
        }
        if self.uncertain.load(TaskServiceOrdering::Acquire) {
            return Err(worker_outcome_unknown());
        }
        let write = Arc::new(WorkerWrite {
            uncertain: Arc::clone(&self.uncertain),
            ..WorkerWrite::default()
        });
        *current = Some(Arc::clone(&write));
        Ok(write)
    }

    fn clear(&self, write: &Arc<WorkerWrite>) {
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, write))
        {
            *current = None;
        }
    }

    pub(super) fn outcome_uncertain(&self) -> bool {
        self.uncertain.load(TaskServiceOrdering::Acquire)
    }

    pub(super) fn application_closed(&self) -> bool {
        self.application_closed.load(TaskServiceOrdering::Acquire)
    }

    pub(super) fn admitted_pending(&self) -> bool {
        self.current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(|write| {
                write.admitted.load(TaskServiceOrdering::Acquire)
                    && !write.settled.load(TaskServiceOrdering::Acquire)
            })
    }

    /// Polls only the provider. Application code is never resumed by this path.
    /// During shutdown, an unadmitted operation is aborted before its factory
    /// or another provider poll; an admitted operation retains its custody.
    pub(super) fn poll_settlement(
        &self,
        poll: &mut Context<'_>,
        abort_unadmitted: bool,
    ) -> Poll<()> {
        if abort_unadmitted {
            // A parent may be cancelled before child-region cancellation has
            // propagated. Close application entry before polling any receipt
            // which could wake that still-live application task.
            self.application_closed
                .store(true, TaskServiceOrdering::Release);
        }
        let current = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(write) = current else {
            return Poll::Ready(());
        };
        if abort_unadmitted {
            write.abort.store(true, TaskServiceOrdering::Release);
        }
        if !abort_unadmitted
            && !write.admitted.load(TaskServiceOrdering::Acquire)
            && !write.abort.load(TaskServiceOrdering::Acquire)
        {
            return Poll::Ready(());
        }
        let result = write.poll(poll);
        if result.is_ready() {
            self.clear(&write);
        }
        result
    }
}

#[derive(Default)]
struct WorkerWrite {
    future: Mutex<Option<FinalTaskStoreFuture<'static, FinalTaskSnapshot>>>,
    result: Mutex<Option<McpResult<FinalTaskSnapshot>>>,
    admitted: Arc<AtomicBool>,
    abort: Arc<AtomicBool>,
    settled: AtomicBool,
    polling: AtomicBool,
    repoll: AtomicBool,
    uncertain: Arc<AtomicBool>,
    waiters: Mutex<Vec<Waker>>,
}

fn catch_worker_provider<R>(callback: impl FnOnce() -> R) -> Result<R, ()> {
    match crate::catch_extension_unwind(callback) {
        Ok(result) => Ok(result),
        Err(payload) => {
            // A provider can panic with an application-defined payload whose
            // destructor also panics. Dispose of that payload inside the same
            // redacted boundary; never let a second destructor strand custody.
            if let Err(second) = crate::catch_extension_unwind(|| drop(payload)) {
                std::mem::forget(second);
            }
            Err(())
        }
    }
}

impl WorkerWrite {
    fn wake_observers(&self) {
        let waiters = std::mem::take(
            &mut *self
                .waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for waiter in waiters {
            waiter.wake();
        }
    }

    fn poll(&self, poll: &mut Context<'_>) -> Poll<()> {
        if self.settled.load(TaskServiceOrdering::Acquire) {
            return Poll::Ready(());
        }
        let evicted = {
            let mut waiters = self
                .waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !waiters.iter().any(|waiter| waiter.will_wake(poll.waker())) {
                // The application/heartbeat task and its region custodian are
                // the only two polling owners. Keep the collection bounded.
                let evicted = if waiters.len() == 2 {
                    Some(waiters.remove(0))
                } else {
                    None
                };
                waiters.push(poll.waker().clone());
                evicted
            } else {
                None
            }
        };
        if let Some(evicted) = evicted {
            evicted.wake();
        }
        if self
            .polling
            .compare_exchange(
                false,
                true,
                TaskServiceOrdering::AcqRel,
                TaskServiceOrdering::Acquire,
            )
            .is_err()
        {
            self.repoll.store(true, TaskServiceOrdering::Release);
            // Close the race where the other polling owner released its
            // future immediately before this repoll request was published.
            if !self.polling.load(TaskServiceOrdering::Acquire) {
                self.wake_observers();
            }
            return Poll::Pending;
        }
        // No slot or provider mutex is retained while backend code is polled.
        let future = self
            .future
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(mut future) = future else {
            self.polling.store(false, TaskServiceOrdering::Release);
            return if self.settled.load(TaskServiceOrdering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            };
        };
        let panicked = || {
            if self.admitted.load(TaskServiceOrdering::Acquire) {
                self.uncertain.store(true, TaskServiceOrdering::Release);
                Err(worker_outcome_unknown())
            } else {
                Err(McpError::internal_error(
                    "Task handoff storage provider panicked",
                ))
            }
        };
        let result = match catch_worker_provider(|| future.as_mut().poll(poll)) {
            Ok(Poll::Pending) => {
                *self
                    .future
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(future);
                self.polling.store(false, TaskServiceOrdering::Release);
                if self.repoll.swap(false, TaskServiceOrdering::AcqRel) {
                    self.wake_observers();
                }
                return Poll::Pending;
            }
            Ok(Poll::Ready(result)) => {
                if catch_worker_provider(|| drop(future)).is_err() {
                    panicked()
                } else {
                    result
                }
            }
            Err(()) => {
                // A panicking poll can leave its owned provider future live.
                // Contain that future's destructor before publishing settlement.
                let _ = catch_worker_provider(|| drop(future));
                panicked()
            }
        };
        *self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
        self.settled.store(true, TaskServiceOrdering::Release);
        self.polling.store(false, TaskServiceOrdering::Release);
        self.wake_observers();
        Poll::Ready(())
    }
}

struct WorkerWriteObserver(Arc<WorkerWrite>);

impl Drop for WorkerWriteObserver {
    fn drop(&mut self) {
        if !self.0.settled.load(TaskServiceOrdering::Acquire) {
            self.0.abort.store(true, TaskServiceOrdering::Release);
            self.0.wake_observers();
        }
    }
}

pub(super) fn worker_outcome_unknown() -> McpError {
    McpError::internal_error(
        "Task handoff mutation may have committed; reconcile its exact fenced operation before retrying",
    )
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
