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
    authorization: Option<FinalTaskStoreFuture<'static, ()>>,
    observed: Option<Poll<McpResult<bool>>>,
    operation_woken: Arc<AtomicBool>,
    checkpoint: Option<Pin<Box<asupersync::time::Sleep>>>,
}

/// A storage wake must survive an intervening authorization read. Wakes from
/// that read must not themselves cause a busy loop polling a parked renewal.
struct FinalTaskOperationWake {
    notified: Arc<AtomicBool>,
    parent: std::task::Waker,
}

impl std::task::Wake for FinalTaskOperationWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.notified.store(true, TaskServiceOrdering::Release);
        self.parent.wake_by_ref();
    }
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
            self.authorization = None;
            self.observed = None;
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
        if let Some(result) = Self::terminal(cx, guard) {
            return Poll::Ready(result);
        }
        let Some(fence) = guard.dispatch_fence else {
            return Poll::Ready(Ok(false));
        };
        loop {
            // Keep both the pre-poll and post-poll probes across suspension.
            // Neither authority reads nor renewal I/O may fall back to a
            // synchronous metadata lookup on this asynchronous service path.
            if self.authorization.is_none() {
                self.authorization = Some(Self::authorization(&caller, guard, fence));
            }
            let authorization = self.authorization.as_mut().expect("authorization is owned");
            let result = match authorization.as_mut().poll(task) {
                Poll::Pending => return self.wait(cx, guard, task),
                Poll::Ready(result) => result,
            };
            self.authorization = None;
            // Metadata callbacks may cancel the caller or advance the backend
            // clock. A late proof never extends this attempt's original bound.
            if let Some(result) = Self::terminal(cx, guard) {
                return Poll::Ready(result);
            }
            if let Err(error) = result {
                guard
                    .execution_revoked
                    .store(true, TaskServiceOrdering::Release);
                return Poll::Ready(Err(error));
            }
            if let Some(observed) = self.observed.take() {
                // Preserve Ready while its post-poll proof awaits storage;
                // polling an already completed provider again is invalid.
                if let Poll::Ready(result) = observed {
                    return Poll::Ready(result);
                }
                if self.operation_woken.load(TaskServiceOrdering::Acquire) {
                    task.waker().wake_by_ref();
                }
                return self.wait(cx, guard, task);
            }
            let operation = self.operation.get_or_insert_with(|| {
                let store = Arc::clone(&guard.runtime.store);
                let task_id = guard.task_id.clone();
                let generation = guard.generation;
                let owner = guard.owner_id.clone();
                let caller = caller.clone();
                Box::pin(async move {
                    CallerContextFuture::new(&caller, async {
                        final_task_service_caller(&caller)?;
                        store
                            .renew_handoff_dispatch_if_current_with_cx(
                                &caller, &task_id, generation, &owner, fence,
                            )
                            .await
                    })
                    .await
                })
            });
            self.operation_woken
                .store(false, TaskServiceOrdering::Release);
            let waker = std::task::Waker::from(Arc::new(FinalTaskOperationWake {
                notified: Arc::clone(&self.operation_woken),
                parent: task.waker().clone(),
            }));
            self.observed = Some(
                operation
                    .as_mut()
                    .poll(&mut std::task::Context::from_waker(&waker)),
            );
            if let Some(result) = Self::terminal(cx, guard) {
                return Poll::Ready(result);
            }
        }
    }

    /// Reproduce the synchronous guard's continuity and exact-generation
    /// fallback checks using only the store's awaitable metadata entrypoints.
    fn authorization(
        caller: &Cx,
        guard: &FinalTaskExecutionGuard,
        fence: u64,
    ) -> FinalTaskStoreFuture<'static, ()> {
        let caller = caller.clone();
        let runtime = guard.runtime.clone();
        let expected = guard.execution_authorization.clone();
        let owner = guard.owner_id.clone();
        Box::pin(async move {
            CallerContextFuture::new(&caller, async {
                let expected = expected.ok_or_else(|| {
                    McpError::internal_error(
                        "Final task handoff has no execution authorization binding",
                    )
                })?;
                final_task_service_caller(&caller)?;
                let ctx = McpContext::new(caller.clone(), 0);
                let continuity = runtime
                    .store
                    .get_handoff_access_metadata_with_context(
                        &ctx,
                        expected.task_id(),
                        expected.generation(),
                        &owner,
                        fence,
                    )
                    .await
                    .map_err(|_| authorization::task_execution_denied())?;
                final_task_service_caller(&caller)?;
                let current = if let Some(current) = continuity {
                    if current.generation() < expected.generation() {
                        return Err(authorization::task_execution_denied());
                    }
                    current
                } else {
                    // Preserve anonymous, policy-free stores whose historical
                    // contract has no metadata endpoint. The exact owner/fence
                    // remains enforced by the renewal transaction itself.
                    if expected.authenticated_principal().is_none()
                        && expected.original_operation().is_none()
                        && runtime
                            .execution_authorizers
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .is_empty()
                    {
                        return runtime.authorize_task_execution(&expected);
                    }
                    let current = runtime
                        .store
                        .get_task_access_metadata_with_cx(&caller, expected.task_id())
                        .await
                        .map_err(|_| authorization::task_execution_denied())?
                        .ok_or_else(authorization::task_execution_denied)?;
                    final_task_service_caller(&caller)?;
                    if current.generation() != expected.generation() {
                        return Err(authorization::task_execution_denied());
                    }
                    current
                };
                if current.task_id() != expected.task_id()
                    || current.creation_generation() != expected.creation_generation()
                    || current.authenticated_principal() != expected.authenticated_principal()
                    || current.original_operation() != expected.original_operation()
                {
                    return Err(authorization::task_execution_denied());
                }
                runtime.authorize_task_execution(&current)
            })
            .await
        })
    }

    fn terminal(cx: &Cx, guard: &FinalTaskExecutionGuard) -> Option<McpResult<bool>> {
        if let Err(error) = final_task_service_caller(cx) {
            return Some(Err(error));
        }
        if Self::expired(guard) {
            return Some(Ok(false));
        }
        if guard.execution_revoked.load(TaskServiceOrdering::Acquire) {
            return Some(Err(authorization::task_execution_denied()));
        }
        let Some(expected) = guard.execution_authorization.as_ref() else {
            return Some(Err(McpError::internal_error(
                "Final task handoff has no execution authorization binding",
            )));
        };
        if expected
            .original_operation()
            .is_some_and(|operation| !operation.is_registered())
        {
            guard
                .execution_revoked
                .store(true, TaskServiceOrdering::Release);
            return Some(Err(authorization::task_execution_denied()));
        }
        // Only this attempt's private commit receipt permits bounded cleanup.
        // No storage I/O is needed after the dispatch lease is consumed.
        if guard
            .transition_committed
            .load(TaskServiceOrdering::Acquire)
        {
            if let Err(error) = guard.runtime.authorize_task_execution(expected) {
                guard
                    .execution_revoked
                    .store(true, TaskServiceOrdering::Release);
                return Some(Err(error));
            }
            // Policy is application code: it may cancel the caller or advance
            // a backend clock while returning success.
            if let Err(error) = final_task_service_caller(cx) {
                return Some(Err(error));
            }
            if Self::expired(guard) {
                return Some(Ok(false));
            }
            return Some(Ok(true));
        }
        None
    }

    fn wait(
        &mut self,
        cx: &Cx,
        guard: &FinalTaskExecutionGuard,
        task: &mut std::task::Context<'_>,
    ) -> Poll<McpResult<bool>> {
        if let Some(result) = Self::terminal(cx, guard) {
            return Poll::Ready(result);
        }
        // While metadata is pending, no renewal or application poll is
        // admitted. Current policy must use the fresh proof when it arrives:
        // an older record generation cannot decide a newer status update's
        // generation-sensitive policy.
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

/// One retained, read-only supervision proof. Storage may suspend between
/// metadata, snapshot and cancellation reads; no application or maintenance
/// poll may borrow a partially checked result.
#[derive(Default)]
pub(super) struct FinalTaskSupervisionProbe {
    operation: Option<FinalTaskStoreFuture<'static, bool>>,
    checkpoint: Option<Pin<Box<asupersync::time::Sleep>>>,
    cancellation_notified: Arc<AtomicBool>,
}

pub(super) enum FinalTaskSupervisionState {
    Active { cancellation_requested: bool },
    Inactive,
}

impl FinalTaskSupervisionProbe {
    pub(super) fn poll(
        &mut self,
        cx: &Cx,
        guard: &FinalTaskExecutionGuard,
        cancellation_wake: &FinalTaskCancellationWakeRegistration,
        task: &mut std::task::Context<'_>,
    ) -> Poll<McpResult<FinalTaskSupervisionState>> {
        let result = self.poll_probe(cx, guard, cancellation_wake, task);
        if result.is_ready() {
            self.operation = None;
            self.checkpoint = None;
            if matches!(
                &result,
                Poll::Ready(Ok(FinalTaskSupervisionState::Active {
                    cancellation_requested: false,
                }))
            ) && self.cancellation_notified.load(TaskServiceOrdering::Acquire)
            {
                // Intent may have been sampled before the post-read proof
                // suspended. A cancellation wake invalidates that false
                // sample; it never supplies cancellation authority itself.
                // Keep any enclosing Ready result while a fresh proof runs.
                task.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        result
    }

    fn poll_probe(
        &mut self,
        cx: &Cx,
        guard: &FinalTaskExecutionGuard,
        cancellation_wake: &FinalTaskCancellationWakeRegistration,
        task: &mut std::task::Context<'_>,
    ) -> Poll<McpResult<FinalTaskSupervisionState>> {
        match Self::terminal(cx, guard) {
            Ok(Some(state)) => return Poll::Ready(Ok(state)),
            Ok(None) => {}
            Err(error) => return Poll::Ready(Err(error)),
        }
        if self.operation.is_none() {
            // Reset only when beginning a new complete proof. The following
            // reads observe any cancellation that preceded this registration.
            self.cancellation_notified
                .store(false, TaskServiceOrdering::Release);
        }
        let cancellation_waker = std::task::Waker::from(Arc::new(FinalTaskOperationWake {
            notified: Arc::clone(&self.cancellation_notified),
            parent: task.waker().clone(),
        }));
        cancellation_wake.register_waker(&cancellation_waker);
        // Storage and timer futures retain the ordinary task waker below, so
        // their progress cannot be mistaken for durable cancellation.
        if self.operation.is_none() {
            let caller = match final_task_service_caller(cx) {
                Ok(caller) => caller,
                Err(error) => return Poll::Ready(Err(error)),
            };
            let authority = match guard.authority() {
                Ok(authority) => authority,
                Err(error) => return Poll::Ready(Err(error)),
            };
            self.operation = Some(Box::pin(async move {
                authority.cancellation_requested_with_cx(&caller).await
            }));
        }
        let observed = self
            .operation
            .as_mut()
            .expect("supervision proof is retained")
            .as_mut()
            .poll(task);
        // Storage and policy callbacks may cancel the caller, consume the
        // original budget, or revoke registration while producing a receipt.
        match Self::terminal(cx, guard) {
            Ok(Some(state)) => return Poll::Ready(Ok(state)),
            Ok(None) => {}
            Err(error) => return Poll::Ready(Err(error)),
        }
        if let Poll::Ready(result) = observed {
            return Poll::Ready(result.map(|cancellation_requested| {
                FinalTaskSupervisionState::Active {
                    cancellation_requested,
                }
            }));
        }
        // Worker reads already subscribe to caller cancellation and its mapped
        // deadline. Also sample the backend clock when an otherwise silent
        // provider spans an authoritative clock advance.
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

    /// These checks are local. Current-generation policy is evaluated only
    /// after the awaitable worker proof obtains fresh continuity metadata.
    fn terminal(
        cx: &Cx,
        guard: &FinalTaskExecutionGuard,
    ) -> McpResult<Option<FinalTaskSupervisionState>> {
        final_task_service_caller(cx)?;
        if guard.pending_write.application_closed() {
            return Err(McpError::request_cancelled());
        }
        if guard
            .transition_committed
            .load(TaskServiceOrdering::Acquire)
            || FinalTaskLeaseRenewal::expired(guard)
        {
            // Return custody to the outer executor. It owns terminalization
            // and region settlement; this read-only wait never retires work.
            return Ok(Some(FinalTaskSupervisionState::Inactive));
        }
        let expected = guard.execution_authorization.as_ref().ok_or_else(|| {
            McpError::internal_error(
                "Final task handoff has no execution authorization binding",
            )
        })?;
        if guard.execution_revoked.load(TaskServiceOrdering::Acquire)
            || expected
                .original_operation()
                .is_some_and(|operation| !operation.is_registered())
        {
            guard
                .execution_revoked
                .store(true, TaskServiceOrdering::Release);
            return Err(authorization::task_execution_denied());
        }
        Ok(None)
    }
}

/// A renewal whose pre- and post-poll cancellation proofs may await storage.
/// A Ready renewal remains retained until its post-proof settles; a parked
/// renewal is preceded by another fresh proof before it is polled again.
#[derive(Default)]
pub(super) struct FinalTaskSupervisedRenewal {
    renewal: FinalTaskLeaseRenewal,
    supervision: FinalTaskSupervisionProbe,
    completed: Option<bool>,
}

impl FinalTaskSupervisedRenewal {
    pub(super) fn poll(
        &mut self,
        cx: &Cx,
        guard: &FinalTaskExecutionGuard,
        cancellation_wake: &FinalTaskCancellationWakeRegistration,
        task: &mut std::task::Context<'_>,
    ) -> Poll<McpResult<Option<bool>>> {
        loop {
            match std::task::ready!(self.supervision.poll(cx, guard, cancellation_wake, task)) {
                Ok(FinalTaskSupervisionState::Active {
                    cancellation_requested: false,
                }) => {}
                Ok(_) => return Poll::Ready(Ok(None)),
                Err(error) => return Poll::Ready(Err(error)),
            }
            if let Some(renewed) = self.completed.take() {
                return Poll::Ready(Ok(Some(renewed)));
            }
            match self.renewal.poll(cx, guard, task) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(renewed)) => self.completed = Some(renewed),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
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

/// Service notifications retain their service admission and periodic checks.
/// Application-owned operations only need their original read authority.
#[derive(Clone, Copy)]
enum NotificationCaller<'a> {
    Service(&'a Cx),
    Application(&'a McpContext),
}

impl<'a> NotificationCaller<'a> {
    fn cx(self) -> &'a Cx {
        match self {
            Self::Service(cx) => cx,
            Self::Application(ctx) => ctx.cx(),
        }
    }

    fn check(self) -> McpResult<()> {
        match self {
            Self::Service(cx) => final_task_service_caller(cx).map(|_| ()),
            Self::Application(ctx) => ctx.ensure_live().map_err(|_| McpError::request_cancelled()),
        }
    }

    async fn read<T>(self, operation: FinalTaskStoreFuture<'_, T>) -> McpResult<T> {
        match self {
            Self::Service(cx) => await_recovery_store(cx, operation, false).await,
            Self::Application(ctx) => {
                control::await_control_read(ctx, operation, || self.check()).await
            }
        }
    }
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
            let snapshot = self.load_application_task_snapshot(&ctx, task_id).await?;
            Ok(fastmcp_protocol::CompleteTaskResult {
                task: snapshot.into_task(),
                meta: None,
                additional: BTreeMap::new(),
            })
        })
    }

    pub(super) async fn load_application_task_snapshot(
        &self,
        ctx: &McpContext,
        task_id: &FinalTaskId,
    ) -> McpResult<FinalTaskSnapshot> {
        ctx.checkpoint()?;
        let live = || ctx.ensure_live().map_err(|_| McpError::request_cancelled());
        let stored = control::await_control_read(
            ctx,
            self.store.get_task_snapshot_with_cx(ctx.cx(), task_id),
            live,
        )
        .await?
        .ok_or_else(|| McpError::invalid_params("Task not found"))?;
        let snapshot = self.validate_loaded_task_snapshot(stored, Some(task_id))?;
        self.expire_application_task_snapshot(ctx, snapshot).await
    }

    pub(super) async fn expire_application_task_snapshot(
        &self,
        ctx: &McpContext,
        mut snapshot: FinalTaskSnapshot,
    ) -> McpResult<FinalTaskSnapshot> {
        let live = || ctx.ensure_live().map_err(|_| McpError::request_cancelled());
        if matches!(snapshot.task(), FinalTask::Working(_) | FinalTask::InputRequired { .. }) {
            live()?;
            let expired = control::await_control_read(
                ctx,
                self.store.expire_task_execution_if_current_with_cx(ctx.cx(), &snapshot),
                live,
            )
            .await?;
            if let Some(committed) = expired {
                snapshot = self.validate_execution_expiry_receipt(&snapshot, committed)?;
                self.emit_embedding_commit(ctx, &snapshot).await;
            }
        }
        live()?;
        Ok(snapshot)
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
        self.emit_task_notification(NotificationCaller::Service(cx), committed)
            .await;
    }

    pub(super) async fn emit_embedding_commit(
        &self,
        ctx: &McpContext,
        committed: &FinalTaskSnapshot,
    ) {
        self.emit_task_notification(NotificationCaller::Application(ctx), committed)
            .await;
    }

    async fn emit_task_notification(
        &self,
        caller: NotificationCaller<'_>,
        committed: &FinalTaskSnapshot,
    ) {
        if caller.check().is_err() {
            return;
        }
        let task_id = &committed.task().base().task_id;
        let Ok(Some(current)) = caller
            .read(self.store.get_task_snapshot_with_cx(caller.cx(), task_id))
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
            if caller.check().is_err() {
                break;
            }
            let current = caller
                .read(self.store.get_task_access_metadata_with_cx(caller.cx(), task_id))
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
            let mut renewal = FinalTaskSupervisedRenewal::default();
            let mut supervision = FinalTaskSupervisionProbe::default();
            let mut checked_before = false;
            let mut checked_after = false;
            let mut maintenance_polled = false;
            let maintenance_woken = Arc::new(AtomicBool::new(false));
            std::future::poll_fn(|task| {
                // These local checks also run while a retained proof or
                // renewal is parked. A silent provider cannot hide expiry,
                // caller cancellation, or an already committed worker write.
                match std::task::ready!(Self::poll_maintenance_local_checkpoint(
                    cx,
                    guard,
                    task,
                )) {
                    Ok(true) => {}
                    Ok(false) => return Poll::Ready(Ok(())),
                    Err(error) => return Poll::Ready(Err(error)),
                }
                if !checked_before {
                    match std::task::ready!(Self::poll_maintenance_checkpoint(
                        cx,
                        guard,
                        cancellation_wake,
                        &mut supervision,
                        task,
                    )) {
                        Ok(true) => checked_before = true,
                        Ok(false) => return Poll::Ready(Ok(())),
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                }
                if heartbeat.is_none() {
                    let interval = match std::task::ready!(Self::poll_renew_maintenance_lease(
                        cx,
                        guard,
                        cancellation_wake,
                        &mut renewal,
                        task,
                    )) {
                        Ok(Some(interval)) => interval,
                        Ok(None) => return Poll::Ready(Ok(())),
                        Err(error) => return Poll::Ready(Err(error)),
                    };
                    heartbeat = Some(Box::pin(asupersync::time::sleep(cx.now(), interval)));
                }
                if !maintenance_polled {
                    // The phase survives an asynchronous post-poll proof.
                    // Neither a Ready provider nor its original result may
                    // be reconstructed or polled again during that wait.
                    if let Err(error) = final_task_service_caller(cx) {
                        return Poll::Ready(Err(error));
                    }
                    let operation = maintenance.get_or_insert_with(|| {
                        Box::pin(self.runtime.expire_pending_execution_with_cx(cx))
                    });
                    maintenance_woken.store(false, TaskServiceOrdering::Release);
                    let waker = std::task::Waker::from(Arc::new(FinalTaskOperationWake {
                        notified: Arc::clone(&maintenance_woken),
                        parent: task.waker().clone(),
                    }));
                    if let Poll::Ready(result) = operation
                        .as_mut()
                        .poll(&mut std::task::Context::from_waker(&waker))
                    {
                        completed = Some(result);
                    }
                    maintenance_polled = true;
                }
                if !checked_after {
                    match std::task::ready!(Self::poll_maintenance_checkpoint(
                        cx,
                        guard,
                        cancellation_wake,
                        &mut supervision,
                        task,
                    )) {
                        Ok(true) => checked_after = true,
                        Ok(false) => return Poll::Ready(Ok(())),
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                }
                if let Some(result) = completed.take() {
                    return Poll::Ready(result);
                }
                if let Err(error) = final_task_service_caller(cx) {
                    return Poll::Ready(Err(error));
                }
                let heartbeat = heartbeat.as_mut().expect("maintenance heartbeat is armed");
                if heartbeat.as_mut().poll(task).is_ready() {
                    let interval = match std::task::ready!(Self::poll_renew_maintenance_lease(
                        cx,
                        guard,
                        cancellation_wake,
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
                checked_before = false;
                checked_after = false;
                maintenance_polled = false;
                // A provider wake may have been consumed while the post-proof
                // was pending. Preserve it until the next actual provider poll.
                if maintenance_woken.load(TaskServiceOrdering::Acquire) {
                    task.waker().wake_by_ref();
                }
                Poll::Pending
            })
            .await
        })
    }

    fn poll_maintenance_local_checkpoint(
        cx: &Cx,
        guard: &mut FinalTaskExecutionGuard,
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
        Poll::Ready(
            FinalTaskSupervisionProbe::terminal(cx, guard)
                .map(|terminal| terminal.is_none()),
        )
    }

    /// Returns false when the ordinary supervisor monitor should regain
    /// control. In particular, durable task cancellation does not revoke its
    /// cooperative cleanup opportunity. The proof is retained across all
    /// asynchronous metadata, snapshot and cancellation-intent reads.
    fn poll_maintenance_checkpoint(
        cx: &Cx,
        guard: &mut FinalTaskExecutionGuard,
        cancellation_wake: &FinalTaskCancellationWakeRegistration,
        supervision: &mut FinalTaskSupervisionProbe,
        task: &mut std::task::Context<'_>,
    ) -> Poll<McpResult<bool>> {
        match std::task::ready!(Self::poll_maintenance_local_checkpoint(
            cx,
            guard,
            task,
        )) {
            Ok(true) => {}
            result => return Poll::Ready(result),
        }
        Poll::Ready(match std::task::ready!(supervision.poll(cx, guard, cancellation_wake, task)) {
            Ok(FinalTaskSupervisionState::Active {
                cancellation_requested,
            }) => Ok(!cancellation_requested),
            Ok(FinalTaskSupervisionState::Inactive) => Ok(false),
            Err(error) => Err(error),
        })
    }

    /// Renews only the guard's exact owner/fence and returns its next bounded
    /// heartbeat. A false renewal never authorizes reconstructing a lease.
    fn poll_renew_maintenance_lease(
        cx: &Cx,
        guard: &mut FinalTaskExecutionGuard,
        cancellation_wake: &FinalTaskCancellationWakeRegistration,
        renewal: &mut FinalTaskSupervisedRenewal,
        task: &mut std::task::Context<'_>,
    ) -> Poll<McpResult<Option<StdDuration>>> {
        let renewed = match std::task::ready!(renewal.poll(cx, guard, cancellation_wake, task)) {
            Ok(Some(renewed)) => renewed,
            Ok(None) => return Poll::Ready(Ok(None)),
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
        if guard
            .transition_committed
            .load(TaskServiceOrdering::Acquire)
            || FinalTaskLeaseRenewal::expired(guard)
        {
            return Ok(None);
        }
        if !renewed {
            return Err(McpError::internal_error(
                "Final task dispatch lease was lost while application work was running",
            ));
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
