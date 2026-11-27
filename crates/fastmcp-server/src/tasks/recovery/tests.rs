//! Pending storage must not block service progress or bypass claim custody.

use super::super::*;
use asupersync::runtime::RuntimeBuilder;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Poll, Waker};

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
enum Step {
    InitialScan,
    InputScan,
    ExpiredScan,
    Read,
    Expire,
    InitialClaim,
    InputClaim,
    Metadata,
    ExecutionBudget,
    Retention,
    Election,
    Finish,
    RestoreInitial,
    RestoreInput,
    CancellationIntent,
}

struct Gate {
    open: AtomicBool,
    waiter: Mutex<Option<Waker>>,
    abandoned: AtomicUsize,
}

impl Gate {
    fn new() -> Self {
        Self {
            open: AtomicBool::new(true),
            waiter: Mutex::new(None),
            abandoned: AtomicUsize::new(0),
        }
    }

    fn close(&self) {
        let _waiter = self.waiter.lock().unwrap();
        self.open.store(false, Ordering::SeqCst);
    }

    fn release(&self) {
        let waiter = {
            let mut waiter = self.waiter.lock().unwrap();
            self.open.store(true, Ordering::SeqCst);
            waiter.take()
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }

    async fn wait(&self) {
        struct Waiting<'a> {
            gate: &'a Gate,
            suspended: bool,
            completed: bool,
        }
        impl Drop for Waiting<'_> {
            fn drop(&mut self) {
                if self.suspended && !self.completed {
                    self.gate.abandoned.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        let mut waiting = Waiting {
            gate: self,
            suspended: false,
            completed: false,
        };
        std::future::poll_fn(|task| {
            let mut waiter = self.waiter.lock().unwrap();
            if self.open.load(Ordering::SeqCst) {
                waiting.completed = true;
                Poll::Ready(())
            } else {
                waiting.suspended = true;
                *waiter = Some(task.waker().clone());
                Poll::Pending
            }
        })
        .await;
    }
}

/// All mutations retain the real store's generation, owner, quota, lease and
/// payload semantics. Recovery, dispatch-election and renewal I/O may be delayed.
struct AsyncRecoveryStore {
    inner: InMemoryFinalTaskStore,
    clock: Arc<Mutex<Instant>>,
    gates: [Gate; 15],
    calls: [AtomicUsize; 15],
    settlement_receipt: Gate,
    sync_settlements: AtomicUsize,
    initial_pause_from: AtomicUsize,
    receipt: Gate,
    claimed: AtomicUsize,
    restored: AtomicUsize,
    renewals: AtomicUsize,
    forbid_sync: AtomicBool,
    sync_calls: AtomicUsize,
    substitute_read: Mutex<Option<FinalTaskSnapshot>>,
    cancel_after_claim: AtomicBool,
    cancel_after_expiry: AtomicBool,
    budget_factories: AtomicUsize,
    election_receipt: Gate,
    elected: AtomicUsize,
    election_pause_for: Mutex<Option<FinalTaskId>>,
    stop_after_election: Mutex<Option<Arc<AtomicBool>>>,
    cancel_after_election: AtomicBool,
    zero_election_receipt: AtomicBool,
    expiry_caller: Mutex<Option<Cx>>,
    parked_worker_expiry: AtomicUsize,
    refuse_renewal_for: Mutex<Option<FinalTaskId>>,
    renewal_gate: Gate,
    renewal_pause_for: Mutex<Option<FinalTaskId>>,
    async_renewal_calls: AtomicUsize,
    sync_renewal_calls: AtomicUsize,
    authorization_gates: [Gate; 2],
    authorization_calls: AtomicUsize,
    substitute_authorization: Mutex<Option<FinalTaskAccessMetadata>>,
    omit_continuity: AtomicBool,
    fail_authorization: AtomicBool,
    pause_authorization_after_expiry_scan: AtomicBool,
    pause_snapshot_after_renewal: AtomicBool,
    pause_snapshot_after_intent: AtomicBool,
}

impl AsyncRecoveryStore {
    fn new() -> Self {
        Self::with_limits(FinalTaskExecutionLimits::default())
    }

    fn with_limits(limits: FinalTaskExecutionLimits) -> Self {
        let clock = Arc::new(Mutex::new(Instant::now()));
        let clock_source = Arc::clone(&clock);
        Self {
            inner: InMemoryFinalTaskStore::with_clock_payload_and_execution_limits(
                16,
                InMemoryFinalTaskStore::DEFAULT_MAX_PAYLOAD_BYTES,
                limits,
                Arc::new(move || *clock_source.lock().unwrap()),
            )
            .unwrap(),
            clock,
            gates: std::array::from_fn(|_| Gate::new()),
            calls: std::array::from_fn(|_| AtomicUsize::new(0)),
            settlement_receipt: Gate::new(),
            sync_settlements: AtomicUsize::new(0),
            initial_pause_from: AtomicUsize::new(1),
            receipt: Gate::new(),
            claimed: AtomicUsize::new(0),
            restored: AtomicUsize::new(0),
            renewals: AtomicUsize::new(0),
            forbid_sync: AtomicBool::new(false),
            sync_calls: AtomicUsize::new(0),
            substitute_read: Mutex::new(None),
            cancel_after_claim: AtomicBool::new(false),
            cancel_after_expiry: AtomicBool::new(false),
            budget_factories: AtomicUsize::new(0),
            election_receipt: Gate::new(),
            elected: AtomicUsize::new(0),
            election_pause_for: Mutex::new(None),
            stop_after_election: Mutex::new(None),
            cancel_after_election: AtomicBool::new(false),
            zero_election_receipt: AtomicBool::new(false),
            expiry_caller: Mutex::new(None),
            parked_worker_expiry: AtomicUsize::new(0),
            refuse_renewal_for: Mutex::new(None),
            renewal_gate: Gate::new(),
            renewal_pause_for: Mutex::new(None),
            async_renewal_calls: AtomicUsize::new(0),
            sync_renewal_calls: AtomicUsize::new(0),
            authorization_gates: std::array::from_fn(|_| Gate::new()),
            authorization_calls: AtomicUsize::new(0),
            substitute_authorization: Mutex::new(None),
            omit_continuity: AtomicBool::new(false),
            fail_authorization: AtomicBool::new(false),
            pause_authorization_after_expiry_scan: AtomicBool::new(false),
            pause_snapshot_after_renewal: AtomicBool::new(false),
            pause_snapshot_after_intent: AtomicBool::new(false),
        }
    }

    fn gate(&self, step: Step) -> &Gate {
        &self.gates[step as usize]
    }

    fn count(&self, step: Step) -> usize {
        self.calls[step as usize].load(Ordering::SeqCst)
    }

    fn caller(&self, cx: &Cx) {
        let current = Cx::current().expect("storage runs under its explicit caller");
        assert_eq!(current.region_id(), cx.region_id());
        assert_eq!(current.task_id(), cx.task_id());
        assert!(cx.blocking_pool_handle().is_none());
    }

    async fn enter(&self, cx: &Cx, step: Step) -> McpResult<()> {
        self.caller(cx);
        let call = self.calls[step as usize].fetch_add(1, Ordering::SeqCst) + 1;
        let pause_initial = !matches!(step, Step::InitialScan)
            || call >= self.initial_pause_from.load(Ordering::SeqCst);
        let pause_expiry = !matches!(step, Step::ExpiredScan)
            || self
                .expiry_caller
                .lock()
                .unwrap()
                .as_ref()
                .is_none_or(|target| target.task_id() == cx.task_id());
        if pause_initial && pause_expiry {
            if matches!(step, Step::ExpiredScan)
                && self.is_expiry_caller(cx)
                && !self.gate(step).open.load(Ordering::SeqCst)
            {
                self.parked_worker_expiry.fetch_add(1, Ordering::SeqCst);
            }
            self.gate(step).wait().await;
        }
        self.caller(cx);
        cx.checkpoint().map_err(|_| McpError::request_cancelled())
    }

    async fn settle(
        &self,
        cx: &Cx,
        step: Step,
        mutation: impl FnOnce() -> McpResult<bool>,
    ) -> McpResult<bool> {
        self.enter(cx, step).await?;
        let receipt = mutation()?;
        if receipt && matches!(step, Step::RestoreInitial | Step::RestoreInput) {
            self.restored.fetch_add(1, Ordering::SeqCst);
        }
        self.settlement_receipt.wait().await;
        self.caller(cx);
        Ok(receipt)
    }

    fn is_expiry_caller(&self, cx: &Cx) -> bool {
        self.expiry_caller
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|target| target.task_id() == cx.task_id())
    }

    fn pause_worker_expiry(&self, cx: &Cx) {
        *self.expiry_caller.lock().unwrap() = Some(cx.clone());
        self.gate(Step::ExpiredScan).close();
    }

    fn synchronous(&self) {
        if self.forbid_sync.load(Ordering::SeqCst) {
            self.sync_calls.fetch_add(1, Ordering::SeqCst);
            // Avoid a second panic if a failure unwinds restoration custody.
            self.forbid_sync.store(false, Ordering::SeqCst);
            panic!("asynchronous recovery used a synchronous storage fallback");
        }
    }

    fn next_candidate(&self, resumed: bool) -> Option<FinalTaskSnapshot> {
        if resumed {
            self.inner.next_accepted_input_snapshot_after(None)
        } else {
            self.inner.next_initial_work_snapshot_after(None)
        }
        .unwrap()
    }

    fn renew_exact_lease(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: u64,
    ) -> McpResult<bool> {
        if self.refuse_renewal_for.lock().unwrap().as_ref() == Some(task_id) {
            return Ok(false);
        }
        let renewed = self.inner.renew_handoff_dispatch_if_current(
            task_id,
            generation,
            owner_id,
            dispatch_fence,
        )?;
        if renewed {
            self.renewals.fetch_add(1, Ordering::SeqCst);
        }
        Ok(renewed)
    }
}

macro_rules! forward_store {
    ($(fn $method:ident(&self $(, $argument:ident: $argument_type:ty)*) -> $result:ty;)+) => {
        $(fn $method(&self $(, $argument: $argument_type)*) -> $result {
            self.inner.$method($($argument),*)
        })+
    };
}

impl FinalTaskStore for AsyncRecoveryStore {
    forward_store! {
        fn execution_limits(&self) -> McpResult<FinalTaskExecutionLimits>;
        fn create_task(&self, task: FinalTask, notification: FinalTaskStatusNotification) -> McpResult<()>;
        fn get_task(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTask>>;
        fn replace_task(&self, task: FinalTask, notification: FinalTaskStatusNotification) -> McpResult<()>;
        fn replace_task_if_current(&self, expected: &FinalTaskSnapshot, task: FinalTask, notification: FinalTaskStatusNotification) -> McpResult<bool>;
        fn replace_task_and_clear_input_for_handoff_if_current(&self, expected: &FinalTaskSnapshot, owner_id: &str, dispatch_fence: u64, cancellation_required: bool, task: FinalTask, notification: FinalTaskStatusNotification) -> McpResult<Option<FinalTaskSnapshot>>;
        fn request_cancellation(&self, task_id: &FinalTaskId) -> McpResult<()>;
        fn request_cancellation_if_current(&self, expected: &FinalTaskSnapshot) -> McpResult<bool>;
        fn request_cancellation_and_clear_input_if_current(&self, expected: &FinalTaskSnapshot, task: FinalTask, notification: FinalTaskStatusNotification) -> McpResult<Option<FinalTaskSnapshot>>;
        fn retention_clock_now(&self) -> Instant;
    }

    fn task_execution_budget_if_current(
        &self,
        expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskExecutionBudget>> {
        self.synchronous();
        self.inner.task_execution_budget_if_current(expected)
    }

    fn task_retention_deadline_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
    ) -> McpResult<Option<FinalTaskRetentionDeadline>> {
        self.synchronous();
        self.inner
            .task_retention_deadline_if_current(task_id, generation)
    }

    fn begin_handoff_dispatch_for_owner_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
    ) -> McpResult<Option<u64>> {
        self.synchronous();
        self.inner
            .begin_handoff_dispatch_for_owner_if_current(task_id, generation, owner_id)
    }

    fn task_execution_budget_if_current_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        expected: &'a FinalTaskSnapshot,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskExecutionBudget>> {
        self.caller(cx);
        self.budget_factories.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            self.enter(cx, Step::ExecutionBudget).await?;
            self.inner.task_execution_budget_if_current(expected)
        })
    }

    fn task_retention_deadline_if_current_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        task_id: &'a FinalTaskId,
        generation: u64,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskRetentionDeadline>> {
        self.caller(cx);
        Box::pin(async move {
            self.enter(cx, Step::Retention).await?;
            self.inner
                .task_retention_deadline_if_current(task_id, generation)
        })
    }

    fn begin_handoff_dispatch_for_owner_if_current_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        task_id: &'a FinalTaskId,
        generation: u64,
        owner_id: &'a str,
    ) -> FinalTaskStoreFuture<'a, Option<u64>> {
        self.caller(cx);
        Box::pin(async move {
            self.calls[Step::Election as usize].fetch_add(1, Ordering::SeqCst);
            let pause = self
                .election_pause_for
                .lock()
                .unwrap()
                .as_ref()
                .is_none_or(|target| target == task_id);
            if pause {
                self.gate(Step::Election).wait().await;
            }
            self.caller(cx);
            cx.checkpoint().map_err(|_| McpError::request_cancelled())?;
            let elected = self
                .inner
                .begin_handoff_dispatch_for_owner_if_current(task_id, generation, owner_id)?;
            if elected.is_some() {
                self.elected.fetch_add(1, Ordering::SeqCst);
                if let Some(stop) = self.stop_after_election.lock().unwrap().as_ref() {
                    stop.store(true, Ordering::Release);
                }
                if self.cancel_after_election.load(Ordering::SeqCst) {
                    cx.cancel_with(asupersync::types::CancelKind::User, None);
                }
                self.election_receipt.wait().await;
            }
            if elected.is_some() && self.zero_election_receipt.load(Ordering::SeqCst) {
                Ok(Some(0))
            } else {
                Ok(elected)
            }
        })
    }

    fn get_task_access_metadata(
        &self,
        task_id: &FinalTaskId,
    ) -> McpResult<Option<FinalTaskAccessMetadata>> {
        self.synchronous();
        self.inner.get_task_access_metadata(task_id)
    }

    fn get_task_access_metadata_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskAccessMetadata>> {
        self.caller(cx);
        Box::pin(async move {
            self.enter(cx, Step::Metadata).await?;
            if let Some(metadata) = self.substitute_authorization.lock().unwrap().as_ref() {
                return Ok(Some(metadata.clone()));
            }
            self.inner.get_task_access_metadata(task_id)
        })
    }

    fn get_task_access_metadata_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskAccessMetadata>> {
        self.caller(ctx.cx());
        Box::pin(async move {
            self.enter(ctx.cx(), Step::Metadata).await?;
            ctx.checkpoint()?;
            if let Some(metadata) = self.substitute_authorization.lock().unwrap().as_ref() {
                return Ok(Some(metadata.clone()));
            }
            self.inner.get_task_access_metadata(task_id)
        })
    }

    fn get_task_snapshot_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.caller(ctx.cx());
        Box::pin(async move {
            self.enter(ctx.cx(), Step::Read).await?;
            ctx.checkpoint()?;
            let substitute = self.substitute_read.lock().unwrap().take();
            match substitute {
                Some(snapshot) => Ok(Some(snapshot)),
                None => self.inner.get_task_snapshot(task_id),
            }
        })
    }

    fn is_cancellation_requested(&self, task_id: &FinalTaskId) -> McpResult<bool> {
        self.synchronous();
        self.inner.is_cancellation_requested(task_id)
    }

    fn is_cancellation_requested_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, bool> {
        self.caller(ctx.cx());
        Box::pin(async move {
            self.enter(ctx.cx(), Step::CancellationIntent).await?;
            ctx.checkpoint()?;
            let requested = self.inner.is_cancellation_requested(task_id)?;
            if self.pause_snapshot_after_intent.swap(false, Ordering::SeqCst) {
                self.gate(Step::Read).close();
            }
            Ok(requested)
        })
    }

    fn get_handoff_access_metadata(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        fence: u64,
    ) -> McpResult<Option<FinalTaskAccessMetadata>> {
        self.synchronous();
        self.inner
            .get_handoff_access_metadata(task_id, generation, owner_id, fence)
    }

    fn get_handoff_access_metadata_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
        generation: u64,
        owner_id: &'a str,
        fence: u64,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskAccessMetadata>> {
        self.caller(ctx.cx());
        Box::pin(async move {
            let call = self.authorization_calls.fetch_add(1, Ordering::SeqCst);
            self.authorization_gates[call % 2].wait().await;
            self.caller(ctx.cx());
            ctx.checkpoint()?;
            if self.fail_authorization.load(Ordering::SeqCst) {
                return Err(McpError::internal_error(
                    "private metadata provider failure",
                ));
            }
            if self.omit_continuity.load(Ordering::SeqCst) {
                return Ok(None);
            }
            if let Some(metadata) = self.substitute_authorization.lock().unwrap().as_ref() {
                return Ok(Some(metadata.clone()));
            }
            self.inner
                .get_handoff_access_metadata(task_id, generation, owner_id, fence)
        })
    }

    fn get_task_snapshot(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTaskSnapshot>> {
        self.synchronous();
        self.inner.get_task_snapshot(task_id)
    }

    fn expire_task_execution_if_current(
        &self,
        expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        self.synchronous();
        self.inner.expire_task_execution_if_current(expected)
    }

    fn next_expired_execution_snapshot(&self) -> McpResult<Option<FinalTaskSnapshot>> {
        // The targeted worker must use the asynchronous maintenance hook.
        // Other trusted synchronous operations retain their existing contract.
        assert!(
            !Cx::current().is_some_and(|cx| self.is_expiry_caller(&cx)),
            "busy worker used synchronous bulk expiry"
        );
        self.synchronous();
        self.inner.next_expired_execution_snapshot()
    }

    fn next_initial_work_snapshot_after(
        &self,
        _after: Option<&FinalTaskId>,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        panic!("service used synchronous initial-work recovery")
    }

    fn next_accepted_input_snapshot_after(
        &self,
        _after: Option<&FinalTaskId>,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        panic!("service used synchronous accepted-input recovery")
    }

    fn take_initial_work_handoff_for_owner_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
        _owner_id: &str,
    ) -> McpResult<Option<FinalTaskInitialWorkClaim>> {
        panic!("service used a synchronous initial-work claim")
    }

    fn take_input_handoff_for_owner_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
        _owner_id: &str,
    ) -> McpResult<Option<FinalTaskAcceptedInputClaim>> {
        panic!("service used a synchronous accepted-input claim")
    }

    fn next_initial_work_snapshot_after_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        after: Option<&'a FinalTaskId>,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.caller(cx);
        Box::pin(async move {
            self.enter(cx, Step::InitialScan).await?;
            self.inner.next_initial_work_snapshot_after(after)
        })
    }

    fn next_accepted_input_snapshot_after_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        after: Option<&'a FinalTaskId>,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.caller(cx);
        Box::pin(async move {
            self.enter(cx, Step::InputScan).await?;
            self.inner.next_accepted_input_snapshot_after(after)
        })
    }

    fn next_expired_execution_snapshot_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.caller(cx);
        Box::pin(async move {
            self.enter(cx, Step::ExpiredScan).await?;
            let result = self.inner.next_expired_execution_snapshot();
            if self
                .pause_authorization_after_expiry_scan
                .swap(false, Ordering::SeqCst)
            {
                for gate in &self.authorization_gates {
                    gate.close();
                }
            }
            result
        })
    }

    fn get_task_snapshot_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.caller(cx);
        Box::pin(async move {
            self.enter(cx, Step::Read).await?;
            let substitute = self.substitute_read.lock().unwrap().take();
            match substitute {
                Some(snapshot) => Ok(Some(snapshot)),
                None => self.inner.get_task_snapshot(task_id),
            }
        })
    }

    fn expire_task_execution_if_current_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        expected: &'a FinalTaskSnapshot,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.caller(cx);
        Box::pin(async move {
            self.enter(cx, Step::Expire).await?;
            let committed = self.inner.expire_task_execution_if_current(expected)?;
            if self.cancel_after_expiry.load(Ordering::SeqCst) {
                cx.cancel_with(asupersync::types::CancelKind::User, None);
            }
            Ok(committed)
        })
    }

    fn take_initial_work_handoff_for_owner_if_current_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        expected: &'a FinalTaskSnapshot,
        owner_id: &'a str,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskInitialWorkClaim>> {
        self.caller(cx);
        Box::pin(async move {
            self.enter(cx, Step::InitialClaim).await?;
            let claim = self
                .inner
                .take_initial_work_handoff_for_owner_if_current(expected, owner_id)?;
            if claim.is_some() {
                self.claimed.fetch_add(1, Ordering::SeqCst);
                if self.cancel_after_claim.load(Ordering::SeqCst) {
                    cx.cancel_with(asupersync::types::CancelKind::User, None);
                }
                self.receipt.wait().await;
            }
            Ok(claim)
        })
    }

    fn take_input_handoff_for_owner_if_current_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        expected: &'a FinalTaskSnapshot,
        owner_id: &'a str,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskAcceptedInputClaim>> {
        self.caller(cx);
        Box::pin(async move {
            self.enter(cx, Step::InputClaim).await?;
            let claim = self
                .inner
                .take_input_handoff_for_owner_if_current(expected, owner_id)?;
            if claim.is_some() {
                self.claimed.fetch_add(1, Ordering::SeqCst);
                if self.cancel_after_claim.load(Ordering::SeqCst) {
                    cx.cancel_with(asupersync::types::CancelKind::User, None);
                }
                self.receipt.wait().await;
            }
            Ok(claim)
        })
    }

    fn restore_initial_work_for_owner_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: Option<u64>,
        descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<bool> {
        self.sync_settlements.fetch_add(1, Ordering::SeqCst);
        let restored = self.inner.restore_initial_work_for_owner_if_current(
            task_id,
            generation,
            owner_id,
            dispatch_fence,
            descriptor,
        )?;
        if restored {
            self.restored.fetch_add(1, Ordering::SeqCst);
        }
        Ok(restored)
    }

    fn restore_input_for_owner_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: Option<u64>,
        inputs: FinalTaskInputResponses,
    ) -> McpResult<bool> {
        self.sync_settlements.fetch_add(1, Ordering::SeqCst);
        let restored = self.inner.restore_input_for_owner_if_current(
            task_id,
            generation,
            owner_id,
            dispatch_fence,
            inputs,
        )?;
        if restored {
            self.restored.fetch_add(1, Ordering::SeqCst);
        }
        Ok(restored)
    }

    fn finish_handoff_dispatch_for_owner_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: u64,
    ) -> McpResult<bool> {
        self.sync_settlements.fetch_add(1, Ordering::SeqCst);
        self.inner.finish_handoff_dispatch_for_owner_if_current(
            task_id,
            generation,
            owner_id,
            dispatch_fence,
        )
    }

    fn finish_handoff_dispatch_for_owner_if_current_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        task_id: &'a FinalTaskId,
        generation: u64,
        owner_id: &'a str,
        dispatch_fence: u64,
    ) -> FinalTaskStoreFuture<'a, bool> {
        self.caller(cx);
        Box::pin(self.settle(cx, Step::Finish, move || {
            self.inner.finish_handoff_dispatch_for_owner_if_current(
                task_id,
                generation,
                owner_id,
                dispatch_fence,
            )
        }))
    }

    fn restore_initial_work_for_owner_if_current_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        task_id: &'a FinalTaskId,
        generation: u64,
        owner_id: &'a str,
        dispatch_fence: u64,
        descriptor: FinalTaskWorkDescriptor,
    ) -> FinalTaskStoreFuture<'a, bool> {
        self.caller(cx);
        Box::pin(self.settle(cx, Step::RestoreInitial, move || {
            self.inner.restore_initial_work_for_owner_if_current(
                task_id,
                generation,
                owner_id,
                Some(dispatch_fence),
                descriptor,
            )
        }))
    }

    fn restore_input_for_owner_if_current_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        task_id: &'a FinalTaskId,
        generation: u64,
        owner_id: &'a str,
        dispatch_fence: u64,
        inputs: FinalTaskInputResponses,
    ) -> FinalTaskStoreFuture<'a, bool> {
        self.caller(cx);
        Box::pin(self.settle(cx, Step::RestoreInput, move || {
            self.inner.restore_input_for_owner_if_current(
                task_id,
                generation,
                owner_id,
                Some(dispatch_fence),
                inputs,
            )
        }))
    }

    fn renew_handoff_dispatch_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: u64,
    ) -> McpResult<bool> {
        self.sync_renewal_calls.fetch_add(1, Ordering::SeqCst);
        self.renew_exact_lease(task_id, generation, owner_id, dispatch_fence)
    }

    fn renew_handoff_dispatch_if_current_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        task_id: &'a FinalTaskId,
        generation: u64,
        owner_id: &'a str,
        dispatch_fence: u64,
    ) -> FinalTaskStoreFuture<'a, bool> {
        self.caller(cx);
        Box::pin(async move {
            self.async_renewal_calls.fetch_add(1, Ordering::SeqCst);
            let pause = self.renewal_pause_for.lock().unwrap().as_ref() == Some(task_id);
            if pause {
                self.renewal_gate.wait().await;
            }
            self.caller(cx);
            cx.checkpoint().map_err(|_| McpError::request_cancelled())?;
            let renewed = self.renew_exact_lease(task_id, generation, owner_id, dispatch_fence)?;
            if self.pause_snapshot_after_renewal.swap(false, Ordering::SeqCst) {
                self.gate(Step::Read).close();
            }
            Ok(renewed)
        })
    }

    fn handoff_dispatch_lease_heartbeat_interval(&self) -> McpResult<StdDuration> {
        // Shorter than the real store's thirty-second lease, without changing
        // the store's expiry/fencing behavior.
        Ok(StdDuration::from_millis(5))
    }
}

struct Fixture {
    store: Arc<AsyncRecoveryStore>,
    runtime: FinalTaskRuntime,
    emitted: Arc<Mutex<Vec<FinalTask>>>,
}

impl Fixture {
    fn new() -> Self {
        Self::with_store(AsyncRecoveryStore::new())
    }

    fn with_store(store: AsyncRecoveryStore) -> Self {
        let store = Arc::new(store);
        let emitted = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&emitted);
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
            Arc::new(move |notification| sink.lock().unwrap().push(notification.params.task)),
        );
        Self {
            store,
            runtime,
            emitted,
        }
    }

    fn seed(&self, name: &str, resumed: bool) -> FinalTaskSnapshot {
        let timestamp = FinalTaskTimestamp::parse("2026-07-28T12:00:00.000Z").unwrap();
        let task = FinalTask::Working(FinalTaskBase {
            task_id: FinalTaskId::parse(name).unwrap(),
            status: FinalTaskStatus::Working,
            status_message: Some("durably queued".to_owned()),
            created_at: timestamp.clone(),
            last_updated_at: timestamp,
            ttl_ms: Some(final_task_duration(60_000).unwrap()),
            poll_interval_ms: None,
        });
        let created = self
            .store
            .inner
            .create_task_with_work(task.clone(), final_task_notification(&task), descriptor())
            .unwrap();
        if !resumed {
            return created;
        }
        let waiting = FinalTask::InputRequired {
            base: transition_final_task_base(
                created.task().base().clone(),
                FinalTaskStatus::InputRequired,
                None,
            )
            .unwrap(),
            input_requests: input_requests(),
        };
        let waiting = self
            .store
            .inner
            .replace_task_and_clear_input_if_current(
                &created,
                waiting.clone(),
                final_task_notification(&waiting),
            )
            .unwrap()
            .unwrap();
        let working = FinalTask::Working(
            transition_final_task_base(
                waiting.task().base().clone(),
                FinalTaskStatus::Working,
                None,
            )
            .unwrap(),
        );
        self.store
            .inner
            .replace_task_and_append_input_if_current(
                &waiting,
                working.clone(),
                final_task_notification(&working),
                input_responses(),
            )
            .unwrap()
            .unwrap()
    }

    fn assert_recoverable(&self, expected: &FinalTaskSnapshot, resumed: bool) {
        let current = self
            .store
            .next_candidate(resumed)
            .expect("exact work is recoverable");
        assert_eq!(
            current.task().base().task_id,
            expected.task().base().task_id
        );
        assert!(final_tasks_match_exactly(current.task(), expected.task()).unwrap());
        assert_eq!(self.store.inner.active_task_count(), 0);
    }
}

fn descriptor() -> FinalTaskWorkDescriptor {
    FinalTaskWorkDescriptor::new(serde_json::json!({
        "handler":"async-recovery",
        "arguments":{"opaque":"retained exactly","number":7}
    }))
    .unwrap()
}

fn input_requests() -> FinalTaskInputRequests {
    serde_json::from_value(serde_json::json!({"roots-input":{"method":"roots/list"}})).unwrap()
}

fn input_responses() -> FinalTaskInputResponses {
    serde_json::from_value(serde_json::json!({
        "roots-input":{"roots":[{"uri":"file:///allowed","name":"exact input"}]}
    }))
    .unwrap()
}

fn run<F, Fut>(test: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = ()>,
{
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    let caller = runtime.request_cx_with_budget(Budget::INFINITE);
    runtime.block_on(async {
        let host = Cx::current().unwrap();
        asupersync::time::timeout(host.now(), StdDuration::from_secs(8), test(caller))
            .await
            .expect("asynchronous recovery must make bounded caller-owned progress");
    });
    assert!(runtime.shutdown_timeout(StdDuration::from_secs(2)));
}

async fn drive_until<F: Future + ?Sized>(
    host: &Cx,
    mut future: Pin<&mut F>,
    condition: impl Fn() -> bool,
) {
    asupersync::time::timeout(host.now(), StdDuration::from_secs(3), async {
        std::future::poll_fn(|task| {
            if condition() {
                return Poll::Ready(());
            }
            match future.as_mut().poll(task) {
                Poll::Ready(_) => panic!("operation completed before its suspended checkpoint"),
                Poll::Pending if condition() => Poll::Ready(()),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
    })
    .await
    .expect("the real operation must reach its declared pending checkpoint");
}

async fn wait_until(host: &Cx, condition: impl Fn() -> bool) {
    asupersync::time::timeout(host.now(), StdDuration::from_secs(3), async {
        while !condition() {
            asupersync::time::sleep(host.now(), StdDuration::from_millis(1)).await;
        }
    })
    .await
    .expect("caller-owned cleanup must settle");
}

async fn recover(
    fixture: &Fixture,
    cx: &Cx,
    snapshot: &FinalTaskSnapshot,
    resumed: bool,
    signaled: bool,
    owner: &str,
) -> McpResult<Option<FinalTaskSupervisorHandoff>> {
    if signaled {
        let id = &snapshot.task().base().task_id;
        if resumed {
            fixture
                .runtime
                .take_accepted_input_with_cx(cx, id, owner)
                .await
                .map(|value| value.map(FinalTaskSupervisorHandoff::Resumed))
        } else {
            fixture
                .runtime
                .take_initial_work_with_cx(cx, id, owner)
                .await
                .map(|value| value.map(FinalTaskSupervisorHandoff::Initial))
        }
    } else {
        let mut cursor = None;
        let excluded = BTreeSet::new();
        if resumed {
            fixture
                .runtime
                .recover_accepted_input_excluding_with_cx(cx, owner, &mut cursor, &excluded)
                .await
                .map(|value| value.map(FinalTaskSupervisorHandoff::Resumed))
        } else {
            fixture
                .runtime
                .recover_initial_work_excluding_with_cx(cx, owner, &mut cursor, &excluded)
                .await
                .map(|value| value.map(FinalTaskSupervisorHandoff::Initial))
        }
    }
}

fn assert_handoff(
    handoff: &FinalTaskSupervisorHandoff,
    snapshot: &FinalTaskSnapshot,
    resumed: bool,
) {
    assert_eq!(
        final_task_handoff_task_id(handoff),
        &snapshot.task().base().task_id
    );
    match handoff {
        FinalTaskSupervisorHandoff::Initial(work) => {
            assert!(!resumed);
            assert_eq!(work.generation(), snapshot.generation());
            assert_eq!(work.work_descriptor(), &descriptor());
            assert!(work.execution_permit.as_ref().unwrap().upgrade().is_some());
        }
        FinalTaskSupervisorHandoff::Resumed(work) => {
            assert!(resumed);
            assert_eq!(work.generation(), snapshot.generation());
            assert_eq!(work.work_descriptor(), &descriptor());
            assert_eq!(work.input_responses(), &input_responses());
            assert!(work.execution_permit.as_ref().unwrap().upgrade().is_some());
        }
    }
}

#[test]
fn task_recovery_async_scan_and_signaled_claims_preserve_exact_handoffs() {
    for resumed in [false, true] {
        for signaled in [false, true] {
            run(|caller| async move {
                let host = Cx::current().unwrap();
                let fixture = Fixture::new();
                let snapshot = fixture.seed("recover-exact", resumed);
                let scan = if resumed {
                    Step::InputScan
                } else {
                    Step::InitialScan
                };
                let claim = if resumed {
                    Step::InputClaim
                } else {
                    Step::InitialClaim
                };
                let first = if signaled { Step::Read } else { scan };
                for step in [first, Step::Expire, claim] {
                    fixture.store.gate(step).close();
                }
                if !signaled {
                    fixture.store.gate(Step::Read).close();
                }
                fixture.store.forbid_sync.store(true, Ordering::SeqCst);
                let mut operation = Box::pin(recover(
                    &fixture,
                    &caller,
                    &snapshot,
                    resumed,
                    signaled,
                    "async-owner",
                ));
                drive_until(&host, operation.as_mut(), || {
                    fixture.store.count(first) == 1
                })
                .await;
                assert_eq!(fixture.store.claimed.load(Ordering::SeqCst), 0);
                let progressed = Arc::new(AtomicBool::new(false));
                let observed = Arc::clone(&progressed);
                let mut sibling = host
                    .spawn(move |cx| async move {
                        asupersync::time::sleep(cx.now(), StdDuration::from_millis(1)).await;
                        observed.store(true, Ordering::SeqCst);
                    })
                    .unwrap();
                sibling.join(&host).await.unwrap();
                assert!(progressed.load(Ordering::SeqCst));
                assert_eq!(fixture.store.claimed.load(Ordering::SeqCst), 0);
                fixture.store.gate(first).release();
                drive_until(&host, operation.as_mut(), || {
                    fixture.store.count(Step::Expire) == 1
                })
                .await;
                fixture.store.gate(Step::Expire).release();
                drive_until(&host, operation.as_mut(), || {
                    fixture.store.count(claim) == 1
                })
                .await;
                assert_eq!(fixture.store.claimed.load(Ordering::SeqCst), 0);
                fixture.store.gate(claim).release();
                if !signaled {
                    drive_until(&host, operation.as_mut(), || {
                        fixture.store.count(Step::Read) == 1
                    })
                    .await;
                    assert_eq!(fixture.store.claimed.load(Ordering::SeqCst), 1);
                    fixture.store.gate(Step::Read).release();
                }
                let handoff = operation.await.unwrap().unwrap();
                assert_eq!(fixture.store.sync_calls.load(Ordering::SeqCst), 0);
                assert_handoff(&handoff, &snapshot, resumed);
                fixture.store.forbid_sync.store(false, Ordering::SeqCst);
                drop(FinalTaskExecutionGuard::new(
                    &fixture.runtime,
                    "async-owner",
                    &handoff,
                ));
                fixture.assert_recoverable(&snapshot, resumed);
            });
        }
    }
}

#[test]
fn task_recovery_async_known_claim_is_restored_on_cancel_drop_and_bad_reread() {
    for resumed in [false, true] {
        for outcome in ["cancel", "drop", "bad-reread", "cancel-at-commit"] {
            run(|caller| async move {
                let host = Cx::current().unwrap();
                let fixture = Fixture::new();
                let snapshot = fixture.seed("recover-custody", resumed);
                fixture.store.gate(Step::Read).close();
                if outcome == "cancel-at-commit" {
                    fixture
                        .store
                        .cancel_after_claim
                        .store(true, Ordering::SeqCst);
                }
                let mut operation = Box::pin(recover(
                    &fixture,
                    &caller,
                    &snapshot,
                    resumed,
                    false,
                    "custody-owner",
                ));
                if outcome == "cancel-at-commit" {
                    assert!(operation.await.is_err());
                } else {
                    drive_until(&host, operation.as_mut(), || {
                        fixture.store.count(Step::Read) == 1
                    })
                    .await;
                    assert_eq!(fixture.store.claimed.load(Ordering::SeqCst), 1);
                    assert!(fixture.store.next_candidate(resumed).is_none());
                    match outcome {
                        "cancel" => {
                            caller.cancel_with(asupersync::types::CancelKind::User, None);
                            assert!(operation.await.is_err());
                            assert!(!fixture.store.gate(Step::Read).open.load(Ordering::SeqCst));
                        }
                        "drop" => drop(operation),
                        "bad-reread" => {
                            let changed = FinalTaskSnapshot::new(
                                snapshot.task().clone(),
                                snapshot.generation() + 1,
                            )
                            .with_creation_generation(snapshot.creation_generation());
                            *fixture.store.substitute_read.lock().unwrap() = Some(changed);
                            fixture.store.gate(Step::Read).release();
                            assert!(operation.await.is_err());
                        }
                        _ => unreachable!(),
                    }
                }
                assert_eq!(fixture.store.restored.load(Ordering::SeqCst), 1);
                fixture.assert_recoverable(&snapshot, resumed);
                assert!(fixture.emitted.lock().unwrap().is_empty());
            });
        }
    }
}

#[test]
fn task_recovery_async_unknown_claim_drop_retains_lease_until_authoritative_expiry() {
    for resumed in [false, true] {
        run(|caller| async move {
            let host = Cx::current().unwrap();
            let fixture = Fixture::new();
            let snapshot = fixture.seed("recover-unknown", resumed);
            fixture.store.receipt.close();
            let mut operation = Box::pin(recover(
                &fixture,
                &caller,
                &snapshot,
                resumed,
                false,
                "unknown-owner",
            ));
            drive_until(&host, operation.as_mut(), || {
                fixture.store.claimed.load(Ordering::SeqCst) == 1
            })
            .await;
            drop(operation);
            assert_eq!(fixture.store.receipt.abandoned.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.store.restored.load(Ordering::SeqCst), 0);
            assert!(fixture.store.next_candidate(resumed).is_none());
            *fixture.store.clock.lock().unwrap() +=
                IN_MEMORY_FINAL_TASK_HANDOFF_LEASE - StdDuration::from_millis(1);
            assert!(fixture.store.next_candidate(resumed).is_none());
            *fixture.store.clock.lock().unwrap() += StdDuration::from_millis(1);
            let candidate = fixture.store.next_candidate(resumed).unwrap();
            assert!(candidate.generation() > snapshot.generation());
            fixture.store.receipt.release();
            let handoff = recover(
                &fixture,
                &caller,
                &candidate,
                resumed,
                false,
                "replacement-owner",
            )
            .await
            .unwrap()
            .unwrap();
            assert_handoff(&handoff, &candidate, resumed);
            drop(FinalTaskExecutionGuard::new(
                &fixture.runtime,
                "replacement-owner",
                &handoff,
            ));
            fixture.assert_recoverable(&candidate, resumed);
        });
    }
}

#[test]
fn task_recovery_async_expiry_awaits_storage_without_releasing_early() {
    run(|caller| async move {
        let host = Cx::current().unwrap();
        let fixture = Fixture::with_store(AsyncRecoveryStore::with_limits(
            FinalTaskExecutionLimits::new(
                StdDuration::from_millis(100),
                StdDuration::from_millis(100),
                3,
            )
            .unwrap(),
        ));
        let snapshot = fixture.seed("recover-expiry", false);
        let observed = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&observed);
        let _observer = fixture
            .runtime
            .add_owned_notification_emitter(Arc::new(move |_, _| {
                count.fetch_add(1, Ordering::SeqCst);
            }));
        *fixture.store.clock.lock().unwrap() += StdDuration::from_millis(99);
        fixture.store.forbid_sync.store(true, Ordering::SeqCst);
        fixture
            .runtime
            .expire_pending_execution_with_cx(&caller)
            .await
            .unwrap();
        assert!(fixture.emitted.lock().unwrap().is_empty());
        *fixture.store.clock.lock().unwrap() += StdDuration::from_millis(1);
        fixture.store.gate(Step::ExpiredScan).close();
        fixture.store.gate(Step::Expire).close();
        fixture.store.gate(Step::Metadata).close();
        let prior_scan = fixture.store.count(Step::ExpiredScan);
        let mut expiry = Box::pin(fixture.runtime.expire_pending_execution_with_cx(&caller));
        drive_until(&host, expiry.as_mut(), || {
            fixture.store.count(Step::ExpiredScan) > prior_scan
        })
        .await;
        fixture.store.gate(Step::ExpiredScan).release();
        drive_until(&host, expiry.as_mut(), || {
            fixture.store.count(Step::Expire) == 1
        })
        .await;
        assert!(matches!(
            fixture
                .store
                .inner
                .get_task(&snapshot.task().base().task_id)
                .unwrap(),
            Some(FinalTask::Working(_)),
        ));
        assert!(fixture.emitted.lock().unwrap().is_empty());
        fixture.store.gate(Step::Expire).release();
        drive_until(&host, expiry.as_mut(), || {
            fixture.store.count(Step::Metadata) == 1
        })
        .await;
        assert_eq!(fixture.emitted.lock().unwrap().len(), 1);
        assert_eq!(observed.load(Ordering::SeqCst), 0);
        assert!(matches!(
            fixture
                .store
                .inner
                .get_task(&snapshot.task().base().task_id)
                .unwrap(),
            Some(FinalTask::Failed { .. }),
        ));
        fixture.store.gate(Step::Metadata).release();
        expiry.await.unwrap();
        assert_eq!(observed.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.sync_calls.load(Ordering::SeqCst), 0);
        fixture.store.forbid_sync.store(false, Ordering::SeqCst);
        let terminal = fixture
            .store
            .inner
            .get_task_snapshot(&snapshot.task().base().task_id)
            .unwrap()
            .unwrap();
        assert!(matches!(terminal.task(), FinalTask::Failed { .. }));
        assert!(terminal.generation() > snapshot.generation());
        assert_eq!(
            terminal.creation_generation(),
            snapshot.creation_generation()
        );
        assert_eq!(fixture.emitted.lock().unwrap().len(), 1);
        assert!(
            final_tasks_match_exactly(&fixture.emitted.lock().unwrap()[0], terminal.task(),)
                .unwrap()
        );
        assert_eq!(fixture.store.claimed.load(Ordering::SeqCst), 0);
    });
}

struct PendingSupervisor {
    constructed: AtomicUsize,
    started: Mutex<Vec<FinalTaskId>>,
    active: AtomicUsize,
    progressed: AtomicUsize,
    release: Gate,
}

impl PendingSupervisor {
    fn new() -> Self {
        let release = Gate::new();
        release.close();
        Self {
            constructed: AtomicUsize::new(0),
            started: Mutex::new(Vec::new()),
            active: AtomicUsize::new(0),
            progressed: AtomicUsize::new(0),
            release,
        }
    }
}

impl ApplicationTaskSupervisor for PendingSupervisor {
    fn resume<'a>(
        &'a self,
        cx: &'a Cx,
        handoff: FinalTaskSupervisorHandoff,
    ) -> FinalTaskSupervisorFuture<'a> {
        self.constructed.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            struct Active<'a>(&'a AtomicUsize);
            impl Drop for Active<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            assert!(cx.blocking_pool_handle().is_none());
            self.active.fetch_add(1, Ordering::SeqCst);
            let _active = Active(&self.active);
            self.started
                .lock()
                .unwrap()
                .push(final_task_handoff_task_id(&handoff).clone());
            asupersync::time::sleep(cx.now(), StdDuration::from_millis(1)).await;
            self.progressed.fetch_add(1, Ordering::SeqCst);
            self.release.wait().await;
            Err(McpError::internal_error(
                "released active recovery test task",
            ))
        })
    }
}

#[test]
fn task_recovery_async_pending_refill_keeps_active_heartbeat_and_settlement_live() {
    for stop in ["error", "cancel", "drop"] {
        run(|caller| async move {
            let host = Cx::current().unwrap();
            let fixture = Fixture::new();
            let first = fixture.seed("a-recover-active", false);
            let second = fixture.seed("z-recover-parked", false);
            let supervisor = Arc::new(PendingSupervisor::new());
            let mut runner = fixture
                .runtime
                .install_task_service(2, supervisor.clone())
                .unwrap()
                .with_max_concurrent_handoffs(2)
                .unwrap();
            fixture.store.initial_pause_from.store(2, Ordering::SeqCst);
            fixture.store.gate(Step::InitialScan).close();
            let mut service = Box::pin(runner.run_service(&caller));
            drive_until(&host, service.as_mut(), || {
                fixture.store.count(Step::InitialScan) >= 2
                    && supervisor.progressed.load(Ordering::SeqCst) == 1
            })
            .await;
            assert_eq!(
                supervisor.started.lock().unwrap().as_slice(),
                &[first.task().base().task_id.clone()]
            );
            let renewals = fixture.store.renewals.load(Ordering::SeqCst);
            drive_until(&host, service.as_mut(), || {
                fixture.store.renewals.load(Ordering::SeqCst) > renewals
            })
            .await;
            assert_eq!(fixture.store.claimed.load(Ordering::SeqCst), 1);
            assert!(
                !fixture
                    .store
                    .gate(Step::InitialScan)
                    .open
                    .load(Ordering::SeqCst)
            );
            match stop {
                "error" => {
                    supervisor.release.release();
                    assert!(
                        asupersync::time::timeout(
                            host.now(),
                            StdDuration::from_secs(3),
                            service.as_mut(),
                        )
                        .await
                        .unwrap()
                        .is_err()
                    );
                    drop(service);
                }
                "cancel" => {
                    caller.cancel_with(asupersync::types::CancelKind::User, None);
                    asupersync::time::timeout(
                        host.now(),
                        StdDuration::from_secs(3),
                        service.as_mut(),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    drop(service);
                }
                "drop" => drop(service),
                _ => unreachable!(),
            }
            wait_until(&host, || {
                supervisor.active.load(Ordering::SeqCst) == 0
                    && fixture.store.inner.active_task_count() == 0
            })
            .await;
            assert!(!fixture.runtime.is_task_service_ready());
            assert!(
                fixture
                    .store
                    .gate(Step::InitialScan)
                    .abandoned
                    .load(Ordering::SeqCst)
                    > 0
            );
            assert_eq!(supervisor.started.lock().unwrap().len(), 1);
            let state = fixture.store.inner.state.lock().unwrap();
            assert!(state.handoff_leases.is_empty());
            assert_eq!(state.initial_work.len(), 2);
            drop(state);
            for expected in [&first, &second] {
                let actual = fixture
                    .store
                    .inner
                    .get_task(&expected.task().base().task_id)
                    .unwrap()
                    .unwrap();
                assert!(final_tasks_match_exactly(&actual, expected.task()).unwrap());
            }
        });
    }
}

/// A parked maintenance scan belongs to exactly one worker. Other workers and
/// the outer recovery loop keep their own independent storage progress.
struct MaintenanceSupervisor {
    store: Arc<AsyncRecoveryStore>,
    target: FinalTaskId,
    live: AtomicUsize,
    target_started: AtomicBool,
    target_polls: AtomicUsize,
    cancellation_seen: AtomicBool,
    cleanup_finished: AtomicBool,
    sibling_started: AtomicBool,
    sibling_finished: AtomicBool,
    release_sibling: Gate,
}

impl MaintenanceSupervisor {
    fn new(store: Arc<AsyncRecoveryStore>, target: FinalTaskId) -> Self {
        let release_sibling = Gate::new();
        release_sibling.close();
        Self {
            store,
            target,
            live: AtomicUsize::new(0),
            target_started: AtomicBool::new(false),
            target_polls: AtomicUsize::new(0),
            cancellation_seen: AtomicBool::new(false),
            cleanup_finished: AtomicBool::new(false),
            sibling_started: AtomicBool::new(false),
            sibling_finished: AtomicBool::new(false),
            release_sibling,
        }
    }
}

impl ApplicationTaskSupervisor for MaintenanceSupervisor {
    fn resume<'a>(
        &'a self,
        cx: &'a Cx,
        handoff: FinalTaskSupervisorHandoff,
    ) -> FinalTaskSupervisorFuture<'a> {
        Box::pin(async move {
            struct Live<'a>(&'a AtomicUsize);
            impl Drop for Live<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            self.live.fetch_add(1, Ordering::SeqCst);
            let _live = Live(&self.live);
            assert!(cx.blocking_pool_handle().is_none());
            if final_task_handoff_task_id(&handoff) == &self.target {
                assert!(!self.target_started.swap(true, Ordering::SeqCst));
                // The first mandatory maintenance pass has already completed.
                // Only this worker's next pass will encounter the closed gate.
                self.store.pause_worker_expiry(cx);
                std::future::poll_fn(|_| {
                    self.target_polls.fetch_add(1, Ordering::SeqCst);
                    let requested = match &handoff {
                        FinalTaskSupervisorHandoff::Initial(work) => {
                            work.is_cancellation_requested()
                        }
                        FinalTaskSupervisorHandoff::Resumed(work) => {
                            work.is_cancellation_requested()
                        }
                    };
                    match requested {
                        Ok(true) => {
                            self.cancellation_seen.store(true, Ordering::SeqCst);
                            Poll::Ready(Ok(()))
                        }
                        Ok(false) => Poll::Pending,
                        Err(error) => Poll::Ready(Err(error)),
                    }
                })
                .await?;
                // Cancellation must return to the existing grace loop so
                // actual asynchronous cleanup can run before terminalization.
                asupersync::time::sleep(cx.now(), StdDuration::from_millis(1)).await;
                self.cleanup_finished.store(true, Ordering::SeqCst);
                Ok(())
            } else {
                assert!(!self.sibling_started.swap(true, Ordering::SeqCst));
                self.release_sibling.wait().await;
                let result = serde_json::from_value(serde_json::json!({
                    "content":[{"type":"text","text":"unrelated task completed"}]
                }))
                .unwrap();
                match handoff {
                    FinalTaskSupervisorHandoff::Initial(work) => {
                        work.complete_task(result, None)?;
                    }
                    FinalTaskSupervisorHandoff::Resumed(work) => {
                        work.complete_task(result, None)?;
                    }
                }
                self.sibling_finished.store(true, Ordering::SeqCst);
                Ok(())
            }
        })
    }
}

fn elected_lease(store: &AsyncRecoveryStore, task_id: &FinalTaskId) -> (u64, String, u64, Instant) {
    let state = store.inner.state.lock().unwrap();
    let lease = state
        .handoff_leases
        .get(task_id)
        .expect("worker retains its exact lease");
    assert!(lease.dispatch_elected);
    (
        lease.generation,
        lease.owner_id.clone(),
        lease
            .dispatch_fence
            .expect("an elected dispatch has a fence"),
        lease
            .recovery_expires_at
            .expect("a dispatch lease remains finite"),
    )
}

#[test]
fn task_recovery_async_worker_maintenance_renews_and_preserves_cancellation_grace() {
    run(|caller| async move {
        let host = Cx::current().unwrap();
        let fixture = Fixture::new();
        let target = fixture.seed("a-maintenance-target", false);
        let sibling = fixture.seed("z-maintenance-sibling", false);
        let task_id = target.task().base().task_id.clone();
        let sibling_id = sibling.task().base().task_id.clone();
        let supervisor = Arc::new(MaintenanceSupervisor::new(
            Arc::clone(&fixture.store),
            task_id.clone(),
        ));
        let mut runner = fixture
            .runtime
            .install_task_service(2, supervisor.clone())
            .unwrap()
            .with_max_concurrent_handoffs(2)
            .unwrap();
        let mut service = Box::pin(runner.run_service(&caller));
        drive_until(&host, service.as_mut(), || {
            fixture.store.parked_worker_expiry.load(Ordering::SeqCst) != 0
                && supervisor.sibling_started.load(Ordering::SeqCst)
        })
        .await;

        let original = elected_lease(&fixture.store, &task_id);
        let sibling_original = elected_lease(&fixture.store, &sibling_id);
        let application_polls = supervisor.target_polls.load(Ordering::SeqCst);
        *fixture.store.clock.lock().unwrap() =
            original.3.checked_sub(StdDuration::from_millis(1)).unwrap();
        drive_until(&host, service.as_mut(), || {
            elected_lease(&fixture.store, &task_id).3 > original.3
                && elected_lease(&fixture.store, &sibling_id).3 > sibling_original.3
        })
        .await;
        let renewed = elected_lease(&fixture.store, &task_id);
        assert_eq!(renewed.0, original.0);
        assert_eq!(renewed.1, original.1);
        assert_eq!(renewed.2, original.2);
        assert_eq!(
            supervisor.target_polls.load(Ordering::SeqCst),
            application_polls
        );
        assert_eq!(fixture.store.parked_worker_expiry.load(Ordering::SeqCst), 1);

        // Cross the old lease boundary. A helper that merely waits for storage
        // would now lose the owner and advance the record generation.
        *fixture.store.clock.lock().unwrap() = original.3 + StdDuration::from_millis(1);
        let current = fixture
            .store
            .inner
            .get_task_snapshot(&task_id)
            .unwrap()
            .unwrap();
        assert_eq!(current.generation(), target.generation());
        assert_eq!(elected_lease(&fixture.store, &task_id).2, original.2);
        assert!(
            !fixture
                .store
                .gate(Step::ExpiredScan)
                .open
                .load(Ordering::SeqCst)
        );

        supervisor.release_sibling.release();
        drive_until(&host, service.as_mut(), || {
            supervisor.sibling_finished.load(Ordering::SeqCst)
        })
        .await;
        assert!(matches!(
            fixture.store.inner.get_task(&sibling_id).unwrap(),
            Some(FinalTask::Completed { .. }),
        ));
        assert!(!supervisor.cancellation_seen.load(Ordering::SeqCst));
        assert!(
            !fixture
                .store
                .gate(Step::ExpiredScan)
                .open
                .load(Ordering::SeqCst)
        );

        fixture.runtime.cancel_task(&task_id).unwrap();
        drive_until(&host, service.as_mut(), || {
            supervisor.cleanup_finished.load(Ordering::SeqCst)
                && supervisor.live.load(Ordering::SeqCst) == 0
                && fixture.store.inner.active_task_count() == 0
        })
        .await;
        assert!(supervisor.cancellation_seen.load(Ordering::SeqCst));
        assert!(matches!(
            fixture.store.inner.get_task(&task_id).unwrap(),
            Some(FinalTask::Cancelled(_)),
        ));
        assert!(
            fixture
                .store
                .gate(Step::ExpiredScan)
                .abandoned
                .load(Ordering::SeqCst)
                > 0
        );
        assert!(
            !fixture
                .store
                .gate(Step::ExpiredScan)
                .open
                .load(Ordering::SeqCst)
        );
        assert!(
            caller.checkpoint().is_ok(),
            "Task cancellation cannot cancel its service"
        );
        drop(service);
        assert!(!fixture.runtime.is_task_service_ready());
    });
}

#[test]
fn task_recovery_async_worker_maintenance_stops_on_lease_loss_without_application_poll() {
    run(|caller| async move {
        let host = Cx::current().unwrap();
        let fixture = Fixture::new();
        let target = fixture.seed("maintenance-lost-lease", false);
        let task_id = target.task().base().task_id.clone();
        let supervisor = Arc::new(MaintenanceSupervisor::new(
            Arc::clone(&fixture.store),
            task_id.clone(),
        ));
        let mut runner = fixture
            .runtime
            .install_task_service(2, supervisor.clone())
            .unwrap()
            .with_max_concurrent_handoffs(2)
            .unwrap();
        let mut service = Box::pin(runner.run_service(&caller));
        drive_until(&host, service.as_mut(), || {
            fixture.store.parked_worker_expiry.load(Ordering::SeqCst) != 0
        })
        .await;
        let application_polls = supervisor.target_polls.load(Ordering::SeqCst);
        *fixture.store.refuse_renewal_for.lock().unwrap() = Some(task_id.clone());
        let result =
            asupersync::time::timeout(host.now(), StdDuration::from_secs(3), service.as_mut())
                .await
                .expect("lease refusal must not wait for the maintenance provider");
        assert!(result.is_err());
        drop(service);
        assert_eq!(
            supervisor.target_polls.load(Ordering::SeqCst),
            application_polls
        );
        assert!(!supervisor.cancellation_seen.load(Ordering::SeqCst));
        assert!(!supervisor.cleanup_finished.load(Ordering::SeqCst));
        assert_eq!(supervisor.live.load(Ordering::SeqCst), 0);
        assert!(!fixture.runtime.is_task_service_ready());
        assert!(
            fixture
                .store
                .gate(Step::ExpiredScan)
                .abandoned
                .load(Ordering::SeqCst)
                > 0
        );
        fixture.assert_recoverable(&target, false);
        assert!(
            fixture
                .store
                .inner
                .state
                .lock()
                .unwrap()
                .handoff_leases
                .is_empty()
        );
    });
}

#[test]
fn task_dispatch_async_preflight_and_election_never_use_sync_fallbacks() {
    for resumed in [false, true] {
        for step in [
            Step::Read,
            Step::Expire,
            Step::ExecutionBudget,
            Step::Retention,
            Step::Election,
        ] {
            run(|caller| async move {
                let host = Cx::current().unwrap();
                let fixture = Fixture::new();
                let snapshot = fixture.seed("dispatch-async", resumed);
                let handoff = recover(
                    &fixture,
                    &caller,
                    &snapshot,
                    resumed,
                    true,
                    "dispatch-owner",
                )
                .await
                .unwrap()
                .unwrap();
                let budget = fixture
                    .store
                    .inner
                    .task_execution_budget_if_current(&snapshot)
                    .unwrap()
                    .unwrap();
                let mut guard =
                    FinalTaskExecutionGuard::new(&fixture.runtime, "dispatch-owner", &handoff);
                let stop = AtomicBool::new(false);
                let previous = fixture.store.count(step);
                fixture.store.gate(step).close();
                fixture.store.forbid_sync.store(true, Ordering::SeqCst);
                let mut election = Box::pin(guard.elect_with_cx(&caller, &stop));
                drive_until(&host, election.as_mut(), || {
                    fixture.store.count(step) > previous
                })
                .await;
                assert_eq!(fixture.store.elected.load(Ordering::SeqCst), 0);
                fixture.store.gate(step).release();
                assert!(election.await.unwrap());
                assert_eq!(fixture.store.count(step), previous + 1);
                assert_eq!(fixture.store.sync_calls.load(Ordering::SeqCst), 0);
                assert_eq!(fixture.store.elected.load(Ordering::SeqCst), 1);
                assert_eq!(guard.execution_budget, Some(budget));
                assert!(guard.dispatch_fence.is_some_and(|fence| fence != 0));
                assert!(!guard.dispatch_election_uncertain);
                fixture.store.forbid_sync.store(false, Ordering::SeqCst);
                drop(guard);
                assert_eq!(fixture.store.restored.load(Ordering::SeqCst), 1);
                fixture.assert_recoverable(&snapshot, resumed);
            });
        }
    }
}

#[test]
fn task_dispatch_async_preflight_stop_cancel_and_drop_restore_exact_claims() {
    for resumed in [false, true] {
        for outcome in ["stop", "cancel", "drop"] {
            run(|caller| async move {
                let host = Cx::current().unwrap();
                let fixture = Fixture::new();
                let snapshot = fixture.seed("dispatch-preflight", resumed);
                let handoff = recover(
                    &fixture,
                    &caller,
                    &snapshot,
                    resumed,
                    true,
                    "preflight-owner",
                )
                .await
                .unwrap()
                .unwrap();
                let mut guard =
                    FinalTaskExecutionGuard::new(&fixture.runtime, "preflight-owner", &handoff);
                let stop = AtomicBool::new(false);
                fixture.store.gate(Step::Retention).close();
                let mut election = Box::pin(guard.elect_with_cx(&caller, &stop));
                drive_until(&host, election.as_mut(), || {
                    fixture.store.count(Step::Retention) == 1
                })
                .await;
                match outcome {
                    "stop" => {
                        stop.store(true, Ordering::Release);
                        assert!(election.await.is_err());
                    }
                    "cancel" => {
                        caller.cancel_with(asupersync::types::CancelKind::User, None);
                        assert!(election.await.is_err());
                    }
                    "drop" => drop(election),
                    _ => unreachable!(),
                }
                assert!(!guard.dispatch_election_uncertain);
                assert!(guard.dispatch_fence.is_none());
                drop(guard);
                assert_eq!(fixture.store.count(Step::Election), 0);
                assert_eq!(fixture.store.restored.load(Ordering::SeqCst), 1);
                assert_eq!(
                    fixture
                        .store
                        .gate(Step::Retention)
                        .abandoned
                        .load(Ordering::SeqCst),
                    1
                );
                fixture.assert_recoverable(&snapshot, resumed);
            });
        }
    }
}

#[test]
fn task_dispatch_async_known_receipt_precedes_stop_and_cancellation() {
    for resumed in [false, true] {
        for cancel in [false, true] {
            run(|caller| async move {
                let fixture = Fixture::new();
                let snapshot = fixture.seed("dispatch-late-stop", resumed);
                let supervisor = Arc::new(PendingSupervisor::new());
                let runner = fixture
                    .runtime
                    .install_task_service(2, supervisor.clone())
                    .unwrap();
                let handoff = recover(
                    &fixture,
                    &caller,
                    &snapshot,
                    resumed,
                    true,
                    &runner.dispatch_owner,
                )
                .await
                .unwrap()
                .unwrap();
                let stop = Arc::new(AtomicBool::new(false));
                if cancel {
                    fixture
                        .store
                        .cancel_after_election
                        .store(true, Ordering::SeqCst);
                } else {
                    *fixture.store.stop_after_election.lock().unwrap() = Some(Arc::clone(&stop));
                }
                let executor = runner.handoff_executor();
                assert!(
                    executor
                        .resume_handoff_with_stop(&caller, handoff, stop)
                        .await
                        .is_err()
                );
                assert_eq!(fixture.store.elected.load(Ordering::SeqCst), 1);
                assert!(supervisor.started.lock().unwrap().is_empty());
                assert_eq!(fixture.store.restored.load(Ordering::SeqCst), 1);
                fixture.assert_recoverable(&snapshot, resumed);
            });
        }
    }
}

#[test]
fn task_dispatch_async_unknown_or_malformed_receipt_preserves_backend_custody() {
    for resumed in [false, true] {
        for outcome in ["drop", "stop", "zero"] {
            run(|caller| async move {
                let host = Cx::current().unwrap();
                let fixture = Fixture::new();
                let snapshot = fixture.seed("dispatch-uncertain", resumed);
                let handoff = recover(
                    &fixture,
                    &caller,
                    &snapshot,
                    resumed,
                    true,
                    "uncertain-owner",
                )
                .await
                .unwrap()
                .unwrap();
                let mut guard =
                    FinalTaskExecutionGuard::new(&fixture.runtime, "uncertain-owner", &handoff);
                let stop = AtomicBool::new(false);
                if outcome == "zero" {
                    fixture
                        .store
                        .zero_election_receipt
                        .store(true, Ordering::SeqCst);
                } else {
                    fixture.store.election_receipt.close();
                }
                let mut election = Box::pin(guard.elect_with_cx(&caller, &stop));
                if outcome == "zero" {
                    assert!(election.await.is_err());
                } else {
                    drive_until(&host, election.as_mut(), || {
                        fixture.store.elected.load(Ordering::SeqCst) == 1
                    })
                    .await;
                    if outcome == "stop" {
                        stop.store(true, Ordering::Release);
                        assert!(election.await.is_err());
                    } else {
                        drop(election);
                    }
                }
                assert!(guard.dispatch_election_uncertain);
                assert!(guard.dispatch_fence.is_none());
                drop(guard);
                assert_eq!(fixture.store.restored.load(Ordering::SeqCst), 0);
                assert!(fixture.store.next_candidate(resumed).is_none());
                let retained = fixture
                    .store
                    .inner
                    .get_task_snapshot(&snapshot.task().base().task_id)
                    .unwrap()
                    .unwrap();
                assert_eq!(retained.generation(), snapshot.generation());
                assert!(final_tasks_match_exactly(retained.task(), snapshot.task()).unwrap());
                {
                    let state = fixture.store.inner.state.lock().unwrap();
                    let lease = state
                        .handoff_leases
                        .get(&snapshot.task().base().task_id)
                        .unwrap();
                    assert!(lease.dispatch_elected);
                    assert!(lease.dispatch_fence.is_some_and(|fence| fence != 0));
                }
                *fixture.store.clock.lock().unwrap() += IN_MEMORY_FINAL_TASK_HANDOFF_LEASE;
                let recovered = fixture.store.next_candidate(resumed).unwrap();
                assert!(recovered.generation() > snapshot.generation());
                assert_eq!(
                    recovered.creation_generation(),
                    snapshot.creation_generation()
                );
                assert!(final_tasks_match_exactly(recovered.task(), snapshot.task()).unwrap());
                assert_eq!(fixture.store.inner.active_task_count(), 0);
            });
        }
    }
}

#[test]
fn task_dispatch_async_rejects_stale_generation_and_duplicate_election() {
    for resumed in [false, true] {
        run(|caller| async move {
            let fixture = Fixture::new();
            let snapshot = fixture.seed("dispatch-exact-fence", resumed);
            let handoff = recover(&fixture, &caller, &snapshot, resumed, true, "exact-owner")
                .await
                .unwrap()
                .unwrap();
            let stop = AtomicBool::new(false);
            let mut wrong_owner =
                FinalTaskExecutionGuard::new(&fixture.runtime, "wrong-owner", &handoff);
            assert!(!wrong_owner.elect_with_cx(&caller, &stop).await.unwrap());
            drop(wrong_owner);
            assert_eq!(fixture.store.elected.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.store.restored.load(Ordering::SeqCst), 0);

            let mut first = FinalTaskExecutionGuard::new(&fixture.runtime, "exact-owner", &handoff);
            assert!(first.elect_with_cx(&caller, &stop).await.unwrap());
            let fence = first.dispatch_fence.unwrap();
            let mut duplicate =
                FinalTaskExecutionGuard::new(&fixture.runtime, "exact-owner", &handoff);
            assert!(!duplicate.elect_with_cx(&caller, &stop).await.unwrap());
            duplicate.disarm();
            drop(duplicate);
            assert_eq!(fixture.store.elected.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.store.restored.load(Ordering::SeqCst), 0);
            assert_eq!(
                fixture.store.inner.state.lock().unwrap().handoff_leases
                    [&snapshot.task().base().task_id]
                    .dispatch_fence,
                Some(fence)
            );
            drop(first);
            fixture.assert_recoverable(&snapshot, resumed);

            let fresh = recover(&fixture, &caller, &snapshot, resumed, true, "stale-owner")
                .await
                .unwrap()
                .unwrap();
            let mut stale = FinalTaskExecutionGuard::new(&fixture.runtime, "stale-owner", &fresh);
            let mut successor = snapshot.task().clone();
            if let FinalTask::Working(base) = &mut successor {
                base.status_message = Some("new generation wins".to_owned());
            }
            fixture
                .store
                .inner
                .replace_task(successor.clone(), final_task_notification(&successor))
                .unwrap();
            let elected = fixture.store.elected.load(Ordering::SeqCst);
            assert!(!stale.elect_with_cx(&caller, &stop).await.unwrap());
            stale.disarm();
            drop(stale);
            assert_eq!(fixture.store.elected.load(Ordering::SeqCst), elected);
            let current = fixture
                .store
                .inner
                .get_task_snapshot(&snapshot.task().base().task_id)
                .unwrap()
                .unwrap();
            assert!(current.generation() > snapshot.generation());
            assert!(final_tasks_match_exactly(current.task(), &successor).unwrap());
        });
    }
}

#[test]
fn task_dispatch_async_waits_consume_original_execution_deadline() {
    for after_commit in [false, true] {
        run(|caller| async move {
            let host = Cx::current().unwrap();
            let fixture = Fixture::with_store(AsyncRecoveryStore::with_limits(
                FinalTaskExecutionLimits::new(
                    StdDuration::from_millis(100),
                    StdDuration::from_millis(100),
                    3,
                )
                .unwrap(),
            ));
            let snapshot = fixture.seed("dispatch-deadline", false);
            let handoff = recover(&fixture, &caller, &snapshot, false, true, "deadline-owner")
                .await
                .unwrap()
                .unwrap();
            let mut guard =
                FinalTaskExecutionGuard::new(&fixture.runtime, "deadline-owner", &handoff);
            let stop = AtomicBool::new(false);
            if after_commit {
                fixture.store.election_receipt.close();
            } else {
                fixture.store.gate(Step::Retention).close();
            }
            let mut election = Box::pin(guard.elect_with_cx(&caller, &stop));
            drive_until(&host, election.as_mut(), || {
                if after_commit {
                    fixture.store.elected.load(Ordering::SeqCst) == 1
                } else {
                    fixture.store.count(Step::Retention) == 1
                }
            })
            .await;
            *fixture.store.clock.lock().unwrap() += StdDuration::from_millis(100);
            if after_commit {
                fixture.store.election_receipt.release();
                assert!(election.await.is_err());
            } else {
                fixture.store.gate(Step::Retention).release();
                assert!(!election.await.unwrap());
            }
            assert!(!guard.dispatch_election_uncertain);
            drop(guard);
            assert_eq!(
                fixture.store.elected.load(Ordering::SeqCst),
                usize::from(after_commit)
            );
            assert!(matches!(
                fixture
                    .store
                    .inner
                    .get_task(&snapshot.task().base().task_id)
                    .unwrap(),
                Some(FinalTask::Failed { .. })
            ));
            assert_eq!(fixture.store.restored.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.store.inner.active_task_count(), 0);
        });
    }
}

#[test]
fn task_dispatch_async_expiry_receipt_cancellation_prevents_next_provider_factory() {
    run(|caller| async move {
        let fixture = Fixture::new();
        let snapshot = fixture.seed("dispatch-factory-cancel", false);
        let handoff = recover(&fixture, &caller, &snapshot, false, true, "factory-owner")
            .await
            .unwrap()
            .unwrap();
        fixture
            .store
            .cancel_after_expiry
            .store(true, Ordering::SeqCst);
        let mut guard = FinalTaskExecutionGuard::new(&fixture.runtime, "factory-owner", &handoff);
        let stop = AtomicBool::new(false);
        assert!(guard.elect_with_cx(&caller, &stop).await.is_err());
        assert_eq!(fixture.store.budget_factories.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.count(Step::Election), 0);
        drop(guard);
        fixture.assert_recoverable(&snapshot, false);
    });
}

#[test]
fn async_dispatch_renewal_authorization_yields_and_preserves_ready_receipt() {
    for resumed in [false, true] {
        run(|caller| async move {
            let host = Cx::current().unwrap();
            let fixture = Fixture::new();
            let snapshot = fixture.seed("renewal-async-authority", resumed);
            let (guard, _handoff) = settlement_guard(&fixture, &caller, &snapshot, resumed).await;
            let original_budget = guard.execution_budget;
            let task_id = &snapshot.task().base().task_id;
            let original_lease = elected_lease(&fixture.store, task_id);
            fixture.store.authorization_gates[0].close();
            fixture.store.authorization_gates[1].close();
            fixture.store.forbid_sync.store(true, Ordering::SeqCst);
            let mut renewal = Box::pin(guard.renew_with_cx(&caller));
            drive_until(&host, renewal.as_mut(), || {
                fixture.store.authorization_gates[0]
                    .waiter
                    .lock()
                    .unwrap()
                    .is_some()
            })
            .await;
            assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 0);
            assert_eq!(elected_lease(&fixture.store, task_id), original_lease);
            let progressed = Arc::new(AtomicBool::new(false));
            let sibling_progressed = Arc::clone(&progressed);
            let mut sibling = host
                .spawn(move |_| async move {
                    sibling_progressed.store(true, Ordering::SeqCst);
                })
                .unwrap();
            sibling.join(&host).await.unwrap();
            assert!(progressed.load(Ordering::SeqCst));

            *fixture.store.clock.lock().unwrap() += StdDuration::from_secs(1);
            fixture.store.authorization_gates[0].release();
            drive_until(&host, renewal.as_mut(), || {
                fixture.store.authorization_gates[1]
                    .waiter
                    .lock()
                    .unwrap()
                    .is_some()
            })
            .await;
            assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.store.renewals.load(Ordering::SeqCst), 1);
            assert_ne!(elected_lease(&fixture.store, task_id), original_lease);
            assert_eq!(guard.execution_budget, original_budget);
            fixture.store.authorization_gates[1].release();
            assert!(renewal.await.unwrap());
            // The renewal future has completed before its post-poll proof.
            // Re-polling it instead of retaining Ready would panic here.
            assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.store.authorization_calls.load(Ordering::SeqCst), 2);
            assert_eq!(fixture.store.sync_calls.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.store.sync_renewal_calls.load(Ordering::SeqCst), 0);
            fixture.store.forbid_sync.store(false, Ordering::SeqCst);
            drop(guard);
            fixture.assert_recoverable(&snapshot, resumed);
        });
    }
}

#[test]
fn async_dispatch_renewal_rejects_changed_authority_on_both_sides() {
    for after_renewal in [false, true] {
        for invalid in 0..5 {
            run(|caller| async move {
                let host = Cx::current().unwrap();
                let fixture = Fixture::new();
                let snapshot = fixture.seed("renewal-authority-substitution", false);
                let (guard, _handoff) = settlement_guard(&fixture, &caller, &snapshot, false).await;
                let expected = guard.execution_authorization.as_ref().unwrap();
                let gate = &fixture.store.authorization_gates[usize::from(after_renewal)];
                gate.close();
                fixture.store.forbid_sync.store(true, Ordering::SeqCst);
                let mut renewal = Box::pin(guard.renew_with_cx(&caller));
                drive_until(&host, renewal.as_mut(), || {
                    gate.waiter.lock().unwrap().is_some()
                })
                .await;
                let lease = elected_lease(&fixture.store, expected.task_id());
                if invalid == 4 {
                    fixture
                        .store
                        .fail_authorization
                        .store(true, Ordering::SeqCst);
                } else {
                    *fixture.store.substitute_authorization.lock().unwrap() =
                        Some(FinalTaskAccessMetadata::new(
                            if invalid == 0 {
                                FinalTaskId::parse("another-renewal-task").unwrap()
                            } else {
                                expected.task_id().clone()
                            },
                            if invalid == 1 {
                                expected.generation().checked_sub(1).unwrap()
                            } else {
                                expected.generation()
                            },
                            expected.creation_generation() + u64::from(invalid == 2),
                            if invalid == 3 {
                                Some(Sha256Digest::from_bytes([91; 32]))
                            } else {
                                expected.authenticated_principal()
                            },
                            expected.original_operation().cloned(),
                        ));
                }
                gate.release();
                let error = renewal.await.unwrap_err();
                assert_eq!(error.message, "Task execution is no longer authorized");
                assert!(guard.execution_revoked.load(Ordering::Acquire));
                assert_eq!(
                    fixture.store.async_renewal_calls.load(Ordering::SeqCst),
                    usize::from(after_renewal)
                );
                assert_eq!(
                    fixture.store.renewals.load(Ordering::SeqCst),
                    usize::from(after_renewal)
                );
                assert_eq!(elected_lease(&fixture.store, expected.task_id()), lease);
                let current = fixture
                    .store
                    .inner
                    .get_task_snapshot(expected.task_id())
                    .unwrap()
                    .unwrap();
                assert_eq!(current.generation(), snapshot.generation());
                assert!(final_tasks_match_exactly(current.task(), snapshot.task()).unwrap());
                assert_eq!(fixture.store.sync_calls.load(Ordering::SeqCst), 0);
                fixture.store.forbid_sync.store(false, Ordering::SeqCst);
                drop(guard);
                assert_eq!(fixture.store.inner.active_task_count(), 0);
            });
        }
    }
}

struct RenewalPolicy {
    revoked: AtomicBool,
    generation: Option<u64>,
}

impl TaskExecutionAuthorizer for RenewalPolicy {
    fn authorize(&self, metadata: &FinalTaskAccessMetadata) -> McpResult<()> {
        if self.revoked.load(Ordering::SeqCst)
            || self
                .generation
                .is_some_and(|generation| generation != metadata.generation())
        {
            Err(McpError::invalid_request("private renewal policy denial"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn async_dispatch_renewal_continuity_and_fallback_keep_generation_fences() {
    for (continuity, updated) in [(true, true), (false, false), (false, true)] {
        run(|caller| async move {
            let host = Cx::current().unwrap();
            let fixture = Fixture::new();
            let snapshot = fixture.seed("renewal-generation-fence", false);
            let (guard, _handoff) = settlement_guard(&fixture, &caller, &snapshot, false).await;
            let current = if updated {
                let task = FinalTask::Working(
                    transition_final_task_base(
                        snapshot.task().base().clone(),
                        FinalTaskStatus::Working,
                        Some("same invocation, newer status".to_owned()),
                    )
                    .unwrap(),
                );
                fixture
                    .store
                    .inner
                    .update_working_status_for_handoff_if_current(
                        &snapshot,
                        &guard.owner_id,
                        guard.dispatch_fence.unwrap(),
                        task.clone(),
                        final_task_notification(&task),
                    )
                    .unwrap()
                    .unwrap()
            } else {
                snapshot.clone()
            };
            fixture
                .runtime
                .install_execution_authorizer(Arc::new(RenewalPolicy {
                    revoked: AtomicBool::new(false),
                    generation: continuity.then_some(current.generation()),
                }))
                .unwrap();
            fixture
                .store
                .omit_continuity
                .store(!continuity, Ordering::SeqCst);
            fixture.store.forbid_sync.store(true, Ordering::SeqCst);
            let metadata_calls = fixture.store.count(Step::Metadata);
            let mut renewal = Box::pin(guard.renew_with_cx(&caller));
            if continuity {
                // A pending newer-generation proof must not be rejected using
                // the original claim's now-stale policy input.
                fixture.store.authorization_gates[0].close();
                fixture.store.authorization_gates[1].close();
                drive_until(&host, renewal.as_mut(), || {
                    fixture.store.authorization_gates[0]
                        .waiter
                        .lock()
                        .unwrap()
                        .is_some()
                })
                .await;
                assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 0);
                fixture.store.authorization_gates[0].release();
                drive_until(&host, renewal.as_mut(), || {
                    fixture.store.authorization_gates[1]
                        .waiter
                        .lock()
                        .unwrap()
                        .is_some()
                })
                .await;
                fixture.store.authorization_gates[1].release();
            } else {
                fixture.store.gate(Step::Metadata).close();
                drive_until(&host, renewal.as_mut(), || {
                    fixture.store.count(Step::Metadata) > metadata_calls
                })
                .await;
                fixture.store.gate(Step::Metadata).release();
            }
            let accepted = continuity || !updated;
            if accepted {
                assert!(renewal.await.unwrap());
            } else {
                assert_eq!(
                    renewal.await.unwrap_err().message,
                    "Task execution is no longer authorized"
                );
            }
            assert_eq!(
                fixture.store.renewals.load(Ordering::SeqCst),
                usize::from(accepted)
            );
            assert_eq!(
                fixture.store.count(Step::Metadata) - metadata_calls,
                if continuity {
                    0
                } else if accepted {
                    2
                } else {
                    1
                }
            );
            assert_eq!(fixture.store.sync_calls.load(Ordering::SeqCst), 0);
            fixture.store.forbid_sync.store(false, Ordering::SeqCst);
            drop(guard);
            assert_eq!(fixture.store.inner.active_task_count(), 0);
        });
    }
}

#[test]
fn async_dispatch_renewal_pending_proof_never_admits_revoked_work() {
    for after_renewal in [false, true] {
        run(|caller| async move {
            let host = Cx::current().unwrap();
            let fixture = Fixture::new();
            let policy = Arc::new(RenewalPolicy {
                revoked: AtomicBool::new(false),
                generation: None,
            });
            fixture
                .runtime
                .install_execution_authorizer(policy.clone())
                .unwrap();
            let snapshot = fixture.seed("renewal-authority-revoked", false);
            let (guard, _handoff) = settlement_guard(&fixture, &caller, &snapshot, false).await;
            let gate = &fixture.store.authorization_gates[usize::from(after_renewal)];
            gate.close();
            fixture.store.forbid_sync.store(true, Ordering::SeqCst);
            let mut renewal = Box::pin(guard.renew_with_cx(&caller));
            drive_until(&host, renewal.as_mut(), || {
                gate.waiter.lock().unwrap().is_some()
            })
            .await;
            policy.revoked.store(true, Ordering::SeqCst);
            std::future::poll_fn(|task| {
                assert!(renewal.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(
                fixture.store.async_renewal_calls.load(Ordering::SeqCst),
                usize::from(after_renewal)
            );
            assert_eq!(
                fixture.store.renewals.load(Ordering::SeqCst),
                usize::from(after_renewal)
            );
            gate.release();
            assert_eq!(
                renewal.await.unwrap_err().message,
                "Task execution is no longer authorized"
            );
            assert!(guard.execution_revoked.load(Ordering::Acquire));
            assert_eq!(
                fixture.store.async_renewal_calls.load(Ordering::SeqCst),
                usize::from(after_renewal)
            );
            assert_eq!(fixture.store.sync_calls.load(Ordering::SeqCst), 0);
            fixture.store.forbid_sync.store(false, Ordering::SeqCst);
            drop(guard);
            assert_eq!(fixture.store.inner.active_task_count(), 0);
        });
    }
}

#[test]
fn async_dispatch_renewal_policy_cannot_release_late_receipt() {
    struct CancelOnProof {
        store: Arc<AsyncRecoveryStore>,
        caller: Cx,
        expire: bool,
    }
    impl TaskExecutionAuthorizer for CancelOnProof {
        fn authorize(&self, _: &FinalTaskAccessMetadata) -> McpResult<()> {
            if self.store.authorization_calls.load(Ordering::SeqCst) >= 2 {
                if self.expire {
                    *self.store.clock.lock().unwrap() += StdDuration::from_secs(60);
                } else {
                    self.caller
                        .cancel_with(asupersync::types::CancelKind::User, None);
                }
            }
            Ok(())
        }
    }
    for expire in [false, true] {
        run(|caller| async move {
            let fixture = Fixture::new();
            let snapshot = fixture.seed("renewal-policy-late-receipt", false);
            let (guard, _handoff) = settlement_guard(&fixture, &caller, &snapshot, false).await;
            fixture
                .runtime
                .install_execution_authorizer(Arc::new(CancelOnProof {
                    store: Arc::clone(&fixture.store),
                    caller: caller.clone(),
                    expire,
                }))
                .unwrap();
            fixture.store.forbid_sync.store(true, Ordering::SeqCst);
            let result = guard.renew_with_cx(&caller).await;
            if expire {
                assert!(!result.unwrap());
            } else {
                assert!(result.is_err());
            }
            assert_eq!(fixture.store.renewals.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.store.sync_calls.load(Ordering::SeqCst), 0);
            fixture.store.forbid_sync.store(false, Ordering::SeqCst);
            drop(guard);
            assert_eq!(fixture.store.inner.active_task_count(), 0);
        });
    }
}

#[test]
fn async_dispatch_renewal_silent_authorization_observes_terminal_bounds() {
    for after_renewal in [false, true] {
        for terminal in 0..3 {
            run(|caller| async move {
                let host = Cx::current().unwrap();
                let fixture = Fixture::with_store(AsyncRecoveryStore::with_limits(
                    FinalTaskExecutionLimits::new(
                        StdDuration::from_millis(100),
                        StdDuration::from_millis(100),
                        3,
                    )
                    .unwrap(),
                ));
                let snapshot = fixture.seed("renewal-authority-bound", false);
                let (guard, _handoff) = settlement_guard(&fixture, &caller, &snapshot, false).await;
                let original_budget = guard.execution_budget;
                let gate = &fixture.store.authorization_gates[usize::from(after_renewal)];
                gate.close();
                fixture.store.forbid_sync.store(true, Ordering::SeqCst);
                let mut renewal = Box::pin(guard.renew_with_cx(&caller));
                drive_until(&host, renewal.as_mut(), || {
                    gate.waiter.lock().unwrap().is_some()
                })
                .await;
                if terminal == 2 {
                    drop(renewal);
                } else {
                    let trigger_caller = caller.clone();
                    let trigger_store = Arc::clone(&fixture.store);
                    let mut trigger = host
                        .spawn(move |cx| async move {
                            asupersync::time::sleep(cx.now(), StdDuration::from_millis(1)).await;
                            if terminal == 0 {
                                trigger_caller
                                    .cancel_with(asupersync::types::CancelKind::User, None);
                            } else {
                                *trigger_store.clock.lock().unwrap() +=
                                    StdDuration::from_millis(100);
                            }
                        })
                        .unwrap();
                    // Storage never wakes: only the renewal's independent
                    // checkpoint can observe these terminal conditions.
                    let result =
                        asupersync::time::timeout(host.now(), StdDuration::from_secs(1), renewal)
                            .await
                            .unwrap();
                    if terminal == 1 {
                        assert!(!result.unwrap());
                    } else {
                        assert!(result.is_err());
                    }
                    trigger.join(&host).await.unwrap();
                }
                assert_eq!(gate.abandoned.load(Ordering::SeqCst), 1);
                assert_eq!(
                    fixture.store.renewals.load(Ordering::SeqCst),
                    usize::from(after_renewal)
                );
                assert_eq!(
                    fixture.store.async_renewal_calls.load(Ordering::SeqCst),
                    usize::from(after_renewal)
                );
                assert_eq!(guard.execution_budget, original_budget);
                assert_eq!(fixture.store.sync_calls.load(Ordering::SeqCst), 0);
                fixture.store.forbid_sync.store(false, Ordering::SeqCst);
                drop(guard);
                assert_eq!(fixture.store.inner.active_task_count(), 0);
            });
        }
    }
}

#[test]
fn async_dispatch_renewal_retains_provider_wake_during_authorization() {
    struct CountWake(AtomicUsize);
    impl std::task::Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    run(|caller| async move {
        let fixture = Fixture::new();
        let snapshot = fixture.seed("renewal-authority-wake", false);
        let (guard, _handoff) = settlement_guard(&fixture, &caller, &snapshot, false).await;
        *fixture.store.renewal_pause_for.lock().unwrap() =
            Some(snapshot.task().base().task_id.clone());
        fixture.store.renewal_gate.close();
        fixture.store.authorization_gates[1].close();
        fixture.store.forbid_sync.store(true, Ordering::SeqCst);
        let wake = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(wake.clone());
        let mut task = std::task::Context::from_waker(&waker);
        let mut renewal = super::FinalTaskLeaseRenewal::default();
        assert!(renewal.poll(&caller, &guard, &mut task).is_pending());
        assert!(
            fixture.store.authorization_gates[1]
                .waiter
                .lock()
                .unwrap()
                .is_some()
        );
        fixture.store.renewal_gate.release();
        fixture.store.authorization_gates[1].release();
        wake.0.store(0, Ordering::SeqCst);
        assert!(renewal.poll(&caller, &guard, &mut task).is_pending());
        assert!(
            wake.0.load(Ordering::SeqCst) > 0,
            "the renewal wake must outlive the suspended post-poll proof"
        );
        assert!(matches!(
            renewal.poll(&caller, &guard, &mut task),
            Poll::Ready(Ok(true))
        ));
        assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.renewals.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.sync_calls.load(Ordering::SeqCst), 0);
        fixture.store.forbid_sync.store(false, Ordering::SeqCst);
        drop(guard);
        fixture.assert_recoverable(&snapshot, false);
    });
}

#[test]
fn async_dispatch_renewal_yields_before_application_entry() {
    run(|caller| async move {
        let host = Cx::current().unwrap();
        let fixture = Fixture::new();
        let sibling = fixture.seed("a-renewal-sibling", false);
        let target = fixture.seed("z-renewal-pending", false);
        let target_id = target.task().base().task_id.clone();
        *fixture.store.renewal_pause_for.lock().unwrap() = Some(target_id.clone());
        fixture.store.renewal_gate.close();
        let supervisor = Arc::new(PendingSupervisor::new());
        let mut runner = fixture
            .runtime
            .install_task_service(2, supervisor.clone())
            .unwrap()
            .with_max_concurrent_handoffs(2)
            .unwrap();
        let mut service = Box::pin(runner.run_service(&caller));
        drive_until(&host, service.as_mut(), || {
            fixture.store.renewal_gate.waiter.lock().unwrap().is_some()
                && supervisor.progressed.load(Ordering::SeqCst) == 1
        })
        .await;
        assert_eq!(supervisor.constructed.load(Ordering::SeqCst), 1);
        assert_eq!(
            supervisor.started.lock().unwrap().as_slice(),
            &[sibling.task().base().task_id.clone()]
        );
        let original_lease = elected_lease(&fixture.store, &target_id);
        let renewals = fixture.store.renewals.load(Ordering::SeqCst);
        drive_until(&host, service.as_mut(), || {
            fixture.store.renewals.load(Ordering::SeqCst) > renewals
        })
        .await;
        assert_eq!(elected_lease(&fixture.store, &target_id), original_lease);
        assert_eq!(supervisor.constructed.load(Ordering::SeqCst), 1);
        assert_eq!(supervisor.started.lock().unwrap().len(), 1);
        assert_eq!(fixture.store.sync_renewal_calls.load(Ordering::SeqCst), 0);

        fixture.store.renewal_gate.release();
        drive_until(&host, service.as_mut(), || {
            supervisor.started.lock().unwrap().len() == 2
        })
        .await;
        assert!(supervisor.started.lock().unwrap().contains(&target_id));
        caller.cancel_with(asupersync::types::CancelKind::User, None);
        asupersync::time::timeout(host.now(), StdDuration::from_secs(3), service.as_mut())
            .await
            .unwrap()
            .unwrap();
        drop(service);
        wait_until(&host, || fixture.store.inner.active_task_count() == 0).await;
        assert_eq!(supervisor.active.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.restored.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.store.sync_renewal_calls.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn async_dispatch_renewal_lost_fence_stops_application() {
    run(|caller| async move {
        let host = Cx::current().unwrap();
        let fixture = Fixture::new();
        let target = fixture.seed("renewal-lost-fence", false);
        let task_id = target.task().base().task_id.clone();
        *fixture.store.renewal_pause_for.lock().unwrap() = Some(task_id.clone());
        fixture.store.renewal_gate.close();
        let supervisor = Arc::new(PendingSupervisor::new());
        let mut runner = fixture
            .runtime
            .install_task_service(1, supervisor.clone())
            .unwrap();
        let mut service = Box::pin(runner.run_service(&caller));
        drive_until(&host, service.as_mut(), || {
            fixture.store.renewal_gate.waiter.lock().unwrap().is_some()
        })
        .await;
        assert_eq!(supervisor.constructed.load(Ordering::SeqCst), 0);
        *fixture.store.refuse_renewal_for.lock().unwrap() = Some(task_id);
        fixture.store.renewal_gate.release();
        let result =
            asupersync::time::timeout(host.now(), StdDuration::from_secs(3), service.as_mut())
                .await
                .unwrap();
        assert!(result.is_err());
        drop(service);
        assert_eq!(supervisor.constructed.load(Ordering::SeqCst), 0);
        assert!(supervisor.started.lock().unwrap().is_empty());
        assert_eq!(supervisor.active.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.sync_renewal_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.renewals.load(Ordering::SeqCst), 0);
        fixture.assert_recoverable(&target, false);
        assert_eq!(fixture.store.inner.active_task_count(), 0);
    });
}

#[test]
fn async_dispatch_renewal_cancellation_drops_pending_provider() {
    for resumed in [false, true] {
        for cancel in [false, true] {
            run(|caller| async move {
                let host = Cx::current().unwrap();
                let fixture = Fixture::new();
                let snapshot = fixture.seed("renewal-abandonment", resumed);
                let handoff = recover(&fixture, &caller, &snapshot, resumed, true, "renewal-owner")
                    .await
                    .unwrap()
                    .unwrap();
                let mut guard =
                    FinalTaskExecutionGuard::new(&fixture.runtime, "renewal-owner", &handoff);
                let stop = AtomicBool::new(false);
                assert!(guard.elect_with_cx(&caller, &stop).await.unwrap());
                *fixture.store.renewal_pause_for.lock().unwrap() =
                    Some(snapshot.task().base().task_id.clone());
                fixture.store.renewal_gate.close();
                let mut renewal = Box::pin(guard.renew_with_cx(&caller));
                drive_until(&host, renewal.as_mut(), || {
                    fixture.store.renewal_gate.waiter.lock().unwrap().is_some()
                })
                .await;
                if cancel {
                    caller.cancel_with(asupersync::types::CancelKind::User, None);
                    assert!(renewal.await.is_err());
                } else {
                    drop(renewal);
                }
                assert_eq!(
                    fixture.store.renewal_gate.abandoned.load(Ordering::SeqCst),
                    1
                );
                assert_eq!(fixture.store.renewals.load(Ordering::SeqCst), 0);
                assert_eq!(fixture.store.sync_renewal_calls.load(Ordering::SeqCst), 0);
                drop(guard);
                assert_eq!(fixture.store.restored.load(Ordering::SeqCst), 1);
                fixture.assert_recoverable(&snapshot, resumed);
                assert_eq!(fixture.store.inner.active_task_count(), 0);
            });
        }
    }
}

#[test]
fn async_dispatch_renewal_deadline_bounds_silent_provider() {
    run(|caller| async move {
        let host = Cx::current().unwrap();
        let fixture = Fixture::with_store(AsyncRecoveryStore::with_limits(
            FinalTaskExecutionLimits::new(
                StdDuration::from_millis(100),
                StdDuration::from_millis(100),
                3,
            )
            .unwrap(),
        ));
        let snapshot = fixture.seed("renewal-deadline", false);
        let handoff = recover(
            &fixture,
            &caller,
            &snapshot,
            false,
            true,
            "renewal-deadline-owner",
        )
        .await
        .unwrap()
        .unwrap();
        let mut guard =
            FinalTaskExecutionGuard::new(&fixture.runtime, "renewal-deadline-owner", &handoff);
        let stop = AtomicBool::new(false);
        assert!(guard.elect_with_cx(&caller, &stop).await.unwrap());
        let original_budget = guard.execution_budget.unwrap();
        *fixture.store.renewal_pause_for.lock().unwrap() =
            Some(snapshot.task().base().task_id.clone());
        fixture.store.renewal_gate.close();
        let mut renewal = Box::pin(guard.renew_with_cx(&caller));
        drive_until(&host, renewal.as_mut(), || {
            fixture.store.renewal_gate.waiter.lock().unwrap().is_some()
        })
        .await;
        let clock = Arc::clone(&fixture.store.clock);
        let mut advance_clock = host
            .spawn(move |cx| async move {
                asupersync::time::sleep(cx.now(), StdDuration::from_millis(1)).await;
                *clock.lock().unwrap() += StdDuration::from_millis(100);
            })
            .unwrap();
        // Leave storage parked and do not join the clock task yet: the
        // renewal's own checkpoint must wake it to observe backend expiry.
        assert!(
            !asupersync::time::timeout(host.now(), StdDuration::from_secs(1), renewal)
                .await
                .unwrap()
                .unwrap()
        );
        advance_clock.join(&host).await.unwrap();
        assert_eq!(guard.execution_budget, Some(original_budget));
        assert_eq!(fixture.store.renewals.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.sync_renewal_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.store.renewal_gate.abandoned.load(Ordering::SeqCst),
            1
        );
        drop(guard);
        assert!(matches!(
            fixture
                .store
                .inner
                .get_task(&snapshot.task().base().task_id)
                .unwrap(),
            Some(FinalTask::Failed { .. }),
        ));
        assert_eq!(fixture.store.restored.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.inner.active_task_count(), 0);
    });
}

struct RenewalCleanupSupervisor {
    store: Arc<AsyncRecoveryStore>,
    started: AtomicBool,
    polls: AtomicUsize,
    cleanup_finished: AtomicBool,
}

impl ApplicationTaskSupervisor for RenewalCleanupSupervisor {
    fn resume<'a>(
        &'a self,
        cx: &'a Cx,
        handoff: FinalTaskSupervisorHandoff,
    ) -> FinalTaskSupervisorFuture<'a> {
        Box::pin(async move {
            assert!(!self.started.swap(true, Ordering::SeqCst));
            *self.store.renewal_pause_for.lock().unwrap() =
                Some(final_task_handoff_task_id(&handoff).clone());
            self.store.renewal_gate.close();
            std::future::poll_fn(|task| {
                self.polls.fetch_add(1, Ordering::SeqCst);
                let requested = match &handoff {
                    FinalTaskSupervisorHandoff::Initial(work) => work.is_cancellation_requested(),
                    FinalTaskSupervisorHandoff::Resumed(work) => work.is_cancellation_requested(),
                };
                match requested {
                    Ok(true) => Poll::Ready(Ok(())),
                    Ok(false) => {
                        // Offer another application poll; its mandatory
                        // renewal must park before application re-entry.
                        task.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(error) => Poll::Ready(Err(error)),
                }
            })
            .await?;
            asupersync::time::sleep(cx.now(), StdDuration::from_millis(1)).await;
            self.cleanup_finished.store(true, Ordering::SeqCst);
            Ok(())
        })
    }
}

#[test]
fn async_dispatch_renewal_preserves_started_cancellation_grace() {
    for release_renewal in [false, true] {
        run(|caller| async move {
            let host = Cx::current().unwrap();
            let fixture = Fixture::new();
            let target = fixture.seed("renewal-cancellation-grace", false);
            let task_id = target.task().base().task_id.clone();
            let supervisor = Arc::new(RenewalCleanupSupervisor {
                store: Arc::clone(&fixture.store),
                started: AtomicBool::new(false),
                polls: AtomicUsize::new(0),
                cleanup_finished: AtomicBool::new(false),
            });
            let mut runner = fixture
                .runtime
                .install_task_service(1, supervisor.clone())
                .unwrap();
            let mut service = Box::pin(runner.run_service(&caller));
            drive_until(&host, service.as_mut(), || {
                supervisor.started.load(Ordering::SeqCst)
                    && fixture.store.renewal_gate.waiter.lock().unwrap().is_some()
            })
            .await;
            let application_polls = supervisor.polls.load(Ordering::SeqCst);
            fixture.runtime.cancel_task(&task_id).unwrap();
            if release_renewal {
                fixture.store.renewal_gate.release();
            }
            drive_until(&host, service.as_mut(), || {
                fixture.store.inner.active_task_count() == 0
            })
            .await;
            assert!(matches!(
                fixture.store.inner.get_task(&task_id).unwrap(),
                Some(FinalTask::Cancelled(_)),
            ));
            assert_eq!(
                supervisor.cleanup_finished.load(Ordering::SeqCst),
                release_renewal,
            );
            if release_renewal {
                assert!(supervisor.polls.load(Ordering::SeqCst) > application_polls);
                assert_eq!(
                    fixture.store.renewal_gate.abandoned.load(Ordering::SeqCst),
                    0
                );
            } else {
                assert_eq!(supervisor.polls.load(Ordering::SeqCst), application_polls);
                assert_eq!(
                    fixture.store.renewal_gate.abandoned.load(Ordering::SeqCst),
                    1
                );
            }
            assert_eq!(fixture.store.sync_renewal_calls.load(Ordering::SeqCst), 0);
            assert!(caller.checkpoint().is_ok());
            drop(service);
            assert!(!fixture.runtime.is_task_service_ready());
        });
    }
}

#[test]
fn task_dispatch_async_pending_election_keeps_siblings_live_and_settles_service_stop() {
    for finish in ["release", "error", "cancel", "drop"] {
        run(|caller| async move {
            let host = Cx::current().unwrap();
            let fixture = Fixture::new();
            let first = fixture.seed("a-dispatch-active", false);
            let second = fixture.seed("z-dispatch-parked", false);
            let supervisor = Arc::new(PendingSupervisor::new());
            let mut runner = fixture
                .runtime
                .install_task_service(2, supervisor.clone())
                .unwrap()
                .with_max_concurrent_handoffs(2)
                .unwrap();
            *fixture.store.election_pause_for.lock().unwrap() =
                Some(second.task().base().task_id.clone());
            fixture.store.gate(Step::Election).close();
            let mut service = Box::pin(runner.run_service(&caller));
            drive_until(&host, service.as_mut(), || {
                fixture.store.count(Step::Election) >= 2
                    && supervisor.progressed.load(Ordering::SeqCst) == 1
            })
            .await;
            assert_eq!(
                supervisor.started.lock().unwrap().as_slice(),
                &[first.task().base().task_id.clone()]
            );
            let renewed = fixture.store.renewals.load(Ordering::SeqCst);
            drive_until(&host, service.as_mut(), || {
                fixture.store.renewals.load(Ordering::SeqCst) > renewed
            })
            .await;
            match finish {
                "release" => {
                    fixture.store.gate(Step::Election).release();
                    drive_until(&host, service.as_mut(), || {
                        supervisor.started.lock().unwrap().len() == 2
                    })
                    .await;
                    caller.cancel_with(asupersync::types::CancelKind::User, None);
                    asupersync::time::timeout(
                        host.now(),
                        StdDuration::from_secs(3),
                        service.as_mut(),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    drop(service);
                }
                "error" => {
                    supervisor.release.release();
                    assert!(
                        asupersync::time::timeout(
                            host.now(),
                            StdDuration::from_secs(3),
                            service.as_mut(),
                        )
                        .await
                        .unwrap()
                        .is_err()
                    );
                    drop(service);
                }
                "cancel" => {
                    caller.cancel_with(asupersync::types::CancelKind::User, None);
                    asupersync::time::timeout(
                        host.now(),
                        StdDuration::from_secs(3),
                        service.as_mut(),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    drop(service);
                }
                "drop" => drop(service),
                _ => unreachable!(),
            }
            wait_until(&host, || supervisor.active.load(Ordering::SeqCst) == 0).await;
            assert!(!fixture.runtime.is_task_service_ready());
            if finish == "release" {
                wait_until(&host, || fixture.store.inner.active_task_count() == 0).await;
                assert_eq!(supervisor.started.lock().unwrap().len(), 2);
                assert_eq!(fixture.store.restored.load(Ordering::SeqCst), 2);
            } else {
                assert_eq!(supervisor.started.lock().unwrap().len(), 1);
                assert_eq!(
                    fixture
                        .store
                        .gate(Step::Election)
                        .abandoned
                        .load(Ordering::SeqCst),
                    1
                );
                {
                    let state = fixture.store.inner.state.lock().unwrap();
                    let lease = state
                        .handoff_leases
                        .get(&second.task().base().task_id)
                        .unwrap();
                    assert!(!lease.dispatch_elected);
                    assert!(lease.dispatch_fence.is_none());
                }
                // A dropped service still owns its already-running child
                // until cleanup restores that first lease. Do not advance its
                // backend clock while that independent cleanup is in flight.
                wait_until(&host, || {
                    !fixture
                        .store
                        .inner
                        .state
                        .lock()
                        .unwrap()
                        .handoff_leases
                        .contains_key(&first.task().base().task_id)
                })
                .await;
                // The framework cannot infer a noncommit from an abandoned
                // provider. Its original finite claim remains until expiry.
                *fixture.store.clock.lock().unwrap() += IN_MEMORY_FINAL_TASK_HANDOFF_LEASE;
                let recovered = fixture
                    .store
                    .inner
                    .get_task_snapshot(&second.task().base().task_id)
                    .unwrap()
                    .unwrap();
                assert!(recovered.generation() > second.generation());
                assert!(final_tasks_match_exactly(recovered.task(), second.task()).unwrap());
                wait_until(&host, || fixture.store.inner.active_task_count() == 0).await;
            }
        });
    }
}

async fn settlement_guard(
    fixture: &Fixture,
    caller: &Cx,
    snapshot: &FinalTaskSnapshot,
    resumed: bool,
) -> (FinalTaskExecutionGuard, FinalTaskSupervisorHandoff) {
    let owner = "settlement-owner";
    let mut handoff = recover(fixture, caller, snapshot, resumed, true, owner)
        .await
        .unwrap()
        .unwrap();
    assert_handoff(&handoff, snapshot, resumed);
    let mut guard = FinalTaskExecutionGuard::new(&fixture.runtime, owner, &handoff);
    assert!(guard.elect_with_cx(caller, &AtomicBool::new(false)).await.unwrap());
    handoff.attach_authority(guard.authority().unwrap());
    (guard, handoff)
}

fn complete_settlement_work(handoff: FinalTaskSupervisorHandoff) {
    let result = serde_json::from_value(serde_json::json!({
        "content": [{"type": "text", "text": "durably committed"}]
    }))
    .unwrap();
    match handoff {
        FinalTaskSupervisorHandoff::Initial(work) => work.complete_task(result, None),
        FinalTaskSupervisorHandoff::Resumed(work) => work.complete_task(result, None),
    }
    .unwrap();
}

#[test]
fn task_dispatch_async_settlement_preserves_the_transition_or_exact_work() {
    for resumed in [false, true] {
        for outcome in ["complete", "error", "no-transition"] {
            run(|caller| async move {
                let host = Cx::current().unwrap();
                let fixture = Fixture::new();
                let snapshot = fixture.seed("settlement-result", resumed);
                let (guard, handoff) = settlement_guard(&fixture, &caller, &snapshot, resumed).await;
                let (step, application_result) = if outcome == "complete" {
                    complete_settlement_work(handoff);
                    (Step::Finish, Ok(()))
                } else {
                    let result = if outcome == "error" {
                        Err(McpError::internal_error("provider work failed"))
                    } else {
                        Ok(())
                    };
                    (if resumed { Step::RestoreInput } else { Step::RestoreInitial }, result)
                };

                fixture.store.gate(step).close();
                let mut operation = Box::pin(FinalTaskHandoffExecutor::finish_handoff(
                    &caller, guard, application_result,
                ));
                drive_until(&host, operation.as_mut(), || {
                    fixture.store.gate(step).waiter.lock().unwrap().is_some()
                })
                .await;
                assert_eq!(fixture.store.restored.load(Ordering::SeqCst), 0);
                fixture.store.gate(step).release();
                let result = operation.await;
                assert_eq!(fixture.store.count(step), 1);
                assert_eq!(fixture.store.sync_settlements.load(Ordering::SeqCst), 0);
                assert_eq!(fixture.store.inner.active_task_count(), 0);
                if outcome == "complete" {
                    result.unwrap();
                    let task = fixture.store.inner.get_task(&snapshot.task().base().task_id).unwrap().unwrap();
                    assert!(matches!(task, FinalTask::Completed { .. }));
                    assert!(fixture.store.next_candidate(resumed).is_none());
                    assert_eq!(fixture.emitted.lock().unwrap().len(), 1);
                } else {
                    assert!(result.is_err());
                    assert_eq!(fixture.store.restored.load(Ordering::SeqCst), 1);
                    fixture.assert_recoverable(&snapshot, resumed);
                    let work = recover(&fixture, &caller, &snapshot, resumed, true, "replacement-owner")
                        .await.unwrap().unwrap();
                    assert_handoff(&work, &snapshot, resumed);
                }
            });
        }
    }
}

#[test]
fn task_dispatch_async_settlement_abandonment_never_repeats_a_storage_mutation() {
    for resumed in [false, true] {
        for after_commit in [false, true] {
            for cancel in [false, true] {
                run(|caller| async move {
                    let host = Cx::current().unwrap();
                    let fixture = Fixture::new();
                    let snapshot = fixture.seed("settlement-uncertain", resumed);
                    let (guard, _handoff) = settlement_guard(&fixture, &caller, &snapshot, resumed).await;
                    let step = if resumed { Step::RestoreInput } else { Step::RestoreInitial };
                    let gate = if after_commit { &fixture.store.settlement_receipt } else { fixture.store.gate(step) };
                    gate.close();
                    let mut operation = Box::pin(FinalTaskHandoffExecutor::finish_handoff(
                        &caller, guard, Err(McpError::internal_error("interrupted work")),
                    ));
                    drive_until(&host, operation.as_mut(), || gate.waiter.lock().unwrap().is_some()).await;
                    if cancel {
                        caller.cancel_with(asupersync::types::CancelKind::User, None);
                        assert!(operation.await.is_err());
                    } else {
                        drop(operation);
                    }
                    assert_eq!(gate.abandoned.load(Ordering::SeqCst), 1);
                    assert_eq!(fixture.store.count(step), 1);
                    assert_eq!(fixture.store.sync_settlements.load(Ordering::SeqCst), 0);
                    assert_eq!(fixture.store.restored.load(Ordering::SeqCst), usize::from(after_commit));
                    if !after_commit {
                        assert!(fixture.store.next_candidate(resumed).is_none());
                        let (_, owner, _, _) = elected_lease(&fixture.store, &snapshot.task().base().task_id);
                        assert_eq!(owner, "settlement-owner");
                        *fixture.store.clock.lock().unwrap() += IN_MEMORY_FINAL_TASK_HANDOFF_LEASE;
                    }
                    fixture.assert_recoverable(&snapshot, resumed);
                    assert!(fixture.emitted.lock().unwrap().is_empty());
                });
            }
        }
    }
}

#[test]
fn task_dispatch_async_settlement_keeps_committed_success_through_custodian_cancellation() {
    for cancel_during_finish in [false, true] {
        run(|caller| async move {
            let host = Cx::current().unwrap();
            let fixture = Fixture::new();
            let snapshot = fixture.seed("settlement-committed", false);
            let (guard, handoff) = settlement_guard(&fixture, &caller, &snapshot, false).await;
            complete_settlement_work(handoff);
            fixture.store.gate(Step::Finish).close();
            let mut operation = Box::pin(FinalTaskHandoffExecutor::finish_handoff(
                &caller, guard, Ok(()),
            ));
            if cancel_during_finish {
                drive_until(&host, operation.as_mut(), || {
                    fixture.store.gate(Step::Finish).waiter.lock().unwrap().is_some()
                })
                .await;
            }
            caller.cancel_with(asupersync::types::CancelKind::User, None);
            operation.await.unwrap();
            assert_eq!(fixture.store.count(Step::Finish), usize::from(cancel_during_finish));
            assert_eq!(fixture.store.sync_settlements.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.store.inner.active_task_count(), 0);
            let task = fixture.store.inner.get_task(&snapshot.task().base().task_id).unwrap().unwrap();
            assert!(matches!(task, FinalTask::Completed { .. }));
            assert!(fixture.store.next_candidate(false).is_none());
            assert_eq!(fixture.emitted.lock().unwrap().len(), 1);
        });
    }
}

#[test]
fn trusted_async_read_expires_once_and_returns_the_committed_result() {
    run(|caller| async move {
        let fixture = Fixture::with_store(AsyncRecoveryStore::with_limits(
            FinalTaskExecutionLimits::new(
                StdDuration::from_millis(100),
                StdDuration::from_millis(100),
                3,
            )
            .unwrap(),
        ));
        let snapshot = fixture.seed("trusted-observation", false);
        let task_id = &snapshot.task().base().task_id;
        fixture.store.forbid_sync.store(true, Ordering::SeqCst);
        let observed = fixture.runtime.get_task_with_cx(&caller, task_id).await.unwrap();
        assert!(final_tasks_match_exactly(snapshot.task(), &observed.task).unwrap());
        assert!(fixture.emitted.lock().unwrap().is_empty());

        *fixture.store.clock.lock().unwrap() += StdDuration::from_millis(100);
        let received = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&received);
        let _observer = fixture.runtime.add_owned_notification_emitter(Arc::new(move |_, _| {
            assert!(!Cx::current().unwrap().capabilities().spawn);
            count.fetch_add(1, Ordering::SeqCst);
        }));
        let read = {
            // Expiry publication runs on the application caller. It performs
            // bounded store I/O and does not need permission to spawn a service.
            use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
            let _restriction = Cx::push_restriction(CapSet::<false, true, true, true, true>::MASK);
            fixture.runtime.get_task_with_cx(&caller, task_id)
        };
        let expired = read.await.unwrap();
        assert!(matches!(&expired.task, FinalTask::Failed { .. }));
        assert_eq!(received.load(Ordering::SeqCst), 1);
        let observed = fixture.runtime.get_task_with_cx(&caller, task_id).await.unwrap();
        assert!(final_tasks_match_exactly(&expired.task, &observed.task).unwrap());
        assert_eq!(fixture.emitted.lock().unwrap().len(), 1);
        assert_eq!(fixture.store.count(Step::Expire), 2);
        assert_eq!(fixture.store.sync_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.claimed.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn trusted_async_read_cancels_parked_snapshot_or_expiry_without_storage_progress() {
    for step in [Step::Read, Step::Expire] {
        run(|caller| async move {
            let host = Cx::current().unwrap();
            let fixture = Fixture::new();
            let snapshot = fixture.seed("trusted-cancelled-read", false);
            let task_id = &snapshot.task().base().task_id;
            fixture.store.forbid_sync.store(true, Ordering::SeqCst);
            fixture.store.gate(step).close();
            let mut read = Box::pin(fixture.runtime.get_task_with_cx(&caller, task_id));
            drive_until(&host, read.as_mut(), || fixture.store.count(step) == 1).await;
            caller.cancel_with(asupersync::types::CancelKind::User, None);
            assert_eq!(read.await.unwrap_err().code, McpError::request_cancelled().code);
            assert_eq!(fixture.store.gate(step).abandoned.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.store.sync_calls.load(Ordering::SeqCst), 0);
            assert!(fixture.emitted.lock().unwrap().is_empty());
        });
    }
}

#[test]
fn trusted_async_read_rejects_missing_and_substituted_task_ids_before_expiry() {
    run(|caller| async move {
        let fixture = Fixture::new();
        let snapshot = fixture.seed("other-task", false);
        let requested = FinalTaskId::parse("trusted-missing-task").unwrap();
        fixture.store.forbid_sync.store(true, Ordering::SeqCst);
        let missing = fixture.runtime.get_task_with_cx(&caller, &requested).await.unwrap_err();
        assert_eq!(missing.message, "Task not found");
        *fixture.store.substitute_read.lock().unwrap() = Some(snapshot);
        let wrong = fixture.runtime.get_task_with_cx(&caller, &requested).await.unwrap_err();
        assert_eq!(wrong.message, "Final task store returned a task under the wrong identifier");
        assert_eq!(fixture.store.count(Step::Expire), 0);
        assert_eq!(fixture.store.sync_calls.load(Ordering::SeqCst), 0);
    });
}


/// These regressions exercise the actual asynchronous entry/maintenance waits.
/// The outer supervisor's synchronous retirement and Drop paths remain outside
/// this boundary; disable the fixture's sync trap before explicitly dropping
/// its guard so that residual contract is neither hidden nor misclaimed.
async fn supervision_owner(
    fixture: &Fixture,
    caller: &Cx,
    snapshot: &FinalTaskSnapshot,
    resumed: bool,
) -> (
    AuthorizedTaskServiceRunner,
    FinalTaskExecutionGuard,
    FinalTaskCancellationWakeRegistration,
) {
    let runner = fixture
        .runtime
        .install_task_service(2, Arc::new(PendingSupervisor::new()))
        .unwrap();
    let handoff = recover(
        fixture,
        caller,
        snapshot,
        resumed,
        true,
        &runner.dispatch_owner,
    )
    .await
    .unwrap()
    .unwrap();
    let mut guard =
        FinalTaskExecutionGuard::new(&fixture.runtime, &runner.dispatch_owner, &handoff);
    assert!(guard.elect_with_cx(caller, &AtomicBool::new(false)).await.unwrap());
    let wake = fixture
        .runtime
        .register_task_cancellation_wake(runner.service_id, guard.task_id())
        .unwrap();
    (runner, guard, wake)
}

fn supervision_operation<'a>(
    maintenance: bool,
    executor: &'a FinalTaskHandoffExecutor,
    caller: &'a Cx,
    guard: &'a mut FinalTaskExecutionGuard,
    wake: &'a FinalTaskCancellationWakeRegistration,
) -> FinalTaskSupervisorFuture<'a> {
    if maintenance {
        Box::pin(executor.expire_pending_execution_with_lease_heartbeat(caller, guard, wake))
    } else {
        Box::pin(guard.ensure_live_dispatch_for_application_with_cx(caller, wake))
    }
}

fn assert_supervision_unchanged(fixture: &Fixture, expected: &FinalTaskSnapshot) {
    let current = fixture
        .store
        .inner
        .get_task_snapshot(&expected.task().base().task_id)
        .unwrap()
        .unwrap();
    assert_eq!(current.generation(), expected.generation());
    assert_eq!(current.creation_generation(), expected.creation_generation());
    assert!(final_tasks_match_exactly(current.task(), expected.task()).unwrap());
    assert!(fixture.emitted.lock().unwrap().is_empty());
    assert_eq!(fixture.store.sync_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.store.sync_renewal_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.store.sync_settlements.load(Ordering::SeqCst), 0);
}

#[test]
fn async_supervision_entry_awaits_metadata_snapshot_and_intent() {
    for resumed in [false, true] {
        for stage in ["metadata", "snapshot", "intent"] {
            run(|caller| async move {
                let host = Cx::current().unwrap();
                let fixture = Fixture::new();
                let snapshot = fixture.seed("supervision-entry", resumed);
                let (_runner, guard, wake) =
                    supervision_owner(&fixture, &caller, &snapshot, resumed).await;
                let gate = match stage {
                    "metadata" => &fixture.store.authorization_gates[0],
                    "snapshot" => fixture.store.gate(Step::Read),
                    _ => fixture.store.gate(Step::CancellationIntent),
                };
                gate.close();
                fixture.store.forbid_sync.store(true, Ordering::SeqCst);
                let mut pending =
                    Box::pin(guard.ensure_live_dispatch_for_application_with_cx(&caller, &wake));
                drive_until(&host, pending.as_mut(), || {
                    gate.waiter.lock().unwrap().is_some()
                })
                .await;
                assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 0);
                assert_supervision_unchanged(&fixture, &snapshot);

                gate.release();
                pending.await.unwrap();
                assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 1);
                assert_eq!(fixture.store.renewals.load(Ordering::SeqCst), 1);
                assert_supervision_unchanged(&fixture, &snapshot);
                fixture.store.forbid_sync.store(false, Ordering::SeqCst);
                drop(guard);
                fixture.assert_recoverable(&snapshot, resumed);
            });
        }
    }
}

#[test]
fn async_supervision_maintenance_retains_ready_result_during_post_proof() {
    run(|caller| async move {
        let host = Cx::current().unwrap();
        let fixture = Fixture::new();
        let snapshot = fixture.seed("supervision-maintenance-ready", false);
        let (runner, mut guard, wake) =
            supervision_owner(&fixture, &caller, &snapshot, false).await;
        let executor = runner.handoff_executor();
        let scans = fixture.store.count(Step::ExpiredScan);
        fixture
            .store
            .pause_authorization_after_expiry_scan
            .store(true, Ordering::SeqCst);
        fixture.store.forbid_sync.store(true, Ordering::SeqCst);
        let mut pending = Box::pin(
            executor.expire_pending_execution_with_lease_heartbeat(&caller, &mut guard, &wake),
        );
        drive_until(&host, pending.as_mut(), || {
            fixture
                .store
                .authorization_gates
                .iter()
                .any(|gate| gate.waiter.lock().unwrap().is_some())
        })
        .await;
        assert_eq!(fixture.store.count(Step::ExpiredScan), scans + 1);
        for _ in 0..3 {
            std::future::poll_fn(|poll| {
                assert!(pending.as_mut().poll(poll).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert_eq!(fixture.store.count(Step::ExpiredScan), scans + 1);
        assert_supervision_unchanged(&fixture, &snapshot);
        for gate in &fixture.store.authorization_gates {
            gate.release();
        }
        pending.await.unwrap();
        assert_eq!(fixture.store.count(Step::ExpiredScan), scans + 1);
        assert_supervision_unchanged(&fixture, &snapshot);
        fixture.store.forbid_sync.store(false, Ordering::SeqCst);
        drop(guard);
        fixture.assert_recoverable(&snapshot, false);
    });
}

#[test]
fn async_supervision_entry_retains_ready_renewal_during_post_proof() {
    run(|caller| async move {
        let host = Cx::current().unwrap();
        let fixture = Fixture::new();
        let snapshot = fixture.seed("supervision-renewal-ready", false);
        let (_runner, guard, wake) =
            supervision_owner(&fixture, &caller, &snapshot, false).await;
        fixture.store.pause_snapshot_after_renewal.store(true, Ordering::SeqCst);
        fixture.store.forbid_sync.store(true, Ordering::SeqCst);
        let mut pending =
            Box::pin(guard.ensure_live_dispatch_for_application_with_cx(&caller, &wake));
        drive_until(&host, pending.as_mut(), || {
            fixture.store.gate(Step::Read).waiter.lock().unwrap().is_some()
        })
        .await;
        assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.renewals.load(Ordering::SeqCst), 1);
        for _ in 0..3 {
            std::future::poll_fn(|poll| {
                assert!(pending.as_mut().poll(poll).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 1);
        assert_supervision_unchanged(&fixture, &snapshot);
        fixture.store.gate(Step::Read).release();
        pending.await.unwrap();
        assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 1);
        assert_supervision_unchanged(&fixture, &snapshot);
        fixture.store.forbid_sync.store(false, Ordering::SeqCst);
        drop(guard);
        fixture.assert_recoverable(&snapshot, false);
    });
}

#[test]
fn async_supervision_accepts_current_generation_of_the_same_claim() {
    for resumed in [false, true] {
        run(|caller| async move {
            let host = Cx::current().unwrap();
            let fixture = Fixture::new();
            let snapshot = fixture.seed("supervision-current-generation", resumed);
            let (_runner, guard, wake) =
                supervision_owner(&fixture, &caller, &snapshot, resumed).await;
            let task = FinalTask::Working(
                transition_final_task_base(
                    snapshot.task().base().clone(),
                    FinalTaskStatus::Working,
                    Some("same invocation advanced its status".to_owned()),
                )
                .unwrap(),
            );
            let current = fixture
                .store
                .inner
                .update_working_status_for_handoff_if_current(
                    &snapshot,
                    &guard.owner_id,
                    guard.dispatch_fence.unwrap(),
                    task.clone(),
                    final_task_notification(&task),
                )
                .unwrap()
                .unwrap();
            assert!(current.generation() > snapshot.generation());
            fixture
                .runtime
                .install_execution_authorizer(Arc::new(RenewalPolicy {
                    revoked: AtomicBool::new(false),
                    generation: Some(current.generation()),
                }))
                .unwrap();
            fixture.store.authorization_gates[0].close();
            fixture.store.forbid_sync.store(true, Ordering::SeqCst);
            let mut pending =
                Box::pin(guard.ensure_live_dispatch_for_application_with_cx(&caller, &wake));
            drive_until(&host, pending.as_mut(), || {
                fixture.store.authorization_gates[0].waiter.lock().unwrap().is_some()
            })
            .await;
            assert!(!guard.execution_revoked.load(Ordering::Acquire));
            assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 0);
            fixture.store.authorization_gates[0].release();
            pending.await.unwrap();
            assert_supervision_unchanged(&fixture, &current);
            fixture.store.forbid_sync.store(false, Ordering::SeqCst);
            drop(guard);
            fixture.assert_recoverable(&current, resumed);
        });
    }
}

#[test]
fn async_supervision_rejects_substituted_authority_and_known_revocation() {
    for resumed in [false, true] {
        for invalid in ["snapshot", "principal", "revoked"] {
            run(|caller| async move {
                let host = Cx::current().unwrap();
                let fixture = Fixture::new();
                let snapshot = fixture.seed("supervision-authority", resumed);
                let (_runner, guard, wake) =
                    supervision_owner(&fixture, &caller, &snapshot, resumed).await;
                let revoked = Arc::clone(&guard.execution_revoked);
                let gate = if invalid == "snapshot" {
                    fixture.store.gate(Step::Read)
                } else {
                    &fixture.store.authorization_gates[0]
                };
                gate.close();
                fixture.store.forbid_sync.store(true, Ordering::SeqCst);
                let mut pending =
                    Box::pin(guard.ensure_live_dispatch_for_application_with_cx(&caller, &wake));
                drive_until(&host, pending.as_mut(), || {
                    gate.waiter.lock().unwrap().is_some()
                })
                .await;
                match invalid {
                    "snapshot" => {
                        let mut task = snapshot.task().clone();
                        let FinalTask::Working(base) = &mut task else {
                            panic!("the elected fixture must be working");
                        };
                        base.task_id = FinalTaskId::parse("substituted-supervision-task").unwrap();
                        *fixture.store.substitute_read.lock().unwrap() = Some(
                            FinalTaskSnapshot::new(task, snapshot.generation())
                                .with_creation_generation(snapshot.creation_generation()),
                        );
                        gate.release();
                    }
                    "principal" => {
                        *fixture.store.substitute_authorization.lock().unwrap() =
                            Some(FinalTaskAccessMetadata::new(
                                snapshot.task().base().task_id.clone(),
                                snapshot.generation(),
                                snapshot.creation_generation(),
                                Some(Sha256Digest::from_bytes([91; 32])),
                                snapshot.original_operation().cloned(),
                            ));
                        gate.release();
                    }
                    _ => {
                        // No provider wake: the retained probe's own local
                        // checkpoint must observe an already revoked attempt.
                        revoked.store(true, Ordering::Release);
                    }
                }
                assert!(pending.await.is_err());
                assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 0);
                assert_supervision_unchanged(&fixture, &snapshot);
                fixture.store.forbid_sync.store(false, Ordering::SeqCst);
                drop(guard);
            });
        }
    }
}

#[test]
fn async_supervision_silent_reads_release_on_cancellation_or_drop() {
    for maintenance in [false, true] {
        for cancel in [false, true] {
            run(|caller| async move {
                let host = Cx::current().unwrap();
                let fixture = Fixture::new();
                let snapshot = fixture.seed("supervision-read-abandonment", false);
                let (runner, mut guard, wake) =
                    supervision_owner(&fixture, &caller, &snapshot, false).await;
                let executor = runner.handoff_executor();
                let gate = fixture.store.gate(Step::CancellationIntent);
                gate.close();
                fixture.store.forbid_sync.store(true, Ordering::SeqCst);
                let mut pending =
                    supervision_operation(maintenance, &executor, &caller, &mut guard, &wake);
                drive_until(&host, pending.as_mut(), || {
                    gate.waiter.lock().unwrap().is_some()
                })
                .await;
                if cancel {
                    caller.cancel_with(asupersync::types::CancelKind::User, None);
                    let error = pending.await.unwrap_err();
                    assert_eq!(error.code, McpError::request_cancelled().code);
                } else {
                    drop(pending);
                }
                assert!(!gate.open.load(Ordering::SeqCst));
                assert_eq!(gate.abandoned.load(Ordering::SeqCst), 1);
                assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 0);
                assert_supervision_unchanged(&fixture, &snapshot);
                fixture.store.forbid_sync.store(false, Ordering::SeqCst);
                drop(guard);
                fixture.assert_recoverable(&snapshot, false);
            });
        }
    }
}

#[test]
fn async_supervision_silent_reads_keep_the_original_caller_deadline() {
    for maintenance in [false, true] {
        let clock = Arc::new(asupersync::time::VirtualClock::new());
        let timer = asupersync::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let setup_caller = runtime.request_cx_with_budget(Budget::INFINITE);
        let fixture = Fixture::new();
        let snapshot = fixture.seed("supervision-caller-deadline", false);
        let (runner, mut guard, wake) =
            runtime.block_on(supervision_owner(&fixture, &setup_caller, &snapshot, false));
        let executor = runner.handoff_executor();
        let caller = runtime.request_cx_with_budget(
            Budget::INFINITE.with_deadline(setup_caller.now().saturating_add_nanos(1_000_000_000)),
        );
        let gate = fixture.store.gate(Step::CancellationIntent);
        gate.close();
        fixture.store.forbid_sync.store(true, Ordering::SeqCst);
        let mut pending =
            supervision_operation(maintenance, &executor, &caller, &mut guard, &wake);
        let first = runtime.block_on(std::future::poll_fn(|poll| {
            Poll::Ready(pending.as_mut().poll(poll))
        }));
        assert!(first.is_pending());
        assert!(gate.waiter.lock().unwrap().is_some());
        runtime.block_on(async {
            clock.advance(1_000_000_000);
            assert!(timer.process_timers() > 0);
        });
        let result = runtime.block_on(std::future::poll_fn(|poll| {
            Poll::Ready(pending.as_mut().poll(poll))
        }));
        let Poll::Ready(result) = result else {
            panic!("the original caller deadline must release silent storage");
        };
        assert_eq!(result.unwrap_err().code, McpError::request_cancelled().code);
        drop(pending);
        assert!(!caller.is_cancel_requested());
        assert!(!gate.open.load(Ordering::SeqCst));
        assert_eq!(gate.abandoned.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 0);
        assert_supervision_unchanged(&fixture, &snapshot);
        fixture.store.forbid_sync.store(false, Ordering::SeqCst);
        drop(guard);
        drop(wake);
        drop(executor);
        drop(runner);
        drop(fixture);
        drop(caller);
        drop(setup_caller);
        assert_eq!(timer.pending_count(), 0);
        assert!(runtime.shutdown_timeout(StdDuration::from_secs(2)));
    }
}

fn commit_supervision_cancellation(fixture: &Fixture, task_id: &FinalTaskId) -> FinalTaskSnapshot {
    let expected = fixture.store.inner.get_task_snapshot(task_id).unwrap().unwrap();
    let cancelled = FinalTask::Cancelled(
        transition_final_task_base(
            expected.task().base().clone(),
            FinalTaskStatus::Cancelled,
            None,
        )
        .unwrap(),
    );
    let retained = fixture
        .store
        .inner
        .request_cancellation_and_clear_input_if_current(
            &expected,
            cancelled.clone(),
            final_task_notification(&cancelled),
        )
        .unwrap()
        .unwrap();
    assert!(matches!(retained.task(), FinalTask::Working(_)));
    fixture.runtime.signal_task_service_cancellation(task_id.clone());
    retained
}

#[test]
fn async_supervision_cancellation_drops_pending_renewal_before_return() {
    for resumed in [false, true] {
        run(|caller| async move {
            let host = Cx::current().unwrap();
            let fixture = Fixture::new();
            let snapshot = fixture.seed("supervision-pending-renewal", resumed);
            let task_id = snapshot.task().base().task_id.clone();
            let (_runner, guard, wake) =
                supervision_owner(&fixture, &caller, &snapshot, resumed).await;
            *fixture.store.renewal_pause_for.lock().unwrap() = Some(task_id.clone());
            fixture.store.renewal_gate.close();
            fixture.store.forbid_sync.store(true, Ordering::SeqCst);
            let mut pending =
                Box::pin(guard.ensure_live_dispatch_for_application_with_cx(&caller, &wake));
            drive_until(&host, pending.as_mut(), || {
                fixture.store.renewal_gate.waiter.lock().unwrap().is_some()
            })
            .await;
            let retained = commit_supervision_cancellation(&fixture, &task_id);
            let error = pending.await.unwrap_err();
            assert_eq!(error.code, McpError::request_cancelled().code);
            assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.store.renewals.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.store.renewal_gate.abandoned.load(Ordering::SeqCst), 1);
            assert_supervision_unchanged(&fixture, &retained);
            assert!(fixture.store.inner.is_cancellation_requested(&task_id).unwrap());
            fixture.store.forbid_sync.store(false, Ordering::SeqCst);
            drop(guard);
            assert!(matches!(
                fixture.store.inner.get_task(&task_id).unwrap().unwrap(),
                FinalTask::Cancelled(_)
            ));
        });
    }
}

#[test]
fn async_supervision_post_renewal_cancellation_rechecks_consumed_intent() {
    for resumed in [false, true] {
        run(|caller| async move {
            let host = Cx::current().unwrap();
            let fixture = Fixture::new();
            let snapshot = fixture.seed("supervision-late-cancellation", resumed);
            let task_id = snapshot.task().base().task_id.clone();
            let (_runner, guard, wake) =
                supervision_owner(&fixture, &caller, &snapshot, resumed).await;
            fixture.store.pause_snapshot_after_renewal.store(true, Ordering::SeqCst);
            fixture.store.forbid_sync.store(true, Ordering::SeqCst);
            let mut pending =
                Box::pin(guard.ensure_live_dispatch_for_application_with_cx(&caller, &wake));
            drive_until(&host, pending.as_mut(), || {
                fixture.store.gate(Step::Read).waiter.lock().unwrap().is_some()
            })
            .await;
            assert_eq!(fixture.store.renewals.load(Ordering::SeqCst), 1);
            let intent_reads = fixture.store.count(Step::CancellationIntent);
            fixture.store.pause_snapshot_after_intent.store(true, Ordering::SeqCst);
            fixture.store.gate(Step::Read).release();
            drive_until(&host, pending.as_mut(), || {
                fixture.store.count(Step::CancellationIntent) > intent_reads
                    && fixture.store.gate(Step::Read).waiter.lock().unwrap().is_some()
            })
            .await;
            // The pending proof has already read false intent. Cancellation
            // does not need to change the working Task's record generation.
            let retained = commit_supervision_cancellation(&fixture, &task_id);
            assert_eq!(retained.generation(), snapshot.generation());
            fixture.store.gate(Step::Read).release();
            let error = pending.await.unwrap_err();
            assert_eq!(error.code, McpError::request_cancelled().code);
            assert_eq!(fixture.store.async_renewal_calls.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.store.renewals.load(Ordering::SeqCst), 1);
            assert!(fixture.store.count(Step::CancellationIntent) > intent_reads + 1);
            assert_supervision_unchanged(&fixture, &retained);
            fixture.store.forbid_sync.store(false, Ordering::SeqCst);
            drop(guard);
        });
    }
}
