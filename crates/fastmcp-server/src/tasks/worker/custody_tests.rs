use super::*;
use asupersync::runtime::{RuntimeBuilder, TaskHandle};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Gate {
    open: AtomicBool,
    waiter: Mutex<Option<Waker>>,
    polls: AtomicUsize,
}

impl Gate {
    fn new(open: bool) -> Self {
        Self {
            open: AtomicBool::new(open),
            waiter: Mutex::new(None),
            polls: AtomicUsize::new(0),
        }
    }

    fn close(&self) {
        self.open.store(false, Ordering::SeqCst);
    }

    fn release(&self) {
        self.open.store(true, Ordering::SeqCst);
        self.pulse();
    }

    fn pulse(&self) {
        let waiter = self.waiter.lock().unwrap().clone();
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }

    async fn wait(&self) {
        std::future::poll_fn(|poll| {
            self.polls.fetch_add(1, Ordering::SeqCst);
            let mut waiter = self.waiter.lock().unwrap();
            if self.open.load(Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                *waiter = Some(poll.waker().clone());
                Poll::Pending
            }
        })
        .await;
    }
}

struct AsyncWorkerStore {
    inner: InMemoryFinalTaskStore,
    clock: Arc<Mutex<Instant>>,
    metadata_gate: Gate,
    payload_gate: Gate,
    write_gate: Gate,
    receipt_gate: Gate,
    intent_gate: Gate,
    committed: Gate,
    deny_sync: AtomicBool,
    unexpected_sync: AtomicUsize,
    metadata_reads: AtomicUsize,
    payload_reads: AtomicUsize,
    write_factories: AtomicUsize,
    writes: AtomicUsize,
    restorations: AtomicUsize,
    provider_cx: Mutex<Option<Cx>>,
    after_commit: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    forged_receipt: AtomicBool,
    fail_after_admission: AtomicBool,
    omit_admission: AtomicBool,
}

impl AsyncWorkerStore {
    fn new() -> Self {
        let clock = Arc::new(Mutex::new(Instant::now()));
        let clock_reader = Arc::clone(&clock);
        Self {
            inner: InMemoryFinalTaskStore::with_clock(
                8,
                Arc::new(move || *clock_reader.lock().unwrap()),
            )
            .unwrap(),
            clock,
            metadata_gate: Gate::new(true),
            payload_gate: Gate::new(true),
            write_gate: Gate::new(true),
            receipt_gate: Gate::new(true),
            intent_gate: Gate::new(true),
            committed: Gate::new(false),
            deny_sync: AtomicBool::new(false),
            unexpected_sync: AtomicUsize::new(0),
            metadata_reads: AtomicUsize::new(0),
            payload_reads: AtomicUsize::new(0),
            write_factories: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            restorations: AtomicUsize::new(0),
            provider_cx: Mutex::new(None),
            after_commit: Mutex::new(None),
            forged_receipt: AtomicBool::new(false),
            fail_after_admission: AtomicBool::new(false),
            omit_admission: AtomicBool::new(false),
        }
    }

    fn sync_admission(&self) -> McpResult<()> {
        if self.deny_sync.load(Ordering::SeqCst) {
            self.unexpected_sync.fetch_add(1, Ordering::SeqCst);
            return Err(McpError::internal_error(
                "async worker used a synchronous storage hook",
            ));
        }
        Ok(())
    }

    fn caller(cx: &Cx) {
        assert_eq!(
            Cx::current()
                .expect("provider has original caller context")
                .task_id(),
            cx.task_id()
        );
        assert_eq!(Cx::current().unwrap().region_id(), cx.region_id());
    }

    fn mutate<'a>(
        &'a self,
        admission: FinalTaskWorkerAdmission<'a>,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
        status: bool,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.write_factories.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            Self::caller(admission.context().cx());
            *self.provider_cx.lock().unwrap() = Some(admission.context().cx().clone());
            self.write_gate.wait().await;
            Self::caller(admission.context().cx());
            if !self.omit_admission.load(Ordering::SeqCst) {
                admission.checkpoint_before_write()?;
            }
            let expected = admission.expected();
            assert!(admission.claim_generation() <= expected.generation());
            let result = if status {
                self.inner.update_working_status_for_handoff_if_current(
                    expected,
                    admission.owner_id(),
                    admission.dispatch_fence(),
                    task,
                    notification,
                )?
            } else {
                self.inner
                    .replace_task_and_clear_input_for_handoff_if_current(
                        expected,
                        admission.owner_id(),
                        admission.dispatch_fence(),
                        admission.cancellation_required(),
                        task,
                        notification,
                    )?
            };
            if result.is_some() {
                self.writes.fetch_add(1, Ordering::SeqCst);
                self.committed.release();
                let hook = self.after_commit.lock().unwrap().take();
                if let Some(hook) = hook {
                    hook();
                }
            }
            self.receipt_gate.wait().await;
            Self::caller(admission.context().cx());
            if self.fail_after_admission.load(Ordering::SeqCst) {
                return Err(McpError::internal_error("backend receipt unavailable"));
            }
            Ok(result.map(|receipt| {
                if self.forged_receipt.load(Ordering::SeqCst) {
                    receipt.with_authenticated_principal(Some(Sha256Digest::from_bytes([91; 32])))
                } else {
                    receipt
                }
            }))
        })
    }
}

// These are the still-synchronous service/recovery contracts. The direct API
// tests forbid them while an async worker method is polled; the real runner
// tests allow them for election, heartbeat and structured-region cleanup.
macro_rules! forward_store {
    ($(fn $name:ident($($arg:ident: $argty:ty),*) -> $ret:ty;)+) => {$ (
        fn $name(&self, $($arg: $argty),*) -> $ret {
            self.sync_admission()?;
            self.inner.$name($($arg),*)
        }
    )+};
}

impl FinalTaskStore for AsyncWorkerStore {
    forward_store! {
        fn create_task(task: FinalTask, notification: FinalTaskStatusNotification) -> McpResult<()>;
        fn get_task(task_id: &FinalTaskId) -> McpResult<Option<FinalTask>>;
        fn get_task_snapshot(task_id: &FinalTaskId) -> McpResult<Option<FinalTaskSnapshot>>;
        fn get_task_access_metadata(task_id: &FinalTaskId) -> McpResult<Option<FinalTaskAccessMetadata>>;
        fn get_handoff_access_metadata(task_id: &FinalTaskId, claim_generation: u64, owner_id: &str, fence: u64) -> McpResult<Option<FinalTaskAccessMetadata>>;
        fn replace_task(task: FinalTask, notification: FinalTaskStatusNotification) -> McpResult<()>;
        fn replace_task_if_current(expected: &FinalTaskSnapshot, task: FinalTask, notification: FinalTaskStatusNotification) -> McpResult<bool>;
        fn replace_task_and_append_input_if_current(expected: &FinalTaskSnapshot, task: FinalTask, notification: FinalTaskStatusNotification, inputs: FinalTaskInputResponses) -> McpResult<Option<FinalTaskSnapshot>>;
        fn replace_task_and_clear_input_for_handoff_if_current(expected: &FinalTaskSnapshot, owner: &str, fence: u64, cancellation: bool, task: FinalTask, notification: FinalTaskStatusNotification) -> McpResult<Option<FinalTaskSnapshot>>;
        fn request_cancellation(task_id: &FinalTaskId) -> McpResult<()>;
        fn request_cancellation_if_current(expected: &FinalTaskSnapshot) -> McpResult<bool>;
        fn request_cancellation_and_clear_input_if_current(expected: &FinalTaskSnapshot, task: FinalTask, notification: FinalTaskStatusNotification) -> McpResult<Option<FinalTaskSnapshot>>;
        fn is_cancellation_requested(task_id: &FinalTaskId) -> McpResult<bool>;
        fn task_retention_deadline_if_current(task_id: &FinalTaskId, generation: u64) -> McpResult<Option<FinalTaskRetentionDeadline>>;
        fn execution_limits() -> McpResult<FinalTaskExecutionLimits>;
        fn task_execution_budget_if_current(expected: &FinalTaskSnapshot) -> McpResult<Option<FinalTaskExecutionBudget>>;
        fn expire_task_execution_if_current(expected: &FinalTaskSnapshot) -> McpResult<Option<FinalTaskSnapshot>>;
        fn next_expired_execution_snapshot() -> McpResult<Option<FinalTaskSnapshot>>;
        fn next_initial_work_snapshot_after(after: Option<&FinalTaskId>) -> McpResult<Option<FinalTaskSnapshot>>;
        fn next_accepted_input_snapshot_after(after: Option<&FinalTaskId>) -> McpResult<Option<FinalTaskSnapshot>>;
        fn take_initial_work_handoff_for_owner_if_current(expected: &FinalTaskSnapshot, owner: &str) -> McpResult<Option<FinalTaskInitialWorkClaim>>;
        fn take_input_handoff_for_owner_if_current(expected: &FinalTaskSnapshot, owner: &str) -> McpResult<Option<FinalTaskAcceptedInputClaim>>;
        fn begin_handoff_dispatch_for_owner_if_current(task_id: &FinalTaskId, generation: u64, owner: &str) -> McpResult<Option<u64>>;
        fn renew_handoff_dispatch_if_current(task_id: &FinalTaskId, generation: u64, owner: &str, fence: u64) -> McpResult<bool>;
        fn handoff_dispatch_lease_heartbeat_interval() -> McpResult<StdDuration>;
        fn finish_handoff_dispatch_for_owner_if_current(task_id: &FinalTaskId, generation: u64, owner: &str, fence: u64) -> McpResult<bool>;
    }

    fn retention_clock_now(&self) -> Instant {
        self.inner.retention_clock_now()
    }

    fn restore_initial_work_for_owner_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner: &str,
        fence: Option<u64>,
        descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<bool> {
        self.restorations.fetch_add(1, Ordering::SeqCst);
        self.inner.restore_initial_work_for_owner_if_current(
            task_id, generation, owner, fence, descriptor,
        )
    }

    fn restore_input_for_owner_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner: &str,
        fence: Option<u64>,
        inputs: FinalTaskInputResponses,
    ) -> McpResult<bool> {
        self.restorations.fetch_add(1, Ordering::SeqCst);
        self.inner
            .restore_input_for_owner_if_current(task_id, generation, owner, fence, inputs)
    }

    fn get_task_access_metadata_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskAccessMetadata>> {
        Box::pin(async move {
            Self::caller(ctx.cx());
            self.metadata_reads.fetch_add(1, Ordering::SeqCst);
            self.metadata_gate.wait().await;
            self.inner.get_task_access_metadata(task_id)
        })
    }

    fn get_handoff_access_metadata_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
        claim_generation: u64,
        owner: &'a str,
        fence: u64,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskAccessMetadata>> {
        Box::pin(async move {
            Self::caller(ctx.cx());
            self.metadata_reads.fetch_add(1, Ordering::SeqCst);
            self.metadata_gate.wait().await;
            self.inner
                .get_handoff_access_metadata(task_id, claim_generation, owner, fence)
        })
    }

    fn get_task_snapshot_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        Box::pin(async move {
            Self::caller(ctx.cx());
            self.payload_reads.fetch_add(1, Ordering::SeqCst);
            self.payload_gate.wait().await;
            self.inner.get_task_snapshot(task_id)
        })
    }

    fn is_cancellation_requested_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, bool> {
        Box::pin(async move {
            Self::caller(ctx.cx());
            self.intent_gate.wait().await;
            self.inner.is_cancellation_requested(task_id)
        })
    }

    fn replace_task_and_clear_input_for_handoff_with_context<'a>(
        &'a self,
        admission: FinalTaskWorkerAdmission<'a>,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.mutate(admission, task, notification, false)
    }

    fn update_working_status_for_handoff_with_context<'a>(
        &'a self,
        admission: FinalTaskWorkerAdmission<'a>,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.mutate(admission, task, notification, true)
    }
}

struct Permission(AtomicBool);

impl TaskExecutionAuthorizer for Permission {
    fn authorize(&self, _metadata: &FinalTaskAccessMetadata) -> McpResult<()> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(McpError::invalid_request("execution revoked"))
        }
    }
}

struct Fixture {
    store: Arc<AsyncWorkerStore>,
    runtime: FinalTaskRuntime,
    permission: Arc<Permission>,
    task_id: FinalTaskId,
    _registration: Arc<()>,
}

impl Fixture {
    fn pending(resumed: bool) -> Self {
        let store = Arc::new(AsyncWorkerStore::new());
        let registration = Arc::new(());
        let task_id = FinalTaskId::parse("async-worker-task").unwrap();
        let timestamp = FinalTaskTimestamp::parse("2026-07-28T12:00:00.000Z").unwrap();
        let task = FinalTask::Working(FinalTaskBase {
            task_id: task_id.clone(),
            status: FinalTaskStatus::Working,
            status_message: None,
            created_at: timestamp.clone(),
            last_updated_at: timestamp,
            ttl_ms: Some(final_task_duration(86_400_000).unwrap()),
            poll_interval_ms: None,
        });
        let snapshot = store
            .inner
            .create_task_with_operation(
                task.clone(),
                final_task_notification(&task),
                FinalTaskWorkDescriptor::new(serde_json::json!({"handler":"async-worker"}))
                    .unwrap(),
                None,
                FinalTaskOperation::for_tool("async-worker", &registration).unwrap(),
            )
            .unwrap();
        if resumed {
            let awaiting = FinalTask::InputRequired {
                base: transition_final_task_base(
                    snapshot.task().base().clone(),
                    FinalTaskStatus::InputRequired,
                    None,
                )
                .unwrap(),
                input_requests: input_requests(),
            };
            let waiting = store
                .inner
                .replace_task_and_clear_input_if_current(
                    &snapshot,
                    awaiting.clone(),
                    final_task_notification(&awaiting),
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
            store
                .inner
                .replace_task_and_append_input_if_current(
                    &waiting,
                    working.clone(),
                    final_task_notification(&working),
                    input_responses(),
                )
                .unwrap()
                .unwrap();
        }
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(86_400_000, None).unwrap(),
            Arc::new(|_| {}),
        );
        let permission = Arc::new(Permission(AtomicBool::new(true)));
        runtime
            .install_execution_authorizer(permission.clone())
            .unwrap();
        Self {
            store,
            runtime,
            permission,
            task_id,
            _registration: registration,
        }
    }

    fn new(resumed: bool) -> (Self, FinalTaskSupervisorHandoff) {
        let fixture = Self::pending(resumed);
        let handoff = if resumed {
            FinalTaskSupervisorHandoff::Resumed(
                fixture.runtime.recover_accepted_input().unwrap().unwrap(),
            )
        } else {
            FinalTaskSupervisorHandoff::Initial(
                fixture.runtime.recover_initial_work().unwrap().unwrap(),
            )
        };
        (fixture, handoff)
    }

    fn elect(&self, handoff: &mut FinalTaskSupervisorHandoff) -> FinalTaskExecutionGuard {
        let mut guard =
            FinalTaskExecutionGuard::new(&self.runtime, FINAL_TASK_TEST_DIRECT_OWNER, handoff);
        assert!(guard.elect().unwrap());
        handoff.attach_authority(guard.authority().unwrap());
        guard
    }

    fn snapshot(&self) -> FinalTaskSnapshot {
        self.store
            .inner
            .get_task_snapshot(&self.task_id)
            .unwrap()
            .unwrap()
    }
}

fn input_requests() -> FinalTaskInputRequests {
    serde_json::from_value(serde_json::json!({"roots":{"method":"roots/list"}})).unwrap()
}

fn input_responses() -> FinalTaskInputResponses {
    serde_json::from_value(serde_json::json!({"roots":{"roots":[]}})).unwrap()
}

fn result() -> FinalTaskCallToolResult {
    serde_json::from_value(
        serde_json::json!({"content":[{"type":"text","text":"async worker completed"}]}),
    )
    .unwrap()
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn with_runtime(scenario: impl Future<Output = ()>) {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(scenario);
    assert!(runtime.shutdown_timeout(StdDuration::from_secs(2)));
}

#[test]
fn async_worker_custody_bounds_provider_admission_and_releases_abandoned_prewrite() {
    with_runtime(async {
        let cx = Cx::current().unwrap();
        let (fixture, mut handoff) = Fixture::new(false);
        let guard = fixture.elect(&mut handoff);
        let FinalTaskSupervisorHandoff::Initial(work) = &handoff else {
            unreachable!()
        };
        fixture.store.write_gate.close();
        let mut first = Box::pin(work.complete_task_with_cx(&cx, result(), None));
        assert!(poll_once(first.as_mut()).is_pending());
        let mut second = Box::pin(work.complete_task_with_cx(&cx, result(), None));
        let Poll::Ready(Err(error)) = poll_once(second.as_mut()) else {
            panic!("concurrent provider must be refused");
        };
        assert!(error.message.contains("already pending"));
        assert_eq!(fixture.store.write_factories.load(Ordering::SeqCst), 1);
        drop(second);
        drop(first);
        assert!(
            guard
                .pending_write
                .poll_settlement(&mut Context::from_waker(Waker::noop()), false)
                .is_ready()
        );
        assert!(!guard.pending_write.application_closed());
        assert!(!guard.pending_write.outcome_uncertain());
        assert_eq!(fixture.store.writes.load(Ordering::SeqCst), 0);
        fixture.store.write_gate.release();
        let completed = work
            .complete_task_with_cx(&cx, result(), None)
            .await
            .unwrap();
        assert!(matches!(completed, FinalTask::Completed { .. }));
        assert_eq!(fixture.store.write_factories.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.store.writes.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn async_worker_custody_never_replays_unknown_or_unadmitted_receipts() {
    for mode in 0..3 {
        with_runtime(async {
            let cx = Cx::current().unwrap();
            let (fixture, mut handoff) = Fixture::new(false);
            let guard = fixture.elect(&mut handoff);
            match mode {
                0 => fixture.store.forged_receipt.store(true, Ordering::SeqCst),
                1 => fixture.store.omit_admission.store(true, Ordering::SeqCst),
                _ => fixture
                    .store
                    .fail_after_admission
                    .store(true, Ordering::SeqCst),
            }
            let FinalTaskSupervisorHandoff::Initial(work) = &handoff else {
                unreachable!()
            };
            let error = work
                .complete_task_with_cx(&cx, result(), None)
                .await
                .unwrap_err();
            if mode == 2 {
                assert!(
                    error.message.contains("may have committed"),
                    "generic postwrite errors are uncertain too"
                );
            }
            assert!(!guard.transition_committed.load(Ordering::SeqCst));
            assert!(guard.pending_write.outcome_uncertain());
            assert!(matches!(
                fixture.snapshot().task(),
                FinalTask::Completed { .. }
            ));
            drop(guard);
            assert_eq!(fixture.store.restorations.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.store.write_factories.load(Ordering::SeqCst), 1);
        });
    }
}

#[test]
fn async_worker_custody_retains_effective_caller_and_requires_time_for_waits() {
    use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};
    for time_allowed in [false, true] {
        with_runtime(async {
            let cx = Cx::current().unwrap();
            let (fixture, mut handoff) = Fixture::new(false);
            let _guard = fixture.elect(&mut handoff);
            let FinalTaskSupervisorHandoff::Initial(work) = &handoff else {
                unreachable!()
            };
            fixture.store.write_gate.close();
            let mut pending = Box::pin(work.complete_task_with_cx(&cx, result(), None));
            {
                let _host = Cx::set_current(Some(cx.clone()));
                let mask = if time_allowed {
                    CapSet::<false, true, false, false, false>::MASK
                } else {
                    CapMask::none()
                };
                let _restriction = Cx::push_restriction(mask);
                let polled = poll_once(pending.as_mut());
                if time_allowed {
                    assert!(polled.is_pending());
                } else {
                    let Poll::Ready(Err(error)) = polled else {
                        panic!("pending storage requires caller time authority");
                    };
                    assert!(error.message.contains("timer driver"));
                }
            }
            let retained = fixture
                .store
                .provider_cx
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .clone();
            let effects = retained.capabilities();
            assert_eq!(
                [
                    effects.spawn,
                    effects.time,
                    effects.entropy,
                    effects.io,
                    effects.remote
                ],
                [false, time_allowed, false, false, false]
            );
            assert_eq!(retained.task_id(), cx.task_id());
            if time_allowed {
                fixture.store.write_gate.release();
                assert!(matches!(poll_once(pending.as_mut()), Poll::Ready(Ok(_))));
                let effects = fixture
                    .store
                    .provider_cx
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .capabilities();
                assert_eq!(
                    [
                        effects.spawn,
                        effects.time,
                        effects.entropy,
                        effects.io,
                        effects.remote
                    ],
                    [false, true, false, false, false],
                    "a broad resumed host must not widen the explicit provider context"
                );
            } else {
                assert_eq!(fixture.store.writes.load(Ordering::SeqCst), 0);
            }
        });
    }
}

#[test]
fn async_worker_provider_and_panic_destructors_cannot_strand_custody() {
    struct HostilePayload;
    impl Drop for HostilePayload {
        fn drop(&mut self) {
            panic!("second provider panic");
        }
    }
    struct HostileFuture(Arc<AtomicUsize>);
    impl Future for HostileFuture {
        type Output = McpResult<FinalTaskSnapshot>;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            std::panic::panic_any(HostilePayload);
        }
    }
    impl Drop for HostileFuture {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
            std::panic::panic_any(HostilePayload);
        }
    }
    for admitted in [false, true] {
        let writes = FinalTaskWorkerWrites::default();
        let write = writes.reserve().unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        write.admitted.store(admitted, Ordering::SeqCst);
        *write.future.lock().unwrap() = Some(Box::pin(HostileFuture(Arc::clone(&dropped))));
        assert!(
            write
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        assert!(write.settled.load(Ordering::SeqCst));
        assert!(!write.polling.load(Ordering::SeqCst));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(writes.outcome_uncertain(), admitted);
        let error = write.result.lock().unwrap().take().unwrap().unwrap_err();
        assert_eq!(error.message.contains("may have committed"), admitted);
        assert!(
            writes
                .poll_settlement(&mut Context::from_waker(Waker::noop()), true)
                .is_ready()
        );
    }
}

struct CompletingSupervisor {
    effects_after_await: Arc<AtomicUsize>,
    outcome: Arc<Mutex<Option<FinalTask>>>,
}

impl ApplicationTaskSupervisor for CompletingSupervisor {
    fn resume<'a>(
        &'a self,
        cx: &'a Cx,
        handoff: FinalTaskSupervisorHandoff,
    ) -> FinalTaskSupervisorFuture<'a> {
        Box::pin(async move {
            let outcome = match handoff {
                FinalTaskSupervisorHandoff::Initial(work) => {
                    work.complete_task_with_cx(cx, result(), None).await?
                }
                FinalTaskSupervisorHandoff::Resumed(work) => {
                    work.complete_task_with_cx(cx, result(), None).await?
                }
            };
            self.effects_after_await.fetch_add(1, Ordering::SeqCst);
            *self.outcome.lock().unwrap() = Some(outcome);
            Ok(())
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum ReceiptInterruption {
    None,
    AttemptCancelled,
    ServiceCancelled,
    Revoked,
    Expired,
    ProviderError,
}

struct ListenerReceiptGuard<T> {
    store: Arc<AsyncWorkerStore>,
    listener: Option<TaskHandle<McpResult<T>>>,
}

impl<T> Drop for ListenerReceiptGuard<T> {
    fn drop(&mut self) {
        // A failing assertion or observation timeout must not strand an
        // admitted write while the test runtime closes its child region.
        self.store.receipt_gate.release();
        if let Some(listener) = self.listener.as_mut() {
            listener.abort();
        }
    }
}

#[test]
fn async_worker_http_shutdown_retains_pending_receipt_and_defers_cleanup() {
    use crate::http_admission::security::HttpSecurityPolicy;
    use crate::http_admission::{HttpAdmissionLimits, HttpEndpointConfig};
    use crate::{HttpServerShutdown, HttpShutdownSettlement, Server};
    use fastmcp_protocol::protocol_policy::ProtocolPolicy;

    for secured in [false, true] {
        for hold_receipt in [false, true] {
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
                .blocking_threads(0, 0)
                .build()
                .unwrap();
            runtime.block_on(async move {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::pending(false);
                fixture.store.receipt_gate.close();
                let effects = Arc::new(AtomicUsize::new(0));
                let outcome = Arc::new(Mutex::new(None));
                let cleanups = Arc::new(AtomicUsize::new(0));
                let cleanup_count = Arc::clone(&cleanups);
                let cleanup_runtime = fixture.runtime.clone();
                let server = Server::new("http-hosted-worker-receipt", "1")
                    .protocol_policy(ProtocolPolicy::ModernOnly)
                    .unwrap()
                    .final_tasks(fixture.runtime.clone())
                    .unwrap()
                    .task_supervisor(Arc::new(CompletingSupervisor {
                        effects_after_await: Arc::clone(&effects),
                        outcome: Arc::clone(&outcome),
                    }))
                    .on_shutdown_async(move |_| async move {
                        assert!(
                            !cleanup_runtime.is_task_service_ready(),
                            "cleanup cannot run over an owned Task service"
                        );
                        cleanup_count.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .build();
                let serving = Arc::new(Mutex::new(None));
                let serving_context = Arc::clone(&serving);
                let listener = cx
                    .spawn(move |serve_cx| async move {
                        *serving_context.lock().unwrap() = Some(serve_cx.clone());
                        if secured {
                            let policy = HttpSecurityPolicy::new(
                                HttpEndpointConfig::new(
                                    "/mcp",
                                    HttpAdmissionLimits::new(32, 8192, 65536).unwrap(),
                                )
                                .unwrap(),
                                "https://localhost",
                                Vec::new(),
                            )
                            .unwrap();
                            server
                                .bind_secured_http(&serve_cx, "127.0.0.1:0", policy)
                                .await?
                                .serve(&serve_cx)
                                .await
                        } else {
                            server
                                .bind_http(&serve_cx, "127.0.0.1:0")
                                .await?
                                .serve(&serve_cx)
                                .await
                        }
                    })
                    .unwrap();
                let mut running = ListenerReceiptGuard {
                    store: Arc::clone(&fixture.store),
                    listener: Some(listener),
                };
                asupersync::time::timeout(
                    cx.now(),
                    StdDuration::from_secs(5),
                    fixture.store.committed.wait(),
                )
                .await
                .expect("the hosted service must recover and commit its pending work");
                assert_eq!(fixture.store.writes.load(Ordering::SeqCst), 1);
                assert_eq!(effects.load(Ordering::SeqCst), 0);
                assert!(fixture.runtime.is_task_service_ready());

                if !hold_receipt {
                    // The paired control differs only in when the same
                    // committed operation's receipt becomes available.
                    fixture.store.receipt_gate.release();
                    asupersync::time::timeout(cx.now(), StdDuration::from_secs(5), async {
                        while effects.load(Ordering::SeqCst) == 0 {
                            asupersync::time::sleep(cx.now(), StdDuration::from_millis(1)).await;
                        }
                    })
                    .await
                    .expect("the released receipt must reach the application");
                }

                let stopping = Instant::now();
                serving
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .cancel_with(CancelKind::User, Some("HTTP receipt shutdown regression"));
                let joined = asupersync::time::timeout(
                    cx.now(),
                    StdDuration::from_secs(12),
                    running.listener.as_mut().unwrap().join(&cx),
                )
                .await
                .expect("HTTP shutdown must return ownership within its observation bound");
                running.listener = None;
                let shutdown = joined.unwrap().unwrap();
                if hold_receipt {
                    assert!(stopping.elapsed() >= HOSTED_TASK_SERVICE_SETTLEMENT_BOUND);
                    let HttpServerShutdown::Nonquiescent(mut retained) = shutdown else {
                        panic!(
                            "a pending worker receipt must remain caller-owned: secured={secured}"
                        );
                    };
                    let expected = "The hosted Task service did not settle within its bound";
                    assert_eq!(retained.listener_error().unwrap().message, expected);
                    assert_eq!(cleanups.load(Ordering::SeqCst), 0);
                    assert!(fixture.runtime.is_task_service_ready());
                    assert!(matches!(
                        retained.poll_settlement(),
                        HttpShutdownSettlement::Pending { remaining: 1 }
                    ));
                    assert!(matches!(
                        retained.settle_for(StdDuration::from_millis(5)).await,
                        HttpShutdownSettlement::Pending { remaining: 1 }
                    ));
                    assert_eq!(cleanups.load(Ordering::SeqCst), 0);
                    assert_eq!(effects.load(Ordering::SeqCst), 0);
                    fixture.store.receipt_gate.release();
                    if secured {
                        assert!(matches!(
                            retained.settle_for(StdDuration::from_secs(5)).await,
                            HttpShutdownSettlement::Settled
                        ));
                        assert!(matches!(
                            retained.poll_settlement(),
                            HttpShutdownSettlement::Settled
                        ));
                        assert_eq!(cleanups.load(Ordering::SeqCst), 1);
                    }
                    let error = asupersync::time::timeout(
                        cx.now(),
                        StdDuration::from_secs(5),
                        retained.settle(&cx),
                    )
                    .await
                    .expect("releasing the receipt must settle its original owner")
                    .unwrap_err();
                    assert_eq!(error.message, expected);
                } else {
                    assert!(matches!(shutdown, HttpServerShutdown::Quiescent));
                }
                assert_eq!(cleanups.load(Ordering::SeqCst), 1);
                assert!(!fixture.runtime.is_task_service_ready());
                assert_eq!(effects.load(Ordering::SeqCst), usize::from(!hold_receipt));
                assert_eq!(outcome.lock().unwrap().is_some(), !hold_receipt);
                assert_eq!(fixture.store.writes.load(Ordering::SeqCst), 1);
                assert!(
                    fixture
                        .store
                        .inner
                        .next_initial_work_snapshot_after(None)
                        .unwrap()
                        .is_none()
                );
                assert!(matches!(
                    fixture.snapshot().task(),
                    FinalTask::Completed { .. }
                ));
                assert!(cx.checkpoint().is_ok());
            });
            assert!(runtime.shutdown_timeout(StdDuration::from_secs(2)));
        }
    }
}

#[cfg(feature = "websocket")]
#[test]
fn async_worker_websocket_shutdown_retains_pending_receipt_and_defers_cleanup() {
    use crate::{Server, WebSocketServerShutdown};
    use fastmcp_protocol::protocol_policy::ProtocolPolicy;

    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let fixture = Fixture::pending(false);
        fixture.store.receipt_gate.close();
        let effects = Arc::new(AtomicUsize::new(0));
        let outcome = Arc::new(Mutex::new(None));
        let cleanups = Arc::new(AtomicUsize::new(0));
        let cleanup_count = Arc::clone(&cleanups);
        let cleanup_runtime = fixture.runtime.clone();
        let server = Server::new("websocket-hosted-worker-receipt", "1")
            .protocol_policy(ProtocolPolicy::ModernOnly)
            .unwrap()
            .final_tasks(fixture.runtime.clone())
            .unwrap()
            .task_supervisor(Arc::new(CompletingSupervisor {
                effects_after_await: Arc::clone(&effects),
                outcome: Arc::clone(&outcome),
            }))
            .on_shutdown_async(move |_| async move {
                assert!(!cleanup_runtime.is_task_service_ready());
                cleanup_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .build();
        let serving = Arc::new(Mutex::new(None));
        let serving_context = Arc::clone(&serving);
        let listener = cx
            .spawn(move |serve_cx| async move {
                *serving_context.lock().unwrap() = Some(serve_cx.clone());
                server
                    .bind_websocket(&serve_cx, "127.0.0.1:0")
                    .await?
                    .serve(&serve_cx)
                    .await
            })
            .unwrap();
        let mut running = ListenerReceiptGuard {
            store: Arc::clone(&fixture.store),
            listener: Some(listener),
        };
        asupersync::time::timeout(
            cx.now(),
            StdDuration::from_secs(5),
            fixture.store.committed.wait(),
        )
        .await
        .expect("the WebSocket-hosted service must commit its pending work");
        assert_eq!(fixture.store.writes.load(Ordering::SeqCst), 1);
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        serving.lock().unwrap().as_ref().unwrap().cancel_with(
            CancelKind::User,
            Some("WebSocket receipt shutdown regression"),
        );
        // WebSocket retains its five-second child/cleanup observation after
        // the four-second Task settlement grace. Leave ample scheduling margin.
        let joined = asupersync::time::timeout(
            cx.now(),
            StdDuration::from_secs(20),
            running.listener.as_mut().unwrap().join(&cx),
        )
        .await
        .expect("WebSocket shutdown must return its pending Task owner");
        running.listener = None;
        let WebSocketServerShutdown::Nonquiescent(mut retained) = joined.unwrap().unwrap() else {
            panic!("the WebSocket listener must retain the pending worker receipt");
        };
        let expected = "The hosted Task service did not settle within its bound";
        assert_eq!(retained.remaining_connections(), 0);
        assert_eq!(retained.listener_error().unwrap().message, expected);
        assert!(fixture.runtime.is_task_service_ready());
        assert_eq!(cleanups.load(Ordering::SeqCst), 0);
        assert!(
            !retained
                .settle_for(StdDuration::from_millis(5))
                .await
                .unwrap()
        );
        assert_eq!(cleanups.load(Ordering::SeqCst), 0);
        fixture.store.receipt_gate.release();
        let error = retained
            .settle_for(StdDuration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(error.message, expected);
        assert_eq!(cleanups.load(Ordering::SeqCst), 1);
        assert!(!fixture.runtime.is_task_service_ready());
        assert_eq!(
            retained
                .settle_for(StdDuration::ZERO)
                .await
                .unwrap_err()
                .message,
            expected
        );
        let error =
            asupersync::time::timeout(cx.now(), StdDuration::from_secs(5), retained.settle(&cx))
                .await
                .expect("the completed WebSocket shutdown owner must remain settled")
                .unwrap_err();
        assert_eq!(error.message, expected);
        assert_eq!(cleanups.load(Ordering::SeqCst), 1);
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        assert!(outcome.lock().unwrap().is_none());
        assert_eq!(fixture.store.writes.load(Ordering::SeqCst), 1);
        assert!(matches!(
            fixture.snapshot().task(),
            FinalTask::Completed { .. }
        ));
        assert!(cx.checkpoint().is_ok());
    });
    assert!(runtime.shutdown_timeout(StdDuration::from_secs(2)));
}

#[test]
fn async_worker_real_service_keeps_committed_receipt_without_late_application_poll() {
    for resumed in [false, true] {
        for interruption in [
            ReceiptInterruption::None,
            ReceiptInterruption::AttemptCancelled,
            ReceiptInterruption::ServiceCancelled,
            ReceiptInterruption::Revoked,
            ReceiptInterruption::Expired,
            ReceiptInterruption::ProviderError,
        ] {
            let (fixture, handoff) = Fixture::new(resumed);
            fixture.store.receipt_gate.close();
            let effects = Arc::new(AtomicUsize::new(0));
            let outcome = Arc::new(Mutex::new(None));
            let runner = fixture
                .runtime
                .install_task_service(
                    1,
                    Arc::new(CompletingSupervisor {
                        effects_after_await: Arc::clone(&effects),
                        outcome: Arc::clone(&outcome),
                    }),
                )
                .unwrap();
            let store = Arc::clone(&fixture.store);
            let permission = Arc::clone(&fixture.permission);
            let effects_in_lab = Arc::clone(&effects);
            let service_context = Arc::new(Mutex::new(None));
            let captured_service = Arc::clone(&service_context);
            asupersync::lab::run_async_under_lab(0xA51C_2026, move |cx| async move {
                let mut running = cx
                    .spawn(move |service_cx| async move {
                        *captured_service.lock().unwrap() = Some(service_cx.clone());
                        runner.resume_handoff(&service_cx, handoff).await
                    })
                    .unwrap();
                store.committed.wait().await;
                assert_eq!(store.writes.load(Ordering::SeqCst), 1);
                assert_eq!(effects_in_lab.load(Ordering::SeqCst), 0);
                // An ordinary wake after commit must not revalidate the now
                // consumed lease as though a different owner stole it.
                store.receipt_gate.pulse();
                let mut sibling = cx.spawn(|_| async { 17usize }).unwrap();
                assert_eq!(sibling.join(&cx).await.unwrap(), 17);
                match interruption {
                    ReceiptInterruption::None => {}
                    ReceiptInterruption::AttemptCancelled => {
                        store
                            .provider_cx
                            .lock()
                            .unwrap()
                            .as_ref()
                            .unwrap()
                            .cancel_with(CancelKind::User, None);
                    }
                    ReceiptInterruption::ServiceCancelled => {
                        service_context
                            .lock()
                            .unwrap()
                            .as_ref()
                            .unwrap()
                            .cancel_with(CancelKind::User, None);
                    }
                    ReceiptInterruption::Revoked => {
                        permission.0.store(false, Ordering::SeqCst);
                    }
                    ReceiptInterruption::Expired => {
                        *store.clock.lock().unwrap() += StdDuration::from_secs(7_200);
                    }
                    ReceiptInterruption::ProviderError => {
                        store.fail_after_admission.store(true, Ordering::SeqCst);
                    }
                }
                store.receipt_gate.pulse();
                let mut sibling = cx.spawn(|_| async { 23usize }).unwrap();
                assert_eq!(sibling.join(&cx).await.unwrap(), 23);
                assert_eq!(
                    effects_in_lab.load(Ordering::SeqCst),
                    0,
                    "receipt remains pending: {interruption:?}"
                );
                store.receipt_gate.release();
                let joined = running.join(&cx).await;
                if matches!(interruption, ReceiptInterruption::None) {
                    assert!(matches!(joined, Ok(Ok(()))), "{joined:?}");
                }
                assert_eq!(
                    effects_in_lab.load(Ordering::SeqCst),
                    usize::from(matches!(interruption, ReceiptInterruption::None)),
                    "settlement cannot resume expired/cancelled/revoked application code: {interruption:?}"
                );
            });
            assert!(
                matches!(fixture.snapshot().task(), FinalTask::Completed { .. }),
                "committed result survives {interruption:?}"
            );
            assert!(
                fixture
                    .store
                    .inner
                    .next_initial_work_snapshot_after(None)
                    .unwrap()
                    .is_none()
            );
            assert!(
                fixture
                    .store
                    .inner
                    .next_accepted_input_snapshot_after(None)
                    .unwrap()
                    .is_none()
            );
            if let Some(outcome) = outcome.lock().unwrap().as_ref() {
                assert!(final_tasks_match_exactly(outcome, fixture.snapshot().task()).unwrap());
            }
            if matches!(interruption, ReceiptInterruption::ProviderError) {
                assert_eq!(
                    fixture.store.restorations.load(Ordering::SeqCst),
                    0,
                    "uncertain writes cannot be replayed"
                );
            }
        }
    }
}
