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
/// payload semantics. Only the eight new I/O boundaries are delayed.
struct AsyncRecoveryStore {
    inner: InMemoryFinalTaskStore,
    clock: Arc<Mutex<Instant>>,
    gates: [Gate; 8],
    calls: [AtomicUsize; 8],
    initial_pause_from: AtomicUsize,
    receipt: Gate,
    claimed: AtomicUsize,
    restored: AtomicUsize,
    renewals: AtomicUsize,
    forbid_sync: AtomicBool,
    sync_calls: AtomicUsize,
    substitute_read: Mutex<Option<FinalTaskSnapshot>>,
    cancel_after_claim: AtomicBool,
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
            initial_pause_from: AtomicUsize::new(1),
            receipt: Gate::new(),
            claimed: AtomicUsize::new(0),
            restored: AtomicUsize::new(0),
            renewals: AtomicUsize::new(0),
            forbid_sync: AtomicBool::new(false),
            sync_calls: AtomicUsize::new(0),
            substitute_read: Mutex::new(None),
            cancel_after_claim: AtomicBool::new(false),
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
        if !matches!(step, Step::InitialScan)
            || call >= self.initial_pause_from.load(Ordering::SeqCst)
        {
            self.gate(step).wait().await;
        }
        self.caller(cx);
        cx.checkpoint().map_err(|_| McpError::request_cancelled())
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
        fn task_execution_budget_if_current(&self, expected: &FinalTaskSnapshot) -> McpResult<Option<FinalTaskExecutionBudget>>;
        fn get_handoff_access_metadata(&self, task_id: &FinalTaskId, generation: u64, owner_id: &str, fence: u64) -> McpResult<Option<FinalTaskAccessMetadata>>;
        fn create_task(&self, task: FinalTask, notification: FinalTaskStatusNotification) -> McpResult<()>;
        fn get_task(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTask>>;
        fn replace_task(&self, task: FinalTask, notification: FinalTaskStatusNotification) -> McpResult<()>;
        fn replace_task_if_current(&self, expected: &FinalTaskSnapshot, task: FinalTask, notification: FinalTaskStatusNotification) -> McpResult<bool>;
        fn replace_task_and_clear_input_for_handoff_if_current(&self, expected: &FinalTaskSnapshot, owner_id: &str, dispatch_fence: u64, cancellation_required: bool, task: FinalTask, notification: FinalTaskStatusNotification) -> McpResult<Option<FinalTaskSnapshot>>;
        fn begin_handoff_dispatch_for_owner_if_current(&self, task_id: &FinalTaskId, generation: u64, owner_id: &str) -> McpResult<Option<u64>>;
        fn finish_handoff_dispatch_for_owner_if_current(&self, task_id: &FinalTaskId, generation: u64, owner_id: &str, dispatch_fence: u64) -> McpResult<bool>;
        fn request_cancellation(&self, task_id: &FinalTaskId) -> McpResult<()>;
        fn request_cancellation_if_current(&self, expected: &FinalTaskSnapshot) -> McpResult<bool>;
        fn request_cancellation_and_clear_input_if_current(&self, expected: &FinalTaskSnapshot, task: FinalTask, notification: FinalTaskStatusNotification) -> McpResult<Option<FinalTaskSnapshot>>;
        fn is_cancellation_requested(&self, task_id: &FinalTaskId) -> McpResult<bool>;
        fn retention_clock_now(&self) -> Instant;
        fn task_retention_deadline_if_current(&self, task_id: &FinalTaskId, generation: u64) -> McpResult<Option<FinalTaskRetentionDeadline>>;
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
            self.inner.get_task_access_metadata(task_id)
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
        // The existing elected worker's maintenance remains a bounded sync
        // contract. Direct recovery tests forbid this fallback independently.
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
            self.inner.next_expired_execution_snapshot()
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
            self.inner.expire_task_execution_if_current(expected)
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

    fn renew_handoff_dispatch_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: u64,
    ) -> McpResult<bool> {
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
