use super::*;
use asupersync::runtime::RuntimeBuilder;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Wake, Waker};

struct Gate {
    open: AtomicBool,
    waiter: Mutex<Option<Waker>>,
}

impl Gate {
    fn new() -> Self {
        Self {
            open: AtomicBool::new(true),
            waiter: Mutex::new(None),
        }
    }

    fn close(&self) {
        let _waiter = self.waiter.lock().unwrap();
        self.open.store(false, TaskServiceOrdering::SeqCst);
    }

    fn release(&self) {
        let waiter = {
            let mut waiter = self.waiter.lock().unwrap();
            self.open.store(true, TaskServiceOrdering::SeqCst);
            waiter.take()
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }

    async fn wait(&self) {
        std::future::poll_fn(|cx| {
            let mut waiter = self.waiter.lock().unwrap();
            if self.open.load(TaskServiceOrdering::SeqCst) {
                Poll::Ready(())
            } else {
                *waiter = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await;
    }
}

type Hook = Box<dyn FnOnce() + Send>;

/// Suspends the actual in-memory store operations without changing their CAS,
/// authorization metadata, payload accounting, or elected-lease semantics.
struct AsyncWorkerStore {
    inner: InMemoryFinalTaskStore,
    read_gate: Gate,
    cancellation_gate: Gate,
    write_gate: Gate,
    receipt_gate: Gate,
    paused_read: Mutex<Option<FinalTaskId>>,
    before_write: Mutex<Option<Hook>>,
    after_write: Mutex<Option<Hook>>,
    substituted_receipt: Mutex<Option<FinalTaskSnapshot>>,
    error_after_write: AtomicBool,
    omit_metadata: AtomicBool,
    forbid_sync: AtomicBool,
    synchronous_calls: AtomicUsize,
    reads: AtomicUsize,
    transitions: AtomicUsize,
    status_updates: AtomicUsize,
    committed: AtomicUsize,
}

impl AsyncWorkerStore {
    fn new() -> Self {
        Self {
            inner: InMemoryFinalTaskStore::default(),
            read_gate: Gate::new(),
            cancellation_gate: Gate::new(),
            write_gate: Gate::new(),
            receipt_gate: Gate::new(),
            paused_read: Mutex::new(None),
            before_write: Mutex::new(None),
            after_write: Mutex::new(None),
            substituted_receipt: Mutex::new(None),
            error_after_write: AtomicBool::new(false),
            omit_metadata: AtomicBool::new(false),
            forbid_sync: AtomicBool::new(false),
            synchronous_calls: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            transitions: AtomicUsize::new(0),
            status_updates: AtomicUsize::new(0),
            committed: AtomicUsize::new(0),
        }
    }

    fn check_sync(&self) {
        if self.forbid_sync.load(TaskServiceOrdering::SeqCst) {
            self.synchronous_calls
                .fetch_add(1, TaskServiceOrdering::SeqCst);
            panic!("asynchronous worker operation called a synchronous store method");
        }
    }

    fn asynchronous_only(&self) -> AsyncOnly<'_> {
        assert!(!self.forbid_sync.swap(true, TaskServiceOrdering::SeqCst));
        AsyncOnly(self)
    }

    fn pause_reads_for(&self, task_id: &FinalTaskId) {
        *self.paused_read.lock().unwrap() = Some(task_id.clone());
        self.read_gate.close();
    }

    async fn read(&self, ctx: &McpContext, task_id: &FinalTaskId) {
        self.reads.fetch_add(1, TaskServiceOrdering::SeqCst);
        assert!(Cx::current().is_some(), "the provider retains its caller");
        assert!(ctx.cx().blocking_pool_handle().is_none());
        let paused = self.paused_read.lock().unwrap().as_ref() == Some(task_id);
        if paused {
            self.read_gate.wait().await;
        }
    }

    async fn write(
        &self,
        admission: FinalTaskWorkerAdmission<'_>,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
        status_only: bool,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        assert!(Cx::current().is_some(), "the provider retains its caller");
        assert!(admission.context().cx().blocking_pool_handle().is_none());
        self.write_gate.wait().await;
        admission.checkpoint_before_write()?;
        let hook = self.before_write.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        let committed = if status_only {
            self.inner.update_working_status_for_handoff_if_current(
                admission.expected(),
                admission.owner_id(),
                admission.dispatch_fence(),
                task,
                notification,
            )?
        } else {
            self.inner
                .replace_task_and_clear_input_for_handoff_if_current(
                    admission.expected(),
                    admission.owner_id(),
                    admission.dispatch_fence(),
                    admission.cancellation_required(),
                    task,
                    notification,
                )?
        };
        if committed.is_some() {
            self.committed.fetch_add(1, TaskServiceOrdering::SeqCst);
        }
        let hook = self.after_write.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        self.receipt_gate.wait().await;
        if self.error_after_write.load(TaskServiceOrdering::SeqCst) {
            return Err(McpError::request_cancelled());
        }
        if let Some(substitute) = self.substituted_receipt.lock().unwrap().take() {
            return Ok(Some(substitute));
        }
        Ok(committed)
    }
}

struct AsyncOnly<'a>(&'a AsyncWorkerStore);

impl Drop for AsyncOnly<'_> {
    fn drop(&mut self) {
        // A failed assertion must not make the existing synchronous service
        // guard panic a second time while restoring its handoff during unwind.
        self.0.forbid_sync.store(false, TaskServiceOrdering::SeqCst);
    }
}

impl FinalTaskStore for AsyncWorkerStore {
    fn create_task(
        &self,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> McpResult<()> {
        self.check_sync();
        self.inner.create_task(task, notification)
    }

    fn get_task(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTask>> {
        self.check_sync();
        self.inner.get_task(task_id)
    }

    fn get_task_snapshot(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTaskSnapshot>> {
        self.check_sync();
        self.inner.get_task_snapshot(task_id)
    }

    fn get_task_access_metadata(
        &self,
        task_id: &FinalTaskId,
    ) -> McpResult<Option<FinalTaskAccessMetadata>> {
        self.check_sync();
        self.inner.get_task_access_metadata(task_id)
    }

    fn get_handoff_access_metadata(
        &self,
        task_id: &FinalTaskId,
        claim_generation: u64,
        owner_id: &str,
        dispatch_fence: u64,
    ) -> McpResult<Option<FinalTaskAccessMetadata>> {
        self.check_sync();
        self.inner
            .get_handoff_access_metadata(task_id, claim_generation, owner_id, dispatch_fence)
    }

    fn get_task_access_metadata_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskAccessMetadata>> {
        Box::pin(async move {
            self.read(ctx, task_id).await;
            if self.omit_metadata.load(TaskServiceOrdering::SeqCst) {
                Ok(None)
            } else {
                self.inner.get_task_access_metadata(task_id)
            }
        })
    }

    fn get_handoff_access_metadata_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
        claim_generation: u64,
        owner_id: &'a str,
        dispatch_fence: u64,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskAccessMetadata>> {
        Box::pin(async move {
            self.read(ctx, task_id).await;
            if self.omit_metadata.load(TaskServiceOrdering::SeqCst) {
                Ok(None)
            } else {
                self.inner.get_handoff_access_metadata(
                    task_id,
                    claim_generation,
                    owner_id,
                    dispatch_fence,
                )
            }
        })
    }

    fn get_task_snapshot_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        Box::pin(async move {
            self.read(ctx, task_id).await;
            self.inner.get_task_snapshot(task_id)
        })
    }

    fn replace_task_and_clear_input_for_handoff_with_context<'a>(
        &'a self,
        admission: FinalTaskWorkerAdmission<'a>,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.transitions.fetch_add(1, TaskServiceOrdering::SeqCst);
        Box::pin(self.write(admission, task, notification, false))
    }

    fn update_working_status_for_handoff_with_context<'a>(
        &'a self,
        admission: FinalTaskWorkerAdmission<'a>,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.status_updates
            .fetch_add(1, TaskServiceOrdering::SeqCst);
        Box::pin(self.write(admission, task, notification, true))
    }

    fn is_cancellation_requested_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, bool> {
        Box::pin(async move {
            self.read(ctx, task_id).await;
            self.cancellation_gate.wait().await;
            self.inner.is_cancellation_requested(task_id)
        })
    }

    fn replace_task(
        &self,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> McpResult<()> {
        self.check_sync();
        self.inner.replace_task(task, notification)
    }

    fn replace_task_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> McpResult<bool> {
        self.check_sync();
        self.inner
            .replace_task_if_current(expected, task, notification)
    }

    fn replace_task_and_clear_input_for_handoff_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        owner_id: &str,
        dispatch_fence: u64,
        cancellation_required: bool,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        self.check_sync();
        self.inner
            .replace_task_and_clear_input_for_handoff_if_current(
                expected,
                owner_id,
                dispatch_fence,
                cancellation_required,
                task,
                notification,
            )
    }

    fn update_working_status_for_handoff_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        owner_id: &str,
        dispatch_fence: u64,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        self.check_sync();
        self.inner.update_working_status_for_handoff_if_current(
            expected,
            owner_id,
            dispatch_fence,
            task,
            notification,
        )
    }

    fn is_cancellation_requested(&self, task_id: &FinalTaskId) -> McpResult<bool> {
        self.check_sync();
        self.inner.is_cancellation_requested(task_id)
    }

    fn request_cancellation(&self, task_id: &FinalTaskId) -> McpResult<()> {
        self.check_sync();
        self.inner.request_cancellation(task_id)
    }

    fn request_cancellation_if_current(&self, expected: &FinalTaskSnapshot) -> McpResult<bool> {
        self.check_sync();
        self.inner.request_cancellation_if_current(expected)
    }

    fn retention_clock_now(&self) -> Instant {
        // A backend clock sample is explicitly synchronous and must never do I/O.
        self.inner.retention_clock_now()
    }

    fn task_retention_deadline_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
    ) -> McpResult<Option<FinalTaskRetentionDeadline>> {
        self.check_sync();
        self.inner
            .task_retention_deadline_if_current(task_id, generation)
    }

    fn execution_limits(&self) -> McpResult<FinalTaskExecutionLimits> {
        self.inner.execution_limits()
    }

    fn task_execution_budget_if_current(
        &self,
        expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskExecutionBudget>> {
        self.check_sync();
        self.inner.task_execution_budget_if_current(expected)
    }

    fn expire_task_execution_if_current(
        &self,
        expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        self.check_sync();
        self.inner.expire_task_execution_if_current(expected)
    }

    fn next_initial_work_snapshot_after(
        &self,
        after_task_id: Option<&FinalTaskId>,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        self.check_sync();
        self.inner.next_initial_work_snapshot_after(after_task_id)
    }

    fn take_initial_work_handoff_for_owner_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        owner_id: &str,
    ) -> McpResult<Option<FinalTaskInitialWorkClaim>> {
        self.check_sync();
        self.inner
            .take_initial_work_handoff_for_owner_if_current(expected, owner_id)
    }

    fn next_accepted_input_snapshot_after(
        &self,
        after_task_id: Option<&FinalTaskId>,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        self.check_sync();
        self.inner.next_accepted_input_snapshot_after(after_task_id)
    }

    fn take_input_handoff_for_owner_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        owner_id: &str,
    ) -> McpResult<Option<FinalTaskAcceptedInputClaim>> {
        self.check_sync();
        self.inner
            .take_input_handoff_for_owner_if_current(expected, owner_id)
    }

    fn begin_handoff_dispatch_for_owner_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
    ) -> McpResult<Option<u64>> {
        self.check_sync();
        self.inner
            .begin_handoff_dispatch_for_owner_if_current(task_id, generation, owner_id)
    }

    fn restore_initial_work_for_owner_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: Option<u64>,
        work_descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<bool> {
        self.check_sync();
        self.inner.restore_initial_work_for_owner_if_current(
            task_id,
            generation,
            owner_id,
            dispatch_fence,
            work_descriptor,
        )
    }

    fn restore_input_for_owner_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: Option<u64>,
        input_responses: FinalTaskInputResponses,
    ) -> McpResult<bool> {
        self.check_sync();
        self.inner.restore_input_for_owner_if_current(
            task_id,
            generation,
            owner_id,
            dispatch_fence,
            input_responses,
        )
    }
}

struct CurrentPolicy {
    allowed: AtomicBool,
}

impl TaskExecutionAuthorizer for CurrentPolicy {
    fn authorize(&self, _metadata: &FinalTaskAccessMetadata) -> McpResult<()> {
        if self.allowed.load(TaskServiceOrdering::SeqCst) {
            Ok(())
        } else {
            Err(McpError::invalid_request("worker grant was revoked"))
        }
    }
}

struct Fixture {
    store: Arc<AsyncWorkerStore>,
    runtime: FinalTaskRuntime,
    policy: Arc<CurrentPolicy>,
    task_id: FinalTaskId,
    handoff: FinalTaskSupervisorHandoff,
    guard: Option<FinalTaskExecutionGuard>,
    notifications: Arc<Mutex<Vec<FinalTask>>>,
    _registration: Arc<()>,
}

impl Fixture {
    fn new(resumed: bool) -> Self {
        Self::with_store(
            Arc::new(AsyncWorkerStore::new()),
            "async-worker-task",
            resumed,
        )
    }

    fn with_store(store: Arc<AsyncWorkerStore>, name: &str, resumed: bool) -> Self {
        Self::with_identity(store, name, resumed, true)
    }

    fn with_identity(
        store: Arc<AsyncWorkerStore>,
        name: &str,
        resumed: bool,
        authenticated: bool,
    ) -> Self {
        let notifications = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&notifications);
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
            Arc::new(move |notification| sink.lock().unwrap().push(notification.params.task)),
        );
        let policy = Arc::new(CurrentPolicy {
            allowed: AtomicBool::new(true),
        });
        if authenticated {
            runtime
                .install_execution_authorizer(policy.clone())
                .unwrap();
        }
        let registration = Arc::new(());
        let task_id = FinalTaskId::parse(name).unwrap();
        let timestamp = FinalTaskTimestamp::parse("2026-07-28T12:00:00.000Z").unwrap();
        let task = FinalTask::Working(FinalTaskBase {
            task_id: task_id.clone(),
            status: FinalTaskStatus::Working,
            status_message: None,
            created_at: timestamp.clone(),
            last_updated_at: timestamp,
            ttl_ms: Some(final_task_duration(60_000).unwrap()),
            poll_interval_ms: None,
        });
        let descriptor =
            FinalTaskWorkDescriptor::new(serde_json::json!({"handler":"async-worker"})).unwrap();
        let created = if authenticated {
            store.inner.create_task_with_operation(
                task.clone(),
                final_task_notification(&task),
                descriptor,
                Some(Sha256Digest::from_bytes([41; 32])),
                FinalTaskOperation::for_tool("async-worker", &registration).unwrap(),
            )
        } else {
            store.inner.create_task_with_work(
                task.clone(),
                final_task_notification(&task),
                descriptor,
            )
        }
        .unwrap();
        if resumed {
            let waiting = FinalTask::InputRequired {
                base: transition_final_task_base(
                    created.task().base().clone(),
                    FinalTaskStatus::InputRequired,
                    None,
                )
                .unwrap(),
                input_requests: roots_request(),
            };
            let waiting = store
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
            store
                .inner
                .replace_task_and_append_input_if_current(
                    &waiting,
                    working.clone(),
                    final_task_notification(&working),
                    roots_response(),
                )
                .unwrap()
                .unwrap();
        }
        let mut handoff = if resumed {
            FinalTaskSupervisorHandoff::Resumed(runtime.recover_accepted_input().unwrap().unwrap())
        } else {
            FinalTaskSupervisorHandoff::Initial(runtime.recover_initial_work().unwrap().unwrap())
        };
        assert_eq!(final_task_handoff_task_id(&handoff), &task_id);
        let mut guard =
            FinalTaskExecutionGuard::new(&runtime, FINAL_TASK_TEST_DIRECT_OWNER, &handoff);
        assert!(guard.elect().unwrap());
        handoff.attach_authority(guard.authority().unwrap());
        Self {
            store,
            runtime,
            policy,
            task_id,
            handoff,
            guard: Some(guard),
            notifications,
            _registration: registration,
        }
    }

    fn snapshot(&self) -> FinalTaskSnapshot {
        self.store
            .inner
            .get_task_snapshot(&self.task_id)
            .unwrap()
            .unwrap()
    }

    fn wire(&self) -> String {
        serde_json::to_string(self.snapshot().task()).unwrap()
    }

    fn retained_facts(&self) -> (u64, String, usize, serde_json::Value) {
        (
            self.snapshot().generation(),
            self.wire(),
            self.store.inner.retained_payload_bytes(),
            serde_json::to_value(self.store.inner.latest_notification(&self.task_id)).unwrap(),
        )
    }
}

fn roots_request() -> FinalTaskInputRequests {
    serde_json::from_value(serde_json::json!({"roots":{"method":"roots/list"}})).unwrap()
}

fn roots_response() -> FinalTaskInputResponses {
    serde_json::from_value(serde_json::json!({"roots":{"roots":[]}})).unwrap()
}

fn result() -> FinalTaskCallToolResult {
    serde_json::from_str(r#"{"content":[{"type":"text","text":"completed asynchronously"}],"structuredContent":{"answer":7},"_meta":{"worker":"async"},"vendor":{"number":1e+00}}"#).unwrap()
}

async fn complete(handoff: &FinalTaskSupervisorHandoff, cx: &Cx) -> McpResult<FinalTask> {
    match handoff {
        FinalTaskSupervisorHandoff::Initial(work) => {
            work.complete_task_with_cx(cx, result(), None).await
        }
        FinalTaskSupervisorHandoff::Resumed(work) => {
            work.complete_task_with_cx(cx, result(), None).await
        }
    }
}

async fn update(
    handoff: &mut FinalTaskSupervisorHandoff,
    cx: &Cx,
    message: &str,
) -> McpResult<FinalTask> {
    match handoff {
        FinalTaskSupervisorHandoff::Initial(work) => {
            work.update_status_message_with_cx(cx, Some(message.to_owned()))
                .await
        }
        FinalTaskSupervisorHandoff::Resumed(work) => {
            work.update_status_message_with_cx(cx, Some(message.to_owned()))
                .await
        }
    }
}

async fn require_input(
    handoff: &FinalTaskSupervisorHandoff,
    cx: &Cx,
    requests: FinalTaskInputRequests,
) -> McpResult<FinalTask> {
    match handoff {
        FinalTaskSupervisorHandoff::Initial(work) => {
            work.require_input_with_cx(cx, requests, None).await
        }
        FinalTaskSupervisorHandoff::Resumed(work) => {
            work.require_input_with_cx(cx, requests, None).await
        }
    }
}

async fn cancellation_requested(handoff: &FinalTaskSupervisorHandoff, cx: &Cx) -> McpResult<bool> {
    match handoff {
        FinalTaskSupervisorHandoff::Initial(work) => {
            work.is_cancellation_requested_with_cx(cx).await
        }
        FinalTaskSupervisorHandoff::Resumed(work) => {
            work.is_cancellation_requested_with_cx(cx).await
        }
    }
}

async fn honor_cancellation(handoff: &FinalTaskSupervisorHandoff, cx: &Cx) -> McpResult<FinalTask> {
    match handoff {
        FinalTaskSupervisorHandoff::Initial(work) => {
            work.honor_cancellation_with_cx(cx, None).await
        }
        FinalTaskSupervisorHandoff::Resumed(work) => {
            work.honor_cancellation_with_cx(cx, None).await
        }
    }
}

fn with_runtime(scenario: impl Future<Output = ()>) {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(scenario);
    assert!(runtime.shutdown_timeout(StdDuration::from_secs(2)));
}

fn poll_once<T>(future: Pin<&mut impl Future<Output = McpResult<T>>>) -> Poll<McpResult<T>> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn ready<T>(outcome: Poll<McpResult<T>>) -> McpResult<T> {
    match outcome {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("released in-memory operation remained pending"),
    }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, TaskServiceOrdering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, TaskServiceOrdering::SeqCst);
    }
}

#[test]
fn async_worker_status_and_completion_preserve_initial_and_resumed_claims() {
    with_runtime(async {
        let cx = Cx::current().unwrap();
        for resumed in [false, true] {
            let mut fixture = Fixture::new(resumed);
            let original = fixture.snapshot();
            let budget = fixture.handoff.execution_budget().unwrap();
            let claim = fixture.guard.as_ref().unwrap().generation;
            let fence = fixture.guard.as_ref().unwrap().dispatch_fence;
            let _async_only = fixture.store.asynchronous_only();

            let first = update(&mut fixture.handoff, &cx, "loading").await.unwrap();
            assert!(matches!(first, FinalTask::Working(_)));
            assert_eq!(first.base().status_message.as_deref(), Some("loading"));
            let first_generation = fixture.snapshot().generation();
            assert!(first_generation > original.generation());

            let second = update(&mut fixture.handoff, &cx, "finishing")
                .await
                .unwrap();
            assert_eq!(second.base().status_message.as_deref(), Some("finishing"));
            assert!(fixture.snapshot().generation() > first_generation);
            assert_eq!(fixture.handoff.execution_budget().unwrap(), budget);
            {
                let state = fixture.store.inner.state.lock().unwrap();
                let lease = state.handoff_leases.get(&fixture.task_id).unwrap();
                assert_eq!(lease.generation, claim);
                assert_eq!(lease.dispatch_fence, fence);
                assert_eq!(state.execution_budgets[&fixture.task_id], budget);
                assert_eq!(
                    state.creation_generations[&fixture.task_id],
                    original.creation_generation()
                );
                if resumed {
                    assert_eq!(
                        serde_json::to_value(state.accepted_inputs.get(&fixture.task_id)).unwrap(),
                        serde_json::to_value(Some(roots_response())).unwrap(),
                    );
                }
            }

            let completed = complete(&fixture.handoff, &cx).await.unwrap();
            let FinalTask::Completed {
                result: committed, ..
            } = &completed
            else {
                panic!("worker did not retain the completion");
            };
            assert_eq!(
                serde_json::to_string(committed).unwrap(),
                serde_json::to_string(&result()).unwrap()
            );
            assert_eq!(serde_json::to_string(&completed).unwrap(), fixture.wire());
            assert_eq!(fixture.notifications.lock().unwrap().len(), 3);
            assert_eq!(
                fixture
                    .store
                    .status_updates
                    .load(TaskServiceOrdering::SeqCst),
                2
            );
            assert_eq!(
                fixture.store.transitions.load(TaskServiceOrdering::SeqCst),
                1
            );
            assert_eq!(fixture.store.committed.load(TaskServiceOrdering::SeqCst), 3);

            let settled = fixture.retained_facts();
            assert!(complete(&fixture.handoff, &cx).await.is_err());
            assert_eq!(fixture.retained_facts(), settled);
            assert_eq!(
                fixture
                    .store
                    .synchronous_calls
                    .load(TaskServiceOrdering::SeqCst),
                0
            );
        }
    });
}

#[test]
fn async_worker_pending_read_keeps_another_task_runnable() {
    with_runtime(async {
        let cx = Cx::current().unwrap();
        let store = Arc::new(AsyncWorkerStore::new());
        let paused = Fixture::with_store(store.clone(), "paused-worker", false);
        let sibling = Fixture::with_store(store.clone(), "runnable-worker", true);
        store.pause_reads_for(&paused.task_id);
        let _async_only = store.asynchronous_only();
        let mut pending = Box::pin(complete(&paused.handoff, &cx));
        assert!(poll_once(pending.as_mut()).is_pending());

        let completed = complete(&sibling.handoff, &cx).await.unwrap();
        assert!(matches!(completed, FinalTask::Completed { .. }));
        assert!(matches!(paused.snapshot().task(), FinalTask::Working(_)));
        assert_eq!(store.committed.load(TaskServiceOrdering::SeqCst), 1);

        store.read_gate.release();
        assert!(matches!(
            ready(poll_once(pending.as_mut())).unwrap(),
            FinalTask::Completed { .. }
        ));
        assert_eq!(store.committed.load(TaskServiceOrdering::SeqCst), 2);
        assert_eq!(store.synchronous_calls.load(TaskServiceOrdering::SeqCst), 0);
    });
}

#[test]
fn async_worker_revoked_during_pending_write_cannot_change_the_record() {
    with_runtime(async {
        let cx = Cx::current().unwrap();
        for resumed in [false, true] {
            let fixture = Fixture::new(resumed);
            let original = fixture.retained_facts();
            fixture.store.write_gate.close();
            let _async_only = fixture.store.asynchronous_only();
            let mut pending = Box::pin(complete(&fixture.handoff, &cx));
            assert!(poll_once(pending.as_mut()).is_pending());
            assert_eq!(
                fixture.store.transitions.load(TaskServiceOrdering::SeqCst),
                1
            );

            fixture
                .policy
                .allowed
                .store(false, TaskServiceOrdering::SeqCst);
            fixture.store.write_gate.release();
            assert!(ready(poll_once(pending.as_mut())).is_err());
            assert_eq!(fixture.retained_facts(), original);
            assert_eq!(fixture.store.committed.load(TaskServiceOrdering::SeqCst), 0);
            assert!(fixture.notifications.lock().unwrap().is_empty());
            assert_eq!(
                fixture
                    .store
                    .synchronous_calls
                    .load(TaskServiceOrdering::SeqCst),
                0
            );
        }
    });
}

#[test]
fn async_worker_cancellation_wakes_a_pending_read_or_unadmitted_write() {
    for pause_read in [false, true] {
        with_runtime(async {
            let cx = Cx::current().unwrap();
            let fixture = Fixture::new(false);
            let original = fixture.retained_facts();
            if pause_read {
                fixture.store.pause_reads_for(&fixture.task_id);
            } else {
                fixture.store.write_gate.close();
            }
            let _async_only = fixture.store.asynchronous_only();
            let wakes = Arc::new(WakeCount::default());
            let waker = Waker::from(wakes.clone());
            let mut pending = Box::pin(complete(&fixture.handoff, &cx));
            assert!(
                pending
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            let before = wakes.0.load(TaskServiceOrdering::SeqCst);

            cx.set_cancel_requested(true);
            assert!(wakes.0.load(TaskServiceOrdering::SeqCst) > before);
            let error = ready(poll_once(pending.as_mut())).unwrap_err();
            assert_eq!(error.code, McpError::request_cancelled().code);
            assert_eq!(fixture.retained_facts(), original);
            assert_eq!(fixture.store.committed.load(TaskServiceOrdering::SeqCst), 0);
            assert!(fixture.notifications.lock().unwrap().is_empty());
        });
    }
}

#[test]
fn async_worker_committed_receipt_survives_late_cancellation_and_revocation() {
    for resumed in [false, true] {
        with_runtime(async {
            let cx = Cx::current().unwrap();
            let fixture = Fixture::new(resumed);
            fixture.store.receipt_gate.close();
            let policy = fixture.policy.clone();
            let cancel = cx.clone();
            *fixture.store.after_write.lock().unwrap() = Some(Box::new(move || {
                cancel.set_cancel_requested(true);
                policy.allowed.store(false, TaskServiceOrdering::SeqCst);
            }));
            let _async_only = fixture.store.asynchronous_only();
            let mut pending = Box::pin(complete(&fixture.handoff, &cx));
            assert!(poll_once(pending.as_mut()).is_pending());
            assert_eq!(fixture.store.committed.load(TaskServiceOrdering::SeqCst), 1);
            assert!(matches!(
                fixture.snapshot().task(),
                FinalTask::Completed { .. }
            ));
            let committed = fixture.retained_facts();

            fixture.store.receipt_gate.release();
            let completed = ready(poll_once(pending.as_mut())).unwrap();
            assert_eq!(serde_json::to_string(&completed).unwrap(), fixture.wire());
            assert_eq!(fixture.retained_facts(), committed);
            assert_eq!(
                fixture.store.transitions.load(TaskServiceOrdering::SeqCst),
                1
            );
            assert!(
                fixture
                    .guard
                    .as_ref()
                    .unwrap()
                    .transition_committed
                    .load(TaskServiceOrdering::SeqCst)
            );
            assert_eq!(
                fixture
                    .store
                    .synchronous_calls
                    .load(TaskServiceOrdering::SeqCst),
                0
            );
        });
    }
}

#[test]
fn async_worker_input_receipt_is_preserved_after_the_next_input_arrives() {
    with_runtime(async {
        let cx = Cx::current().unwrap();
        for resumed in [false, true] {
            let fixture = Fixture::new(resumed);
            let task_id = fixture.task_id.clone();
            let store = fixture.store.clone();
            let committed = Arc::new(Mutex::new(None));
            let receipt = committed.clone();
            *fixture.store.after_write.lock().unwrap() = Some(Box::new(move || {
                let waiting = store.inner.get_task_snapshot(&task_id).unwrap().unwrap();
                assert!(matches!(waiting.task(), FinalTask::InputRequired { .. }));
                *receipt.lock().unwrap() = Some(waiting.clone());
                let working = FinalTask::Working(
                    transition_final_task_base(
                        waiting.task().base().clone(),
                        FinalTaskStatus::Working,
                        None,
                    )
                    .unwrap(),
                );
                let response =
                    serde_json::from_value(serde_json::json!({"next-roots":{"roots":[]}})).unwrap();
                store
                    .inner
                    .replace_task_and_append_input_if_current(
                        &waiting,
                        working.clone(),
                        final_task_notification(&working),
                        response,
                    )
                    .unwrap()
                    .unwrap();
            }));
            let requests =
                serde_json::from_value(serde_json::json!({"next-roots":{"method":"roots/list"}}))
                    .unwrap();
            let _async_only = fixture.store.asynchronous_only();
            let waiting = require_input(&fixture.handoff, &cx, requests)
                .await
                .unwrap();
            let receipt = committed.lock().unwrap().clone().unwrap();
            assert_eq!(
                serde_json::to_string(&waiting).unwrap(),
                serde_json::to_string(receipt.task()).unwrap()
            );
            assert!(matches!(waiting, FinalTask::InputRequired { .. }));
            assert!(matches!(fixture.snapshot().task(), FinalTask::Working(_)));
            assert!(fixture.snapshot().generation() > receipt.generation());
            assert_eq!(
                fixture.store.transitions.load(TaskServiceOrdering::SeqCst),
                1
            );
            assert_eq!(fixture.store.committed.load(TaskServiceOrdering::SeqCst), 1);
            assert_eq!(
                fixture
                    .store
                    .synchronous_calls
                    .load(TaskServiceOrdering::SeqCst),
                0
            );
        }
    });
}

#[test]
fn async_worker_lost_cas_preserves_the_concurrent_terminal_winner() {
    with_runtime(async {
        let cx = Cx::current().unwrap();
        for resumed in [false, true] {
            let fixture = Fixture::new(resumed);
            let store = fixture.store.clone();
            let expected = fixture.snapshot();
            let winner = FinalTask::Completed {
                base: transition_final_task_base(
                    expected.task().base().clone(),
                    FinalTaskStatus::Completed,
                    Some("other worker won".to_owned()),
                )
                .unwrap(),
                result: serde_json::from_value(
                    serde_json::json!({"content":[],"structuredContent":{"winner":"other"}}),
                )
                .unwrap(),
            };
            let winner_wire = serde_json::to_string(&winner).unwrap();
            *fixture.store.before_write.lock().unwrap() = Some(Box::new(move || {
                assert!(
                    store
                        .inner
                        .replace_task_if_current(
                            &expected,
                            winner.clone(),
                            final_task_notification(&winner),
                        )
                        .unwrap()
                );
            }));
            let _async_only = fixture.store.asynchronous_only();
            assert!(complete(&fixture.handoff, &cx).await.is_err());
            assert_eq!(fixture.wire(), winner_wire);
            assert_eq!(
                fixture.store.transitions.load(TaskServiceOrdering::SeqCst),
                1
            );
            assert_eq!(fixture.store.committed.load(TaskServiceOrdering::SeqCst), 0);
            assert!(fixture.notifications.lock().unwrap().is_empty());
        }
    });
}

#[test]
fn async_worker_stale_dispatch_cannot_commit_after_restoration_and_reelection() {
    with_runtime(async {
        let cx = Cx::current().unwrap();
        for resumed in [false, true] {
            let mut fixture = Fixture::new(resumed);
            let mut old_guard = fixture.guard.take().unwrap();
            let old_fence = old_guard.dispatch_fence.unwrap();
            assert!(old_guard.restore().unwrap());
            drop(old_guard);
            let mut successor = if resumed {
                FinalTaskSupervisorHandoff::Resumed(
                    fixture.runtime.recover_accepted_input().unwrap().unwrap(),
                )
            } else {
                FinalTaskSupervisorHandoff::Initial(
                    fixture.runtime.recover_initial_work().unwrap().unwrap(),
                )
            };
            let mut successor_guard = FinalTaskExecutionGuard::new(
                &fixture.runtime,
                FINAL_TASK_TEST_DIRECT_OWNER,
                &successor,
            );
            assert!(successor_guard.elect().unwrap());
            assert_ne!(successor_guard.dispatch_fence.unwrap(), old_fence);
            successor.attach_authority(successor_guard.authority().unwrap());
            let current = fixture.retained_facts();
            let _async_only = fixture.store.asynchronous_only();

            assert!(complete(&fixture.handoff, &cx).await.is_err());
            assert_eq!(fixture.retained_facts(), current);
            assert_eq!(fixture.store.committed.load(TaskServiceOrdering::SeqCst), 0);
            let completed = complete(&successor, &cx).await.unwrap();
            assert!(matches!(completed, FinalTask::Completed { .. }));
            assert_eq!(fixture.store.committed.load(TaskServiceOrdering::SeqCst), 1);
        }
    });
}

#[test]
fn async_worker_cooperative_cancellation_requires_retained_intent() {
    with_runtime(async {
        let cx = Cx::current().unwrap();
        for resumed in [false, true] {
            let fixture = Fixture::new(resumed);
            let _async_only = fixture.store.asynchronous_only();
            let original = fixture.retained_facts();
            assert!(!cancellation_requested(&fixture.handoff, &cx).await.unwrap());
            assert!(honor_cancellation(&fixture.handoff, &cx).await.is_err());
            assert_eq!(fixture.retained_facts(), original);

            let expected = fixture.snapshot();
            let cancelled = FinalTask::Cancelled(
                transition_final_task_base(
                    expected.task().base().clone(),
                    FinalTaskStatus::Cancelled,
                    None,
                )
                .unwrap(),
            );
            let intent = fixture
                .store
                .inner
                .request_cancellation_and_clear_input_if_current(
                    &expected,
                    cancelled.clone(),
                    final_task_notification(&cancelled),
                )
                .unwrap()
                .unwrap();
            assert!(matches!(intent.task(), FinalTask::Working(_)));
            assert!(cancellation_requested(&fixture.handoff, &cx).await.unwrap());
            assert!(complete(&fixture.handoff, &cx).await.is_err());
            assert!(matches!(fixture.snapshot().task(), FinalTask::Working(_)));

            let cancelled = honor_cancellation(&fixture.handoff, &cx).await.unwrap();
            assert!(matches!(cancelled, FinalTask::Cancelled(_)));
            assert_eq!(serde_json::to_string(&cancelled).unwrap(), fixture.wire());
            assert_eq!(fixture.store.committed.load(TaskServiceOrdering::SeqCst), 1);
            assert_eq!(
                fixture
                    .store
                    .synchronous_calls
                    .load(TaskServiceOrdering::SeqCst),
                0
            );
            assert!(
                !fixture
                    .store
                    .inner
                    .state
                    .lock()
                    .unwrap()
                    .accepted_inputs
                    .contains_key(&fixture.task_id)
            );
        }
    });
}

#[test]
fn async_worker_failure_retains_open_error_members_for_both_handoffs() {
    with_runtime(async {
        let cx = Cx::current().unwrap();
        for resumed in [false, true] {
            let fixture = Fixture::new(resumed);
            let error: FinalTaskError = serde_json::from_value(serde_json::json!({
                "code":-32042,"message":"upstream unavailable","data":{"retry":false},"vendor":"preserved"
            })).unwrap();
            let _async_only = fixture.store.asynchronous_only();
            let failed = match &fixture.handoff {
                FinalTaskSupervisorHandoff::Initial(work) => {
                    work.fail_task_with_cx(&cx, error.clone(), None).await
                }
                FinalTaskSupervisorHandoff::Resumed(work) => {
                    work.fail_task_with_cx(&cx, error.clone(), None).await
                }
            }
            .unwrap();
            let FinalTask::Failed {
                error: retained, ..
            } = &failed
            else {
                panic!("worker did not commit its failure");
            };
            assert_eq!(retained, &error);
            assert_eq!(serde_json::to_string(&failed).unwrap(), fixture.wire());
            assert_eq!(fixture.store.committed.load(TaskServiceOrdering::SeqCst), 1);
            assert_eq!(fixture.notifications.lock().unwrap().len(), 1);
        }
    });
}

#[test]
fn async_worker_rejects_foreign_commit_receipts_without_publishing_them() {
    with_runtime(async {
        let cx = Cx::current().unwrap();
        let store = Arc::new(AsyncWorkerStore::new());
        let fixture = Fixture::with_store(store.clone(), "receipt-owner", false);
        let foreign = Fixture::with_store(store.clone(), "receipt-foreign", false);
        *store.substituted_receipt.lock().unwrap() = Some(foreign.snapshot());
        let _async_only = store.asynchronous_only();
        assert!(complete(&fixture.handoff, &cx).await.is_err());
        assert!(matches!(
            fixture.snapshot().task(),
            FinalTask::Completed { .. }
        ));
        assert!(matches!(foreign.snapshot().task(), FinalTask::Working(_)));
        assert_eq!(store.transitions.load(TaskServiceOrdering::SeqCst), 1);
        assert_eq!(store.committed.load(TaskServiceOrdering::SeqCst), 1);
        assert!(fixture.notifications.lock().unwrap().is_empty());
        assert!(foreign.notifications.lock().unwrap().is_empty());
    });
}

#[test]
fn async_worker_postwrite_cancellation_reports_commit_uncertainty_without_retry() {
    with_runtime(async {
        let cx = Cx::current().unwrap();
        let fixture = Fixture::new(false);
        fixture
            .store
            .error_after_write
            .store(true, TaskServiceOrdering::SeqCst);
        let _async_only = fixture.store.asynchronous_only();
        let error = complete(&fixture.handoff, &cx).await.unwrap_err();
        assert_ne!(error.code, McpError::request_cancelled().code);
        assert!(error.message.contains("may have committed"), "{error}");
        assert!(matches!(
            fixture.snapshot().task(),
            FinalTask::Completed { .. }
        ));
        assert_eq!(
            fixture.store.transitions.load(TaskServiceOrdering::SeqCst),
            1
        );
        assert_eq!(fixture.store.committed.load(TaskServiceOrdering::SeqCst), 1);
        assert!(fixture.notifications.lock().unwrap().is_empty());
    });
}

#[test]
fn async_worker_anonymous_cancellation_rejects_a_successor_after_pending_read() {
    with_runtime(async {
        let cx = Cx::current().unwrap();
        let store = Arc::new(AsyncWorkerStore::new());
        let fixture = Fixture::with_identity(store.clone(), "anonymous-worker", false, false);
        store.omit_metadata.store(true, TaskServiceOrdering::SeqCst);
        let _async_only = store.asynchronous_only();
        assert!(!cancellation_requested(&fixture.handoff, &cx).await.unwrap());
        store.cancellation_gate.close();
        let mut pending = Box::pin(cancellation_requested(&fixture.handoff, &cx));
        assert!(poll_once(pending.as_mut()).is_pending());

        // This legacy anonymous store has no metadata continuity operation.
        // A newer working record's cancellation must not become authority for
        // the old exact-generation handoff simply because its ID is unchanged.
        let expected = fixture.snapshot();
        let successor = FinalTask::Working(
            transition_final_task_base(
                expected.task().base().clone(),
                FinalTaskStatus::Working,
                Some("successor".to_owned()),
            )
            .unwrap(),
        );
        assert!(
            store
                .inner
                .replace_task_if_current(
                    &expected,
                    successor.clone(),
                    final_task_notification(&successor),
                )
                .unwrap()
        );
        store.inner.request_cancellation(&fixture.task_id).unwrap();
        assert!(
            store
                .inner
                .is_cancellation_requested(&fixture.task_id)
                .unwrap()
        );
        let current = fixture.retained_facts();

        store.cancellation_gate.release();
        assert!(ready(poll_once(pending.as_mut())).is_err());
        assert_eq!(fixture.retained_facts(), current);
        assert_eq!(store.committed.load(TaskServiceOrdering::SeqCst), 0);
        assert_eq!(store.synchronous_calls.load(TaskServiceOrdering::SeqCst), 0);
        assert!(fixture.notifications.lock().unwrap().is_empty());
    });
}
