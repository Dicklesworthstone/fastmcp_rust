use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

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
        std::future::poll_fn(|cx| {
            let mut waiter = self.waiter.lock().unwrap();
            if self.open.load(Ordering::SeqCst) {
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

struct AsyncCreationStore {
    inner: InMemoryFinalTaskStore,
    before_commit: Gate,
    after_commit: Gate,
    notification_read: Gate,
    create_calls: AtomicUsize,
    committed_writes: AtomicUsize,
    async_payload_reads: AtomicUsize,
    cancel_after_commit: AtomicBool,
    substitute_receipt: AtomicBool,
    before_limits: Mutex<Option<Hook>>,
    created_task_id: Mutex<Option<FinalTaskId>>,
}

impl AsyncCreationStore {
    fn new() -> Self {
        Self {
            inner: InMemoryFinalTaskStore::default(),
            before_commit: Gate::new(),
            after_commit: Gate::new(),
            notification_read: Gate::new(),
            create_calls: AtomicUsize::new(0),
            committed_writes: AtomicUsize::new(0),
            async_payload_reads: AtomicUsize::new(0),
            cancel_after_commit: AtomicBool::new(false),
            substitute_receipt: AtomicBool::new(false),
            before_limits: Mutex::new(None),
            created_task_id: Mutex::new(None),
        }
    }

    fn snapshot(&self) -> FinalTaskSnapshot {
        let id = self.created_task_id.lock().unwrap().clone().unwrap();
        self.inner.get_task_snapshot(&id).unwrap().unwrap()
    }
}

impl FinalTaskStore for AsyncCreationStore {
    fn execution_limits(&self) -> McpResult<FinalTaskExecutionLimits> {
        let hook = self.before_limits.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        self.inner.execution_limits()
    }

    fn create_task_with_work_with_context<'a>(
        &'a self,
        admission: FinalTaskCreationAdmission<'a>,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
        work_descriptor: FinalTaskWorkDescriptor,
    ) -> FinalTaskStoreFuture<'a, FinalTaskSnapshot> {
        Box::pin(async move {
            let ctx = admission.context();
            assert!(ctx.auth().is_none(), "embedding does not invent credentials");
            assert!(Cx::current().is_some(), "provider inherits the caller's Cx");
            self.create_calls.fetch_add(1, Ordering::SeqCst);
            self.before_commit.wait().await;
            admission.checkpoint_before_write()?;
            let mut committed =
                self.inner.create_task_with_work(task, notification, work_descriptor)?;
            *self.created_task_id.lock().unwrap() = Some(committed.task().base().task_id.clone());
            self.committed_writes.fetch_add(1, Ordering::SeqCst);
            if self.cancel_after_commit.load(Ordering::SeqCst) {
                ctx.cx().cancel_with(asupersync::types::CancelKind::User, None);
            }
            self.after_commit.wait().await;
            if self.substitute_receipt.load(Ordering::SeqCst) {
                committed = committed
                    .with_authenticated_principal(Some(Sha256Digest::from_bytes([91; 32])));
            }
            Ok(committed)
        })
    }

    fn get_task_snapshot_with_cx<'a>(
        &'a self,
        _cx: &'a Cx,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        Box::pin(async move {
            self.async_payload_reads.fetch_add(1, Ordering::SeqCst);
            self.notification_read.wait().await;
            self.inner.get_task_snapshot(task_id)
        })
    }

    fn get_task_access_metadata_with_cx<'a>(
        &'a self,
        _cx: &'a Cx,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskAccessMetadata>> {
        Box::pin(async move { self.inner.get_task_access_metadata(task_id) })
    }

    fn create_task_with_work(
        &self,
        _task: FinalTask,
        _notification: FinalTaskStatusNotification,
        _work_descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<FinalTaskSnapshot> {
        panic!("embedding Task creation called the synchronous fallback")
    }

    fn create_task_with_operation_with_context<'a>(
        &'a self,
        admission: FinalTaskCreationAdmission<'a>,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
        work_descriptor: FinalTaskWorkDescriptor,
        principal: Option<Sha256Digest>,
        operation: FinalTaskOperation,
    ) -> FinalTaskStoreFuture<'a, FinalTaskSnapshot> {
        Box::pin(async move {
            let ctx = admission.context();
            self.create_calls.fetch_add(1, Ordering::SeqCst);
            assert!(Cx::current().is_some(), "provider inherits the caller's Cx");
            self.before_commit.wait().await;
            admission.checkpoint_before_write()?;
            let mut committed = self.inner.create_task_with_operation(
                task,
                notification,
                work_descriptor,
                principal,
                operation,
            )?;
            *self.created_task_id.lock().unwrap() = Some(committed.task().base().task_id.clone());
            self.committed_writes.fetch_add(1, Ordering::SeqCst);
            if self.cancel_after_commit.load(Ordering::SeqCst) {
                ctx.request_cancellation().cancel();
            }
            self.after_commit.wait().await;
            if self.substitute_receipt.load(Ordering::SeqCst) {
                committed = committed.with_original_operation(None);
            }
            // Cancellation after commit cannot erase the exact receipt.
            Ok(committed)
        })
    }

    fn get_task_access_metadata_with_context<'a>(
        &'a self,
        _ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskAccessMetadata>> {
        Box::pin(async move { self.inner.get_task_access_metadata(task_id) })
    }

    fn get_task_snapshot_with_context<'a>(
        &'a self,
        _ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        Box::pin(async move {
            self.async_payload_reads.fetch_add(1, Ordering::SeqCst);
            self.notification_read.wait().await;
            self.inner.get_task_snapshot(task_id)
        })
    }

    fn expire_task_execution_if_current_with_context<'a>(
        &'a self,
        _ctx: &'a McpContext,
        expected: &'a FinalTaskSnapshot,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        Box::pin(async move { self.inner.expire_task_execution_if_current(expected) })
    }

    fn create_task_with_operation(
        &self,
        _task: FinalTask,
        _notification: FinalTaskStatusNotification,
        _work_descriptor: FinalTaskWorkDescriptor,
        _principal: Option<Sha256Digest>,
        _operation: FinalTaskOperation,
    ) -> McpResult<FinalTaskSnapshot> {
        panic!("request-owned Task creation called the synchronous fallback")
    }

    fn create_task(
        &self,
        _task: FinalTask,
        _notification: FinalTaskStatusNotification,
    ) -> McpResult<()> {
        panic!("request-owned Task creation called bare synchronous creation")
    }

    fn get_task(&self, _task_id: &FinalTaskId) -> McpResult<Option<FinalTask>> {
        panic!("asynchronous Task creation read a synchronous payload")
    }

    fn get_task_snapshot(&self, _task_id: &FinalTaskId) -> McpResult<Option<FinalTaskSnapshot>> {
        panic!("asynchronous Task creation read a synchronous snapshot")
    }

    fn replace_task(
        &self,
        _task: FinalTask,
        _notification: FinalTaskStatusNotification,
    ) -> McpResult<()> {
        panic!("asynchronous Task creation replaced unrelated state")
    }

    fn replace_task_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
        _task: FinalTask,
        _notification: FinalTaskStatusNotification,
    ) -> McpResult<bool> {
        panic!("asynchronous Task creation replaced unrelated state")
    }

    fn request_cancellation(&self, _task_id: &FinalTaskId) -> McpResult<()> {
        panic!("asynchronous Task creation cancelled unrelated state")
    }

    fn request_cancellation_if_current(&self, _expected: &FinalTaskSnapshot) -> McpResult<bool> {
        panic!("asynchronous Task creation cancelled unrelated state")
    }

    fn is_cancellation_requested(&self, _task_id: &FinalTaskId) -> McpResult<bool> {
        panic!("asynchronous Task creation read synchronous cancellation state")
    }

    fn retention_clock_now(&self) -> Instant {
        panic!("asynchronous Task creation read the synchronous retention clock")
    }

    fn task_retention_deadline_if_current(
        &self,
        _task_id: &FinalTaskId,
        _generation: u64,
    ) -> McpResult<Option<FinalTaskRetentionDeadline>> {
        panic!("asynchronous Task creation read synchronous retention state")
    }
}

struct AllowAccess;

impl TaskAccessAuthorizer for AllowAccess {
    fn authorize(
        &self,
        _ctx: &McpContext,
        _action: TaskAccessAction,
        _original: &FinalTaskOperation,
    ) -> McpResult<()> {
        Ok(())
    }
}

impl TaskExecutionAuthorizer for AllowAccess {
    fn authorize(&self, _task: &FinalTaskAccessMetadata) -> McpResult<()> {
        Ok(())
    }
}

struct Fixture {
    store: Arc<AsyncCreationStore>,
    runtime: FinalTaskRuntime,
    ctx: McpContext,
    registration: Arc<()>,
    receiver: mpsc::Receiver<FinalTaskId>,
    notifications: Arc<AtomicUsize>,
}

impl Fixture {
    fn new() -> Self {
        let store = Arc::new(AsyncCreationStore::new());
        let notifications = Arc::new(AtomicUsize::new(0));
        let observer = Arc::clone(&notifications);
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, None)
                .unwrap()
                .with_admission_capacity(1, 1, 16_384, 16_384)
                .unwrap(),
            Arc::new(move |_| {
                observer.fetch_add(1, Ordering::SeqCst);
            }),
        );
        runtime
            .install_access_authorizer(Arc::new(AllowAccess))
            .unwrap();
        runtime
            .install_execution_authorizer(Arc::new(AllowAccess))
            .unwrap();
        // Isolate the creation boundary from worker storage. The service
        // generation and real bounded wakeup channel obey the same readiness
        // contract exercised by the runner's separate integration tests.
        let (sender, receiver) = mpsc::channel(1);
        *runtime.service_signal.lock().unwrap() = Some(FinalTaskServiceSignal {
            service_id: 1,
            sender,
            ready_generation: Some(1),
            last_ready_generation: 1,
            cancellation_wake: Arc::new(FinalTaskCancellationWake::default()),
        });
        Self {
            store,
            runtime,
            ctx: McpContext::with_state(Cx::for_testing(), 1, fastmcp_core::SessionState::new())
                .with_auth(
                    fastmcp_core::AuthContext::with_subject("async-create-owner")
                        .with_session_owner(Sha256Digest::from_bytes([23; 32])),
                ),
            registration: Arc::new(()),
            receiver,
            notifications,
        }
    }

    fn operation(&self) -> FinalTaskOperation {
        FinalTaskOperation::for_tool("async-create", &self.registration).unwrap()
    }

    fn create(&self) -> impl Future<Output = McpResult<CreateTaskResult>> + '_ {
        self.runtime.create_task_for_operation_with_cx(
            &self.ctx,
            self.operation(),
            work(),
            Some("queued application work".into()),
        )
    }

    fn assert_admission_empty(&self) {
        let ledger = self.runtime.admission.lock().unwrap();
        assert_eq!(ledger.total.permits, 0);
        assert_eq!(ledger.total.payload_bytes, 0);
        assert!(ledger.principals.is_empty());
    }
}

fn work() -> FinalTaskWorkDescriptor {
    FinalTaskWorkDescriptor::new(serde_json::json!({"handler":"async-create"})).unwrap()
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn ready<T>(result: Poll<T>) -> T {
    match result {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("released creation operation unexpectedly remained pending"),
    }
}

fn with_embedding_caller(test: impl FnOnce(Cx)) {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    let caller = runtime.request_cx_with_budget(Budget::INFINITE);
    runtime.block_on(async { test(caller) });
    assert!(runtime.shutdown_timeout(StdDuration::from_secs(2)));
}

#[test]
fn async_creation_retains_bounded_admission_and_recoverable_work_across_pending_io() {
    let mut fixture = Fixture::new();
    fixture.store.before_commit.close();
    let runtime = fixture.runtime.clone();
    let operation = fixture.operation();
    let mut create =
        Box::pin(runtime.create_task_for_operation_with_cx(&fixture.ctx, operation, work(), None));
    assert!(poll_once(create.as_mut()).is_pending());
    assert_eq!(fixture.store.create_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.store.inner.task_count(), 0);
    assert_eq!(fixture.runtime.admission.lock().unwrap().total.permits, 1);
    assert!(
        fixture
            .runtime
            .admission
            .lock()
            .unwrap()
            .total
            .payload_bytes
            > 0
    );
    assert!(fixture.runtime.service_signal.try_lock().is_ok());
    assert!(fixture.runtime.admission.try_lock().is_ok());

    let mut second = Box::pin(fixture.create());
    ready(poll_once(second.as_mut())).expect_err("pending creation retains its bounded slot");
    assert_eq!(fixture.store.create_calls.load(Ordering::SeqCst), 1);
    drop(second);

    fixture.store.before_commit.release();
    let created = ready(poll_once(create.as_mut())).unwrap();
    drop(create);
    assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.store.async_payload_reads.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.notifications.load(Ordering::SeqCst), 1);
    fixture.assert_admission_empty();
    let snapshot = fixture.store.snapshot();
    assert_eq!(
        snapshot.authenticated_principal(),
        task_request_principal(&fixture.ctx).unwrap()
    );
    assert_eq!(snapshot.original_operation(), Some(&fixture.operation()));
    assert!(final_tasks_match_exactly(snapshot.task(), &created.task).unwrap());
    let claim = fixture
        .store
        .inner
        .take_initial_work_handoff_for_owner_if_current(&snapshot, "recovered-owner")
        .unwrap()
        .expect("creation retains application work for authoritative recovery");
    assert_eq!(claim.work_descriptor, work());
    let cx = Cx::for_testing();
    let mut wakeup = Box::pin(fixture.receiver.recv(&cx));
    assert_eq!(
        ready(poll_once(wakeup.as_mut())).unwrap(),
        created.task.base().task_id
    );
}

#[test]
fn async_creation_prewrite_cancellation_never_creates_a_task() {
    let fixture = Fixture::new();
    fixture.ctx.request_cancellation().cancel();
    let mut create = Box::pin(fixture.create());
    ready(poll_once(create.as_mut())).expect_err("cancelled ingress cannot admit work");
    assert_eq!(fixture.store.create_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.store.inner.task_count(), 0);
    fixture.assert_admission_empty();
}

#[test]
fn async_creation_provider_cancels_before_its_write_without_releasing_early() {
    let fixture = Fixture::new();
    fixture.store.before_commit.close();
    let mut create = Box::pin(fixture.create());
    assert!(poll_once(create.as_mut()).is_pending());
    fixture.ctx.request_cancellation().cancel();
    assert_eq!(fixture.runtime.admission.lock().unwrap().total.permits, 1);
    fixture.store.before_commit.release();
    let error = ready(poll_once(create.as_mut())).unwrap_err();
    assert_ne!(error.code, McpError::request_cancelled().code);
    assert_eq!(fixture.store.inner.task_count(), 0);
    fixture.assert_admission_empty();
}

#[test]
fn async_creation_revalidates_original_operation_after_pending_io() {
    let fixture = Fixture::new();
    fixture.store.before_commit.close();
    let mut create = Box::pin(fixture.create());
    assert!(poll_once(create.as_mut()).is_pending());
    assert!(fixture.ctx.disable_tool("async-create"));
    fixture.store.before_commit.release();
    ready(poll_once(create.as_mut())).expect_err("a revoked operation cannot begin the write");
    assert_eq!(fixture.store.create_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.store.inner.task_count(), 0);
    fixture.assert_admission_empty();
}

#[test]
fn async_creation_committed_receipt_survives_cancellation_and_service_exit() {
    let fixture = Fixture::new();
    fixture.store.after_commit.close();
    let mut create = Box::pin(fixture.create());
    assert!(poll_once(create.as_mut()).is_pending());
    assert_eq!(fixture.store.inner.task_count(), 1);
    fixture.ctx.request_cancellation().cancel();
    fixture
        .runtime
        .service_signal
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .ready_generation = None;
    assert_eq!(fixture.runtime.admission.lock().unwrap().total.permits, 1);
    fixture.store.after_commit.release();
    let created = ready(poll_once(create.as_mut())).unwrap();
    assert!(final_tasks_match_exactly(&created.task, fixture.store.snapshot().task()).unwrap());
    assert_eq!(fixture.notifications.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
    assert!(
        fixture
            .store
            .inner
            .next_initial_work_snapshot()
            .unwrap()
            .is_some()
    );
    fixture.assert_admission_empty();
}

#[test]
fn async_creation_wakes_service_before_pending_notification_and_keeps_the_handle() {
    let mut fixture = Fixture::new();
    fixture.store.notification_read.close();
    let runtime = fixture.runtime.clone();
    let operation = fixture.operation();
    let mut create =
        Box::pin(runtime.create_task_for_operation_with_cx(&fixture.ctx, operation, work(), None));
    assert!(poll_once(create.as_mut()).is_pending());
    let snapshot = fixture.store.snapshot();
    let cx = Cx::for_testing();
    let mut wakeup = Box::pin(fixture.receiver.recv(&cx));
    assert_eq!(
        ready(poll_once(wakeup.as_mut())).unwrap(),
        snapshot.task().base().task_id
    );
    drop(wakeup);
    assert_eq!(fixture.runtime.admission.lock().unwrap().total.permits, 1);
    fixture.ctx.request_cancellation().cancel();
    let result = ready(poll_once(create.as_mut())).unwrap();
    assert!(final_tasks_match_exactly(&result.task, snapshot.task()).unwrap());
    assert_eq!(fixture.notifications.load(Ordering::SeqCst), 0);
    fixture.assert_admission_empty();
}

#[test]
fn async_creation_rechecks_request_and_service_after_capability_callback() {
    for exit_service in [false, true] {
        let fixture = Fixture::new();
        let cancellation = fixture.ctx.request_cancellation().clone();
        let runtime = fixture.runtime.clone();
        *fixture.store.before_limits.lock().unwrap() = Some(Box::new(move || {
            if exit_service {
                runtime
                    .service_signal
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .ready_generation = None;
            } else {
                cancellation.cancel();
            }
        }));
        let mut create = Box::pin(fixture.create());
        ready(poll_once(create.as_mut())).expect_err("reentrant provider cannot bypass admission");
        assert_eq!(fixture.store.create_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.inner.task_count(), 0);
        fixture.assert_admission_empty();
    }
}

struct CreationTool;

impl crate::ToolHandler for CreationTool {
    fn definition(&self) -> fastmcp_protocol::Tool {
        fastmcp_protocol::Tool {
            name: "async-create".into(),
            description: None,
            input_schema: serde_json::json!({"type":"object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn declares_final_tasks(&self) -> bool {
        true
    }

    fn call(
        &self,
        _ctx: &McpContext,
        _args: serde_json::Value,
    ) -> McpResult<Vec<fastmcp_protocol::Content>> {
        Ok(Vec::new())
    }

    fn call_final_outcome(
        &self,
        _ctx: &McpContext,
        _args: serde_json::Value,
    ) -> McpResult<crate::FinalToolOutcome> {
        Ok(crate::FinalToolOutcome::CreateTask {
            work_descriptor: work(),
            status_message: None,
        })
    }
}

fn wire_request(id: i64) -> fastmcp_protocol::JsonRpcRequest {
    fastmcp_protocol::JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name":"async-create", "arguments":{},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {
                    "extensions": {"io.modelcontextprotocol/tasks": {}}
                }
            }
        })),
        id,
    )
}

#[test]
fn async_creation_public_tools_call_uses_async_storage_and_returns_committed_task() {
    let fixture = Fixture::new();
    fixture.store.before_commit.close();
    let server = crate::Server::new("async-creation", "1.0")
        .tool(CreationTool)
        .final_tasks(fixture.runtime.clone())
        .unwrap()
        .build();
    let inbound = crate::InboundRequestContext::new(
        Cx::for_testing(),
        41,
        crate::InboundRequestTransport::Memory,
    );
    let request = wire_request(41);
    let mut dispatch = Box::pin(server.dispatch_with_protocol_policy(
        crate::ProtocolPolicy::ModernOnly,
        &inbound,
        &request,
    ));
    assert!(poll_once(dispatch.as_mut()).is_pending());
    assert_eq!(fixture.store.inner.task_count(), 0);
    fixture.store.before_commit.release();
    let response = ready(poll_once(dispatch.as_mut())).unwrap();
    assert!(
        response.error.is_none(),
        "creation must return its handle: {response:?}"
    );
    let result = response.result.unwrap();
    assert_eq!(
        result["taskId"],
        fixture.store.snapshot().task().base().task_id.as_str()
    );
    assert_eq!(result["status"], "working");
    assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
    assert!(
        fixture
            .store
            .inner
            .latest_notification(&fixture.store.snapshot().task().base().task_id)
            .is_some()
    );
    fixture.assert_admission_empty();
}

#[test]
fn async_creation_public_tools_call_never_describes_committed_work_as_clean_cancellation() {
    let fixture = Fixture::new();
    fixture
        .store
        .cancel_after_commit
        .store(true, Ordering::SeqCst);
    let server = crate::Server::new("async-creation", "1.0")
        .tool(CreationTool)
        .final_tasks(fixture.runtime.clone())
        .unwrap()
        .build();
    let inbound = crate::InboundRequestContext::new(
        Cx::for_testing(),
        42,
        crate::InboundRequestTransport::Memory,
    );
    let request = wire_request(42);
    let mut dispatch = Box::pin(server.dispatch_with_protocol_policy(
        crate::ProtocolPolicy::ModernOnly,
        &inbound,
        &request,
    ));
    let response = ready(poll_once(dispatch.as_mut())).unwrap();
    assert!(response.result.is_none());
    let error = response.error.unwrap();
    assert_ne!(
        error.code.as_i32(),
        Some(i32::from(McpError::request_cancelled().code))
    );
    assert_eq!(error.data.unwrap()["reason"], "TaskStateUnknown");
    assert_eq!(fixture.store.inner.task_count(), 1);
    assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
    assert!(
        fixture
            .store
            .inner
            .latest_notification(&fixture.store.snapshot().task().base().task_id)
            .is_some()
    );
    fixture.assert_admission_empty();
}

#[test]
fn async_creation_invalid_receipt_cannot_publish_an_unverified_handle() {
    let fixture = Fixture::new();
    fixture
        .store
        .substitute_receipt
        .store(true, Ordering::SeqCst);
    let receipt = TaskControlReceipt::default();
    let mut create = Box::pin(fixture.runtime.create_task_for_operation_with_receipt(
        &fixture.ctx,
        fixture.operation(),
        work(),
        None,
        receipt.clone(),
    ));
    let result = ready(poll_once(create.as_mut()));
    let error = receipt.resolve_liveness(result, None).unwrap_err();
    assert_eq!(error.data.unwrap()["reason"], "TaskStateUnknown");
    assert_eq!(fixture.store.inner.task_count(), 1);
    assert_eq!(fixture.notifications.load(Ordering::SeqCst), 0);
    fixture.assert_admission_empty();
}

#[test]
fn async_embedding_creation_retains_admission_and_exact_recoverable_work() {
    with_embedding_caller(|cx| {
        let mut fixture = Fixture::new();
        fixture.store.before_commit.close();
        let runtime = fixture.runtime.clone();
        let mut create = Box::pin(runtime.create_task_with_work_with_cx(&cx, work(), None));
        assert!(poll_once(create.as_mut()).is_pending());
        assert_eq!(fixture.store.create_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.inner.task_count(), 0);
        {
            let ledger = fixture.runtime.admission.lock().unwrap();
            assert_eq!(ledger.total.permits, 1);
            assert!(ledger.total.payload_bytes > 0);
        }
        assert!(fixture.runtime.service_signal.try_lock().is_ok());
        assert!(fixture.runtime.admission.try_lock().is_ok());
        let mut second = Box::pin(runtime.create_task_with_work_with_cx(&cx, work(), None));
        ready(poll_once(second.as_mut())).expect_err("pending creation retains its bounded slot");
        assert_eq!(fixture.store.create_calls.load(Ordering::SeqCst), 1);
        drop(second);

        fixture.store.before_commit.release();
        let created = ready(poll_once(create.as_mut())).unwrap();
        drop(create);
        assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.async_payload_reads.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.notifications.load(Ordering::SeqCst), 1);
        fixture.assert_admission_empty();
        let snapshot = fixture.store.snapshot();
        assert!(snapshot.authenticated_principal().is_none());
        assert!(snapshot.original_operation().is_none());
        assert!(final_tasks_match_exactly(snapshot.task(), &created.task).unwrap());
        let claim = fixture
            .store
            .inner
            .take_initial_work_handoff_for_owner_if_current(&snapshot, "embedding-recovery")
            .unwrap()
            .expect("accepted embedding work remains recoverable");
        assert_eq!(claim.work_descriptor, work());
        let mut wakeup = Box::pin(fixture.receiver.recv(&cx));
        assert_eq!(
            ready(poll_once(wakeup.as_mut())).unwrap(),
            created.task.base().task_id
        );
    });
}

#[test]
fn async_embedding_creation_rechecks_cancellation_and_service_before_write() {
    for stop in ["cancel-before-poll", "cancel-while-pending", "service-exit"] {
        with_embedding_caller(|cx| {
            let fixture = Fixture::new();
            fixture.store.before_commit.close();
            if stop == "cancel-before-poll" {
                cx.cancel_with(asupersync::types::CancelKind::User, None);
            }
            let mut create = Box::pin(
                fixture.runtime.create_task_with_work_with_cx(&cx, work(), None),
            );
            if stop != "cancel-before-poll" {
                assert!(poll_once(create.as_mut()).is_pending());
                assert_eq!(fixture.runtime.admission.lock().unwrap().total.permits, 1);
                if stop == "cancel-while-pending" {
                    cx.cancel_with(asupersync::types::CancelKind::User, None);
                } else {
                    fixture
                        .runtime
                        .service_signal
                        .lock()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .ready_generation = None;
                }
            }
            fixture.store.before_commit.release();
            ready(poll_once(create.as_mut())).expect_err("stopped admission cannot write");
            assert_eq!(
                fixture.store.create_calls.load(Ordering::SeqCst),
                usize::from(stop != "cancel-before-poll")
            );
            assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.store.inner.task_count(), 0);
            assert_eq!(fixture.notifications.load(Ordering::SeqCst), 0);
            fixture.assert_admission_empty();
        });
    }
}

#[test]
fn async_embedding_creation_preserves_commit_after_cancellation_and_service_exit() {
    with_embedding_caller(|cx| {
        let fixture = Fixture::new();
        fixture.store.after_commit.close();
        let mut create = Box::pin(
            fixture.runtime.create_task_with_work_with_cx(&cx, work(), None),
        );
        assert!(poll_once(create.as_mut()).is_pending());
        assert_eq!(fixture.store.inner.task_count(), 1);
        assert_eq!(fixture.runtime.admission.lock().unwrap().total.permits, 1);
        cx.cancel_with(asupersync::types::CancelKind::User, None);
        fixture
            .runtime
            .service_signal
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .ready_generation = None;
        fixture.store.after_commit.release();
        let created = ready(poll_once(create.as_mut())).unwrap();
        assert!(final_tasks_match_exactly(&created.task, fixture.store.snapshot().task()).unwrap());
        assert_eq!(fixture.store.create_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.notifications.load(Ordering::SeqCst), 0);
        assert!(fixture.store.inner.next_initial_work_snapshot().unwrap().is_some());
        fixture.assert_admission_empty();
    });
}

#[test]
fn async_embedding_creation_drop_releases_admission_and_preserves_committed_work() {
    for committed in [false, true] {
        with_embedding_caller(|cx| {
            let fixture = Fixture::new();
            if committed {
                fixture.store.after_commit.close();
            } else {
                fixture.store.before_commit.close();
            }
            let mut create = Box::pin(
                fixture.runtime.create_task_with_work_with_cx(&cx, work(), None),
            );
            assert!(poll_once(create.as_mut()).is_pending());
            assert_eq!(fixture.runtime.admission.lock().unwrap().total.permits, 1);
            drop(create);
            assert_eq!(fixture.store.inner.task_count(), usize::from(committed));
            assert_eq!(
                fixture.store.committed_writes.load(Ordering::SeqCst),
                usize::from(committed)
            );
            assert_eq!(fixture.notifications.load(Ordering::SeqCst), 0);
            assert_eq!(
                fixture.store.inner.next_initial_work_snapshot().unwrap().is_some(),
                committed
            );
            fixture.assert_admission_empty();
        });
    }
}

#[test]
fn async_embedding_creation_rejects_substituted_committed_identity() {
    with_embedding_caller(|cx| {
        let fixture = Fixture::new();
        fixture.store.substitute_receipt.store(true, Ordering::SeqCst);
        let mut create = Box::pin(
            fixture.runtime.create_task_with_work_with_cx(&cx, work(), None),
        );
        ready(poll_once(create.as_mut())).expect_err("a different owner cannot validate the receipt");
        assert_eq!(fixture.store.inner.task_count(), 1);
        assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.notifications.load(Ordering::SeqCst), 0);
        assert!(fixture.store.snapshot().authenticated_principal().is_none());
        fixture.assert_admission_empty();
    });
}

#[test]
fn async_embedding_creation_wakes_recovery_before_pending_notification() {
    with_embedding_caller(|cx| {
        let mut fixture = Fixture::new();
        fixture.store.notification_read.close();
        let runtime = fixture.runtime.clone();
        let mut create = Box::pin(runtime.create_task_with_work_with_cx(&cx, work(), None));
        assert!(poll_once(create.as_mut()).is_pending());
        let snapshot = fixture.store.snapshot();
        let mut wakeup = Box::pin(fixture.receiver.recv(&cx));
        assert_eq!(
            ready(poll_once(wakeup.as_mut())).unwrap(),
            snapshot.task().base().task_id
        );
        drop(wakeup);
        assert_eq!(fixture.runtime.admission.lock().unwrap().total.permits, 1);
        cx.cancel_with(asupersync::types::CancelKind::User, None);
        let created = ready(poll_once(create.as_mut())).unwrap();
        assert!(final_tasks_match_exactly(&created.task, snapshot.task()).unwrap());
        assert_eq!(fixture.notifications.load(Ordering::SeqCst), 0);
        fixture.assert_admission_empty();
    });
}
