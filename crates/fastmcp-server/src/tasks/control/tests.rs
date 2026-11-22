use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Waker};

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

struct AsyncControlStore {
    inner: InMemoryFinalTaskStore,
    metadata_gate: Gate,
    payload_gate: Gate,
    write_gate: Gate,
    metadata_calls: AtomicUsize,
    payload_calls: AtomicUsize,
    update_calls: AtomicUsize,
    cancel_calls: AtomicUsize,
    intent_reads: AtomicUsize,
    committed_writes: AtomicUsize,
    synchronous_calls: AtomicUsize,
    change_principal: AtomicBool,
    strip_operation: AtomicBool,
    lie_about_cancellation: AtomicBool,
    cancel_write_with_error: AtomicBool,
    wait_for_request_cancellation: AtomicBool,
    request_cancellation_observed: AtomicBool,
    after_write: Mutex<Option<Hook>>,
    before_intent_read: Mutex<Option<Hook>>,
}

impl AsyncControlStore {
    fn new() -> Self {
        Self {
            inner: InMemoryFinalTaskStore::default(),
            metadata_gate: Gate::new(),
            payload_gate: Gate::new(),
            write_gate: Gate::new(),
            metadata_calls: AtomicUsize::new(0),
            payload_calls: AtomicUsize::new(0),
            update_calls: AtomicUsize::new(0),
            cancel_calls: AtomicUsize::new(0),
            intent_reads: AtomicUsize::new(0),
            committed_writes: AtomicUsize::new(0),
            synchronous_calls: AtomicUsize::new(0),
            change_principal: AtomicBool::new(false),
            strip_operation: AtomicBool::new(false),
            lie_about_cancellation: AtomicBool::new(false),
            cancel_write_with_error: AtomicBool::new(false),
            wait_for_request_cancellation: AtomicBool::new(false),
            request_cancellation_observed: AtomicBool::new(false),
            after_write: Mutex::new(None),
            before_intent_read: Mutex::new(None),
        }
    }

    fn unexpected_sync<T>(&self) -> T {
        self.synchronous_calls.fetch_add(1, Ordering::SeqCst);
        panic!("a control RPC called a synchronous store fallback");
    }

    fn after_write(&self) {
        let hook = self.after_write.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
    }

    fn assert_async_only(&self) {
        assert_eq!(self.synchronous_calls.load(Ordering::SeqCst), 0);
    }
}

impl FinalTaskStore for AsyncControlStore {
    fn get_task_access_metadata_with_context<'a>(
        &'a self,
        _ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskAccessMetadata>> {
        self.metadata_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            self.metadata_gate.wait().await;
            assert!(
                Cx::current().is_some(),
                "provider polls keep caller context"
            );
            self.inner.get_task_access_metadata(task_id)
        })
    }

    fn get_task_snapshot_with_context<'a>(
        &'a self,
        _ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.payload_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            self.payload_gate.wait().await;
            let snapshot = self.inner.get_task_snapshot(task_id)?;
            Ok(snapshot.map(|mut snapshot| {
                if self.change_principal.load(Ordering::SeqCst) {
                    snapshot = snapshot
                        .with_authenticated_principal(Some(Sha256Digest::from_bytes([99; 32])));
                }
                if self.strip_operation.load(Ordering::SeqCst) {
                    snapshot = snapshot.with_original_operation(None);
                }
                snapshot
            }))
        })
    }

    fn expire_task_execution_if_current_with_context<'a>(
        &'a self,
        _ctx: &'a McpContext,
        expected: &'a FinalTaskSnapshot,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        Box::pin(async move { self.inner.expire_task_execution_if_current(expected) })
    }

    fn replace_task_and_append_input_if_current_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        expected: &'a FinalTaskSnapshot,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
        input_responses: FinalTaskInputResponses,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.update_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if self.wait_for_request_cancellation.load(Ordering::SeqCst) {
                ctx.request_cancelled().await;
                self.request_cancellation_observed
                    .store(true, Ordering::SeqCst);
                return Err(McpError::request_cancelled());
            }
            self.write_gate.wait().await;
            self.request_cancellation_observed
                .store(ctx.ensure_live().is_err(), Ordering::SeqCst);
            if self.cancel_write_with_error.load(Ordering::SeqCst) {
                self.after_write();
                return Err(McpError::request_cancelled());
            }
            let committed = self.inner.replace_task_and_append_input_if_current(
                expected,
                task,
                notification,
                input_responses,
            )?;
            if committed.is_some() {
                self.committed_writes.fetch_add(1, Ordering::SeqCst);
                self.after_write();
            }
            Ok(committed)
        })
    }

    fn request_cancellation_and_clear_input_if_current_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        expected: &'a FinalTaskSnapshot,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.cancel_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            self.write_gate.wait().await;
            self.request_cancellation_observed
                .store(ctx.ensure_live().is_err(), Ordering::SeqCst);
            if self.lie_about_cancellation.load(Ordering::SeqCst) {
                self.after_write();
                return Ok(Some(expected.clone()));
            }
            let committed = self.inner.request_cancellation_and_clear_input_if_current(
                expected,
                task,
                notification,
            )?;
            if committed.is_some() {
                self.committed_writes.fetch_add(1, Ordering::SeqCst);
                self.after_write();
            }
            Ok(committed)
        })
    }

    fn is_cancellation_requested_with_context<'a>(
        &'a self,
        _ctx: &'a McpContext,
        task_id: &'a FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, bool> {
        self.intent_reads.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let hook = self.before_intent_read.lock().unwrap().take();
            if let Some(hook) = hook {
                hook();
            }
            self.inner.is_cancellation_requested(task_id)
        })
    }

    fn create_task(
        &self,
        _task: FinalTask,
        _notification: FinalTaskStatusNotification,
    ) -> McpResult<()> {
        self.unexpected_sync()
    }

    fn get_task_access_metadata(
        &self,
        _task_id: &FinalTaskId,
    ) -> McpResult<Option<FinalTaskAccessMetadata>> {
        self.unexpected_sync()
    }

    fn get_task(&self, _task_id: &FinalTaskId) -> McpResult<Option<FinalTask>> {
        self.unexpected_sync()
    }

    fn get_task_snapshot(&self, _task_id: &FinalTaskId) -> McpResult<Option<FinalTaskSnapshot>> {
        self.unexpected_sync()
    }

    fn replace_task(
        &self,
        _task: FinalTask,
        _notification: FinalTaskStatusNotification,
    ) -> McpResult<()> {
        self.unexpected_sync()
    }

    fn replace_task_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
        _task: FinalTask,
        _notification: FinalTaskStatusNotification,
    ) -> McpResult<bool> {
        self.unexpected_sync()
    }

    fn replace_task_and_append_input_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
        _task: FinalTask,
        _notification: FinalTaskStatusNotification,
        _input_responses: FinalTaskInputResponses,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        self.unexpected_sync()
    }

    fn expire_task_execution_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        self.unexpected_sync()
    }

    fn request_cancellation_and_clear_input_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
        _task: FinalTask,
        _notification: FinalTaskStatusNotification,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        self.unexpected_sync()
    }

    fn request_cancellation(&self, _task_id: &FinalTaskId) -> McpResult<()> {
        self.unexpected_sync()
    }

    fn request_cancellation_if_current(&self, _expected: &FinalTaskSnapshot) -> McpResult<bool> {
        self.unexpected_sync()
    }

    fn is_cancellation_requested(&self, _task_id: &FinalTaskId) -> McpResult<bool> {
        self.unexpected_sync()
    }

    fn retention_clock_now(&self) -> Instant {
        self.unexpected_sync()
    }

    fn task_retention_deadline_if_current(
        &self,
        _task_id: &FinalTaskId,
        _generation: u64,
    ) -> McpResult<Option<FinalTaskRetentionDeadline>> {
        self.unexpected_sync()
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

struct Fixture {
    store: Arc<AsyncControlStore>,
    runtime: FinalTaskRuntime,
    ctx: McpContext,
    task_id: FinalTaskId,
    notifications: Arc<AtomicUsize>,
    _registration: Arc<()>,
}

impl Fixture {
    fn new(waiting_for_input: bool) -> Self {
        let store = Arc::new(AsyncControlStore::new());
        let ctx = McpContext::with_state(Cx::for_testing(), 1, fastmcp_core::SessionState::new())
            .with_auth(
                fastmcp_core::AuthContext::with_subject("async-task-owner")
                    .with_session_owner(Sha256Digest::from_bytes([17; 32])),
            );
        let registration = Arc::new(());
        let timestamp = FinalTaskTimestamp::parse("2026-07-28T12:00:00.000Z").unwrap();
        let task_id = FinalTaskId::parse("async-control-task").unwrap();
        let task = FinalTask::Working(FinalTaskBase {
            task_id: task_id.clone(),
            status: FinalTaskStatus::Working,
            status_message: None,
            created_at: timestamp.clone(),
            last_updated_at: timestamp,
            ttl_ms: Some(final_task_duration(60_000).unwrap()),
            poll_interval_ms: None,
        });
        let snapshot = store
            .inner
            .create_task_with_operation(
                task.clone(),
                final_task_notification(&task),
                FinalTaskWorkDescriptor::new(serde_json::json!({"handler":"async-control"}))
                    .unwrap(),
                task_request_principal(&ctx).unwrap(),
                FinalTaskOperation::for_tool("async-control", &registration).unwrap(),
            )
            .unwrap();
        if waiting_for_input {
            let awaiting = FinalTask::InputRequired {
                base: transition_final_task_base(
                    snapshot.task().base().clone(),
                    FinalTaskStatus::InputRequired,
                    None,
                )
                .unwrap(),
                input_requests: serde_json::from_value(
                    serde_json::json!({"roots":{"method":"roots/list"}}),
                )
                .unwrap(),
            };
            store
                .inner
                .replace_task_and_clear_input_if_current(
                    &snapshot,
                    awaiting.clone(),
                    final_task_notification(&awaiting),
                )
                .unwrap()
                .expect("input fixture commits");
        }
        let notifications = Arc::new(AtomicUsize::new(0));
        let observer_count = Arc::clone(&notifications);
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
            Arc::new(move |_| {
                observer_count.fetch_add(1, Ordering::SeqCst);
            }),
        );
        runtime
            .install_access_authorizer(Arc::new(AllowAccess))
            .unwrap();
        Self {
            store,
            runtime,
            ctx,
            task_id,
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

    fn elect_worker(&self) -> (FinalTaskSnapshot, u64) {
        let snapshot = self.snapshot();
        assert!(
            self.store
                .inner
                .take_initial_work_handoff_for_owner_if_current(&snapshot, "async-worker")
                .unwrap()
                .is_some()
        );
        let fence = self
            .store
            .inner
            .begin_handoff_dispatch_for_owner_if_current(
                &self.task_id,
                snapshot.generation(),
                "async-worker",
            )
            .unwrap()
            .expect("test worker is elected");
        (snapshot, fence)
    }

    fn assert_accepted_roots(&self) {
        let snapshot = self.snapshot();
        assert!(matches!(snapshot.task(), FinalTask::Working(_)));
        let claim = self
            .store
            .inner
            .take_input_handoff_for_owner_if_current(&snapshot, "input-consumer")
            .unwrap()
            .expect("accepted input remains available to the caller-owned worker");
        assert_eq!(
            serde_json::to_value(&claim.input_responses).unwrap(),
            serde_json::json!({"roots":{"roots":[]}})
        );
    }
}

fn roots_response() -> FinalTaskInputResponses {
    serde_json::from_value(serde_json::json!({"roots":{"roots":[]}})).unwrap()
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn ready<T>(result: Poll<McpResult<T>>) -> McpResult<T> {
    match result {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("released control operation unexpectedly remained pending"),
    }
}

struct WakeCount(AtomicUsize);

impl std::task::Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn async_control_get_suspends_and_resumes_without_synchronous_store_reads() {
    let fixture = Fixture::new(true);
    fixture.store.metadata_gate.close();
    let mut request = Box::pin(fixture.runtime.task_for_request_with_cx(
        &fixture.ctx,
        &fixture.task_id,
        TaskAccessAction::Get,
    ));
    assert!(poll_once(request.as_mut()).is_pending());
    assert_eq!(fixture.store.payload_calls.load(Ordering::SeqCst), 0);
    fixture.store.metadata_gate.release();
    let snapshot = ready(poll_once(request.as_mut())).unwrap();
    assert!(matches!(snapshot.task(), FinalTask::InputRequired { .. }));
    assert_eq!(fixture.store.metadata_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.store.payload_calls.load(Ordering::SeqCst), 1);
    fixture.store.assert_async_only();
}

#[test]
fn async_control_cancelled_metadata_read_never_loads_payload_or_accepts_input() {
    let fixture = Fixture::new(true);
    let original_generation = fixture.snapshot().generation();
    fixture.store.metadata_gate.close();
    let responses = roots_response();
    let mut request = Box::pin(fixture.runtime.update_task_for_request_with_cx(
        &fixture.ctx,
        &fixture.task_id,
        &responses,
    ));
    assert!(poll_once(request.as_mut()).is_pending());
    fixture.ctx.request_cancellation().cancel();
    fixture.store.metadata_gate.release();
    let error = ready(poll_once(request.as_mut())).err().unwrap();
    assert_eq!(error.code, McpError::request_cancelled().code);
    assert_eq!(fixture.store.payload_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.store.update_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.snapshot().generation(), original_generation);
    fixture.store.assert_async_only();
}

#[test]
fn async_control_request_cancellation_wakes_a_parked_read_without_provider_progress() {
    let fixture = Fixture::new(true);
    fixture.store.metadata_gate.close();
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wakes));
    let mut poll = Context::from_waker(&waker);
    let mut request = Box::pin(fixture.runtime.task_for_request_with_cx(
        &fixture.ctx,
        &fixture.task_id,
        TaskAccessAction::Get,
    ));
    assert!(request.as_mut().poll(&mut poll).is_pending());
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    assert!(fixture.ctx.request_cancellation().cancel());
    assert!(
        wakes.0.load(Ordering::SeqCst) > 0,
        "cancellation must wake the executor before any provider release or repoll"
    );
    let error = ready(request.as_mut().poll(&mut poll)).err().unwrap();
    assert_eq!(error.code, McpError::request_cancelled().code);
    assert_eq!(fixture.store.payload_calls.load(Ordering::SeqCst), 0);
    let wakes_after_completion = wakes.0.load(Ordering::SeqCst);
    fixture.store.metadata_gate.release();
    assert_eq!(
        wakes.0.load(Ordering::SeqCst),
        wakes_after_completion,
        "a late provider wake cannot retain the completed caller"
    );
    fixture.store.assert_async_only();
}

#[test]
fn async_control_changed_principal_or_operation_after_pending_payload_is_rejected() {
    for change_principal in [true, false] {
        let fixture = Fixture::new(true);
        let original_generation = fixture.snapshot().generation();
        fixture.store.payload_gate.close();
        let responses = roots_response();
        let mut request = Box::pin(fixture.runtime.update_task_for_request_with_cx(
            &fixture.ctx,
            &fixture.task_id,
            &responses,
        ));
        assert!(poll_once(request.as_mut()).is_pending());
        if change_principal {
            fixture.store.change_principal.store(true, Ordering::SeqCst);
        } else {
            fixture.store.strip_operation.store(true, Ordering::SeqCst);
        }
        fixture.store.payload_gate.release();
        let error = ready(poll_once(request.as_mut())).err().unwrap();
        assert_eq!(error.code, McpError::invalid_params("Task not found").code);
        assert_eq!(fixture.store.update_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.snapshot().generation(), original_generation);
        fixture.store.assert_async_only();
    }
}

#[test]
fn async_control_hidden_operation_cannot_resume_a_pending_payload_read() {
    let fixture = Fixture::new(true);
    fixture.store.payload_gate.close();
    let mut request = Box::pin(fixture.runtime.task_for_request_with_cx(
        &fixture.ctx,
        &fixture.task_id,
        TaskAccessAction::Get,
    ));
    assert!(poll_once(request.as_mut()).is_pending());
    assert!(fixture.ctx.disable_tool("async-control"));
    fixture.store.payload_gate.release();
    let error = ready(poll_once(request.as_mut())).err().unwrap();
    assert_eq!(error.code, McpError::invalid_params("Task not found").code);
    fixture.store.assert_async_only();
}

#[test]
fn async_control_update_preserves_commit_after_caller_cancels_while_write_is_pending() {
    let fixture = Fixture::new(true);
    fixture.store.write_gate.close();
    let responses = roots_response();
    let mut request = Box::pin(fixture.runtime.update_task_for_request_with_cx(
        &fixture.ctx,
        &fixture.task_id,
        &responses,
    ));
    assert!(poll_once(request.as_mut()).is_pending());
    assert_eq!(fixture.store.update_calls.load(Ordering::SeqCst), 1);
    fixture.ctx.request_cancellation().cancel();
    fixture.store.write_gate.release();
    ready(poll_once(request.as_mut())).expect("the exact accepted input receipt wins cancellation");
    assert!(
        fixture
            .store
            .request_cancellation_observed
            .load(Ordering::SeqCst)
    );
    assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.notifications.load(Ordering::SeqCst), 0);
    fixture.assert_accepted_roots();
    fixture.store.assert_async_only();
}

#[test]
fn async_control_cancel_preserves_mutation_but_reports_unverifiable_outcome_after_caller_ends() {
    let fixture = Fixture::new(false);
    fixture.store.write_gate.close();
    let mut request = Box::pin(
        fixture
            .runtime
            .cancel_task_for_request_with_cx(&fixture.ctx, &fixture.task_id),
    );
    assert!(poll_once(request.as_mut()).is_pending());
    fixture.ctx.request_cancellation().cancel();
    fixture.store.write_gate.release();
    let error = ready(poll_once(request.as_mut())).err().unwrap();
    assert_eq!(error.code, McpError::internal_error("").code);
    assert!(error.message.contains("may have committed"));
    assert!(
        error
            .message
            .contains("Reconcile Task state before retrying")
    );
    assert!(
        fixture
            .store
            .request_cancellation_observed
            .load(Ordering::SeqCst)
    );
    assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.store.cancel_calls.load(Ordering::SeqCst), 1);
    assert!(matches!(fixture.snapshot().task(), FinalTask::Cancelled(_)));
    fixture.store.assert_async_only();
}

#[test]
fn async_control_fabricated_cancel_receipt_cannot_use_caller_cancellation_to_skip_verification() {
    for end_caller in [false, true] {
        let fixture = Fixture::new(false);
        let original_generation = fixture.snapshot().generation();
        fixture
            .store
            .lie_about_cancellation
            .store(true, Ordering::SeqCst);
        if end_caller {
            let cancellation = fixture.ctx.request_cancellation();
            *fixture.store.after_write.lock().unwrap() = Some(Box::new(move || {
                cancellation.cancel();
            }));
        }
        let mut request = Box::pin(
            fixture
                .runtime
                .cancel_task_for_request_with_cx(&fixture.ctx, &fixture.task_id),
        );
        let error = ready(poll_once(request.as_mut())).err().unwrap();
        assert_eq!(error.code, McpError::internal_error("").code);
        if end_caller {
            assert!(error.message.contains("may have committed"));
        } else {
            assert!(error.message.contains("did not retain"));
        }
        assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.snapshot().generation(), original_generation);
        assert!(
            !fixture
                .store
                .inner
                .is_cancellation_requested(&fixture.task_id)
                .unwrap()
        );
        fixture.store.assert_async_only();
    }
}

#[test]
fn async_control_provider_cancellation_after_write_admission_is_an_unknown_outcome() {
    let fixture = Fixture::new(true);
    fixture
        .store
        .cancel_write_with_error
        .store(true, Ordering::SeqCst);
    let cancellation = fixture.ctx.request_cancellation();
    *fixture.store.after_write.lock().unwrap() = Some(Box::new(move || {
        cancellation.cancel();
    }));
    let responses = roots_response();
    let mut request = Box::pin(fixture.runtime.update_task_for_request_with_cx(
        &fixture.ctx,
        &fixture.task_id,
        &responses,
    ));
    let error = ready(poll_once(request.as_mut())).err().unwrap();
    assert_eq!(error.code, McpError::internal_error("").code);
    assert!(
        error
            .message
            .contains("Task input update may have committed")
    );
    assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 0);
    fixture.store.assert_async_only();
}

#[test]
fn async_control_write_provider_receives_request_cancellation_and_wakes_to_settle() {
    let fixture = Fixture::new(true);
    fixture
        .store
        .wait_for_request_cancellation
        .store(true, Ordering::SeqCst);
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wakes));
    let mut poll = Context::from_waker(&waker);
    let responses = roots_response();
    let mut request = Box::pin(fixture.runtime.update_task_for_request_with_cx(
        &fixture.ctx,
        &fixture.task_id,
        &responses,
    ));
    assert!(request.as_mut().poll(&mut poll).is_pending());
    assert_eq!(fixture.store.update_calls.load(Ordering::SeqCst), 1);
    assert!(fixture.ctx.request_cancellation().cancel());
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    let error = ready(request.as_mut().poll(&mut poll)).err().unwrap();
    assert_eq!(error.code, McpError::internal_error("").code);
    assert!(error.message.contains("may have committed"));
    assert!(
        fixture
            .store
            .request_cancellation_observed
            .load(Ordering::SeqCst)
    );
    assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 0);
    fixture.store.assert_async_only();
}

#[test]
fn async_control_elected_worker_cancellation_retains_and_verifies_intent() {
    let fixture = Fixture::new(false);
    fixture.elect_worker();
    let mut request = Box::pin(
        fixture
            .runtime
            .cancel_task_for_request_with_cx(&fixture.ctx, &fixture.task_id),
    );
    ready(poll_once(request.as_mut())).expect("cooperative cancellation is retained");
    assert!(matches!(fixture.snapshot().task(), FinalTask::Working(_)));
    assert!(
        fixture
            .store
            .inner
            .is_cancellation_requested(&fixture.task_id)
            .unwrap()
    );
    assert_eq!(fixture.store.intent_reads.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
    fixture.store.assert_async_only();
}

#[test]
fn async_control_worker_consuming_intent_before_readback_keeps_cancellation_accepted() {
    let fixture = Fixture::new(false);
    let (expected, fence) = fixture.elect_worker();
    let store = Arc::clone(&fixture.store);
    *fixture.store.before_intent_read.lock().unwrap() = Some(Box::new(move || {
        let cancelled = FinalTask::Cancelled(
            transition_terminal_final_task_base(
                expected.task().base().clone(),
                FinalTaskStatus::Cancelled,
                Some("worker acknowledged cancellation".to_owned()),
            )
            .unwrap(),
        );
        store
            .inner
            .replace_task_and_clear_input_for_handoff_if_current(
                &expected,
                "async-worker",
                fence,
                true,
                cancelled.clone(),
                final_task_notification(&cancelled),
            )
            .unwrap()
            .expect("the elected worker consumes intent with its terminal commit");
    }));
    let mut request = Box::pin(
        fixture
            .runtime
            .cancel_task_for_request_with_cx(&fixture.ctx, &fixture.task_id),
    );
    ready(poll_once(request.as_mut())).expect("a newer terminal cancellation proves acceptance");
    assert!(matches!(fixture.snapshot().task(), FinalTask::Cancelled(_)));
    assert!(
        !fixture
            .store
            .inner
            .is_cancellation_requested(&fixture.task_id)
            .unwrap()
    );
    assert_eq!(fixture.store.intent_reads.load(Ordering::SeqCst), 1);
    fixture.store.assert_async_only();
}

#[test]
fn async_control_notification_fence_does_not_retain_a_dropped_observer_while_pending() {
    let fixture = Fixture::new(true);
    let store = Arc::clone(&fixture.store);
    let applications = Arc::new(AtomicUsize::new(0));
    let application_count = Arc::clone(&applications);
    let runtime = FinalTaskRuntime::new(
        fixture.store.clone(),
        FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
        Arc::new(move |_| {
            application_count.fetch_add(1, Ordering::SeqCst);
            store.metadata_gate.close();
        }),
    );
    runtime
        .install_access_authorizer(Arc::new(AllowAccess))
        .unwrap();
    let deliveries = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&deliveries);
    let observer: OwnedTaskNotificationEmitter = Arc::new(move |_, _| {
        observed.fetch_add(1, Ordering::SeqCst);
    });
    let weak = Arc::downgrade(&observer);
    runtime
        .notification_emitters
        .lock()
        .unwrap()
        .push(weak.clone());
    let responses = roots_response();
    let mut request = Box::pin(runtime.update_task_for_request_with_cx(
        &fixture.ctx,
        &fixture.task_id,
        &responses,
    ));
    assert!(poll_once(request.as_mut()).is_pending());
    assert_eq!(applications.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
    drop(observer);
    assert!(
        weak.upgrade().is_none(),
        "pending metadata must not retain the observer"
    );
    fixture.store.metadata_gate.release();
    ready(poll_once(request.as_mut())).unwrap();
    assert_eq!(deliveries.load(Ordering::SeqCst), 0);
    fixture.assert_accepted_roots();
    fixture.store.assert_async_only();
}

#[test]
fn async_control_update_and_terminal_cancel_publish_through_async_hooks() {
    let fixture = Fixture::new(true);
    let responses = roots_response();
    let mut update = Box::pin(fixture.runtime.update_task_for_request_with_cx(
        &fixture.ctx,
        &fixture.task_id,
        &responses,
    ));
    ready(poll_once(update.as_mut())).unwrap();
    assert_eq!(fixture.notifications.load(Ordering::SeqCst), 1);
    let mut cancellation = Box::pin(
        fixture
            .runtime
            .cancel_task_for_request_with_cx(&fixture.ctx, &fixture.task_id),
    );
    ready(poll_once(cancellation.as_mut())).unwrap();
    assert!(matches!(fixture.snapshot().task(), FinalTask::Cancelled(_)));
    assert_eq!(fixture.notifications.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 2);
    fixture.store.assert_async_only();
}
