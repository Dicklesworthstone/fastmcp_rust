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
    audit_gate: Gate,
    retention_receipt_gate: Gate,
    metadata_calls: AtomicUsize,
    payload_calls: AtomicUsize,
    update_calls: AtomicUsize,
    cancel_calls: AtomicUsize,
    intent_reads: AtomicUsize,
    committed_writes: AtomicUsize,
    retention_calls: AtomicUsize,
    audit_calls: AtomicUsize,
    synchronous_calls: AtomicUsize,
    change_principal: AtomicBool,
    strip_operation: AtomicBool,
    lie_about_cancellation: AtomicBool,
    cancel_write_with_error: AtomicBool,
    wait_for_request_cancellation: AtomicBool,
    request_cancellation_observed: AtomicBool,
    after_write: Mutex<Option<Hook>>,
    before_intent_read: Mutex<Option<Hook>>,
    audit_override: Mutex<Option<TaskRetentionAuditPage>>,
    substitute_retention_receipt: AtomicBool,
    fail_reclamation_after_write: AtomicBool,
}

impl AsyncControlStore {
    fn new() -> Self {
        Self {
            inner: InMemoryFinalTaskStore::default(),
            metadata_gate: Gate::new(),
            payload_gate: Gate::new(),
            write_gate: Gate::new(),
            audit_gate: Gate::new(),
            retention_receipt_gate: Gate::new(),
            metadata_calls: AtomicUsize::new(0),
            payload_calls: AtomicUsize::new(0),
            update_calls: AtomicUsize::new(0),
            cancel_calls: AtomicUsize::new(0),
            intent_reads: AtomicUsize::new(0),
            committed_writes: AtomicUsize::new(0),
            retention_calls: AtomicUsize::new(0),
            audit_calls: AtomicUsize::new(0),
            synchronous_calls: AtomicUsize::new(0),
            change_principal: AtomicBool::new(false),
            strip_operation: AtomicBool::new(false),
            lie_about_cancellation: AtomicBool::new(false),
            cancel_write_with_error: AtomicBool::new(false),
            wait_for_request_cancellation: AtomicBool::new(false),
            request_cancellation_observed: AtomicBool::new(false),
            after_write: Mutex::new(None),
            before_intent_read: Mutex::new(None),
            audit_override: Mutex::new(None),
            substitute_retention_receipt: AtomicBool::new(false),
            fail_reclamation_after_write: AtomicBool::new(false),
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
    fn retention_administration_policy(&self) -> McpResult<TaskRetentionPolicy> {
        self.inner.retention_administration_policy()
    }

    fn reclaim_terminal_task_with_context<'a>(
        &'a self,
        admission: FinalTaskRetentionAdmission<'a>,
    ) -> FinalTaskStoreFuture<'a, TaskRetentionReclamation> {
        self.retention_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            self.write_gate.wait().await;
            assert!(Cx::current().is_some(), "retention polls retain the caller");
            admission.checkpoint_before_write()?;
            let outcome = self.inner.reclaim_terminal_task_if_current(
                admission.context().cx(),
                admission.task_id(),
                admission.generation(),
                admission.reason(),
            )?;
            if matches!(&outcome, TaskRetentionReclamation::Reclaimed(_)) {
                self.committed_writes.fetch_add(1, Ordering::SeqCst);
                self.after_write();
            }
            self.retention_receipt_gate.wait().await;
            if self.fail_reclamation_after_write.load(Ordering::SeqCst) {
                return Err(McpError::request_cancelled());
            }
            if self.substitute_retention_receipt.load(Ordering::SeqCst) {
                return Ok(TaskRetentionReclamation::Reclaimed(
                    TaskRetentionReceipt::new(
                        1,
                        &FinalTaskId::parse("unrelated-retained-task").unwrap(),
                        admission.generation(),
                        admission.reason(),
                        0,
                    )?,
                ));
            }
            Ok(outcome)
        })
    }

    fn task_retention_audit_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        after: Option<u64>,
        limit: usize,
    ) -> FinalTaskStoreFuture<'a, TaskRetentionAuditPage> {
        self.audit_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            self.audit_gate.wait().await;
            assert!(Cx::current().is_some(), "audit polls retain the caller");
            if let Some(page) = self.audit_override.lock().unwrap().take() {
                return Ok(page);
            }
            self.inner.task_retention_audit(ctx.cx(), after, limit)
        })
    }

    fn reclaim_terminal_task_if_current(
        &self,
        _cx: &Cx,
        _task_id: &FinalTaskId,
        _generation: u64,
        _reason: TaskRetentionReason,
    ) -> McpResult<TaskRetentionReclamation> {
        self.unexpected_sync()
    }

    fn task_retention_audit(
        &self,
        _cx: &Cx,
        _after: Option<u64>,
        _limit: usize,
    ) -> McpResult<TaskRetentionAuditPage> {
        self.unexpected_sync()
    }

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
        Self::with_store(waiting_for_input, Arc::new(AsyncControlStore::new()))
    }

    fn with_store(waiting_for_input: bool, store: Arc<AsyncControlStore>) -> Self {
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

struct RetentionAdmin {
    allowed: AtomicBool,
}

impl TaskRetentionAdministrator for RetentionAdmin {
    fn authorize(
        &self,
        _ctx: &McpContext,
        _action: &TaskRetentionAuthorization<'_>,
    ) -> McpResult<()> {
        if self.allowed.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(McpError::invalid_request("test administrator was revoked"))
        }
    }
}

fn terminal_retention_fixture() -> (Fixture, Arc<RetentionAdmin>) {
    terminal_retention_fixture_from(Fixture::new(false))
}

fn terminal_retention_fixture_from(fixture: Fixture) -> (Fixture, Arc<RetentionAdmin>) {
    let current = fixture.snapshot();
    let terminal = FinalTask::Cancelled(
        transition_terminal_final_task_base(
            current.task().base().clone(),
            FinalTaskStatus::Cancelled,
            None,
        )
        .unwrap(),
    );
    fixture
        .store
        .inner
        .replace_task_and_clear_input_if_current(
            &current,
            terminal.clone(),
            final_task_notification(&terminal),
        )
        .unwrap()
        .expect("terminal fixture commits");
    let administrator = Arc::new(RetentionAdmin {
        allowed: AtomicBool::new(true),
    });
    fixture
        .runtime
        .install_retention_administrator(fixture.ctx.cx(), administrator.clone())
        .unwrap();
    (fixture, administrator)
}

fn inspect_retention(fixture: &Fixture) -> TaskRetentionTarget {
    let mut inspect = Box::pin(
        fixture
            .runtime
            .inspect_task_retention_with_context(&fixture.ctx, &fixture.task_id),
    );
    ready(poll_once(inspect.as_mut())).expect("authorized terminal inspection")
}

#[test]
fn async_retention_inspection_suspends_without_blocking_sibling_audit() {
    let (fixture, _administrator) = terminal_retention_fixture();
    fixture.store.payload_gate.close();
    let mut inspect = Box::pin(
        fixture
            .runtime
            .inspect_task_retention_with_context(&fixture.ctx, &fixture.task_id),
    );
    assert!(poll_once(inspect.as_mut()).is_pending());
    let mut audit = Box::pin(fixture.runtime.task_retention_audit_with_context(
        &fixture.ctx,
        None,
        1,
    ));
    assert!(
        ready(poll_once(audit.as_mut()))
            .unwrap()
            .records()
            .is_empty()
    );
    fixture.store.payload_gate.release();
    let target = ready(poll_once(inspect.as_mut())).unwrap();
    assert_eq!(target.task_id(), &fixture.task_id);
    assert_eq!(target.generation(), fixture.snapshot().generation());
    assert_eq!(fixture.store.payload_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.store.audit_calls.load(Ordering::SeqCst), 1);
    fixture.store.assert_async_only();
}

#[test]
fn async_retention_denied_administrator_never_opens_payload_or_audit() {
    let (fixture, administrator) = terminal_retention_fixture();
    administrator.allowed.store(false, Ordering::SeqCst);
    let mut inspect = Box::pin(
        fixture
            .runtime
            .inspect_task_retention_with_context(&fixture.ctx, &fixture.task_id),
    );
    assert!(ready(poll_once(inspect.as_mut())).is_err());
    let mut audit = Box::pin(fixture.runtime.task_retention_audit_with_context(
        &fixture.ctx,
        None,
        1,
    ));
    assert!(ready(poll_once(audit.as_mut())).is_err());
    assert_eq!(fixture.store.payload_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.store.audit_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.store.inner.task_count(), 1);
    fixture.store.assert_async_only();
}

#[test]
fn async_retention_suspended_reads_reject_revocation_before_returning_data() {
    for inspect in [true, false] {
        let (fixture, administrator) = terminal_retention_fixture();
        fixture.store.payload_gate.close();
        fixture.store.audit_gate.close();
        let mut read: Pin<Box<dyn Future<Output = McpResult<()>> + Send + '_>> = if inspect {
            Box::pin(async {
                fixture
                    .runtime
                    .inspect_task_retention_with_context(&fixture.ctx, &fixture.task_id)
                    .await
                    .map(|_| ())
            })
        } else {
            Box::pin(async {
                fixture
                    .runtime
                    .task_retention_audit_with_context(&fixture.ctx, None, 1)
                    .await
                    .map(|_| ())
            })
        };
        assert!(
            read.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        administrator.allowed.store(false, Ordering::SeqCst);
        let error = ready(read.as_mut().poll(&mut Context::from_waker(Waker::noop())))
            .expect_err("revocation fences the still-parked read");
        assert_eq!(
            error.message,
            "Task retention administration is not authorized"
        );
        assert_eq!(fixture.store.inner.task_count(), 1);
        fixture.store.assert_async_only();
    }
}

#[test]
fn async_retention_cancelled_read_wakes_without_a_store_wakeup() {
    let (fixture, _administrator) = terminal_retention_fixture();
    fixture.store.payload_gate.close();
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wakes));
    let mut poll = Context::from_waker(&waker);
    let mut inspect = Box::pin(
        fixture
            .runtime
            .inspect_task_retention_with_context(&fixture.ctx, &fixture.task_id),
    );
    assert!(inspect.as_mut().poll(&mut poll).is_pending());
    fixture.ctx.request_cancellation().cancel();
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(ready(inspect.as_mut().poll(&mut poll)).is_err());
    assert_eq!(fixture.store.inner.task_count(), 1);
    fixture.store.assert_async_only();
}

#[test]
fn async_retention_reclamation_revalidates_before_first_write() {
    for cancel in [false, true] {
        let (fixture, administrator) = terminal_retention_fixture();
        let target = inspect_retention(&fixture);
        let before = fixture.snapshot();
        let retained = fixture.store.inner.retained_payload_bytes();
        fixture.store.write_gate.close();
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut poll = Context::from_waker(&waker);
        let mut reclaim = Box::pin(fixture.runtime.reclaim_task_retention_with_context(
            &fixture.ctx,
            &target,
            TaskRetentionReason::OperatorRequest,
        ));
        assert!(reclaim.as_mut().poll(&mut poll).is_pending());
        if cancel {
            fixture.ctx.request_cancellation().cancel();
            assert!(
                wakes.0.load(Ordering::SeqCst) > 0,
                "prewrite cancellation must wake the caller without storage progress"
            );
        } else {
            administrator.allowed.store(false, Ordering::SeqCst);
        }
        // Leave the provider parked. The runtime must settle a read-only wait
        // without requiring an unrelated storage wake or claiming a mutation.
        let error = ready(reclaim.as_mut().poll(&mut poll)).unwrap_err();
        if cancel {
            assert_eq!(error.code, McpError::request_cancelled().code);
        } else {
            assert_eq!(
                error.message,
                "Task retention administration is not authorized"
            );
        }
        assert!(!error.message.contains("may have committed"));
        assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.inner.retained_payload_bytes(), retained);
        let after = fixture.snapshot();
        assert_eq!(after.generation(), before.generation());
        assert!(final_tasks_match_exactly(after.task(), before.task()).unwrap());
        let audit = fixture
            .store
            .inner
            .task_retention_audit(&Cx::for_testing(), None, 1)
            .unwrap();
        assert!(audit.records().is_empty());
        fixture.store.assert_async_only();
    }
}

#[test]
fn async_retention_committed_receipt_survives_cancellation_and_retry_is_idempotent() {
    for cancel_in_commit_poll in [false, true] {
        let (fixture, administrator) = terminal_retention_fixture();
        let target = inspect_retention(&fixture);
        if cancel_in_commit_poll {
            let cancellation = fixture.ctx.request_cancellation();
            let revoked = Arc::clone(&administrator);
            *fixture.store.after_write.lock().unwrap() = Some(Box::new(move || {
                cancellation.cancel();
                revoked.allowed.store(false, Ordering::SeqCst);
            }));
        }
        fixture.store.retention_receipt_gate.close();
        let mut reclaim = Box::pin(fixture.runtime.reclaim_task_retention_with_context(
            &fixture.ctx,
            &target,
            TaskRetentionReason::OperatorRequest,
        ));
        assert!(poll_once(reclaim.as_mut()).is_pending());
        assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.inner.task_count(), 0);
        if !cancel_in_commit_poll {
            fixture.ctx.request_cancellation().cancel();
            administrator.allowed.store(false, Ordering::SeqCst);
        }
        assert!(fixture.ctx.ensure_live().is_err());
        fixture.store.retention_receipt_gate.release();
        let committed = ready(poll_once(reclaim.as_mut())).unwrap();
        let TaskRetentionReclamation::Reclaimed(receipt) = committed else {
            panic!("a proven commit must retain its receipt");
        };
        administrator.allowed.store(true, Ordering::SeqCst);
        let fresh = McpContext::with_state(Cx::for_testing(), 2, fastmcp_core::SessionState::new());
        let mut retry = Box::pin(fixture.runtime.reclaim_task_retention_with_context(
            &fresh,
            &target,
            TaskRetentionReason::SubjectRemoved,
        ));
        assert_eq!(
            ready(poll_once(retry.as_mut())).unwrap(),
            TaskRetentionReclamation::AlreadyReclaimed(receipt.clone()),
        );
        let mut audit = Box::pin(
            fixture
                .runtime
                .task_retention_audit_with_context(&fresh, None, 1),
        );
        assert_eq!(
            ready(poll_once(audit.as_mut())).unwrap().records(),
            &[receipt]
        );
        assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
        fixture.store.assert_async_only();
    }
}

#[test]
fn async_retention_nonmutating_receipts_require_authority_after_write_admission() {
    for receipt_expired in [false, true] {
        for cancelled in [None, Some(false), Some(true)] {
            let now = Arc::new(Mutex::new(Instant::now()));
            let clock = Arc::clone(&now);
            let inner = InMemoryFinalTaskStore::with_clock(
                16,
                Arc::new(move || *clock.lock().unwrap()),
            )
            .unwrap();
            let store = Arc::new(AsyncControlStore {
                inner,
                ..AsyncControlStore::new()
            });
            let (fixture, administrator) =
                terminal_retention_fixture_from(Fixture::with_store(false, store));
            let target = inspect_retention(&fixture);
            let mut first = Box::pin(fixture.runtime.reclaim_task_retention_with_context(
                &fixture.ctx,
                &target,
                TaskRetentionReason::RetentionPolicy,
            ));
            let TaskRetentionReclamation::Reclaimed(receipt) =
                ready(poll_once(first.as_mut())).unwrap()
            else {
                panic!("the original terminal generation must reclaim");
            };
            if receipt_expired {
                let mut now = now.lock().unwrap();
                *now = now.checked_add(StdDuration::from_hours(48)).unwrap();
            }
            // The provider runs its write-admission checkpoint in both cases.
            // The exact store transaction then returns an old receipt or a
            // failed comparison, without performing another reclamation.
            fixture.store.retention_receipt_gate.close();
            let mut repeated = Box::pin(fixture.runtime.reclaim_task_retention_with_context(
                &fixture.ctx,
                &target,
                TaskRetentionReason::OperatorRequest,
            ));
            assert!(poll_once(repeated.as_mut()).is_pending());
            assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
            if let Some(cancel) = cancelled {
                if cancel {
                    fixture.ctx.request_cancellation().cancel();
                } else {
                    administrator.allowed.store(false, Ordering::SeqCst);
                }
            }
            fixture.store.retention_receipt_gate.release();
            let outcome = ready(poll_once(repeated.as_mut()));
            if let Some(cancel) = cancelled {
                let error = outcome.expect_err("a nonmutating receipt needs current authority");
                if cancel {
                    assert_eq!(error.code, McpError::request_cancelled().code);
                } else {
                    assert_eq!(
                        error.message,
                        "Task retention administration is not authorized"
                    );
                }
                assert!(!error.message.contains("may have committed"));
            } else if receipt_expired {
                assert_eq!(outcome.unwrap(), TaskRetentionReclamation::NotCurrent);
            } else {
                assert_eq!(
                    outcome.unwrap(),
                    TaskRetentionReclamation::AlreadyReclaimed(receipt)
                );
            }
            assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.store.inner.task_count(), 0);
            assert_eq!(fixture.store.inner.retained_payload_bytes(), 0);
            fixture.store.assert_async_only();
        }
    }
}

#[test]
fn async_retention_rejects_foreign_runtime_target_before_backend_mutation() {
    let (fixture, _administrator) = terminal_retention_fixture();
    let target = inspect_retention(&fixture);
    let other = FinalTaskRuntime::new(
        fixture.store.clone(),
        FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
        Arc::new(|_| {}),
    );
    other
        .install_retention_administrator(
            fixture.ctx.cx(),
            Arc::new(RetentionAdmin {
                allowed: AtomicBool::new(true),
            }),
        )
        .unwrap();
    let mut reclaim = Box::pin(other.reclaim_task_retention_with_context(
        &fixture.ctx,
        &target,
        TaskRetentionReason::OperatorRequest,
    ));
    let error = ready(poll_once(reclaim.as_mut())).unwrap_err();
    assert_eq!(
        error.message,
        "Task retention target belongs to another runtime"
    );
    assert_eq!(fixture.store.retention_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.store.inner.task_count(), 1);
    fixture.store.assert_async_only();
}

#[test]
fn async_retention_old_target_cannot_reclaim_a_reused_task_identifier() {
    let (fixture, _administrator) = terminal_retention_fixture();
    let target = inspect_retention(&fixture);
    let original = fixture.snapshot();
    let old_receipt = fixture
        .store
        .inner
        .reclaim_terminal_task_if_current(
            fixture.ctx.cx(),
            &fixture.task_id,
            target.generation(),
            TaskRetentionReason::RetentionPolicy,
        )
        .unwrap()
        .receipt()
        .unwrap()
        .clone();
    fixture
        .store
        .inner
        .create_task(
            original.task().clone(),
            final_task_notification(original.task()),
        )
        .unwrap();
    let successor = fixture.snapshot();
    assert!(successor.generation() > target.generation());
    let mut reclaim = Box::pin(fixture.runtime.reclaim_task_retention_with_context(
        &fixture.ctx,
        &target,
        TaskRetentionReason::SubjectRemoved,
    ));
    assert_eq!(
        ready(poll_once(reclaim.as_mut())).unwrap(),
        TaskRetentionReclamation::AlreadyReclaimed(old_receipt),
    );
    assert_eq!(fixture.snapshot().generation(), successor.generation());
    assert_eq!(fixture.store.inner.task_count(), 1);
    assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 0);
    fixture.store.assert_async_only();
}

#[test]
fn async_retention_rejects_substituted_receipts_and_ambiguous_write_errors() {
    for substitute in [true, false] {
        let (fixture, _administrator) = terminal_retention_fixture();
        let target = inspect_retention(&fixture);
        fixture
            .store
            .substitute_retention_receipt
            .store(substitute, Ordering::SeqCst);
        fixture
            .store
            .fail_reclamation_after_write
            .store(!substitute, Ordering::SeqCst);
        let mut reclaim = Box::pin(fixture.runtime.reclaim_task_retention_with_context(
            &fixture.ctx,
            &target,
            TaskRetentionReason::RetentionPolicy,
        ));
        let error = ready(poll_once(reclaim.as_mut())).unwrap_err();
        assert_eq!(error.code, McpError::internal_error("").code);
        if substitute {
            assert_eq!(
                error.message,
                "Task retention backend returned an unrelated receipt"
            );
        } else {
            assert!(
                error
                    .message
                    .contains("Task retention reclamation may have committed")
            );
        }
        assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.inner.task_count(), 0);
        fixture.store.assert_async_only();
    }
}

#[test]
fn async_retention_audit_rejects_backend_page_and_cursor_widening() {
    for violation in 0..4 {
        let (fixture, _administrator) = terminal_retention_fixture();
        let receipt = TaskRetentionReceipt::new(
            1,
            &fixture.task_id,
            fixture.snapshot().generation(),
            TaskRetentionReason::OperatorRequest,
            0,
        )
        .unwrap();
        let mut page = TaskRetentionAuditPage::new(vec![receipt.clone()], None, 1, 128).unwrap();
        let mut after = None;
        match violation {
            0 => {
                let mut second = receipt;
                second.sequence = 2;
                page.records.push(second);
                page.retained_records = 2;
            }
            1 => page.retained_records = TaskRetentionPolicy::default().max_records() + 1,
            2 => page.retained_bytes = TaskRetentionPolicy::default().max_bytes() + 1,
            _ => after = Some(1),
        }
        *fixture.store.audit_override.lock().unwrap() = Some(page);
        let mut audit = Box::pin(fixture.runtime.task_retention_audit_with_context(
            &fixture.ctx,
            after,
            1,
        ));
        let error = ready(poll_once(audit.as_mut())).unwrap_err();
        assert_eq!(
            error.message,
            "Task retention backend exceeded its audit bounds"
        );
        assert_eq!(fixture.store.inner.task_count(), 1);
        fixture.store.assert_async_only();
    }
}


#[test]
fn async_control_caller_cancellation_wakes_parked_metadata_and_payload_reads() {
    for metadata in [true, false] {
        let fixture = Fixture::new(true);
        let before = fixture.snapshot();
        if metadata {
            fixture.store.metadata_gate.close();
        } else {
            fixture.store.payload_gate.close();
        }
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut poll = Context::from_waker(&waker);
        let mut request = Box::pin(fixture.runtime.task_for_request_with_cx(
            &fixture.ctx,
            &fixture.task_id,
            TaskAccessAction::Get,
        ));
        assert!(request.as_mut().poll(&mut poll).is_pending());
        let before_cancel = wakes.0.load(Ordering::SeqCst);
        fixture.ctx.cx().set_cancel_requested(true);
        assert!(
            wakes.0.load(Ordering::SeqCst) > before_cancel,
            "caller cancellation must wake the parked read without storage progress"
        );
        assert!(!fixture.ctx.request_cancellation().is_cancel_requested());
        let error = ready(request.as_mut().poll(&mut poll)).unwrap_err();
        assert_eq!(error.code, McpError::request_cancelled().code);
        if metadata {
            assert_eq!(fixture.store.payload_calls.load(Ordering::SeqCst), 0);
        }
        assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 0);
        let after = fixture.snapshot();
        assert_eq!(after.generation(), before.generation());
        assert!(final_tasks_match_exactly(after.task(), before.task()).unwrap());
        let after_completion = wakes.0.load(Ordering::SeqCst);
        fixture.store.metadata_gate.release();
        fixture.store.payload_gate.release();
        assert_eq!(wakes.0.load(Ordering::SeqCst), after_completion);
        fixture.store.assert_async_only();
    }
}

#[test]
fn async_retention_caller_cancellation_wakes_prewrite_without_mutation() {
    let (fixture, _administrator) = terminal_retention_fixture();
    let target = inspect_retention(&fixture);
    let before = fixture.snapshot();
    let retained = fixture.store.inner.retained_payload_bytes();
    fixture.store.write_gate.close();
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wakes));
    let mut poll = Context::from_waker(&waker);
    let mut reclaim = Box::pin(fixture.runtime.reclaim_task_retention_with_context(
        &fixture.ctx,
        &target,
        TaskRetentionReason::OperatorRequest,
    ));
    assert!(reclaim.as_mut().poll(&mut poll).is_pending());
    let before_cancel = wakes.0.load(Ordering::SeqCst);
    fixture.ctx.cx().set_cancel_requested(true);
    assert!(wakes.0.load(Ordering::SeqCst) > before_cancel);
    let error = ready(reclaim.as_mut().poll(&mut poll)).unwrap_err();
    assert_eq!(error.code, McpError::request_cancelled().code);
    assert!(!error.message.contains("may have committed"));
    assert!(!fixture.ctx.request_cancellation().is_cancel_requested());
    assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.store.inner.retained_payload_bytes(), retained);
    let after = fixture.snapshot();
    assert_eq!(after.generation(), before.generation());
    assert!(final_tasks_match_exactly(after.task(), before.task()).unwrap());
    let audit = fixture
        .store
        .inner
        .task_retention_audit(&Cx::for_testing(), None, 1)
        .unwrap();
    assert!(audit.records().is_empty());
    let after_completion = wakes.0.load(Ordering::SeqCst);
    fixture.store.write_gate.release();
    assert_eq!(wakes.0.load(Ordering::SeqCst), after_completion);
    fixture.store.assert_async_only();
}

#[test]
fn async_retention_committed_receipt_survives_caller_cancellation() {
    for cancel_in_commit_poll in [false, true] {
        let (fixture, _administrator) = terminal_retention_fixture();
        let target = inspect_retention(&fixture);
        if cancel_in_commit_poll {
            let caller = fixture.ctx.cx().clone();
            *fixture.store.after_write.lock().unwrap() = Some(Box::new(move || {
                caller.set_cancel_requested(true);
            }));
        }
        fixture.store.retention_receipt_gate.close();
        let mut reclaim = Box::pin(fixture.runtime.reclaim_task_retention_with_context(
            &fixture.ctx,
            &target,
            TaskRetentionReason::OperatorRequest,
        ));
        assert!(poll_once(reclaim.as_mut()).is_pending());
        assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.inner.task_count(), 0);
        if !cancel_in_commit_poll {
            fixture.ctx.cx().set_cancel_requested(true);
        }
        assert!(fixture.ctx.ensure_live().is_err());
        assert!(!fixture.ctx.request_cancellation().is_cancel_requested());
        assert!(
            poll_once(reclaim.as_mut()).is_pending(),
            "an admitted write retains its receipt future after caller cancellation"
        );
        fixture.store.retention_receipt_gate.release();
        let TaskRetentionReclamation::Reclaimed(receipt) =
            ready(poll_once(reclaim.as_mut())).unwrap()
        else {
            panic!("caller cancellation cannot erase an acknowledged reclamation");
        };
        let fresh = McpContext::with_state(Cx::for_testing(), 2, fastmcp_core::SessionState::new());
        let mut retry = Box::pin(fixture.runtime.reclaim_task_retention_with_context(
            &fresh,
            &target,
            TaskRetentionReason::SubjectRemoved,
        ));
        assert_eq!(
            ready(poll_once(retry.as_mut())).unwrap(),
            TaskRetentionReclamation::AlreadyReclaimed(receipt.clone()),
        );
        let mut audit = Box::pin(
            fixture
                .runtime
                .task_retention_audit_with_context(&fresh, None, 1),
        );
        assert_eq!(ready(poll_once(audit.as_mut())).unwrap().records(), &[receipt]);
        assert_eq!(fixture.store.committed_writes.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.inner.retained_payload_bytes(), 0);
        fixture.store.assert_async_only();
    }
}
