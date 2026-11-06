//! Public Task creation admission and service-generation recovery.
//! The store is deliberately process-local; these tests claim no crash durability.
#![cfg(feature = "tasks")]

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use asupersync::runtime::{RuntimeBuilder, TaskHandle};
use asupersync::{CancelReason, Cx};
use fastmcp_core::{McpError, McpResult};
use fastmcp_protocol::tasks_extension::{Task, TaskStatusNotification};
use fastmcp_protocol::{FinalTaskCallToolResult, FinalTaskId};
use fastmcp_server::{
    ApplicationTaskSupervisor, FinalTaskAccessMetadata, FinalTaskExecutionBudget,
    FinalTaskExecutionLimits, FinalTaskInitialWorkClaim, FinalTaskRetentionDeadline,
    FinalTaskRuntime, FinalTaskRuntimeConfig, FinalTaskSnapshot, FinalTaskStore,
    FinalTaskSupervisorFuture, FinalTaskSupervisorHandoff, FinalTaskWorkDescriptor,
    InMemoryFinalTaskStore,
};

type StoreHook = Box<dyn FnOnce() -> McpResult<()> + Send>;

struct Store {
    inner: Arc<InMemoryFinalTaskStore>,
    before_policy: Mutex<Option<StoreHook>>,
    before_create: Mutex<Option<StoreHook>>,
    creates: AtomicUsize,
}

impl Store {
    fn new() -> Self {
        Self {
            inner: Arc::new(InMemoryFinalTaskStore::new(16).unwrap()),
            before_policy: Mutex::new(None),
            before_create: Mutex::new(None),
            creates: AtomicUsize::new(0),
        }
    }
}

// Forward the real store's attestations, fencing and recovery without
// reconstructing its private execution-admission custody.
impl FinalTaskStore for Store {
    fn create_task(&self, task: Task, notification: TaskStatusNotification) -> McpResult<()> {
        self.inner.create_task(task, notification)
    }

    fn create_task_with_work(
        &self,
        task: Task,
        notification: TaskStatusNotification,
        descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<FinalTaskSnapshot> {
        self.creates.fetch_add(1, Ordering::SeqCst);
        let hook = self.before_create.lock().unwrap().take();
        if let Some(hook) = hook {
            hook()?;
        }
        self.inner
            .create_task_with_work(task, notification, descriptor)
    }

    fn execution_limits(&self) -> McpResult<FinalTaskExecutionLimits> {
        let hook = self.before_policy.lock().unwrap().take();
        if let Some(hook) = hook {
            hook()?;
        }
        self.inner.execution_limits()
    }

    fn get_task_access_metadata(
        &self,
        id: &FinalTaskId,
    ) -> McpResult<Option<FinalTaskAccessMetadata>> {
        self.inner.get_task_access_metadata(id)
    }

    fn get_task(&self, id: &FinalTaskId) -> McpResult<Option<Task>> {
        self.inner.get_task(id)
    }

    fn get_task_snapshot(&self, id: &FinalTaskId) -> McpResult<Option<FinalTaskSnapshot>> {
        self.inner.get_task_snapshot(id)
    }

    fn replace_task(&self, task: Task, notification: TaskStatusNotification) -> McpResult<()> {
        self.inner.replace_task(task, notification)
    }

    fn replace_task_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        task: Task,
        notification: TaskStatusNotification,
    ) -> McpResult<bool> {
        self.inner
            .replace_task_if_current(expected, task, notification)
    }

    fn request_cancellation(&self, id: &FinalTaskId) -> McpResult<()> {
        self.inner.request_cancellation(id)
    }

    fn request_cancellation_if_current(&self, expected: &FinalTaskSnapshot) -> McpResult<bool> {
        self.inner.request_cancellation_if_current(expected)
    }

    fn is_cancellation_requested(&self, id: &FinalTaskId) -> McpResult<bool> {
        self.inner.is_cancellation_requested(id)
    }

    fn task_execution_budget_if_current(
        &self,
        expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskExecutionBudget>> {
        self.inner.task_execution_budget_if_current(expected)
    }

    fn expire_task_execution_if_current(
        &self,
        expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        self.inner.expire_task_execution_if_current(expected)
    }

    fn next_expired_execution_snapshot(&self) -> McpResult<Option<FinalTaskSnapshot>> {
        self.inner.next_expired_execution_snapshot()
    }

    fn next_initial_work_snapshot_after(
        &self,
        after: Option<&FinalTaskId>,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        self.inner.next_initial_work_snapshot_after(after)
    }

    fn next_accepted_input_snapshot_after(
        &self,
        after: Option<&FinalTaskId>,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        self.inner.next_accepted_input_snapshot_after(after)
    }

    fn take_initial_work_handoff_for_owner_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        owner: &str,
    ) -> McpResult<Option<FinalTaskInitialWorkClaim>> {
        self.inner
            .take_initial_work_handoff_for_owner_if_current(expected, owner)
    }

    fn restore_initial_work_for_owner_if_current(
        &self,
        id: &FinalTaskId,
        generation: u64,
        owner: &str,
        fence: Option<u64>,
        descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<bool> {
        self.inner
            .restore_initial_work_for_owner_if_current(id, generation, owner, fence, descriptor)
    }

    fn begin_handoff_dispatch_for_owner_if_current(
        &self,
        id: &FinalTaskId,
        generation: u64,
        owner: &str,
    ) -> McpResult<Option<u64>> {
        self.inner
            .begin_handoff_dispatch_for_owner_if_current(id, generation, owner)
    }

    fn renew_handoff_dispatch_if_current(
        &self,
        id: &FinalTaskId,
        generation: u64,
        owner: &str,
        fence: u64,
    ) -> McpResult<bool> {
        self.inner
            .renew_handoff_dispatch_if_current(id, generation, owner, fence)
    }

    fn handoff_dispatch_lease_heartbeat_interval(&self) -> McpResult<Duration> {
        self.inner.handoff_dispatch_lease_heartbeat_interval()
    }

    fn finish_handoff_dispatch_for_owner_if_current(
        &self,
        id: &FinalTaskId,
        generation: u64,
        owner: &str,
        fence: u64,
    ) -> McpResult<bool> {
        self.inner
            .finish_handoff_dispatch_for_owner_if_current(id, generation, owner, fence)
    }

    fn replace_task_and_clear_input_for_handoff_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        owner: &str,
        fence: u64,
        cancellation_required: bool,
        task: Task,
        notification: TaskStatusNotification,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        self.inner
            .replace_task_and_clear_input_for_handoff_if_current(
                expected,
                owner,
                fence,
                cancellation_required,
                task,
                notification,
            )
    }

    fn retention_clock_now(&self) -> Instant {
        self.inner.retention_clock_now()
    }

    fn task_retention_deadline_if_current(
        &self,
        id: &FinalTaskId,
        generation: u64,
    ) -> McpResult<Option<FinalTaskRetentionDeadline>> {
        self.inner
            .task_retention_deadline_if_current(id, generation)
    }
}

#[derive(Default)]
struct Supervisor(Mutex<Vec<(FinalTaskId, serde_json::Value)>>);

impl ApplicationTaskSupervisor for Supervisor {
    fn resume<'a>(
        &'a self,
        _cx: &'a Cx,
        handoff: FinalTaskSupervisorHandoff,
    ) -> FinalTaskSupervisorFuture<'a> {
        Box::pin(async move {
            let FinalTaskSupervisorHandoff::Initial(work) = handoff else {
                panic!("these creations never request client input")
            };
            self.0.lock().unwrap().push((
                work.task_id().clone(),
                work.work_descriptor().as_value().clone(),
            ));
            let result: FinalTaskCallToolResult =
                serde_json::from_value(serde_json::json!({"content":[]})).unwrap();
            work.complete_task(result, None)?;
            Ok(())
        })
    }
}

#[derive(Default)]
struct Gate {
    entered: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn wait(&self) -> McpResult<()> {
        self.entered.store(true, Ordering::Release);
        let (released, _) = self
            .changed
            .wait_timeout_while(
                self.released.lock().unwrap(),
                Duration::from_secs(5),
                |released| !*released,
            )
            .unwrap();
        if !*released {
            return Err(McpError::internal_error("test provider release timed out"));
        }
        Ok(())
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

struct ReleaseGate(Arc<Gate>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[derive(Default)]
struct ReentryWorkers(Mutex<Vec<thread::JoinHandle<()>>>);
impl Drop for ReentryWorkers {
    fn drop(&mut self) {
        for worker in self.0.get_mut().unwrap().drain(..) {
            worker.join().unwrap();
        }
    }
}

fn check_provider_reentry(runtime: FinalTaskRuntime, workers: &ReentryWorkers) -> McpResult<()> {
    // First bound the regression: a former lock-held callback fails promptly
    // instead of deadlocking its own thread forever. After that proof, invoke
    // the exact public readiness API directly from the store callback too.
    let (sender, receiver) = mpsc::channel();
    let probe = runtime.clone();
    workers.0.lock().unwrap().push(thread::spawn(move || {
        let _ = sender.send(probe.is_task_service_ready());
    }));
    let ready = receiver
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| McpError::internal_error("provider cannot re-enter Task readiness"))?;
    assert!(ready);
    assert!(runtime.is_task_service_ready());
    Ok(())
}

fn work(name: &str) -> FinalTaskWorkDescriptor {
    FinalTaskWorkDescriptor::new(serde_json::json!({"operation":name})).unwrap()
}

fn run(scenario: impl Future<Output = ()>) {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(scenario);
    assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
}

async fn until(cx: &Cx, reason: &str, predicate: impl Fn() -> bool) {
    asupersync::time::timeout(cx.now(), Duration::from_secs(3), async {
        while !predicate() {
            asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
        }
    })
    .await
    .expect(reason);
}

async fn start(
    cx: &Cx,
    runtime: &FinalTaskRuntime,
    supervisor: Arc<Supervisor>,
) -> TaskHandle<McpResult<()>> {
    let runner = runtime.install_task_service(1, supervisor).unwrap();
    let service = cx
        .spawn(move |child| async move { runner.run(&child).await })
        .unwrap();
    until(cx, "the caller-owned service enters", || {
        runtime.is_task_service_ready()
    })
    .await;
    service
}

async fn stop(cx: &Cx, service: &mut TaskHandle<McpResult<()>>, runtime: &FinalTaskRuntime) {
    service.abort_with_reason(CancelReason::user("test service generation stopped"));
    let _ = asupersync::time::timeout(cx.now(), Duration::from_secs(3), service.join(cx))
        .await
        .expect("service teardown must not wait for a store callback");
    assert!(!runtime.is_task_service_ready());
}

fn fixture(config: FinalTaskRuntimeConfig) -> (Arc<Store>, FinalTaskRuntime, Arc<Supervisor>) {
    let store = Arc::new(Store::new());
    let runtime = FinalTaskRuntime::new(store.clone(), config, Arc::new(|_| {}));
    (store, runtime, Arc::new(Supervisor::default()))
}

#[test]
fn committed_create_survives_service_exit_and_replacement_recovers_once() {
    run(async {
        let cx = Cx::current().unwrap();
        let config = FinalTaskRuntimeConfig::new(60_000, None)
            .unwrap()
            .with_admission_capacity(1, 1, 1_048_576, 1_048_576)
            .unwrap();
        let (store, runtime, supervisor) = fixture(config);
        let mut old_service = start(&cx, &runtime, supervisor.clone()).await;
        let gate = Arc::new(Gate::default());
        let _release = ReleaseGate(gate.clone());
        let workers = Arc::new(ReentryWorkers::default());
        let hook_runtime = runtime.clone();
        let hook_gate = gate.clone();
        let hook_workers = workers.clone();
        *store.before_create.lock().unwrap() = Some(Box::new(move || {
            check_provider_reentry(hook_runtime, &hook_workers)?;
            hook_gate.wait()
        }));
        let creator_runtime = runtime.clone();
        let creation =
            thread::spawn(move || creator_runtime.create_task_with_work(work("first"), None));
        until(&cx, "store callback enters without a service mutex", || {
            gate.entered.load(Ordering::Acquire)
        })
        .await;
        assert_eq!(store.inner.task_count(), 0);
        stop(&cx, &mut old_service, &runtime).await;
        assert!(
            !creation.is_finished(),
            "service teardown completes while the create callback still owns custody"
        );
        let mut replacement = start(&cx, &runtime, supervisor.clone()).await;
        let refusal = runtime
            .create_task_with_work(work("over-capacity"), None)
            .unwrap_err();
        assert!(refusal.message.contains("admission capacity"));
        assert_eq!(
            store.creates.load(Ordering::SeqCst),
            1,
            "old generation retains its pending charge"
        );
        gate.release();
        let accepted = creation
            .join()
            .unwrap()
            .expect("a valid committed Task retains its handle after service exit");
        let first = accepted.task.base().task_id.clone();
        until(&cx, "replacement recovers the committed task", || {
            matches!(
                store.inner.get_task(&first).unwrap(),
                Some(Task::Completed { .. })
            ) && store.inner.active_task_count() == 0
        })
        .await;
        assert_eq!(
            supervisor.0.lock().unwrap().as_slice(),
            &[(first, work("first").as_value().clone())]
        );
        let next = runtime
            .create_task_with_work(work("second"), None)
            .expect("settled create releases its permit");
        let next_id = next.task.base().task_id.clone();
        until(&cx, "a sibling Task remains usable", || {
            matches!(
                store.inner.get_task(&next_id).unwrap(),
                Some(Task::Completed { .. })
            ) && store.inner.active_task_count() == 0
        })
        .await;
        assert_eq!(supervisor.0.lock().unwrap().len(), 2);
        assert_eq!(store.creates.load(Ordering::SeqCst), 2);
        stop(&cx, &mut replacement, &runtime).await;
    });
}

#[test]
fn service_exit_during_precommit_preparation_refuses_without_a_task() {
    run(async {
        let cx = Cx::current().unwrap();
        let config = FinalTaskRuntimeConfig::new(60_000, None)
            .unwrap()
            .with_admission_capacity(1, 1, 1_048_576, 1_048_576)
            .unwrap();
        let (store, runtime, supervisor) = fixture(config);
        let mut old_service = start(&cx, &runtime, supervisor.clone()).await;
        let gate = Arc::new(Gate::default());
        let _release = ReleaseGate(gate.clone());
        let workers = Arc::new(ReentryWorkers::default());
        let hook_runtime = runtime.clone();
        let hook_gate = gate.clone();
        let hook_workers = workers.clone();
        // This differs from the accepted-commit case only at the boundary:
        // provider policy preparation has not entered the create operation.
        *store.before_policy.lock().unwrap() = Some(Box::new(move || {
            check_provider_reentry(hook_runtime, &hook_workers)?;
            hook_gate.wait()
        }));
        let creator_runtime = runtime.clone();
        let creation =
            thread::spawn(move || creator_runtime.create_task_with_work(work("first"), None));
        until(&cx, "policy preparation owns its permit", || {
            gate.entered.load(Ordering::Acquire)
        })
        .await;
        stop(&cx, &mut old_service, &runtime).await;
        assert!(
            !creation.is_finished(),
            "service teardown does not wait for an unstarted commit's preparation"
        );
        let mut replacement = start(&cx, &runtime, supervisor.clone()).await;
        assert!(
            runtime
                .create_task_with_work(work("over-capacity"), None)
                .unwrap_err()
                .message
                .contains("admission capacity")
        );
        assert_eq!(store.creates.load(Ordering::SeqCst), 0);
        gate.release();
        let error = creation
            .join()
            .unwrap()
            .expect_err("the old generation cannot begin a new commit");
        assert!(error.message.contains("generation exited"));
        assert_eq!(store.creates.load(Ordering::SeqCst), 0);
        assert_eq!(store.inner.task_count(), 0);
        assert!(supervisor.0.lock().unwrap().is_empty());
        let next = runtime.create_task_with_work(work("second"), None).unwrap();
        let id = next.task.base().task_id.clone();
        until(&cx, "replacement accepts a fresh creation", || {
            matches!(
                store.inner.get_task(&id).unwrap(),
                Some(Task::Completed { .. })
            ) && store.inner.active_task_count() == 0
        })
        .await;
        assert_eq!(
            supervisor.0.lock().unwrap().as_slice(),
            &[(id, work("second").as_value().clone())]
        );
        assert_eq!(store.creates.load(Ordering::SeqCst), 1);
        stop(&cx, &mut replacement, &runtime).await;
    });
}

#[test]
fn exited_service_refuses_before_store_and_provider_failure_releases_admission() {
    for panic in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let config = FinalTaskRuntimeConfig::new(60_000, None)
                .unwrap()
                .with_admission_capacity(1, 1, 1_048_576, 1_048_576)
                .unwrap();
            let (store, runtime, supervisor) = fixture(config);
            let mut service = start(&cx, &runtime, supervisor.clone()).await;
            stop(&cx, &mut service, &runtime).await;
            assert!(
                runtime
                    .create_task_with_work(work("not-admitted"), None)
                    .is_err()
            );
            assert_eq!(store.creates.load(Ordering::SeqCst), 0);
            assert_eq!(store.inner.task_count(), 0);
            let mut service = start(&cx, &runtime, supervisor.clone()).await;
            *store.before_create.lock().unwrap() = Some(Box::new(move || {
                if panic {
                    panic!("planted provider failure before commit");
                }
                Err(McpError::internal_error(
                    "planted provider refusal before commit",
                ))
            }));
            let creator_runtime = runtime.clone();
            let rejected =
                thread::spawn(move || creator_runtime.create_task_with_work(work("refused"), None))
                    .join();
            if panic {
                assert!(rejected.is_err());
            } else {
                assert!(rejected.unwrap().is_err());
            }
            assert_eq!(store.inner.task_count(), 0);
            let accepted = runtime
                .create_task_with_work(work("after-refusal"), None)
                .unwrap();
            let id = accepted.task.base().task_id.clone();
            until(
                &cx,
                "rejection releases capacity without affecting recovery",
                || {
                    matches!(
                        store.inner.get_task(&id).unwrap(),
                        Some(Task::Completed { .. })
                    ) && store.inner.active_task_count() == 0
                },
            )
            .await;
            assert_eq!(
                supervisor.0.lock().unwrap().as_slice(),
                &[(id, work("after-refusal").as_value().clone())]
            );
            assert_eq!(
                store.creates.load(Ordering::SeqCst),
                2,
                "the failed create is never retried"
            );
            stop(&cx, &mut service, &runtime).await;
        });
    }
}

#[test]
fn pending_creations_share_bounded_encoded_payload_capacity() {
    run(async {
        let cx = Cx::current().unwrap();
        let config = FinalTaskRuntimeConfig::new(60_000, None)
            .unwrap()
            .with_admission_capacity(4, 4, 10_000, 10_000)
            .unwrap();
        let (store, runtime, supervisor) = fixture(config);
        let mut service = start(&cx, &runtime, supervisor).await;
        let gate = Arc::new(Gate::default());
        let _release = ReleaseGate(gate.clone());
        let hook_gate = gate.clone();
        *store.before_create.lock().unwrap() = Some(Box::new(move || hook_gate.wait()));
        let descriptor =
            FinalTaskWorkDescriptor::new(serde_json::json!({"payload":"x".repeat(6_000)})).unwrap();
        let creator_runtime = runtime.clone();
        let first_descriptor = descriptor.clone();
        let creation =
            thread::spawn(move || creator_runtime.create_task_with_work(first_descriptor, None));
        until(&cx, "first payload is charged while provider waits", || {
            gate.entered.load(Ordering::Acquire)
        })
        .await;
        assert!(
            runtime
                .create_task_with_work(descriptor.clone(), None)
                .unwrap_err()
                .message
                .contains("admission capacity")
        );
        assert_eq!(store.creates.load(Ordering::SeqCst), 1);
        gate.release();
        let first = creation
            .join()
            .unwrap()
            .unwrap()
            .task
            .base()
            .task_id
            .clone();
        let second = runtime
            .create_task_with_work(descriptor, None)
            .unwrap()
            .task
            .base()
            .task_id
            .clone();
        until(
            &cx,
            "released bytes permit both distinct tasks to complete",
            || {
                [first.clone(), second.clone()].iter().all(|id| {
                    matches!(
                        store.inner.get_task(id).unwrap(),
                        Some(Task::Completed { .. })
                    )
                }) && store.inner.active_task_count() == 0
            },
        )
        .await;
        assert_ne!(first, second);
        assert_eq!(store.creates.load(Ordering::SeqCst), 2);
        stop(&cx, &mut service, &runtime).await;
    });
}
