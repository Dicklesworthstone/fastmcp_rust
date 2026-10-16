//! Real file/callback ownership tests. The parent vault is a reference fixture,
//! not an encryption or process-restart key-custody implementation.

use super::*;
use std::future::poll_fn;
use std::sync::{Condvar, atomic::AtomicBool};
use std::task::Poll;

use super::super::persistence::{
    TaskResumePersistence, TaskResumePersistenceError, TaskResumePersistenceStatus,
};
use super::super::super::super::client::creation::{TaskResumeCapturePolicy, TaskResumeInsert};
use super::super::super::super::client::lifecycle::TaskResumeChange;

fn task(id: &str, updated: u8) -> Task {
    serde_json::from_value(json!({
        "taskId":id, "status":"working", "createdAt":"2020-01-01T00:00:00Z",
        "lastUpdatedAt":format!("2020-01-01T00:00:{updated:02}Z"), "ttlMs":null,
    })).unwrap()
}

fn insert(cx: &Cx, current: &TaskResumeBinding, id: &str) -> TaskResumeInsert {
    TaskResumeInsert::capture(
        cx, current, &task(id, 1), TaskResumeCapturePolicy::new(Duration::from_secs(3600)).unwrap(),
    ).unwrap()
}

#[test]
fn callbacks_acknowledge_insert_and_conditional_change_but_refuse_stale_cleanup() {
    run(|cx| async move {
        let guard = ProcessGenerationGuard::install().unwrap();
        let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
        let directory = Directory::new();
        let vault = Vault::default();
        let current = binding("one");
        let initial = insert(&cx, &current, "callback-task");
        let saved = initial.record().clone();
        let store = open(&cx, &lane, &directory, vault.clone(), current.clone()).await;
        let writer = TaskResumePersistence::new(store, current.clone());
        let retained = writer.clone();
        let mut capture = writer.insert_callback(cx.clone());
        let mut persist = writer.change_callback(cx.clone());
        capture(initial.clone()).await.unwrap();
        assert_eq!(vault.calls.load(Ordering::SeqCst), 1);
        assert_eq!(writer.status().unwrap(), TaskResumePersistenceStatus::Ready);
        assert!(matches!(capture(initial).await,
            Err(TaskResumePersistenceError::Store(TaskResumeStoreError::Resume(TaskResumeError::ConflictingSnapshot)))
        ));
        assert_eq!(vault.calls.load(Ordering::SeqCst), 1, "insert is never silently upgraded to put");
        let change = TaskResumeChange::from_snapshot(&cx, &current, &saved, &task("callback-task", 2)).unwrap();
        let replacement = change.replacement().unwrap().clone();
        persist(change).await.unwrap();
        let committed = fs::read(directory.0.join("tasks")).unwrap();
        assert_eq!(vault.calls.load(Ordering::SeqCst), 2);
        let stale = TaskResumeChange::discard(&cx, &current, &saved).unwrap();
        assert!(matches!(persist(stale).await,
            Err(TaskResumePersistenceError::Store(TaskResumeStoreError::Resume(TaskResumeError::ConflictingSnapshot)))
        ));
        assert_eq!(vault.calls.load(Ordering::SeqCst), 2);
        assert_eq!(fs::read(directory.0.join("tasks")).unwrap(), committed);
        persist(TaskResumeChange::discard(&cx, &current, &replacement).unwrap()).await.unwrap();
        let store = retained.take_store().unwrap();
        assert_eq!(writer.status().unwrap(), TaskResumePersistenceStatus::Closed);
        assert!(matches!(persist(TaskResumeChange::discard(&cx, &current, &replacement).unwrap()).await,
            Err(TaskResumePersistenceError::Closed)
        ));
        let (store, loaded) = store.try_get(&cx, current, saved.key()).unwrap()
            .wait(&cx).await.unwrap().into_parts();
        assert!(loaded.unwrap().is_none());
        store.close(&cx).unwrap().wait(&cx).await.unwrap();
        lane.begin_shutdown().unwrap();
        lane.wait_drained(&cx, Duration::from_secs(2)).await.unwrap();
    });
}

#[derive(Default)]
struct Gate {
    entered: AtomicUsize,
    released: Mutex<bool>,
    condition: Condvar,
}
impl Gate {
    fn block(&self) {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let held = self.released.lock().unwrap();
        let (held, _) = self.condition.wait_timeout_while(
            held, Duration::from_secs(5), |released| !*released,
        ).unwrap();
        assert!(*held, "bounded fixture provider was not released");
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }
    async fn wait_entered(&self, cx: &Cx) {
        asupersync::time::timeout(cx.now(), Duration::from_secs(2), async {
            while self.entered.load(Ordering::SeqCst) == 0 {
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
        }).await.expect("provider must enter without blocking the async poller");
    }
}
struct Release(Arc<Gate>);
impl Drop for Release {
    fn drop(&mut self) { self.0.release(); }
}

#[derive(Clone)]
struct ControlledVault {
    vault: Vault,
    gate: Option<Arc<Gate>>,
    fail: Arc<AtomicBool>,
}
impl TaskResumeProtector for ControlledVault {
    fn profile(&self) -> [u8; 32] { self.vault.profile() }
    fn seal(&mut self, cx: &Cx, binding: &[u8; 32], bytes: &[u8], maximum: usize) -> Result<Vec<u8>, TaskResumeError> {
        if let Some(gate) = &self.gate { gate.block(); }
        if self.fail.load(Ordering::SeqCst) { return Err(TaskResumeError::Protection); }
        self.vault.seal(cx, binding, bytes, maximum)
    }
    fn open(&mut self, cx: &Cx, binding: &[u8; 32], bytes: &[u8], maximum: usize) -> Result<Vec<u8>, TaskResumeError> {
        self.vault.open(cx, binding, bytes, maximum)
    }
}

async fn controlled_store(
    cx: &Cx, lane: &CredentialIoLane, directory: &Directory,
    vault: ControlledVault, current: TaskResumeBinding,
) -> AsyncTaskResumeStore<ControlledVault> {
    let process = ProcessGenerationGuard::install().unwrap().token();
    AsyncTaskResumeStore::open(
        cx, lane, process, directory.handle(), "tasks".to_owned(), 65536,
        vault, current, TaskResumeStoreLimits::new(8, 65536).unwrap(),
    ).unwrap().wait(cx).await.unwrap().unwrap()
}

#[test]
fn abandoned_callback_and_cancelled_observer_retain_one_unreplayed_write() {
    run(|cx| async move {
        let guard = ProcessGenerationGuard::install().unwrap();
        let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
        let directory = Directory::new();
        let vault = Vault::default();
        let gate = Arc::new(Gate::default());
        let _release_on_failure = Release(Arc::clone(&gate));
        let current = binding("one");
        let initial = insert(&cx, &current, "pending-task");
        let saved = initial.record().clone();
        let store = controlled_store(&cx, &lane, &directory, ControlledVault {
            vault: vault.clone(), gate: Some(Arc::clone(&gate)), fail: Arc::new(AtomicBool::new(false)),
        }, current.clone()).await;
        let writer = TaskResumePersistence::new(store, current.clone());
        let mut callback = writer.insert_callback(cx.clone());
        let mut pending = callback(initial.clone());
        poll_fn(|task| {
            assert!(pending.as_mut().poll(task).is_pending());
            Poll::Ready(())
        }).await;
        gate.wait_entered(&cx).await;
        assert!(matches!(writer.status(), Err(TaskResumePersistenceError::Busy)));
        drop(pending);
        assert_eq!(writer.status().unwrap(), TaskResumePersistenceStatus::Pending);
        let charged = lane.snapshot().unwrap();
        assert_eq!(charged.operations, 1);
        assert!(charged.reserved_bytes > 0);
        assert!(matches!(callback(initial).await, Err(TaskResumePersistenceError::OperationPending)));
        assert!(matches!(writer.clone().close(&cx).await, Err(TaskResumePersistenceError::OperationPending)));
        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        assert!(matches!(writer.finish_pending(&cancelled).await,
            Err(TaskResumePersistenceError::Io(CredentialIoError::WaitCancelled))
        ));
        assert_eq!(writer.status().unwrap(), TaskResumePersistenceStatus::Pending);
        assert_eq!(gate.entered.load(Ordering::SeqCst), 1);
        assert!(!directory.0.join("tasks").exists());
        gate.release();
        writer.finish_pending(&cx).await.unwrap();
        assert_eq!(gate.entered.load(Ordering::SeqCst), 1);
        assert_eq!(vault.calls.load(Ordering::SeqCst), 1);
        assert_eq!(writer.status().unwrap(), TaskResumePersistenceStatus::Ready);
        let store = writer.take_store().unwrap();
        let (store, loaded) = store.try_get(&cx, current, saved.key()).unwrap()
            .wait(&cx).await.unwrap().into_parts();
        assert_eq!(loaded.unwrap().as_ref(), Some(&saved));
        store.close(&cx).unwrap().wait(&cx).await.unwrap();
        lane.begin_shutdown().unwrap();
        lane.wait_drained(&cx, Duration::from_secs(2)).await.unwrap();
        assert!(!cx.is_cancel_requested());
    });
}

#[test]
fn protection_failure_returns_the_owner_and_preserves_the_prior_checkpoint() {
    run(|cx| async move {
        let guard = ProcessGenerationGuard::install().unwrap();
        let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
        let directory = Directory::new();
        let vault = Vault::default();
        let fail = Arc::new(AtomicBool::new(false));
        let current = binding("one");
        let initial = insert(&cx, &current, "protected-task");
        let saved = initial.record().clone();
        let store = controlled_store(&cx, &lane, &directory, ControlledVault {
            vault: vault.clone(), gate: None, fail: Arc::clone(&fail),
        }, current.clone()).await;
        let writer = TaskResumePersistence::new(store, current.clone());
        writer.persist_insert(&cx, initial).await.unwrap();
        let before = fs::read(directory.0.join("tasks")).unwrap();
        let change = TaskResumeChange::from_snapshot(&cx, &current, &saved, &task("protected-task", 2)).unwrap();
        fail.store(true, Ordering::SeqCst);
        assert!(matches!(writer.persist_change(&cx, change).await,
            Err(TaskResumePersistenceError::Store(TaskResumeStoreError::Resume(TaskResumeError::Protection)))
        ));
        assert_eq!(writer.status().unwrap(), TaskResumePersistenceStatus::Ready);
        assert_eq!(fs::read(directory.0.join("tasks")).unwrap(), before);
        let store = writer.take_store().unwrap();
        let (store, loaded) = store.try_get(&cx, current, saved.key()).unwrap()
            .wait(&cx).await.unwrap().into_parts();
        assert_eq!(loaded.unwrap().as_ref(), Some(&saved));
        store.close(&cx).unwrap().wait(&cx).await.unwrap();
        lane.begin_shutdown().unwrap();
        lane.wait_drained(&cx, Duration::from_secs(2)).await.unwrap();
    });
}

#[test]
fn asynchronous_page_cursors_survive_reads_but_not_a_committed_mutation() {
    run(|cx| async move {
        let guard = ProcessGenerationGuard::install().unwrap();
        let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
        let directory = Directory::new();
        let vault = Vault::default();
        let current = binding("one");
        let one = record(&cx, &current, "one");
        let two = record(&cx, &current, "two");
        let store = open(&cx, &lane, &directory, vault.clone(), current.clone()).await;
        let (store, result) = store.try_insert(&cx, current.clone(), one.clone()).unwrap()
            .wait(&cx).await.unwrap().into_parts();
        result.unwrap();
        let (store, result) = store.try_insert(&cx, current.clone(), two).unwrap()
            .wait(&cx).await.unwrap().into_parts();
        result.unwrap();
        let (store, page) = store.try_page(&cx, current.clone(), None, 1).unwrap()
            .wait(&cx).await.unwrap().into_parts();
        let page = page.unwrap();
        assert_eq!(page.keys.len(), 1);
        let cursor = page.next.unwrap();
        let (store, result) = store.try_get(&cx, current.clone(), one.key()).unwrap()
            .wait(&cx).await.unwrap().into_parts();
        assert!(result.unwrap().is_some());
        let (store, page) = store.try_page(&cx, current.clone(), Some(cursor.clone()), 1).unwrap()
            .wait(&cx).await.unwrap().into_parts();
        let page = page.unwrap();
        assert_eq!(page.keys.len(), 1);
        assert!(page.next.is_none());
        let (store, result) = store.try_put(&cx, current.clone(), one).unwrap()
            .wait(&cx).await.unwrap().into_parts();
        result.unwrap();
        let version = store.revision();
        let (store, stale) = store.try_page(&cx, current.clone(), Some(cursor), 1).unwrap()
            .wait(&cx).await.unwrap().into_parts();
        assert!(matches!(stale, Err(TaskResumeStoreError::Resume(TaskResumeError::StaleCursor))));
        assert_eq!(store.revision(), version);
        let (store, result) = store.try_prune_expired(&cx, current.clone()).unwrap()
            .wait(&cx).await.unwrap().into_parts();
        assert_eq!(result.unwrap(), 0);
        let (store, result) = store.try_reconcile(&cx, current).unwrap()
            .wait(&cx).await.unwrap().into_parts();
        result.unwrap();
        assert_eq!(store.revision(), version);
        store.close(&cx).unwrap().wait(&cx).await.unwrap();
        lane.begin_shutdown().unwrap();
        lane.wait_drained(&cx, Duration::from_secs(2)).await.unwrap();
    });
}
