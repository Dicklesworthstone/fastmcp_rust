//! Real-file tests of the production restart acknowledgement state machine.
//! Task outcomes are explicit fixtures, NOT live authentication evidence. The
//! reference vault is not encryption or restart-capable key-custody qualification.

use super::*;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::future::{Future, poll_fn};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_core::runtime::ProcessGenerationGuard;
use fastmcp_protocol::tasks_extension::Task;
use serde_json::json;
use crate::http_auth::managed::tasks::watch::checkpoint::ManagedTaskWatchCheckpoint;
use crate::http_auth::managed::tasks::watch::checkpoint::resume::TaskResumeRecord;
use crate::http_auth::managed::tasks::watch::checkpoint::resume::client::TaskResumeReconciliation;
use crate::http_auth::managed::tasks::watch::checkpoint::resume::client::restart::TaskResumeRestartOutcome;
use crate::http_auth::managed::tasks::watch::checkpoint::resume::store::{
    TaskResumeStoreError, TaskResumeStoreLimits,
};
use crate::http_auth::secure_file::slot::coordinator::asynchronous::{
    CredentialIoError, CredentialIoLane, CredentialIoLimits,
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fastmcp-restart-commit-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("owned restart fixture directory: {error}"),
            }
        }
        panic!("restart fixture directory attempts exhausted");
    }
    fn bytes(&self) -> Vec<u8> {
        fs::read(self.0.join("tasks")).unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("tasks"));
        let _ = fs::remove_file(self.0.join(".tasks.lock"));
        let _ = fs::remove_dir(&self.0);
    }
}

#[derive(Default)]
struct Gate {
    entered: AtomicBool,
    released: Mutex<bool>,
    condition: Condvar,
}
impl Gate {
    fn block(&self) {
        self.entered.store(true, Ordering::Release);
        let held = self.released.lock().unwrap();
        let (held, _) = self.condition
            .wait_timeout_while(held, Duration::from_secs(5), |released| !*released)
            .unwrap();
        assert!(*held, "bounded restart fixture provider was not released");
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }
    async fn wait_entered(&self, cx: &Cx) {
        asupersync::time::timeout(cx.now(), Duration::from_secs(2), async {
            while !self.entered.load(Ordering::Acquire) {
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
        }).await.expect("fixture worker must enter without blocking the poller");
    }
}
struct Release(Arc<Gate>);
impl Drop for Release {
    fn drop(&mut self) { self.0.release(); }
}

type VaultRecords = BTreeMap<Vec<u8>, ([u8; 32], Vec<u8>)>;
#[derive(Clone, Default)]
struct Vault {
    records: Arc<Mutex<VaultRecords>>,
    seals: Arc<AtomicUsize>,
    fail: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
    gate: Arc<Gate>,
}
impl TaskResumeProtector for Vault {
    fn profile(&self) -> [u8; 32] { [4; 32] }
    fn seal(
        &mut self, _: &Cx, binding: &[u8; 32], plaintext: &[u8], maximum: usize,
    ) -> Result<Vec<u8>, TaskResumeError> {
        let serial = self.seals.fetch_add(1, Ordering::SeqCst);
        if self.pause.load(Ordering::SeqCst) { self.gate.block(); }
        if self.fail.load(Ordering::SeqCst) || plaintext.len() > 65536 || maximum < 8 {
            return Err(TaskResumeError::Protection);
        }
        let token = (serial as u64).to_be_bytes().to_vec();
        let mut records = self.records.lock().unwrap();
        if records.len() >= 16 { return Err(TaskResumeError::Capacity); }
        records.insert(token.clone(), (*binding, plaintext.to_vec()));
        Ok(token)
    }
    fn open(
        &mut self, _: &Cx, binding: &[u8; 32], ciphertext: &[u8], maximum: usize,
    ) -> Result<Vec<u8>, TaskResumeError> {
        let records = self.records.lock().unwrap();
        let (saved, plaintext) = records.get(ciphertext).ok_or(TaskResumeError::Protection)?;
        if saved != binding || plaintext.len() > maximum {
            return Err(TaskResumeError::Protection);
        }
        Ok(plaintext.clone())
    }
}

fn binding() -> TaskResumeBinding {
    TaskResumeBinding::derive(
        CanonicalHttpUrl::parse("https://service.example/mcp").unwrap(),
        "restart-fixture", &[1; 32], [2; 32], [3; 32], [4; 32],
    ).unwrap()
}
fn task(completed: bool, second: u8) -> Task {
    let mut value = json!({
        "taskId":"saved-task", "status":"working", "ttlMs":null,
        "createdAt":"2020-01-01T00:00:00Z",
        "lastUpdatedAt":format!("2020-01-01T00:00:{second:02}Z"),
    });
    if completed {
        value["status"] = json!("completed");
        value["result"] = json!({"content":[{"type":"text","text":"PRIVATE-PAYLOAD"}]});
    }
    serde_json::from_value(value).unwrap()
}
fn terminal(previous: TaskResumeRecord) -> TaskResumeRestartItem {
    TaskResumeRestartItem {
        previous,
        outcome: TaskResumeRestartOutcome::Reconciled(
            TaskResumeReconciliation::Terminal(Box::new(task(true, 2))),
        ),
    }
}
fn assert_terminal(item: &TaskResumeRestartItem) {
    let TaskResumeRestartOutcome::Reconciled(TaskResumeReconciliation::Terminal(task)) = &item.outcome else {
        panic!("the original terminal result must remain in custody");
    };
    assert_eq!(serde_json::to_value(task).unwrap()["result"]["content"][0]["text"], "PRIVATE-PAYLOAD");
}
fn run<F, Fut>(test: F)
where F: FnOnce(Cx) -> Fut, Fut: Future<Output = ()> {
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .blocking_threads(1, 1).build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(10), test(cx))
            .await.expect("restart acknowledgement test exceeded its bound");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
}
async fn populated(
    cx: &Cx, lane: &CredentialIoLane, directory: &Directory, vault: Vault,
) -> (AsyncTaskResumeStore<Vault>, TaskResumeRecord) {
    let current = binding();
    let saved = TaskResumeRecord::capture(cx, &current, &task(false, 1), Duration::from_secs(3600)).unwrap();
    let process = ProcessGenerationGuard::install().unwrap().token();
    let store = AsyncTaskResumeStore::open(
        cx, lane, process, File::open(&directory.0).unwrap(), "tasks".to_owned(),
        65536, vault, current.clone(), TaskResumeStoreLimits::new(8, 65536).unwrap(),
    ).unwrap().wait(cx).await.unwrap().unwrap();
    let (store, result) = store.try_insert(cx, current, saved.clone()).unwrap()
        .wait(cx).await.unwrap().into_parts();
    result.unwrap();
    (store, saved)
}
async fn close(cx: &Cx, lane: &CredentialIoLane, commit: RestartCommit<Vault>) {
    let store = commit.storage.take_store().unwrap();
    store.close(cx).unwrap().wait(cx).await.unwrap();
    lane.begin_shutdown().unwrap();
    lane.wait_drained(cx, Duration::from_secs(2)).await.unwrap();
}

#[test]
fn terminal_result_is_retained_until_explicit_durable_acknowledgement() {
    run(|cx| async move {
        let guard = ProcessGenerationGuard::install().unwrap();
        let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
        let directory = Directory::new();
        let vault = Vault::default();
        let (store, saved) = populated(&cx, &lane, &directory, vault.clone()).await;
        let before = directory.bytes();
        let mut commit = RestartCommit::new(store, binding());
        commit.pending = Some(terminal(saved.clone()));
        drop(commit.acknowledge(&cx));
        assert_eq!(commit.state, RestartCheckpointState::NotAttempted);
        assert_terminal(commit.pending.as_ref().unwrap());
        assert_eq!(directory.bytes(), before, "unpolled acknowledgement has no storage effect");
        let item = commit.acknowledge(&cx).await.unwrap();
        assert_terminal(&item);
        assert!(commit.pending.is_none());
        assert!(commit.change.is_none());
        assert_eq!(vault.seals.load(Ordering::SeqCst), 2);
        assert!(matches!(commit.acknowledge(&cx).await, Err(PersistedTaskRestartError::NoPending)));
        for (_, plaintext) in vault.records.lock().unwrap().values() {
            assert!(!plaintext.windows(15).any(|window| window == b"PRIVATE-PAYLOAD"));
        }
        let store = commit.storage.take_store().unwrap();
        let (store, record) = store.try_get(&cx, binding(), saved.key()).unwrap()
            .wait(&cx).await.unwrap().into_parts();
        assert!(record.unwrap().is_none());
        store.close(&cx).unwrap().wait(&cx).await.unwrap();
        lane.begin_shutdown().unwrap();
        lane.wait_drained(&cx, Duration::from_secs(2)).await.unwrap();
    });
}

#[test]
fn active_controls_are_saved_and_stale_cleanup_cannot_replace_them() {
    run(|cx| async move {
        let guard = ProcessGenerationGuard::install().unwrap();
        let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
        let directory = Directory::new();
        let vault = Vault::default();
        let (store, saved) = populated(&cx, &lane, &directory, vault.clone()).await;
        let current = binding();
        let fresh = task(false, 2);
        let changed = TaskResumeChange::from_snapshot(&cx, &current, &saved, &fresh).unwrap();
        let replacement = changed.replacement().unwrap().clone();
        let selection = ManagedTaskWatchCheckpoint::new(current.resource(), vec![saved.task_id().clone()]).unwrap();
        let mut commit = RestartCommit::new(store, current.clone());
        commit.pending = Some(TaskResumeRestartItem {
            previous: saved.clone(),
            outcome: TaskResumeRestartOutcome::Reconciled(TaskResumeReconciliation::Active {
                task: Box::new(fresh), record: replacement.clone(), selection,
            }),
        });
        commit.acknowledge(&cx).await.unwrap();
        let updated = directory.bytes();
        commit.pending = Some(TaskResumeRestartItem { previous: saved.clone(), outcome: TaskResumeRestartOutcome::Unavailable });
        assert!(matches!(commit.acknowledge(&cx).await,
            Err(PersistedTaskRestartError::Persistence(TaskResumePersistenceError::Store(
                TaskResumeStoreError::Resume(TaskResumeError::ConflictingSnapshot)
            )))
        ));
        assert_eq!(commit.state, RestartCheckpointState::Failed);
        assert!(commit.pending.is_some());
        assert!(commit.change.is_some());
        assert!(matches!(commit.acknowledge(&cx).await, Err(PersistedTaskRestartError::PersistenceFailed)));
        assert_eq!(directory.bytes(), updated);
        assert_eq!(vault.seals.load(Ordering::SeqCst), 2);
        let store = commit.storage.take_store().unwrap();
        let (store, loaded) = store.try_get(&cx, current, saved.key()).unwrap()
            .wait(&cx).await.unwrap().into_parts();
        assert_eq!(loaded.unwrap(), Some(replacement));
        store.close(&cx).unwrap().wait(&cx).await.unwrap();
        lane.begin_shutdown().unwrap();
        lane.wait_drained(&cx, Duration::from_secs(2)).await.unwrap();
    });
}

#[test]
fn abandoned_acknowledgement_resumes_one_write_and_keeps_its_result() {
    run(|cx| async move {
        let guard = ProcessGenerationGuard::install().unwrap();
        let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
        let directory = Directory::new();
        let vault = Vault::default();
        let _release = Release(Arc::clone(&vault.gate));
        let (store, saved) = populated(&cx, &lane, &directory, vault.clone()).await;
        let before = directory.bytes();
        let mut commit = RestartCommit::new(store, binding());
        commit.pending = Some(terminal(saved));
        vault.pause.store(true, Ordering::SeqCst);
        let mut waiting = Box::pin(commit.acknowledge(&cx));
        poll_fn(|task| {
            assert!(waiting.as_mut().poll(task).is_pending());
            Poll::Ready(())
        }).await;
        vault.gate.wait_entered(&cx).await;
        drop(waiting);
        assert_eq!(commit.state, RestartCheckpointState::Pending);
        assert_terminal(commit.pending.as_ref().unwrap());
        assert_eq!(directory.bytes(), before);
        assert!(matches!(commit.take_without_persisting(), Err(PersistedTaskRestartError::AcknowledgementRequired)));
        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        assert!(matches!(commit.acknowledge(&cancelled).await,
            Err(PersistedTaskRestartError::Persistence(TaskResumePersistenceError::Io(CredentialIoError::WaitCancelled)))
        ));
        assert_eq!(commit.state, RestartCheckpointState::Pending);
        assert_eq!(lane.snapshot().unwrap().operations, 1);
        assert_eq!(vault.seals.load(Ordering::SeqCst), 2, "the same write is observed, never replayed");
        vault.gate.release();
        assert_terminal(&commit.acknowledge(&cx).await.unwrap());
        assert_eq!(vault.seals.load(Ordering::SeqCst), 2);
        assert!(commit.pending.is_none());
        close(&cx, &lane, commit).await;
    });
}

#[test]
fn failed_protection_retains_terminal_result_and_original_checkpoint() {
    run(|cx| async move {
        let guard = ProcessGenerationGuard::install().unwrap();
        let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
        let directory = Directory::new();
        let vault = Vault::default();
        let (store, saved) = populated(&cx, &lane, &directory, vault.clone()).await;
        let before = directory.bytes();
        let mut commit = RestartCommit::new(store, binding());
        commit.pending = Some(terminal(saved));
        vault.fail.store(true, Ordering::SeqCst);
        assert!(matches!(commit.acknowledge(&cx).await,
            Err(PersistedTaskRestartError::Persistence(TaskResumePersistenceError::Store(
                TaskResumeStoreError::Resume(TaskResumeError::Protection)
            )))
        ));
        assert_terminal(commit.pending.as_ref().unwrap());
        assert_eq!(commit.state, RestartCheckpointState::Failed);
        assert_eq!(directory.bytes(), before);
        assert!(matches!(commit.acknowledge(&cx).await, Err(PersistedTaskRestartError::PersistenceFailed)));
        assert_eq!(vault.seals.load(Ordering::SeqCst), 2);
        close(&cx, &lane, commit).await;
    });
}

#[test]
fn explicit_keep_disposition_leaves_unavailable_checkpoint_untouched() {
    run(|cx| async move {
        let guard = ProcessGenerationGuard::install().unwrap();
        let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
        let directory = Directory::new();
        let vault = Vault::default();
        let (store, saved) = populated(&cx, &lane, &directory, vault.clone()).await;
        let before = directory.bytes();
        let mut commit = RestartCommit::new(store, binding());
        commit.pending = Some(TaskResumeRestartItem { previous: saved.clone(), outcome: TaskResumeRestartOutcome::Unavailable });
        let kept = commit.take_without_persisting().unwrap();
        assert_eq!(kept.previous, saved);
        assert!(matches!(kept.outcome, TaskResumeRestartOutcome::Unavailable));
        assert_eq!(directory.bytes(), before);
        assert_eq!(vault.seals.load(Ordering::SeqCst), 1);
        assert!(commit.pending.is_none());
        assert!(commit.change.is_none());
        close(&cx, &lane, commit).await;
    });
}
