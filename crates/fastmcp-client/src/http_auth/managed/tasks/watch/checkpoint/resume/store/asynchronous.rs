//! Caller-owned asynchronous access to protected Task checkpoints.
//!
//! The whole store, file lock and protection provider move into one bounded
//! credential-I/O job. Waiting never submits another transaction. Keep the
//! returned task after an interrupted wait to recover the SAME owner and
//! disposition; cancellation is not a rollback receipt.

/// Persistence callbacks retaining Task creation and watch write custody.
pub mod persistence;
/// Complete asynchronous staging for freshly authorized restart recovery.
pub mod restart;

use std::fmt;
use std::fs::File;

use asupersync::Cx;
use fastmcp_core::runtime::ProcessBoundToken;

use super::{
    MAX_BYTES, TaskResumeCursor, TaskResumePage, TaskResumeProtector, TaskResumeStore,
    TaskResumeStoreError, TaskResumeStoreLimits,
};
use super::super::{
    MAX_TASK_RESUME_RECORD_BYTES, TaskResumeBinding, TaskResumeKey, TaskResumeRecord,
};
use crate::http_auth::secure_file::{AtomicFileVersion, SecureAtomicFile};
use crate::http_auth::secure_file::slot::coordinator::asynchronous::{
    CredentialIoError, CredentialIoLane, CredentialSlotTask, composed::ComposedCredentialIo,
};

/// Failed scheduling, separate from a completed storage transaction's result.
/// Retained custody means no worker was scheduled. A runtime scheduling failure
/// can consume its closure; None then requires reopening and reconciliation,
/// not reconstructing an input or assuming a transaction was rolled back.
pub struct TaskResumeSubmissionFailure<P, I> {
    cause: CredentialIoError,
    retained: Option<Box<(AsyncTaskResumeStore<P>, TaskResumeBinding, I)>>,
}

impl<P, I> TaskResumeSubmissionFailure<P, I> {
    pub fn cause(&self) -> CredentialIoError {
        self.cause
    }

    pub fn into_parts(
        self,
    ) -> (
        CredentialIoError,
        Option<(AsyncTaskResumeStore<P>, TaskResumeBinding, I)>,
    ) {
        (self.cause, self.retained.map(|retained| *retained))
    }
}

impl<P, I> fmt::Debug for TaskResumeSubmissionFailure<P, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskResumeSubmissionFailure")
            .field("cause", &self.cause)
            .field("ownership_retained", &self.retained.is_some())
            .finish()
    }
}

impl<P, I> fmt::Display for TaskResumeSubmissionFailure<P, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(f)
    }
}

impl<P, I> std::error::Error for TaskResumeSubmissionFailure<P, I> {}

/// The same exclusive owner and the transaction's exact storage outcome.
/// Even a protection or uncertain-commit error returns the owner, preserving
/// quarantine. This completion implements neither Debug, Clone nor serialization.
pub struct TaskResumeCompletion<P, T> {
    owner: AsyncTaskResumeStore<P>,
    outcome: Result<T, TaskResumeStoreError>,
}

impl<P, T> TaskResumeCompletion<P, T> {
    pub fn into_parts(self) -> (AsyncTaskResumeStore<P>, Result<T, TaskResumeStoreError>) {
        (self.owner, self.outcome)
    }
}

/// Exclusive asynchronous owner of the existing protected Linux file store.
///
/// All protection, file loading, synchronized mutation and reconciliation run
/// in the host's blocking pool, never in the async poller. The host supplies
/// one shared CredentialIoLane; cloning that lane does not create capacity.
/// Slots, queued/running jobs and unread completions share its admission and
/// shutdown domain with credential stores. No runtime or worker is detached.
///
/// Each operation consumes this owner. Retrieve it from the returned task's
/// completion before another operation. A failed wait leaves that task usable;
/// a failed transaction returns its owner without hiding uncertain writes.
/// Pre-scheduling refusals retain the exact owner, binding and command input.
///
/// This adapter adds neither encryption keys nor a rollback anchor. The host's
/// restart-capable protector remains mandatory. Provider memory and destructors
/// are provider-owned; destructors must not block. Explicit close runs on the
/// reserved cleanup lane, including after ordinary admission shuts down.
/// Drop and failed scheduling can still destroy an owner synchronously.
/// Checkpoints remain lookup hints, never permission to replay remote work.
pub struct AsyncTaskResumeStore<P> {
    // Release provider/file custody before returning the lane's slot charge.
    store: TaskResumeStore<P>,
    io: ComposedCredentialIo,
}

impl<P> fmt::Debug for AsyncTaskResumeStore<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncTaskResumeStore")
            .field("requires_recovery", &self.store.uncertain.is_some())
            .finish_non_exhaustive()
    }
}

// Conservative framework-buffer reservation: old/staged/decoded manifests,
// encoded plaintext, captured/returned records, BTree node/control overhead and
// bounded binding/cursor copies. Atomic-file buffers are charged separately by
// ComposedCredentialIo. Provider-internal memory is not a framework guarantee.
fn extra_work_bytes(limits: TaskResumeStoreLimits) -> Result<usize, CredentialIoError> {
    limits.plaintext_bytes.checked_mul(4)
        .and_then(|bytes| bytes.checked_add(
            limits.records.checked_mul(
                4 * (std::mem::size_of::<TaskResumeRecord>() + 128),
            )?,
        ))
        .and_then(|bytes| bytes.checked_add(3 * MAX_TASK_RESUME_RECORD_BYTES + 32 * 1024))
        .ok_or(CredentialIoError::InvalidLimits)
}

impl<P: TaskResumeProtector + 'static> AsyncTaskResumeStore<P> {
    /// Opens and authenticates one manifest in a single admitted worker.
    /// Directory authority comes from the already-open host handle. No path,
    /// protector method or file is consulted during local admission. An open
    /// failure returns no usable store; it never enables plaintext fallback.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        cx: &Cx,
        lane: &CredentialIoLane,
        process: ProcessBoundToken,
        directory: File,
        leaf: String,
        maximum_file_bytes: usize,
        protector: P,
        binding: TaskResumeBinding,
        limits: TaskResumeStoreLimits,
    ) -> Result<CredentialSlotTask<Result<Self, TaskResumeStoreError>>, CredentialIoError> {
        if leaf.is_empty()
            || leaf.len() > 96
            || matches!(leaf.as_str(), "." | "..")
            || leaf.bytes().any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'\\'))
            || !(64..=MAX_BYTES).contains(&maximum_file_bytes)
        {
            return Err(CredentialIoError::InvalidSlotConfiguration);
        }
        process.verify().map_err(|_| CredentialIoError::ProcessChanged)?;
        let io = ComposedCredentialIo::reserve(
            cx, lane, maximum_file_bytes, extra_work_bytes(limits)?,
        )?;
        let leaf = leaf.into_boxed_str();
        io.submit(cx, move |worker, io| {
            let file = SecureAtomicFile::open(worker, directory, &leaf, maximum_file_bytes)?;
            let store = TaskResumeStore::open(worker, process, file, protector, binding, limits)?;
            Ok(Self { store, io })
        })
    }

    /// Introspection only; neither value authorizes a storage or remote effect.
    pub fn revision(&self) -> Option<AtomicFileVersion> {
        self.store.revision
    }

    pub fn requires_recovery(&self) -> bool {
        self.store.uncertain.is_some()
    }

    pub fn try_get(
        self,
        cx: &Cx,
        current: TaskResumeBinding,
        key: TaskResumeKey,
    ) -> Result<
        CredentialSlotTask<TaskResumeCompletion<P, Option<TaskResumeRecord>>>,
        TaskResumeSubmissionFailure<P, TaskResumeKey>,
    > {
        self.try_operate(cx, current, key, |store, worker, current, key| {
            store.get(worker, current, key)
        })
    }

    /// Insert-only custody for a newly accepted Task; never an upsert or retry.
    pub fn try_insert(
        self,
        cx: &Cx,
        current: TaskResumeBinding,
        record: TaskResumeRecord,
    ) -> Result<
        CredentialSlotTask<TaskResumeCompletion<P, TaskResumeKey>>,
        TaskResumeSubmissionFailure<P, TaskResumeRecord>,
    > {
        self.try_operate(cx, current, record, |store, worker, current, record| {
            store.insert(worker, current, record)
        })
    }

    /// Retains the synchronous store's monotonic controls and retention rules.
    pub fn try_put(
        self,
        cx: &Cx,
        current: TaskResumeBinding,
        record: TaskResumeRecord,
    ) -> Result<
        CredentialSlotTask<TaskResumeCompletion<P, TaskResumeKey>>,
        TaskResumeSubmissionFailure<P, TaskResumeRecord>,
    > {
        self.try_operate(cx, current, record, |store, worker, current, record| {
            store.put(worker, current, record)
        })
    }

    /// Compare and remove the exact physical version, including an expired
    /// record. No unconditional delete-by-ID escape is exposed by this adapter.
    pub fn try_remove_expected(
        self,
        cx: &Cx,
        current: TaskResumeBinding,
        expected: TaskResumeRecord,
    ) -> Result<
        CredentialSlotTask<TaskResumeCompletion<P, ()>>,
        TaskResumeSubmissionFailure<P, TaskResumeRecord>,
    > {
        self.try_operate(cx, current, expected, |store, worker, current, expected| {
            store.remove_expected(worker, current, &expected)
        })
    }

    pub fn try_page(
        self,
        cx: &Cx,
        current: TaskResumeBinding,
        cursor: Option<TaskResumeCursor>,
        limit: usize,
    ) -> Result<
        CredentialSlotTask<TaskResumeCompletion<P, TaskResumePage>>,
        TaskResumeSubmissionFailure<P, (Option<TaskResumeCursor>, usize)>,
    > {
        self.try_operate(cx, current, (cursor, limit), |store, worker, current, (cursor, limit)| {
            store.page(worker, current, cursor.as_ref(), limit)
        })
    }

    pub fn try_prune_expired(
        self,
        cx: &Cx,
        current: TaskResumeBinding,
    ) -> Result<CredentialSlotTask<TaskResumeCompletion<P, usize>>, TaskResumeSubmissionFailure<P, ()>> {
        self.try_operate(cx, current, (), |store, worker, current, ()| {
            store.prune_expired(worker, current)
        })
    }

    /// Reconcile the exact previous/attempted file version after an uncertain
    /// commit. This never repeats the original mutation or clears quarantine
    /// on an unrelated version, failed protector or malformed manifest.
    pub fn try_reconcile(
        self,
        cx: &Cx,
        current: TaskResumeBinding,
    ) -> Result<CredentialSlotTask<TaskResumeCompletion<P, ()>>, TaskResumeSubmissionFailure<P, ()>> {
        self.try_operate(cx, current, (), |store, worker, current, ()| {
            store.reconcile(worker, current)
        })
    }

    /// Releases this store off the poller, even after lane shutdown. A live
    /// caller with the lane's required runtime capabilities is still necessary.
    pub fn close(self, cx: &Cx) -> Result<CredentialSlotTask<()>, CredentialIoError> {
        let Self { store, io } = self;
        io.close(cx, store)
    }

    // Not public: callers cannot schedule arbitrary closures or capture
    // unbounded state under the fixed checkpoint reservation.
    fn try_operate<I, T, F>(
        self,
        cx: &Cx,
        current: TaskResumeBinding,
        input: I,
        operation: F,
    ) -> Result<CredentialSlotTask<TaskResumeCompletion<P, T>>, TaskResumeSubmissionFailure<P, I>>
    where
        I: Send + 'static,
        T: Send + 'static,
        F: FnOnce(&mut TaskResumeStore<P>, &Cx, &TaskResumeBinding, I)
            -> Result<T, TaskResumeStoreError> + Send + 'static,
    {
        let Self { store, io } = self;
        io.try_submit(cx, (store, current, input), move |worker, io, (mut store, current, input)| {
            let outcome = operation(&mut store, worker, &current, input);
            TaskResumeCompletion { owner: Self { store, io }, outcome }
        }).map_err(|(cause, retained)| TaskResumeSubmissionFailure {
            cause,
            retained: retained.map(|(io, (store, current, input))| {
                Box::new((Self { store, io }, current, input))
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    mod persistence;
    mod restart;

    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::future::Future;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::thread::ThreadId;
    use std::time::Duration;

    use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
    use fastmcp_core::CanonicalHttpUrl;
    use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
    use fastmcp_core::runtime::ProcessGenerationGuard;
    use fastmcp_protocol::tasks_extension::Task;
    use serde_json::json;
    use crate::http_auth::secure_file::slot::coordinator::asynchronous::{
        CredentialIoLimits, CredentialIoSnapshot,
    };
    use super::super::super::TaskResumeError;

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            for _ in 0..64 {
                let path = std::env::temp_dir().join(format!(
                    "fastmcp-async-task-resume-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
                ));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("owned test directory: {error}"),
                }
            }
            panic!("test directory names exhausted");
        }
        fn handle(&self) -> File { File::open(&self.0).unwrap() }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.0.join("tasks"));
            let _ = fs::remove_file(self.0.join(".tasks.lock"));
            let _ = fs::remove_dir(&self.0);
        }
    }

    // Reference vault only: opaque tokens exercise real file persistence and
    // binding, not cryptography or restart-capable provider qualification.
    #[derive(Clone, Default)]
    struct Vault {
        records: Arc<Mutex<BTreeMap<Vec<u8>, ([u8; 32], Vec<u8>)>>>,
        calls: Arc<AtomicUsize>,
        threads: Arc<Mutex<Vec<ThreadId>>>,
    }
    impl TaskResumeProtector for Vault {
        fn profile(&self) -> [u8; 32] {
            self.threads.lock().unwrap().push(std::thread::current().id());
            [4; 32]
        }
        fn seal(&mut self, _: &Cx, binding: &[u8; 32], bytes: &[u8], maximum: usize) -> Result<Vec<u8>, TaskResumeError> {
            self.threads.lock().unwrap().push(std::thread::current().id());
            let ordinal = self.calls.fetch_add(1, Ordering::SeqCst);
            let token = (ordinal as u64).to_be_bytes().to_vec();
            if token.len() > maximum || bytes.len() > 65536 { return Err(TaskResumeError::Protection); }
            self.records.lock().unwrap().insert(token.clone(), (*binding, bytes.to_vec()));
            Ok(token)
        }
        fn open(&mut self, _: &Cx, binding: &[u8; 32], bytes: &[u8], maximum: usize) -> Result<Vec<u8>, TaskResumeError> {
            self.threads.lock().unwrap().push(std::thread::current().id());
            let records = self.records.lock().unwrap();
            let (saved, plaintext) = records.get(bytes).ok_or(TaskResumeError::Protection)?;
            if saved != binding || plaintext.len() > maximum { return Err(TaskResumeError::Protection); }
            Ok(plaintext.clone())
        }
    }

    fn binding(subject: &str) -> TaskResumeBinding {
        let resource = "https://service.example/mcp";
        let facts = PartitionDescriptor::from_verified_facts(
            "fixture", 1, "https://issuer.example", resource, "tenant", subject,
            "client", 1, 1, &[b"bound-resource".as_slice()],
        ).unwrap();
        let owner = DurableOwnerKey::derive(&facts, 1).unwrap();
        TaskResumeBinding::from_verified_owner(
            CanonicalHttpUrl::parse(resource).unwrap(), "async-fixture", &owner,
            [2; 32], [3; 32], [4; 32],
        ).unwrap()
    }

    fn record(cx: &Cx, binding: &TaskResumeBinding, id: &str) -> TaskResumeRecord {
        let task: Task = serde_json::from_value(json!({
            "taskId":id, "status":"working", "createdAt":"2020-01-01T00:00:00Z",
            "lastUpdatedAt":"2020-01-01T00:00:01Z", "ttlMs":null,
        })).unwrap();
        TaskResumeRecord::capture(cx, binding, &task, Duration::from_secs(3600)).unwrap()
    }

    fn run<F, Fut>(test: F)
    where F: FnOnce(Cx) -> Fut, Fut: Future<Output = ()> {
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap()).blocking_threads(1, 1).build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(10), test(cx))
                .await.expect("async Task checkpoint test exceeded its bound");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
    }

    async fn open(cx: &Cx, lane: &CredentialIoLane, directory: &Directory, vault: Vault, binding: TaskResumeBinding) -> AsyncTaskResumeStore<Vault> {
        let process = ProcessGenerationGuard::install().unwrap().token();
        AsyncTaskResumeStore::open(
            cx, lane, process, directory.handle(), "tasks".to_owned(), 65536,
            vault, binding, TaskResumeStoreLimits::new(8, 65536).unwrap(),
        ).unwrap().wait(cx).await.unwrap().unwrap()
    }

    #[test]
    fn worker_persists_reopens_and_conditionally_removes_without_poll_thread_protection() {
        run(|cx| async move {
            let guard = ProcessGenerationGuard::install().unwrap();
            let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
            let directory = Directory::new();
            let vault = Vault::default();
            let current = binding("one");
            let saved = record(&cx, &current, "PRIVATE-task");
            let poll_thread = std::thread::current().id();
            let store = open(&cx, &lane, &directory, vault.clone(), current.clone()).await;
            let (store, inserted) = store.try_insert(&cx, current.clone(), saved.clone()).unwrap()
                .wait(&cx).await.unwrap().into_parts();
            assert_eq!(inserted.unwrap(), saved.key());
            let version = store.revision();
            assert!(version.is_some());
            let before = fs::read(directory.0.join("tasks")).unwrap();
            assert!(!before.windows(7).any(|part| part == b"PRIVATE"));
            let (store, duplicate) = store.try_insert(&cx, current.clone(), saved.clone()).unwrap()
                .wait(&cx).await.unwrap().into_parts();
            assert!(matches!(duplicate, Err(TaskResumeStoreError::Resume(TaskResumeError::ConflictingSnapshot))));
            assert_eq!(store.revision(), version);
            assert_eq!(vault.calls.load(Ordering::SeqCst), 1);
            let (store, denied) = store.try_get(&cx, binding("other"), saved.key()).unwrap()
                .wait(&cx).await.unwrap().into_parts();
            assert!(matches!(denied, Err(TaskResumeStoreError::Resume(TaskResumeError::Unavailable))));
            assert_eq!(fs::read(directory.0.join("tasks")).unwrap(), before);
            store.close(&cx).unwrap().wait(&cx).await.unwrap();
            let store = open(&cx, &lane, &directory, vault.clone(), current.clone()).await;
            let (store, loaded) = store.try_get(&cx, current.clone(), saved.key()).unwrap()
                .wait(&cx).await.unwrap().into_parts();
            assert_eq!(loaded.unwrap().as_ref(), Some(&saved));
            let (store, removed) = store.try_remove_expected(&cx, current.clone(), saved.clone()).unwrap()
                .wait(&cx).await.unwrap().into_parts();
            removed.unwrap();
            let (store, loaded) = store.try_get(&cx, current, saved.key()).unwrap()
                .wait(&cx).await.unwrap().into_parts();
            assert!(loaded.unwrap().is_none());
            assert!(!vault.threads.lock().unwrap().is_empty());
            assert!(vault.threads.lock().unwrap().iter().all(|thread| *thread != poll_thread));
            lane.begin_shutdown().unwrap();
            store.close(&cx).unwrap().wait(&cx).await.unwrap();
            lane.wait_drained(&cx, Duration::from_secs(2)).await.unwrap();
            assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
        });
    }

    #[test]
    fn shutdown_refusal_returns_exact_owner_binding_and_unexecuted_input() {
        run(|cx| async move {
            let guard = ProcessGenerationGuard::install().unwrap();
            let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
            let directory = Directory::new();
            let vault = Vault::default();
            let current = binding("one");
            let saved = record(&cx, &current, "not-submitted");
            let store = open(&cx, &lane, &directory, vault.clone(), current.clone()).await;
            lane.begin_shutdown().unwrap();
            let failure = store.try_insert(&cx, current.clone(), saved.clone()).unwrap_err();
            assert_eq!(failure.cause(), CredentialIoError::LaneClosed);
            let (_, retained) = failure.into_parts();
            let (store, returned_binding, returned_record) = retained.unwrap();
            assert_eq!(returned_binding.associated_data(), current.associated_data());
            assert_eq!(returned_record, saved);
            assert_eq!(vault.calls.load(Ordering::SeqCst), 0);
            assert!(!directory.0.join("tasks").exists());
            store.close(&cx).unwrap().wait(&cx).await.unwrap();
            lane.wait_drained(&cx, Duration::from_secs(2)).await.unwrap();
        });
    }

    #[test]
    fn opening_without_a_caller_blocking_pool_has_no_file_or_provider_effect() {
        let runtime = RuntimeBuilder::current_thread().blocking_threads(0, 0).build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let guard = ProcessGenerationGuard::install().unwrap();
            let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
            let directory = Directory::new();
            let vault = Vault::default();
            let result = AsyncTaskResumeStore::open(
                &cx, &lane, guard.token(), directory.handle(), "tasks".to_owned(), 65536,
                vault.clone(), binding("one"), TaskResumeStoreLimits::default(),
            );
            assert!(matches!(result, Err(CredentialIoError::BlockingPoolUnavailable)));
            assert!(vault.threads.lock().unwrap().is_empty());
            assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
            assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
    }
}
