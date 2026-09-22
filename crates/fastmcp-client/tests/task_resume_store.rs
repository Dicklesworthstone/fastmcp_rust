//! Linux file-adapter tests for protected Task resume storage.
//! Run with --features tasks. The fixture protector is an in-process reference
//! vault, NOT cryptographic or restart-provider qualification. Closing/reopening
//! the real file proves adapter persistence, not persistence of vault keys.
#![cfg(all(target_os = "linux", feature = "tasks"))]

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use asupersync::Cx;
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
use fastmcp_core::runtime::ProcessGenerationGuard;
use fastmcp_client::http_auth::secure_file::SecureAtomicFile;
use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::{
    TaskResumeBinding, TaskResumeError, TaskResumeRecord,
};
use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::store::{
    TaskResumeProtector, TaskResumeStore, TaskResumeStoreError, TaskResumeStoreLimits,
};
use fastmcp_protocol::tasks_extension::Task;
use serde_json::json;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..64 {
            let path = std::env::temp_dir().join(format!("fastmcp-task-resume-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(error) => panic!("could not create owned test directory: {error}"),
            }
        }
        panic!("owned test directory name attempts exhausted");
    }
    fn file(&self, cx: &Cx) -> SecureAtomicFile {
        SecureAtomicFile::open(cx, File::open(&self.0).unwrap(), "tasks", 65536).unwrap()
    }
    fn bytes(&self) -> Vec<u8> { fs::read(self.0.join("tasks")).unwrap() }
}
impl Drop for Directory {
    fn drop(&mut self) {
        // Only this fixture's create-new directory and fixed file/lock names.
        let _ = fs::remove_file(self.0.join("tasks"));
        let _ = fs::remove_file(self.0.join(".tasks.lock"));
        let _ = fs::remove_dir(&self.0);
    }
}

#[derive(Default)]
struct VaultState { next: u64, records: BTreeMap<Vec<u8>, ([u8; 32], Vec<u8>)> }
#[derive(Clone, Default)]
struct TestVault {
    state: Arc<Mutex<VaultState>>,
    fail_seal: Arc<AtomicBool>,
    seals: Arc<AtomicUsize>,
}
impl TaskResumeProtector for TestVault {
    fn profile(&self) -> [u8; 32] { [4; 32] }
    fn seal(&mut self, _: &Cx, binding: &[u8; 32], plaintext: &[u8], maximum: usize)
        -> Result<Vec<u8>, TaskResumeError>
    {
        self.seals.fetch_add(1, Ordering::SeqCst);
        if self.fail_seal.load(Ordering::SeqCst) || maximum < 16 || plaintext.len() > 65536 {
            return Err(TaskResumeError::Protection);
        }
        let mut vault = self.state.lock().unwrap();
        if vault.records.len() >= 64 { return Err(TaskResumeError::Capacity); }
        vault.next = vault.next.checked_add(1).ok_or(TaskResumeError::GenerationExhausted)?;
        let mut token = b"TESTVAUL".to_vec();
        token.extend_from_slice(&vault.next.to_be_bytes());
        vault.records.insert(token.clone(), (*binding, plaintext.to_vec()));
        Ok(token)
    }
    fn open(&mut self, _: &Cx, binding: &[u8; 32], ciphertext: &[u8], maximum: usize)
        -> Result<Vec<u8>, TaskResumeError>
    {
        let vault = self.state.lock().unwrap();
        let (owner, plaintext) = vault.records.get(ciphertext).ok_or(TaskResumeError::Protection)?;
        if owner != binding || plaintext.len() > maximum { return Err(TaskResumeError::Protection); }
        Ok(plaintext.clone())
    }
}

fn binding(subject: &str, protection: u8) -> TaskResumeBinding {
    let resource = "https://service.example/mcp";
    let facts = PartitionDescriptor::from_verified_facts("fixture", 1, "https://issuer.example",
        resource, "tenant", subject, "client", 1, 1, &[b"bound-resource".as_slice()]).unwrap();
    let owner = DurableOwnerKey::derive(&facts, 1).unwrap();
    TaskResumeBinding::from_verified_owner(CanonicalHttpUrl::parse(resource).unwrap(),
        "fixture", &owner, [2; 32], [3; 32], [protection; 32]).unwrap()
}
fn record(cx: &Cx, binding: &TaskResumeBinding, id: &str) -> TaskResumeRecord {
    let task: Task = serde_json::from_value(json!({"taskId":id, "status":"input_required",
        "createdAt":"2020-01-01T00:00:00Z", "lastUpdatedAt":"2020-01-01T00:00:01Z",
        "ttlMs":null, "inputRequests":{"PRIVATE-INPUT":{"method":"roots/list"}},
        "statusMessage":"PRIVATE-STATUS"})).unwrap();
    TaskResumeRecord::capture(cx, binding, &task, Duration::from_secs(3600)).unwrap()
}
fn open(cx: &Cx, directory: &Directory, vault: TestVault, binding: TaskResumeBinding, maximum: usize)
    -> TaskResumeStore<TestVault>
{
    let process = ProcessGenerationGuard::install().unwrap().token();
    TaskResumeStore::open(cx, process, directory.file(cx), vault, binding,
        TaskResumeStoreLimits::new(maximum, 65536).unwrap()).unwrap()
}

#[test]
fn real_file_reopens_control_record_and_persists_terminal_cleanup() {
    let cx = Cx::for_testing();
    let directory = Directory::new();
    let vault = TestVault::default();
    let owner = binding("one", 4);
    let saved = record(&cx, &owner, "PRIVATE-TASK / é");
    let expected = saved.encode().unwrap();
    let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
    let key = store.put(&cx, &owner, saved).unwrap();
    let bytes = directory.bytes();
    assert!(!bytes.windows(7).any(|part| part == b"PRIVATE"));
    assert_ne!(bytes, expected);
    drop(store);
    let mut reopened = open(&cx, &directory, vault.clone(), owner.clone(), 8);
    assert_eq!(reopened.get(&cx, &owner, key).unwrap().unwrap().encode().unwrap(), expected);
    assert!(reopened.remove(&cx, &owner, key).unwrap());
    assert_ne!(directory.bytes(), bytes);
    drop(reopened);
    let reopened = open(&cx, &directory, vault, owner.clone(), 8);
    assert!(reopened.get(&cx, &owner, key).unwrap().is_none());
    assert!(reopened.page(&cx, &owner, None, 8).unwrap().keys.is_empty());
}

#[test]
fn capacity_is_reserved_before_protection_and_failed_seal_leaves_file_unchanged() {
    let cx = Cx::for_testing();
    let directory = Directory::new();
    let vault = TestVault::default();
    let owner = binding("one", 4);
    let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 1);
    let first = record(&cx, &owner, "one");
    let key = store.put(&cx, &owner, first.clone()).unwrap();
    let bytes = directory.bytes();
    let calls = vault.seals.load(Ordering::SeqCst);
    assert!(matches!(store.put(&cx, &owner, record(&cx, &owner, "two")),
        Err(TaskResumeStoreError::Resume(TaskResumeError::Capacity))));
    assert_eq!(vault.seals.load(Ordering::SeqCst), calls);
    assert_eq!(directory.bytes(), bytes);
    vault.fail_seal.store(true, Ordering::SeqCst);
    assert!(matches!(store.remove(&cx, &owner, key), Err(TaskResumeStoreError::Resume(TaskResumeError::Protection))));
    assert_eq!(directory.bytes(), bytes);
    assert_eq!(store.get(&cx, &owner, key).unwrap().unwrap().encode().unwrap(), first.encode().unwrap());
    vault.fail_seal.store(false, Ordering::SeqCst);
    assert!(store.remove(&cx, &owner, key).unwrap());
}

#[test]
fn current_binding_and_provider_profile_cannot_be_selected_from_stored_data() {
    let cx = Cx::for_testing();
    let directory = Directory::new();
    let vault = TestVault::default();
    let owner = binding("one", 4);
    let other = binding("other", 4);
    let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
    let key = store.put(&cx, &owner, record(&cx, &owner, "one")).unwrap();
    let bytes = directory.bytes();
    assert!(matches!(store.get(&cx, &other, key), Err(TaskResumeStoreError::Resume(TaskResumeError::Unavailable))));
    assert!(matches!(store.remove(&cx, &other, key), Err(TaskResumeStoreError::Resume(TaskResumeError::Unavailable))));
    assert_eq!(directory.bytes(), bytes);
    drop(store);
    let process = ProcessGenerationGuard::install().unwrap().token();
    assert!(matches!(TaskResumeStore::open(&cx, process, directory.file(&cx), vault.clone(), binding("one", 5),
        TaskResumeStoreLimits::default()), Err(TaskResumeStoreError::Resume(TaskResumeError::Protection))));
    let process = ProcessGenerationGuard::install().unwrap().token();
    assert!(matches!(TaskResumeStore::open(&cx, process, directory.file(&cx), vault.clone(), other,
        TaskResumeStoreLimits::default()), Err(TaskResumeStoreError::Resume(TaskResumeError::Protection))));
    assert_eq!(directory.bytes(), bytes);
    assert!(open(&cx, &directory, vault, owner.clone(), 8).get(&cx, &owner, key).unwrap().is_some());
}

#[test]
fn page_cursor_cannot_cross_a_committed_mutation() {
    let cx = Cx::for_testing();
    let directory = Directory::new();
    let owner = binding("one", 4);
    let mut store = open(&cx, &directory, TestVault::default(), owner.clone(), 8);
    for id in ["one", "two", "three"] { store.put(&cx, &owner, record(&cx, &owner, id)).unwrap(); }
    let first = store.page(&cx, &owner, None, 1).unwrap();
    let second = store.page(&cx, &owner, first.next.as_ref(), 1).unwrap();
    assert_ne!(first.keys, second.keys);
    assert!(first.next.is_some() && second.next.is_some());
    store.remove(&cx, &owner, first.keys[0]).unwrap();
    assert!(matches!(store.page(&cx, &owner, second.next.as_ref(), 1),
        Err(TaskResumeStoreError::Resume(TaskResumeError::StaleCursor))));
    assert_eq!(store.page(&cx, &owner, None, 8).unwrap().keys.len(), 2);
}

#[test]
fn changed_ciphertext_is_not_reinterpreted_as_an_empty_store() {
    let cx = Cx::for_testing();
    let directory = Directory::new();
    let vault = TestVault::default();
    let owner = binding("one", 4);
    let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
    store.put(&cx, &owner, record(&cx, &owner, "one")).unwrap();
    drop(store);
    let mut bytes = directory.bytes();
    bytes[0] ^= 1;
    fs::write(directory.0.join("tasks"), &bytes).unwrap();
    let process = ProcessGenerationGuard::install().unwrap().token();
    assert!(matches!(TaskResumeStore::open(&cx, process, directory.file(&cx), vault, owner,
        TaskResumeStoreLimits::default()), Err(TaskResumeStoreError::Resume(TaskResumeError::Protection))));
    assert_eq!(directory.bytes(), bytes, "refusal must not overwrite the corrupted evidence");
}

#[path = "task_resume_store/lifecycle.rs"]
mod lifecycle;
