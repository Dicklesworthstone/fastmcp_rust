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

mod restart {
    use super::*;
    use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::client::restart::{
        TaskResumeRestartPlan, TaskResumeRestartPolicy,
    };

    #[test]
    fn every_page_is_staged_before_our_own_mutations_invalidate_cursors() {
        let cx = Cx::for_testing();
        let directory = Directory::new();
        let vault = TestVault::default();
        let owner = binding("one", 4);
        let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
        for id in ["one", "two", "three", "four"] {
            store.insert(&cx, &owner, record(&cx, &owner, id)).unwrap();
        }
        let first = store.page(&cx, &owner, None, 1).unwrap();
        let before = directory.bytes();
        let seals = vault.seals.load(Ordering::SeqCst);
        let plan = TaskResumeRestartPlan::load_store(&cx, &owner, &store, 1, TaskResumeRestartPolicy::default()).unwrap();
        assert_eq!(plan.len(), 4);
        assert_eq!(plan.charged_records(), 4);
        assert_eq!(directory.bytes(), before);
        assert_eq!(vault.seals.load(Ordering::SeqCst), seals, "loading must not write");
        let staged: Vec<_> = plan.records().map(|value| value.encode().unwrap()).collect();
        assert_eq!(plan.charged_bytes(), staged.iter().map(Vec::len).sum::<usize>());
        store.remove(&cx, &owner, first.keys[0]).unwrap();
        assert!(matches!(store.page(&cx, &owner, first.next.as_ref(), 1),
            Err(TaskResumeStoreError::Resume(TaskResumeError::StaleCursor))));
        assert_eq!(plan.records().map(|value| value.encode().unwrap()).collect::<Vec<_>>(), staged);
        assert_eq!(plan.len(), 4, "selection is independent of later host persistence");
    }

    #[test]
    fn incomplete_or_foreign_restart_load_never_escapes_as_a_partial_plan() {
        let cx = Cx::for_testing();
        let directory = Directory::new();
        let vault = TestVault::default();
        let owner = binding("one", 4);
        let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
        for id in ["one", "two", "three"] {
            store.insert(&cx, &owner, record(&cx, &owner, id)).unwrap();
        }
        let baseline = TaskResumeRestartPlan::load_store(&cx, &owner, &store, 1, TaskResumeRestartPolicy::default()).unwrap();
        let before = directory.bytes();
        let seals = vault.seals.load(Ordering::SeqCst);
        let too_few = TaskResumeRestartPolicy::new(2, 65536, Duration::from_secs(60)).unwrap();
        assert!(matches!(TaskResumeRestartPlan::load_store(&cx, &owner, &store, 1, too_few),
            Err(TaskResumeStoreError::Resume(TaskResumeError::Capacity))));
        let too_small = TaskResumeRestartPolicy::new(3, baseline.charged_bytes() - 1, Duration::from_secs(60)).unwrap();
        assert!(matches!(TaskResumeRestartPlan::load_store(&cx, &owner, &store, 1, too_small),
            Err(TaskResumeStoreError::Resume(TaskResumeError::TooLarge))));
        assert!(matches!(TaskResumeRestartPlan::load_store(&cx, &binding("other", 4), &store, 1, TaskResumeRestartPolicy::default()),
            Err(TaskResumeStoreError::Resume(TaskResumeError::Unavailable))));
        assert_eq!(directory.bytes(), before);
        assert_eq!(vault.seals.load(Ordering::SeqCst), seals);
        assert_eq!(TaskResumeRestartPlan::load_store(&cx, &owner, &store, 2, TaskResumeRestartPolicy::default()).unwrap().len(), 3);
    }

    #[test]
    fn reopened_manifest_produces_the_same_complete_restart_selection() {
        let cx = Cx::for_testing();
        let directory = Directory::new();
        let vault = TestVault::default();
        let owner = binding("one", 4);
        let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
        for id in ["PRIVATE-TASK-é", "PRIVATE-TASK-e\u{301}"] {
            store.insert(&cx, &owner, record(&cx, &owner, id)).unwrap();
        }
        let first = TaskResumeRestartPlan::load_store(&cx, &owner, &store, 1, TaskResumeRestartPolicy::default()).unwrap();
        let encoded: Vec<_> = first.records().map(|value| value.encode().unwrap()).collect();
        assert_eq!(encoded.len(), 2);
        drop(store);
        let reopened = open(&cx, &directory, vault, owner.clone(), 8);
        let second = TaskResumeRestartPlan::load_store(&cx, &owner, &reopened, 2, TaskResumeRestartPolicy::default()).unwrap();
        assert_eq!(second.records().map(|value| value.encode().unwrap()).collect::<Vec<_>>(), encoded);
        assert!(!format!("{second:?}").contains("PRIVATE"));
        assert!(!directory.bytes().windows(7).any(|part| part == b"PRIVATE"));
    }
}

mod conditional_cleanup {
    use super::*;

    #[test]
    fn exact_removal_survives_reopen_without_erasing_other_tasks() {
        let cx = Cx::for_testing();
        let directory = Directory::new();
        let vault = TestVault::default();
        let owner = binding("one", 4);
        let first = record(&cx, &owner, "one");
        let second = record(&cx, &owner, "two");
        let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
        store.insert(&cx, &owner, first.clone()).unwrap();
        store.insert(&cx, &owner, second.clone()).unwrap();
        let before = directory.bytes();
        let seals = vault.seals.load(Ordering::SeqCst);
        store.remove_expected(&cx, &owner, &first).unwrap();
        assert_ne!(directory.bytes(), before);
        assert_eq!(vault.seals.load(Ordering::SeqCst), seals + 1);
        assert_eq!(store.get(&cx, &owner, second.key()).unwrap(), Some(second.clone()));
        drop(store);
        let mut reopened = open(&cx, &directory, vault.clone(), owner.clone(), 8);
        assert!(reopened.get(&cx, &owner, first.key()).unwrap().is_none());
        assert_eq!(reopened.get(&cx, &owner, second.key()).unwrap(), Some(second));
        let before = directory.bytes();
        let seals = vault.seals.load(Ordering::SeqCst);
        assert!(matches!(reopened.remove_expected(&cx, &owner, &first),
            Err(TaskResumeStoreError::Resume(TaskResumeError::ConflictingSnapshot))));
        assert_eq!(directory.bytes(), before);
        assert_eq!(vault.seals.load(Ordering::SeqCst), seals);
    }

    #[test]
    fn stale_or_cross_owner_disposal_cannot_delete_current_controls() {
        let cx = Cx::for_testing();
        let directory = Directory::new();
        let vault = TestVault::default();
        let owner = binding("one", 4);
        let original = record(&cx, &owner, "one");
        let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
        store.insert(&cx, &owner, original.clone()).unwrap();
        let task: Task = serde_json::from_value(json!({"taskId":"one", "status":"working",
            "createdAt":"2020-01-01T00:00:00Z", "lastUpdatedAt":"2020-01-01T00:00:02Z", "ttlMs":null})).unwrap();
        let newer = TaskResumeRecord::capture(&cx, &owner, &task, Duration::from_secs(3600)).unwrap();
        store.put(&cx, &owner, newer).unwrap();
        let current = store.get(&cx, &owner, original.key()).unwrap().unwrap();
        let before = directory.bytes();
        let seals = vault.seals.load(Ordering::SeqCst);
        assert!(matches!(store.remove_expected(&cx, &owner, &original),
            Err(TaskResumeStoreError::Resume(TaskResumeError::ConflictingSnapshot))));
        let mut encoded = current.encode().unwrap();
        let start = encoded.len() - 16;
        let expiry = i128::from_be_bytes(encoded[start..].try_into().unwrap());
        encoded[start..].copy_from_slice(&(expiry - 1).to_be_bytes());
        let different_retention = TaskResumeRecord::decode(&encoded).unwrap();
        assert_eq!(current.key(), different_retention.key());
        assert!(matches!(store.remove_expected(&cx, &owner, &different_retention),
            Err(TaskResumeStoreError::Resume(TaskResumeError::ConflictingSnapshot))));
        let other = binding("other", 4);
        assert!(matches!(store.remove_expected(&cx, &other, &current),
            Err(TaskResumeStoreError::Resume(TaskResumeError::Unavailable))));
        assert!(matches!(store.remove_expected(&cx, &owner, &record(&cx, &other, "one")),
            Err(TaskResumeStoreError::Resume(TaskResumeError::Unavailable))));
        assert_eq!(directory.bytes(), before);
        assert_eq!(vault.seals.load(Ordering::SeqCst), seals);
        assert_eq!(store.get(&cx, &owner, current.key()).unwrap(), Some(current.clone()));
        store.remove_expected(&cx, &owner, &current).unwrap();
        assert!(store.get(&cx, &owner, current.key()).unwrap().is_none());
    }

    #[test]
    fn failed_conditional_delete_preserves_file_record_and_page_generation() {
        let cx = Cx::for_testing();
        let directory = Directory::new();
        let vault = TestVault::default();
        let owner = binding("one", 4);
        let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
        let first = record(&cx, &owner, "one");
        store.insert(&cx, &owner, first.clone()).unwrap();
        store.insert(&cx, &owner, record(&cx, &owner, "two")).unwrap();
        let page = store.page(&cx, &owner, None, 1).unwrap();
        let cursor = page.next.unwrap();
        let baseline_page = store.page(&cx, &owner, Some(&cursor), 1).unwrap().keys;
        let before = directory.bytes();
        vault.fail_seal.store(true, Ordering::SeqCst);
        assert!(matches!(store.remove_expected(&cx, &owner, &first),
            Err(TaskResumeStoreError::Resume(TaskResumeError::Protection))));
        assert_eq!(directory.bytes(), before);
        assert_eq!(store.get(&cx, &owner, first.key()).unwrap(), Some(first.clone()));
        assert_eq!(store.page(&cx, &owner, Some(&cursor), 1).unwrap().keys, baseline_page);
        vault.fail_seal.store(false, Ordering::SeqCst);
        store.remove_expected(&cx, &owner, &first).unwrap();
        assert!(matches!(store.page(&cx, &owner, Some(&cursor), 1),
            Err(TaskResumeStoreError::Resume(TaskResumeError::StaleCursor))));
    }

    #[test]
    fn protected_historical_slot_can_be_removed_even_when_live_lookup_filters_it() {
        let cx = Cx::for_testing();
        let directory = Directory::new();
        let mut vault = TestVault::default();
        let owner = binding("one", 4);
        let mut encoded = record(&cx, &owner, "PRIVATE-expired").encode().unwrap();
        let end = encoded.len();
        // Fixed historical record, not a sleep racing filesystem latency.
        // Its 2020 creation/update precede this finite retention deadline.
        encoded[end - 16..].copy_from_slice(&1_577_836_802_000_000_000_i128.to_be_bytes());
        let expired = TaskResumeRecord::decode(&encoded).unwrap();
        let mut manifest = b"FMTRST01".to_vec();
        manifest.extend_from_slice(owner.associated_data());
        manifest.extend_from_slice(&1_u64.to_be_bytes());
        manifest.extend_from_slice(&1_u16.to_be_bytes());
        manifest.extend_from_slice(expired.key().as_bytes());
        manifest.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        manifest.extend_from_slice(&encoded);
        let protected = vault.seal(&cx, owner.associated_data(), &manifest, 65536).unwrap();
        let mut file = directory.file(&cx);
        file.replace(&cx, None, &protected).unwrap();
        drop(file);
        // Production file/provider/manifest decoding admits this historical slot.
        let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
        assert_eq!(expired.admit(&cx, &owner), Err(TaskResumeError::Unavailable));
        assert!(store.get(&cx, &owner, expired.key()).unwrap().is_none());
        let before = directory.bytes();
        let seals = vault.seals.load(Ordering::SeqCst);
        store.remove_expected(&cx, &owner, &expired).unwrap();
        assert_ne!(directory.bytes(), before);
        assert_eq!(vault.seals.load(Ordering::SeqCst), seals + 1);
        drop(store);
        let mut reopened = open(&cx, &directory, vault.clone(), owner.clone(), 8);
        let before = directory.bytes();
        let seals = vault.seals.load(Ordering::SeqCst);
        assert!(matches!(reopened.remove_expected(&cx, &owner, &expired),
            Err(TaskResumeStoreError::Resume(TaskResumeError::ConflictingSnapshot))));
        assert_eq!(directory.bytes(), before);
        assert_eq!(vault.seals.load(Ordering::SeqCst), seals);
    }
}
