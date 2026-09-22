use super::*;
use super::super::{ManagedTaskDriverError, TaskInputRequests};
use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use serde_json::json;

fn binding(subject: &str) -> TaskResumeBinding {
    let target = "https://service.example/mcp";
    let facts = PartitionDescriptor::from_verified_facts("fixture", 1, "https://issuer.example",
        target, "tenant", subject, "client", 1, 1, &[b"bound-resource".as_slice()]).unwrap();
    let owner = DurableOwnerKey::derive(&facts, 1).unwrap();
    TaskResumeBinding::from_verified_owner(CanonicalHttpUrl::parse(target).unwrap(),
        "input-journal", &owner, [2; 32], [3; 32], [4; 32]).unwrap()
}
fn task() -> Task {
    serde_json::from_value(json!({"taskId":"task-one", "status":"input_required",
        "createdAt":"2026-09-22T00:00:00Z", "lastUpdatedAt":"2026-09-22T00:00:01Z",
        "ttlMs":null, "inputRequests":{"one":{"method":"roots/list"},"two":{"method":"roots/list"}}})).unwrap()
}
fn inputs() -> TaskInputRequests {
    let Task::InputRequired { input_requests, .. } = task() else { unreachable!() };
    input_requests
}
fn save(_: Cx, _: McpRequestCancellation, _: Time, change: TaskInputJournalChange)
    -> std::future::Ready<Result<TaskInputJournalRecord, TaskInputJournalError>>
{ std::future::ready(Ok(change.proposed)) }
fn fresh() -> TaskInputJournal {
    let binding = binding("one");
    TaskInputJournal::new(binding.clone(), TaskInputJournalRecord::empty(&binding, task().base().task_id.clone()).unwrap(), save).unwrap()
}
fn intent(journal: &TaskInputJournal, key: &str, id: &str) -> TaskInputJournalChange {
    let mut history = journal.record.history.clone();
    history.unanswered(&inputs(), ManagedTaskWatchDrivePolicy::default()).unwrap();
    journal.intent(&task(), &history, std::iter::once(key.to_owned()), &RequestId::String(id.to_owned())).unwrap()
}
fn persist(journal: &mut TaskInputJournal, change: TaskInputJournalChange) -> Result<(), TaskInputJournalError> {
    let cx = Cx::for_testing();
    let cancellation = McpRequestCancellation::new();
    let mut future = Box::pin(journal.persist(&cx, &cancellation, cx.now().saturating_add_nanos(1_000_000_000), change));
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("unit persistence fixture must complete synchronously"),
    }
}
fn acknowledge(journal: &mut TaskInputJournal) {
    let change = journal.acknowledgement().unwrap();
    persist(journal, change).unwrap();
}

#[test]
fn intents_and_receipts_roundtrip_without_application_payloads() {
    let mut journal = fresh();
    let empty = journal.record().unwrap().encode().unwrap();
    assert_eq!(TaskInputJournalRecord::decode(&empty).unwrap(), *journal.record().unwrap());
    let change = intent(&journal, "one", "first:5");
    assert_eq!(journal.record().unwrap().update_state(), TaskInputUpdateState::NotAttempted);
    persist(&mut journal, change).unwrap();
    let pending = journal.record().unwrap().encode().unwrap();
    let restored = TaskInputJournalRecord::decode(&pending).unwrap();
    assert_eq!(restored.update_state(), TaskInputUpdateState::Unconfirmed);
    assert!(TaskInputJournal::new(binding("one"), restored, save).unwrap().can_update().is_err());
    acknowledge(&mut journal);
    let receipt = journal.record().unwrap().encode().unwrap();
    assert_eq!(TaskInputJournalRecord::decode(&receipt).unwrap().encode().unwrap(), receipt);
    for bytes in [&pending, &receipt] {
        assert!(!bytes.windows(b"roots/list".len()).any(|part| part == b"roots/list"));
        assert!(!bytes.windows(b"inputRequests".len()).any(|part| part == b"inputRequests"));
    }
    assert_eq!(journal.record().unwrap().acknowledged_updates(), 1);
    assert_eq!(journal.record().unwrap().generation(), 2);
}

#[test]
fn acknowledged_keys_and_unanswered_descriptor_identity_survive_restart() {
    let mut journal = fresh();
    let change = intent(&journal, "one", "first:5");
    persist(&mut journal, change).unwrap(); acknowledge(&mut journal);
    let bytes = journal.record().unwrap().encode().unwrap();
    let restored = TaskInputJournal::new(binding("one"), TaskInputJournalRecord::decode(&bytes).unwrap(), save).unwrap();
    let mut history = restored.admit(binding("one").resource(), &task().base().task_id, ManagedTaskWatchDrivePolicy::default()).unwrap();
    assert_eq!(history.unanswered(&inputs(), ManagedTaskWatchDrivePolicy::default()).unwrap().requests.keys().cloned().collect::<Vec<_>>(), ["two"]);
    let before = history.entries.clone();
    for key in ["one", "two"] {
        let changed = serde_json::from_value(json!({key:{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":1}}})).unwrap();
        assert!(matches!(history.unanswered(&changed, ManagedTaskWatchDrivePolicy::default()), Err(ManagedTaskDriverError::InputKeyReused)));
        assert_eq!(history.entries, before);
    }
}

#[test]
fn pending_intent_cannot_be_acked_by_observation_or_replaced_on_restart() {
    let mut journal = fresh();
    let change = intent(&journal, "one", "first:5");
    persist(&mut journal, change).unwrap();
    let record = TaskInputJournalRecord::decode(&journal.record().unwrap().encode().unwrap()).unwrap();
    let restored = TaskInputJournal::new(binding("one"), record, save).unwrap();
    restored.check_task(&task()).unwrap();
    assert_eq!(restored.can_update(), Err(TaskInputJournalError::ReconciliationRequired));
    assert_eq!(restored.record().unwrap().acknowledged_updates(), 0);
    assert_eq!(restored.restore_progress().state, TaskInputUpdateState::Unconfirmed);
}

#[test]
fn stale_request_ids_and_reduced_budgets_cannot_reset_history() {
    let mut journal = fresh();
    let change = intent(&journal, "one", "first:5");
    persist(&mut journal, change).unwrap(); acknowledge(&mut journal);
    let mut history = journal.record.history.clone();
    history.unanswered(&inputs(), ManagedTaskWatchDrivePolicy::default()).unwrap();
    assert!(matches!(journal.intent(&task(), &history, std::iter::once("two".to_owned()), &RequestId::String("first:5".to_owned())),
        Err(TaskInputJournalError::IdentityReused)));
    let mut policy = ManagedTaskWatchDrivePolicy::default();
    policy.maximum_updates = 0;
    assert!(matches!(journal.admit(binding("one").resource(), &task().base().task_id, policy), Err(TaskInputJournalError::Capacity)));
    policy.maximum_updates = 1; policy.maximum_input_keys = 1;
    assert!(matches!(journal.admit(binding("one").resource(), &task().base().task_id, policy), Err(TaskInputJournalError::Capacity)));
    let next = intent(&journal, "two", "restart:5");
    persist(&mut journal, next).unwrap(); acknowledge(&mut journal);
    assert_eq!(journal.record().unwrap().acknowledged_updates(), 2);
}

#[test]
fn wrong_owner_resource_and_reused_task_identity_are_not_admitted() {
    let journal = fresh();
    let record = journal.record().unwrap().clone();
    assert!(matches!(TaskInputJournal::new(binding("other"), record, save), Err(TaskInputJournalError::BindingMismatch)));
    assert!(journal.admit(&CanonicalHttpUrl::parse("https://other.example/mcp").unwrap(), &task().base().task_id,
        ManagedTaskWatchDrivePolicy::default()).is_err());
    let mut journal = fresh();
    let change = intent(&journal, "one", "first:5"); persist(&mut journal, change).unwrap();
    let mut changed = serde_json::to_value(task()).unwrap();
    changed["createdAt"] = json!("2026-09-22T00:00:00.1Z");
    assert_eq!(journal.check_task(&serde_json::from_value(changed).unwrap()), Err(TaskInputJournalError::TaskChanged));
    assert_ne!(journal.record.binding, *binding("one").associated_data(), "purpose-separated from resume controls");
}

#[test]
fn strict_codec_rejects_truncation_trailing_data_and_impossible_receipts() {
    let journal = fresh();
    let record = intent(&journal, "one", "first:5").proposed;
    let bytes = record.encode().unwrap();
    for end in 0..bytes.len() { assert!(TaskInputJournalRecord::decode(&bytes[..end]).is_err()); }
    let mut extra = bytes.clone(); extra.push(0);
    assert!(TaskInputJournalRecord::decode(&extra).is_err());
    for field in 0..4 {
        let mut changed = record.clone();
        match field {
            0 => changed.acknowledged = 1,
            1 => changed.pending_keys.clear(),
            2 => { changed.history.entries.get_mut("one").unwrap().1 = true; },
            _ => changed.generation = u64::MAX,
        }
        assert!(changed.encode().is_err());
    }
    assert_eq!(record.encode().unwrap(), bytes);
}

#[test]
fn failed_or_forged_persistence_receipt_quarantines_before_another_attempt() {
    for wrong_receipt in [false, true] {
        let initial = fresh().record;
        let calls = Arc::new(Mutex::new(0));
        let seen = Arc::clone(&calls);
        let mut journal = TaskInputJournal::new(binding("one"), initial,
            move |_: Cx, _: McpRequestCancellation, _: Time, change: TaskInputJournalChange| {
                *seen.lock().unwrap() += 1;
                std::future::ready(if wrong_receipt { Ok(change.expected) } else { Err(TaskInputJournalError::Persistence) })
            }).unwrap();
        let change = intent(&journal, "one", "first:5");
        assert!(persist(&mut journal, change.clone()).is_err());
        assert!(journal.pending_change().is_some());
        assert!(matches!(journal.record(), Err(TaskInputJournalError::ReconciliationRequired)));
        assert!(persist(&mut journal, change).is_err());
        assert_eq!(*calls.lock().unwrap(), 1);
    }
}

#[test]
fn committed_but_lost_store_reply_restores_uncertainty_not_retry_authority() {
    let saved = Arc::new(Mutex::new(None));
    let stored = Arc::clone(&saved);
    let mut journal = TaskInputJournal::new(binding("one"), fresh().record,
        move |_: Cx, _: McpRequestCancellation, _: Time, change: TaskInputJournalChange| {
            *stored.lock().unwrap() = Some(change.proposed.encode().unwrap());
            std::future::ready(Err(TaskInputJournalError::Persistence))
        }).unwrap();
    let change = intent(&journal, "one", "first:5");
    assert!(persist(&mut journal, change).is_err());
    let bytes = saved.lock().unwrap().clone().unwrap();
    let reopened = TaskInputJournal::new(binding("one"), TaskInputJournalRecord::decode(&bytes).unwrap(), save).unwrap();
    assert_eq!(reopened.can_update(), Err(TaskInputJournalError::ReconciliationRequired));
    assert_eq!(reopened.record().unwrap().acknowledged_updates(), 0);
}

#[test]
fn abandoned_save_retains_pending_change_without_mutating_shared_cancellation() {
    let mut journal = TaskInputJournal::new(binding("one"), fresh().record,
        |_: Cx, _: McpRequestCancellation, _: Time, _: TaskInputJournalChange|
            std::future::pending::<Result<TaskInputJournalRecord, TaskInputJournalError>>()).unwrap();
    let change = intent(&journal, "one", "first:5");
    let cx = Cx::for_testing();
    let cancellation = McpRequestCancellation::new();
    let mut future = Box::pin(journal.persist(&cx, &cancellation, cx.now().saturating_add_nanos(1_000_000_000), change));
    assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    drop(future);
    assert!(journal.pending_change().is_some());
    assert!(journal.record().is_err());
    assert!(!cancellation.is_cancel_requested());
}

#[test]
fn precancelled_save_does_not_call_provider_or_quarantine_clean_state() {
    let mut journal = TaskInputJournal::new(binding("one"), fresh().record,
        |_: Cx, _: McpRequestCancellation, _: Time, _: TaskInputJournalChange| {
            panic!("pre-cancellation must precede provider invocation");
            #[allow(unreachable_code)] std::future::ready(Err(TaskInputJournalError::Persistence))
        }).unwrap();
    let change = intent(&journal, "one", "first:5");
    let cx = Cx::for_testing(); let cancellation = McpRequestCancellation::new(); cancellation.cancel();
    let mut future = Box::pin(journal.persist(&cx, &cancellation, cx.now().saturating_add_nanos(1_000_000_000), change));
    assert!(matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(TaskInputJournalError::Cancelled))));
    drop(future);
    assert!(journal.pending_change().is_none());
    assert_eq!(journal.record().unwrap().generation(), 0);
}

#[cfg(target_os = "linux")]
mod file_storage {
    use super::*;
    use super::super::file::FileTaskInputJournal;
    use crate::http_auth::secure_file::SecureAtomicFile;
    use super::super::super::super::checkpoint::resume::{TaskResumeError, store::TaskResumeProtector};
    use fastmcp_core::runtime::ProcessGenerationGuard;
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            for _ in 0..64 {
                let path = std::env::temp_dir().join(format!("fastmcp-input-journal-{}-{}",
                    std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
                    Err(error) => panic!("could not create private test directory: {error}"),
                }
            }
            panic!("private test directory attempts exhausted");
        }
        fn file(&self, cx: &Cx) -> SecureAtomicFile {
            SecureAtomicFile::open(cx, File::open(&self.0).unwrap(), "journal", 65536).unwrap()
        }
        fn bytes(&self) -> Vec<u8> { fs::read(self.0.join("journal")).unwrap() }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.0.join("journal"));
            let _ = fs::remove_file(self.0.join(".journal.lock"));
            let _ = fs::remove_dir(&self.0);
        }
    }
    // Reference vault only, NOT a cryptographic implementation or key-custody
    // qualification. Tests reopen actual files while retaining this test vault.
    #[derive(Default)]
    struct VaultState { next: u64, entries: BTreeMap<Vec<u8>, ([u8; 32], Vec<u8>)> }
    #[derive(Clone, Default)]
    struct Vault { state: Arc<Mutex<VaultState>>, fail: Arc<AtomicBool> }
    impl TaskResumeProtector for Vault {
        fn profile(&self) -> [u8; 32] { [4; 32] }
        fn seal(&mut self, _: &Cx, aad: &[u8; 32], bytes: &[u8], maximum: usize) -> Result<Vec<u8>, TaskResumeError> {
            if self.fail.load(Ordering::SeqCst) || bytes.len() > 65536 || maximum < 16 { return Err(TaskResumeError::Protection); }
            let mut vault = self.state.lock().unwrap();
            if vault.entries.len() >= 32 { return Err(TaskResumeError::Capacity); }
            vault.next += 1;
            let mut ciphertext = b"TESTVAUL".to_vec(); ciphertext.extend_from_slice(&vault.next.to_be_bytes());
            vault.entries.insert(ciphertext.clone(), (*aad, bytes.to_vec()));
            Ok(ciphertext)
        }
        fn open(&mut self, _: &Cx, aad: &[u8; 32], ciphertext: &[u8], maximum: usize) -> Result<Vec<u8>, TaskResumeError> {
            let vault = self.state.lock().unwrap();
            let (expected, bytes) = vault.entries.get(ciphertext).ok_or(TaskResumeError::Protection)?;
            if expected != aad || bytes.len() > maximum { return Err(TaskResumeError::Protection); }
            Ok(bytes.clone())
        }
    }
    fn open(cx: &Cx, directory: &Directory, vault: Vault) -> FileTaskInputJournal<Vault> {
        FileTaskInputJournal::open(cx, ProcessGenerationGuard::install().unwrap().token(),
            directory.file(cx), vault, binding("one"), task().base().task_id.clone()).unwrap()
    }
    fn apply(store: &mut FileTaskInputJournal<Vault>, cx: &Cx, change: TaskInputJournalChange)
        -> Result<TaskInputJournalRecord, TaskInputJournalError>
    {
        store.apply(cx, &McpRequestCancellation::new(), cx.now().saturating_add_nanos(1_000_000_000), &binding("one"), change)
    }

    #[test]
    fn protected_file_reopens_intent_then_receipt_without_resetting_keys() {
        let cx = Cx::for_testing(); let directory = Directory::new(); let vault = Vault::default();
        let journal = fresh(); let change = intent(&journal, "one", "first:5");
        let mut store = open(&cx, &directory, vault.clone());
        let intent_record = apply(&mut store, &cx, change).unwrap();
        assert!(!directory.bytes().windows(8).any(|bytes| bytes == MAGIC));
        assert_ne!(directory.bytes(), intent_record.encode().unwrap());
        drop(store);
        let mut store = open(&cx, &directory, vault.clone());
        let restored = TaskInputJournal::new(binding("one"), store.record(&cx, &binding("one")).unwrap(), save).unwrap();
        assert_eq!(restored.can_update(), Err(TaskInputJournalError::ReconciliationRequired));
        // The private unit boundary stands for an admitted wire ACK, not a
        // public API allowing a caller to infer acknowledgement from a get.
        let change = restored.acknowledgement().unwrap();
        let acknowledged = apply(&mut store, &cx, change).unwrap(); drop(store);
        let store = open(&cx, &directory, vault);
        assert_eq!(store.record(&cx, &binding("one")).unwrap(), acknowledged);
        let journal = TaskInputJournal::new(binding("one"), acknowledged, save).unwrap();
        let mut history = journal.admit(binding("one").resource(), &task().base().task_id, ManagedTaskWatchDrivePolicy::default()).unwrap();
        assert_eq!(history.unanswered(&inputs(), ManagedTaskWatchDrivePolicy::default()).unwrap().requests.len(), 1);
    }

    #[test]
    fn stale_conditional_write_and_failed_protector_leave_file_unchanged() {
        let cx = Cx::for_testing(); let directory = Directory::new(); let vault = Vault::default();
        let journal = fresh(); let change = intent(&journal, "one", "first:5");
        let mut store = open(&cx, &directory, vault.clone());
        let intent_record = apply(&mut store, &cx, change.clone()).unwrap(); let before = directory.bytes();
        assert_eq!(apply(&mut store, &cx, change), Err(TaskInputJournalError::InvalidReceipt));
        assert_eq!(directory.bytes(), before);
        let journal = TaskInputJournal::new(binding("one"), intent_record.clone(), save).unwrap();
        vault.fail.store(true, Ordering::SeqCst);
        assert_eq!(apply(&mut store, &cx, journal.acknowledgement().unwrap()), Err(TaskInputJournalError::Persistence));
        assert_eq!(directory.bytes(), before);
        assert_eq!(store.record(&cx, &binding("one")).unwrap(), intent_record);
    }

    #[test]
    fn wrong_owner_and_corrupt_file_are_not_treated_as_empty_journals() {
        let cx = Cx::for_testing(); let directory = Directory::new(); let vault = Vault::default();
        let journal = fresh(); let mut store = open(&cx, &directory, vault.clone());
        apply(&mut store, &cx, intent(&journal, "one", "first:5")).unwrap();
        assert!(matches!(store.record(&cx, &binding("other")), Err(TaskInputJournalError::BindingMismatch)));
        let before = directory.bytes(); drop(store);
        assert!(FileTaskInputJournal::open(&cx, ProcessGenerationGuard::install().unwrap().token(),
            directory.file(&cx), vault.clone(), binding("other"), task().base().task_id.clone()).is_err());
        assert_eq!(directory.bytes(), before);
        let mut corrupt = before; corrupt[0] ^= 1; fs::write(directory.0.join("journal"), &corrupt).unwrap();
        assert!(FileTaskInputJournal::open(&cx, ProcessGenerationGuard::install().unwrap().token(),
            directory.file(&cx), vault, binding("one"), task().base().task_id.clone()).is_err());
        assert_eq!(directory.bytes(), corrupt);
    }
}
