//! Conditional lifecycle changes over the existing real Linux file fixture.
//! TestVault remains an in-process reference vault, not a cryptographic claim.
use super::*;
use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::client::lifecycle::TaskResumeChange;

fn observed(status: &str, sequence: u8) -> Task {
    let mut value = json!({"taskId":"one", "status":status,
        "createdAt":"2020-01-01T00:00:00Z",
        "lastUpdatedAt":format!("2020-01-01T00:00:{sequence:02}Z"),
        "ttlMs":null});
    if status == "input_required" {
        value["inputRequests"] = json!({"PRIVATE-INPUT":{"method":"roots/list"}});
    }
    serde_json::from_value(value).unwrap()
}

#[test]
fn conditional_update_and_terminal_removal_are_durable_across_reopen() {
    let cx = Cx::for_testing();
    let directory = Directory::new();
    let vault = TestVault::default();
    let owner = binding("one", 4);
    let original = record(&cx, &owner, "one");
    let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
    let key = store.put(&cx, &owner, original.clone()).unwrap();
    let change = TaskResumeChange::from_snapshot(&cx, &owner, &original, &observed("working", 2)).unwrap();
    let next = change.replacement().unwrap().clone();
    change.apply(&cx, &owner, &mut store).unwrap();
    assert_eq!(store.get(&cx, &owner, key).unwrap(), Some(next.clone()));
    drop(store);
    let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
    assert_eq!(store.get(&cx, &owner, key).unwrap(), Some(next.clone()));
    let cleanup = TaskResumeChange::from_snapshot(&cx, &owner, &next, &observed("cancelled", 3)).unwrap();
    assert!(cleanup.replacement().is_none());
    cleanup.apply(&cx, &owner, &mut store).unwrap();
    drop(store);
    let store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
    assert!(store.get(&cx, &owner, key).unwrap().is_none());
    assert_eq!(vault.seals.load(Ordering::SeqCst), 3);
}

#[test]
fn stale_update_and_terminal_cleanup_cannot_mutate_newer_records() {
    let cx = Cx::for_testing();
    let directory = Directory::new();
    let vault = TestVault::default();
    let owner = binding("one", 4);
    let original = record(&cx, &owner, "one");
    let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
    let key = store.put(&cx, &owner, original.clone()).unwrap();
    let newer = TaskResumeChange::from_snapshot(&cx, &owner, &original, &observed("working", 2)).unwrap();
    newer.apply(&cx, &owner, &mut store).unwrap();
    let bytes = directory.bytes();
    let seals = vault.seals.load(Ordering::SeqCst);
    for status in ["input_required", "cancelled"] {
        let stale = TaskResumeChange::from_snapshot(&cx, &owner, &original, &observed(status, 3)).unwrap();
        assert!(matches!(stale.apply(&cx, &owner, &mut store),
            Err(TaskResumeStoreError::Resume(TaskResumeError::ConflictingSnapshot))));
        assert_eq!(directory.bytes(), bytes);
        assert_eq!(vault.seals.load(Ordering::SeqCst), seals);
    }
    let current = store.get(&cx, &owner, key).unwrap().unwrap();
    let unchanged = TaskResumeChange::from_snapshot(&cx, &owner, &current, &observed("working", 2)).unwrap();
    unchanged.apply(&cx, &owner, &mut store).unwrap();
    assert_eq!(directory.bytes(), bytes);
    assert_eq!(vault.seals.load(Ordering::SeqCst), seals, "no-op must acknowledge existing durability without a new write");
}

#[test]
fn failed_protection_keeps_the_expected_record_and_file_unchanged() {
    let cx = Cx::for_testing();
    let directory = Directory::new();
    let vault = TestVault::default();
    let owner = binding("one", 4);
    let original = record(&cx, &owner, "one");
    let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
    let key = store.put(&cx, &owner, original.clone()).unwrap();
    let bytes = directory.bytes();
    vault.fail_seal.store(true, Ordering::SeqCst);
    for status in ["working", "cancelled"] {
        let change = TaskResumeChange::from_snapshot(&cx, &owner, &original, &observed(status, 2)).unwrap();
        assert!(matches!(change.apply(&cx, &owner, &mut store),
            Err(TaskResumeStoreError::Resume(TaskResumeError::Protection))));
        assert_eq!(store.get(&cx, &owner, key).unwrap(), Some(original.clone()));
        assert_eq!(directory.bytes(), bytes);
    }
    assert_eq!(vault.seals.load(Ordering::SeqCst), 3, "one attempt per explicit operation, no hidden retries");
}

#[test]
fn changed_retention_is_a_conflict_even_with_identical_task_control_timestamps() {
    let cx = Cx::for_testing();
    let directory = Directory::new();
    let vault = TestVault::default();
    let owner = binding("one", 4);
    let original = record(&cx, &owner, "one");
    let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
    store.put(&cx, &owner, original.clone()).unwrap();
    let shorter = TaskResumeRecord::capture(&cx, &owner, &observed("input_required", 1), Duration::from_secs(10)).unwrap();
    store.put(&cx, &owner, shorter).unwrap();
    let bytes = directory.bytes();
    let seals = vault.seals.load(Ordering::SeqCst);
    let cleanup = TaskResumeChange::from_snapshot(&cx, &owner, &original, &observed("cancelled", 2)).unwrap();
    assert!(matches!(cleanup.apply(&cx, &owner, &mut store),
        Err(TaskResumeStoreError::Resume(TaskResumeError::ConflictingSnapshot))));
    assert_eq!(directory.bytes(), bytes);
    assert_eq!(vault.seals.load(Ordering::SeqCst), seals);
}

#[test]
fn missing_or_wrong_owner_changes_cannot_recreate_or_remove_a_record() {
    let cx = Cx::for_testing();
    let directory = Directory::new();
    let vault = TestVault::default();
    let owner = binding("one", 4);
    let original = record(&cx, &owner, "one");
    let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
    let key = store.put(&cx, &owner, original.clone()).unwrap();
    let cleanup = TaskResumeChange::from_snapshot(&cx, &owner, &original, &observed("cancelled", 2)).unwrap();
    let bytes = directory.bytes();
    assert!(matches!(cleanup.apply(&cx, &binding("other", 4), &mut store),
        Err(TaskResumeStoreError::Resume(TaskResumeError::Unavailable))));
    assert_eq!(directory.bytes(), bytes);
    store.remove(&cx, &owner, key).unwrap();
    let bytes = directory.bytes();
    let seals = vault.seals.load(Ordering::SeqCst);
    for status in ["working", "cancelled"] {
        let change = TaskResumeChange::from_snapshot(&cx, &owner, &original, &observed(status, 2)).unwrap();
        assert!(matches!(change.apply(&cx, &owner, &mut store),
            Err(TaskResumeStoreError::Resume(TaskResumeError::ConflictingSnapshot))));
        assert_eq!(directory.bytes(), bytes);
        assert_eq!(vault.seals.load(Ordering::SeqCst), seals);
    }
}

use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::client::creation::{
    TaskResumeCapturePolicy, TaskResumeInsert,
};

#[test]
fn accepted_task_initial_insert_reopens_without_persisting_input_payloads() {
    let cx = Cx::for_testing();
    let directory = Directory::new();
    let vault = TestVault::default();
    let owner = binding("one", 4);
    let insert = TaskResumeInsert::capture(&cx, &owner, &observed("input_required", 2),
        TaskResumeCapturePolicy::new(Duration::from_secs(60)).unwrap()).unwrap();
    assert!(!insert.record().encode().unwrap().windows(7).any(|part| part == b"PRIVATE"));
    let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
    insert.apply(&cx, &owner, &mut store).unwrap();
    drop(store);
    let reopened = open(&cx, &directory, vault.clone(), owner.clone(), 8);
    assert_eq!(reopened.get(&cx, &owner, insert.key()).unwrap().as_ref(), Some(insert.record()));
    assert_eq!(vault.seals.load(Ordering::SeqCst), 1);
}

#[test]
fn duplicate_initial_insert_never_overwrites_identical_or_newer_controls() {
    let cx = Cx::for_testing();
    let directory = Directory::new();
    let vault = TestVault::default();
    let owner = binding("one", 4);
    let original = record(&cx, &owner, "one");
    let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
    store.insert(&cx, &owner, original.clone()).unwrap();
    let bytes = directory.bytes();
    let policy = TaskResumeCapturePolicy::new(Duration::from_secs(60)).unwrap();
    for candidate in [original.clone(), TaskResumeInsert::capture(&cx, &owner,
        &observed("working", 2), policy).unwrap().record().clone()]
    {
        assert!(matches!(store.insert(&cx, &owner, candidate),
            Err(TaskResumeStoreError::Resume(TaskResumeError::ConflictingSnapshot))));
        assert_eq!(directory.bytes(), bytes);
        assert_eq!(vault.seals.load(Ordering::SeqCst), 1);
    }
    assert_eq!(store.get(&cx, &owner, original.key()).unwrap(), Some(original));
}

#[test]
fn initial_insert_admits_capacity_and_owner_before_protection() {
    let cx = Cx::for_testing();
    let directory = Directory::new();
    let vault = TestVault::default();
    let owner = binding("one", 4);
    let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 1);
    let first = record(&cx, &owner, "one");
    store.insert(&cx, &owner, first.clone()).unwrap();
    let bytes = directory.bytes();
    assert!(matches!(store.insert(&cx, &owner, record(&cx, &owner, "two")),
        Err(TaskResumeStoreError::Resume(TaskResumeError::Capacity))));
    assert!(matches!(store.insert(&cx, &binding("other", 4), first),
        Err(TaskResumeStoreError::Resume(TaskResumeError::Unavailable))));
    assert_eq!(directory.bytes(), bytes);
    assert_eq!(vault.seals.load(Ordering::SeqCst), 1);
}

#[test]
fn failed_initial_protection_preserves_absence_and_existing_durable_records() {
    let cx = Cx::for_testing();
    let directory = Directory::new();
    let vault = TestVault::default();
    let owner = binding("one", 4);
    let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
    let first = record(&cx, &owner, "one");
    store.insert(&cx, &owner, first.clone()).unwrap();
    let bytes = directory.bytes();
    let second = record(&cx, &owner, "two");
    vault.fail_seal.store(true, Ordering::SeqCst);
    assert!(matches!(store.insert(&cx, &owner, second.clone()),
        Err(TaskResumeStoreError::Resume(TaskResumeError::Protection))));
    assert!(store.get(&cx, &owner, second.key()).unwrap().is_none());
    assert_eq!(store.get(&cx, &owner, first.key()).unwrap(), Some(first));
    assert_eq!(directory.bytes(), bytes);
    assert_eq!(vault.seals.load(Ordering::SeqCst), 2);
}

mod restart_handoff {
    use super::*;
    use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::ManagedTaskWatchCheckpoint;
    use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::client::TaskResumeReconciliation;
    use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::client::restart::{
        TaskResumeRestartItem, TaskResumeRestartOutcome,
    };

    #[test]
    fn active_then_terminal_restart_changes_use_the_existing_atomic_store() {
        let cx = Cx::for_testing();
        let directory = Directory::new();
        let vault = TestVault::default();
        let owner = binding("one", 4);
        let original = record(&cx, &owner, "one");
        let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
        store.insert(&cx, &owner, original.clone()).unwrap();
        let task = observed("working", 2);
        let updated = TaskResumeChange::from_snapshot(&cx, &owner, &original, &task).unwrap().replacement().unwrap().clone();
        let selection = ManagedTaskWatchCheckpoint::decode(&serde_json::to_vec(&json!({
            "format":"fastmcp/task-watch", "version":1, "protocolVersion":"2026-07-28",
            "resource":owner.resource().as_str(), "taskIds":["one"],
        })).unwrap()).unwrap();
        // Typed outcome fixture: this case tests the public storage handoff,
        // not the network authentication which produces real restart items.
        let active = TaskResumeRestartItem { previous: original.clone(),
            outcome: TaskResumeRestartOutcome::Reconciled(TaskResumeReconciliation::Active {
                task: Box::new(task), record: updated.clone(), selection,
            }) };
        let change = active.storage_change(&cx, &owner).unwrap();
        change.apply(&cx, &owner, &mut store).unwrap();
        assert_eq!(active.previous, original, "storage must not consume result custody");
        drop(store);
        let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
        assert_eq!(store.get(&cx, &owner, updated.key()).unwrap(), Some(updated.clone()));
        let terminal = TaskResumeRestartItem { previous: updated,
            outcome: TaskResumeRestartOutcome::Reconciled(TaskResumeReconciliation::Terminal(Box::new(observed("cancelled", 3)))) };
        assert!(matches!(&terminal.outcome, TaskResumeRestartOutcome::Reconciled(TaskResumeReconciliation::Terminal(_))));
        terminal.storage_change(&cx, &owner).unwrap().apply(&cx, &owner, &mut store).unwrap();
        drop(store);
        let store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
        assert!(store.get(&cx, &owner, terminal.previous.key()).unwrap().is_none());
        assert_eq!(vault.seals.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn unavailable_restart_disposal_preserves_newer_work_and_failed_terminal_results() {
        let cx = Cx::for_testing();
        let directory = Directory::new();
        let vault = TestVault::default();
        let owner = binding("one", 4);
        let original = record(&cx, &owner, "one");
        let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
        store.insert(&cx, &owner, original.clone()).unwrap();
        let unavailable = TaskResumeRestartItem { previous: original.clone(), outcome: TaskResumeRestartOutcome::Unavailable };
        let old_cleanup = unavailable.storage_change(&cx, &owner).unwrap();
        let newer = TaskResumeChange::from_snapshot(&cx, &owner, &original, &observed("working", 2)).unwrap();
        newer.apply(&cx, &owner, &mut store).unwrap();
        let bytes = directory.bytes();
        let seals = vault.seals.load(Ordering::SeqCst);
        assert!(matches!(old_cleanup.apply(&cx, &owner, &mut store),
            Err(TaskResumeStoreError::Resume(TaskResumeError::ConflictingSnapshot))));
        assert_eq!(directory.bytes(), bytes);
        assert_eq!(vault.seals.load(Ordering::SeqCst), seals);
        let current = store.get(&cx, &owner, original.key()).unwrap().unwrap();
        let payload: Task = serde_json::from_value(json!({"taskId":"one", "status":"completed",
            "createdAt":"2020-01-01T00:00:00Z", "lastUpdatedAt":"2020-01-01T00:00:03Z",
            "ttlMs":null, "result":{"content":[{"type":"text","text":"PRIVATE-RESULT"}]}})).unwrap();
        let terminal = TaskResumeRestartItem { previous: current.clone(),
            outcome: TaskResumeRestartOutcome::Reconciled(TaskResumeReconciliation::Terminal(Box::new(payload))) };
        let cleanup = terminal.storage_change(&cx, &owner).unwrap();
        vault.fail_seal.store(true, Ordering::SeqCst);
        assert!(matches!(cleanup.apply(&cx, &owner, &mut store),
            Err(TaskResumeStoreError::Resume(TaskResumeError::Protection))));
        assert_eq!(directory.bytes(), bytes);
        assert_eq!(store.get(&cx, &owner, current.key()).unwrap(), Some(current));
        let TaskResumeRestartOutcome::Reconciled(TaskResumeReconciliation::Terminal(task)) = &terminal.outcome
            else { panic!("storage failure cannot erase terminal custody"); };
        assert!(serde_json::to_string(task).unwrap().contains("PRIVATE-RESULT"));
        assert!(!cleanup.previous().encode().unwrap().windows(7).any(|part| part == b"PRIVATE"));
        assert_eq!(vault.seals.load(Ordering::SeqCst), seals + 1, "no hidden storage retry");
    }

    #[test]
    fn explicit_unavailable_change_removes_a_protected_expired_record() {
        let cx = Cx::for_testing();
        let directory = Directory::new();
        let mut vault = TestVault::default();
        let owner = binding("one", 4);
        let mut encoded = record(&cx, &owner, "one").encode().unwrap();
        let length = encoded.len();
        encoded[length - 16..].copy_from_slice(&1_577_836_802_000_000_000_i128.to_be_bytes());
        let expired = TaskResumeRecord::decode(&encoded).unwrap();
        let mut manifest = b"FMTRST01".to_vec();
        manifest.extend_from_slice(owner.associated_data());
        manifest.extend_from_slice(&1_u64.to_be_bytes());
        manifest.extend_from_slice(&1_u16.to_be_bytes());
        manifest.extend_from_slice(expired.key().as_bytes());
        manifest.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        manifest.extend_from_slice(&encoded);
        let sealed = vault.seal(&cx, owner.associated_data(), &manifest, 65536).unwrap();
        let mut file = directory.file(&cx);
        file.replace(&cx, None, &sealed).unwrap();
        drop(file);
        let mut store = open(&cx, &directory, vault.clone(), owner.clone(), 8);
        assert!(store.get(&cx, &owner, expired.key()).unwrap().is_none());
        assert!(matches!(TaskResumeChange::from_snapshot(&cx, &owner, &expired, &observed("working", 2)),
            Err(TaskResumeError::Unavailable)), "cleanup must not reactivate expired controls");
        let item = TaskResumeRestartItem { previous: expired, outcome: TaskResumeRestartOutcome::Unavailable };
        let change = item.storage_change(&cx, &owner).unwrap();
        assert!(change.replacement().is_none());
        let before = directory.bytes();
        let seals = vault.seals.load(Ordering::SeqCst);
        assert!(matches!(change.apply(&cx, &binding("other", 4), &mut store),
            Err(TaskResumeStoreError::Resume(TaskResumeError::Unavailable))));
        assert_eq!(directory.bytes(), before);
        assert_eq!(vault.seals.load(Ordering::SeqCst), seals);
        change.apply(&cx, &owner, &mut store).unwrap();
        assert_ne!(directory.bytes(), before);
        drop(store);
        let mut reopened = open(&cx, &directory, vault.clone(), owner.clone(), 8);
        let before = directory.bytes();
        let seals = vault.seals.load(Ordering::SeqCst);
        assert!(matches!(change.apply(&cx, &owner, &mut reopened),
            Err(TaskResumeStoreError::Resume(TaskResumeError::ConflictingSnapshot))));
        assert_eq!(directory.bytes(), before);
        assert_eq!(vault.seals.load(Ordering::SeqCst), seals);
    }
}
