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
