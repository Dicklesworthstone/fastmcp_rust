#![cfg(target_os = "linux")]

//! Public storage API exercised against actual files, permissions, locks, and
//! renames. Test payloads are non-secret bytes: these tests do not claim AEAD,
//! rollback-anchor, power-loss, or end-to-end OAuth qualification.

use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::Cx;
use fastmcp_client::http_auth::secure_file::{
    AtomicFileError, MAX_ATOMIC_FILE_BYTES, SecureAtomicFile,
};

static DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        for _ in 0..128 {
            let id = DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("fastmcp-atomic-{}-{id}", std::process::id()));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("private test directory: {error}"),
            }
        }
        panic!("test directory collision bound exceeded");
    }

    fn handle(&self) -> File {
        File::open(&self.0).unwrap()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn open(&self, cx: &Cx, limit: usize) -> SecureAtomicFile {
        SecureAtomicFile::open(cx, self.handle(), "credential", limit).unwrap()
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        // Only the private directory this test successfully created is removed.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn expired() -> Cx {
    Cx::for_testing_with_budget(asupersync::Budget::new().with_deadline(asupersync::Time::ZERO))
}

#[test]
fn atomic_replacement_survives_reopen_with_exact_bytes_and_permissions() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let payload = b"non-secret fixture\0with exact binary\xffbytes";
    let version = {
        let mut file = directory.open(&cx, 4096);
        assert!(file.load(&cx).unwrap().is_none());
        let version = file.replace(&cx, None, payload).unwrap();
        let stored = file.load(&cx).unwrap().unwrap();
        assert_eq!(stored.version(), version);
        assert_eq!(stored.bytes(), payload);
        assert!(!format!("{stored:?}").contains("non-secret fixture"));
        version
    };
    let file = directory.open(&cx, 4096);
    let stored = file.load(&cx).unwrap().unwrap();
    assert_eq!(stored.version(), version);
    assert_eq!(stored.into_bytes(), payload);
    assert_eq!(fs::read(directory.file("credential")).unwrap(), payload);
    let metadata = fs::metadata(directory.file("credential")).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    let mut entries: Vec<_> = fs::read_dir(&directory.0).unwrap()
        .map(|entry| entry.unwrap().file_name()).collect();
    entries.sort();
    assert_eq!(entries, vec![".credential.lock", "credential"]);
}

#[test]
fn empty_file_is_not_absence_and_stale_compare_exchange_preserves_the_winner() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let mut file = directory.open(&cx, 64);
    let empty = file.replace(&cx, None, b"").unwrap();
    assert!(file.load(&cx).unwrap().unwrap().bytes().is_empty());
    assert_eq!(file.replace(&cx, None, b"must not create twice"), Err(AtomicFileError::Conflict));
    let winner = file.replace(&cx, Some(empty), b"winner").unwrap();
    assert_ne!(empty, winner);
    assert_eq!(file.replace(&cx, Some(empty), b"stale"), Err(AtomicFileError::Conflict));
    assert_eq!(file.load(&cx).unwrap().unwrap().version(), winner);
    assert_eq!(fs::read(directory.file("credential")).unwrap(), b"winner");
}

#[test]
fn independent_writer_is_refused_until_the_first_handle_is_dropped() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let mut first = directory.open(&cx, 64);
    let version = first.replace(&cx, None, b"first").unwrap();
    assert_eq!(
        SecureAtomicFile::open(&cx, directory.handle(), "credential", 64).err(),
        Some(AtomicFileError::Busy),
    );
    drop(first);
    assert!(directory.file(".credential.lock").exists(), "lock inode must survive handle drop");
    let mut second = directory.open(&cx, 64);
    second.replace(&cx, Some(version), b"second").unwrap();
    assert_eq!(fs::read(directory.file("credential")).unwrap(), b"second");
}

#[test]
fn symlink_target_is_refused_without_touching_its_destination() {
    let directory = TestDirectory::new();
    let outside = TestDirectory::new();
    write_private(&outside.file("destination"), b"outside");
    symlink(outside.file("destination"), directory.file("credential")).unwrap();
    assert_eq!(
        SecureAtomicFile::open(&Cx::for_testing(), directory.handle(), "credential", 64).err(),
        Some(AtomicFileError::UnsafeFile),
    );
    assert_eq!(fs::read(outside.file("destination")).unwrap(), b"outside");
    assert!(fs::symlink_metadata(directory.file("credential")).unwrap().file_type().is_symlink());
}

#[test]
fn hardlinked_target_is_refused_without_replacing_either_name() {
    let directory = TestDirectory::new();
    write_private(&directory.file("original"), b"retained");
    fs::hard_link(directory.file("original"), directory.file("credential")).unwrap();
    assert_eq!(
        SecureAtomicFile::open(&Cx::for_testing(), directory.handle(), "credential", 64).err(),
        Some(AtomicFileError::UnsafeFile),
    );
    assert_eq!(fs::read(directory.file("original")).unwrap(), b"retained");
    assert_eq!(fs::read(directory.file("credential")).unwrap(), b"retained");
    assert_eq!(fs::metadata(directory.file("original")).unwrap().nlink(), 2);
}

#[test]
fn symlink_lock_is_refused_and_does_not_create_a_payload() {
    let directory = TestDirectory::new();
    write_private(&directory.file("other"), b"lock target");
    symlink("other", directory.file(".credential.lock")).unwrap();
    assert_eq!(
        SecureAtomicFile::open(&Cx::for_testing(), directory.handle(), "credential", 64).err(),
        Some(AtomicFileError::UnsafeFile),
    );
    assert_eq!(fs::read(directory.file("other")).unwrap(), b"lock target");
    assert!(!directory.file("credential").exists());
}

#[test]
fn public_directory_and_file_permissions_are_not_silently_repaired() {
    let cx = Cx::for_testing();
    let directory = TestDirectory::new();
    fs::set_permissions(&directory.0, Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        SecureAtomicFile::open(&cx, directory.handle(), "credential", 64).err(),
        Some(AtomicFileError::UnsafeDirectory),
    );
    assert_eq!(fs::metadata(&directory.0).unwrap().mode() & 0o777, 0o755);
    assert!(!directory.file(".credential.lock").exists());
    fs::set_permissions(&directory.0, Permissions::from_mode(0o700)).unwrap();
    write_private(&directory.file("credential"), b"not private");
    fs::set_permissions(directory.file("credential"), Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        SecureAtomicFile::open(&cx, directory.handle(), "credential", 64).err(),
        Some(AtomicFileError::UnsafeFile),
    );
    assert_eq!(fs::metadata(directory.file("credential")).unwrap().mode() & 0o777, 0o644);
    assert_eq!(fs::read(directory.file("credential")).unwrap(), b"not private");
}

#[test]
fn invalid_names_and_limits_are_refused_before_creating_any_file() {
    let cx = Cx::for_testing();
    let directory = TestDirectory::new();
    for name in ["", ".", "..", "../escape", "/absolute", "nested/path", "a\\b", "a\0b", "é", ".hidden"] {
        assert_eq!(
            SecureAtomicFile::open(&cx, directory.handle(), name, 64).err(),
            Some(AtomicFileError::InvalidName),
            "name {name:?}",
        );
    }
    assert_eq!(
        SecureAtomicFile::open(&cx, directory.handle(), &"x".repeat(97), 64).err(),
        Some(AtomicFileError::InvalidName),
    );
    for limit in [0, MAX_ATOMIC_FILE_BYTES + 1] {
        assert_eq!(
            SecureAtomicFile::open(&cx, directory.handle(), "credential", limit).err(),
            Some(AtomicFileError::InvalidLimit),
        );
    }
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
}

#[test]
fn write_limit_is_exact_and_oversized_replacement_retains_previous_bytes() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let mut file = directory.open(&cx, 8);
    let version = file.replace(&cx, None, b"12345678").unwrap();
    assert_eq!(file.maximum_bytes(), 8);
    assert_eq!(file.replace(&cx, Some(version), b"123456789"), Err(AtomicFileError::TooLarge));
    assert_eq!(file.load(&cx).unwrap().unwrap().bytes(), b"12345678");
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2, "no abandoned temporary");
}

#[test]
fn oversized_existing_file_is_refused_on_open() {
    let directory = TestDirectory::new();
    write_private(&directory.file("credential"), b"123456789");
    assert_eq!(
        SecureAtomicFile::open(&Cx::for_testing(), directory.handle(), "credential", 8).err(),
        Some(AtomicFileError::TooLarge),
    );
    assert_eq!(fs::read(directory.file("credential")).unwrap(), b"123456789");
}

#[test]
fn changed_lock_inode_refuses_further_writes() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let mut file = directory.open(&cx, 64);
    let version = file.replace(&cx, None, b"before").unwrap();
    fs::rename(directory.file(".credential.lock"), directory.file("old_lock")).unwrap();
    write_private(&directory.file(".credential.lock"), b"");
    assert_eq!(file.replace(&cx, Some(version), b"after"), Err(AtomicFileError::LockReplaced));
    assert_eq!(file.load(&cx).err(), Some(AtomicFileError::LockReplaced));
    assert_eq!(fs::read(directory.file("credential")).unwrap(), b"before");
}

#[test]
fn retained_directory_handle_cannot_be_redirected_by_a_pathname_swap() {
    let directory = TestDirectory::new();
    let held = directory.file("held");
    let moved = directory.file("moved");
    DirBuilder::new().mode(0o700).create(&held).unwrap();
    let cx = Cx::for_testing();
    let mut file = SecureAtomicFile::open(&cx, File::open(&held).unwrap(), "credential", 64).unwrap();
    fs::rename(&held, &moved).unwrap();
    DirBuilder::new().mode(0o700).create(&held).unwrap();
    file.replace(&cx, None, b"original capability").unwrap();
    assert_eq!(fs::read(moved.join("credential")).unwrap(), b"original capability");
    assert_eq!(fs::read_dir(&held).unwrap().count(), 0);
}

#[test]
fn cancellation_and_expiry_are_precommit_refusals_and_do_not_wedge_the_slot() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let mut file = directory.open(&cx, 64);
    let version = file.replace(&cx, None, b"before").unwrap();
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert_eq!(file.replace(&cancelled, Some(version), b"cancelled"), Err(AtomicFileError::Cancelled));
    assert_eq!(file.replace(&expired(), Some(version), b"expired"), Err(AtomicFileError::TimedOut));
    assert_eq!(file.load(&expired()).err(), Some(AtomicFileError::TimedOut));
    assert_eq!(fs::read(directory.file("credential")).unwrap(), b"before");
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
    file.replace(&cx, Some(version), b"after").unwrap();
    assert_eq!(file.reconcile(&cx).unwrap().unwrap().bytes(), b"after");
}

#[test]
fn cancelled_open_has_no_namespace_effects() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    assert_eq!(
        SecureAtomicFile::open(&cx, directory.handle(), "credential", 64).err(),
        Some(AtomicFileError::Cancelled),
    );
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
}

#[test]
fn permission_changes_after_open_are_rechecked_before_mutation() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let mut file = directory.open(&cx, 64);
    let version = file.replace(&cx, None, b"before").unwrap();
    fs::set_permissions(&directory.0, Permissions::from_mode(0o755)).unwrap();
    assert_eq!(file.replace(&cx, Some(version), b"after"), Err(AtomicFileError::UnsafeDirectory));
    fs::set_permissions(&directory.0, Permissions::from_mode(0o700)).unwrap();
    assert_eq!(file.load(&cx).unwrap().unwrap().bytes(), b"before");
    fs::set_permissions(directory.file("credential"), Permissions::from_mode(0o640)).unwrap();
    assert_eq!(file.replace(&cx, Some(version), b"after"), Err(AtomicFileError::UnsafeFile));
    assert_eq!(fs::read(directory.file("credential")).unwrap(), b"before");
}

// Durable-slot tests exercise production framing, CAS, tombstones and recovery
// against real files. The in-test anchor values model independently retained
// trusted input; they are NOT evidence of an external rollback-anchor service.
use fastmcp_client::http_auth::secure_file::slot::{
    CredentialSlotError, DurableCredentialSlot, SlotCommitIntent, SlotRecoveryOutcome,
    SlotRevision, SLOT_INTENT_BYTES, SLOT_REVISION_BYTES,
};
use fastmcp_core::partition::{
    CredentialStoreKey, DurableOwnerKey, PartitionAuthorization, PartitionDescriptor,
};

fn partition(subject: &str, policy: u64) -> (CredentialStoreKey, PartitionAuthorization) {
    // These are declared fixture facts, not a proof of ingress authentication.
    let descriptor = PartitionDescriptor::from_verified_facts(
        "fixture-provider", 1, "https://issuer.example", "https://resource.example/mcp",
        "tenant", subject, "native-client", 1, policy, &[b"fixture-audience"],
    ).unwrap();
    let owner = DurableOwnerKey::derive(&descriptor, 1).unwrap();
    (
        CredentialStoreKey::derive(&descriptor, "private-store", "refresh-family", "fixture-lineage").unwrap(),
        PartitionAuthorization::current(&descriptor, &owner),
    )
}

fn slot(
    directory: &TestDirectory,
    cx: &Cx,
    key: &CredentialStoreKey,
    authorization: &PartitionAuthorization,
    revision: Option<SlotRevision>,
) -> DurableCredentialSlot {
    DurableCredentialSlot::open(cx, directory.open(cx, 4096), key, authorization, revision).unwrap()
}

#[test]
fn slot_take_commits_a_tombstone_before_releasing_exact_bytes_and_survives_reopen() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let (key, authorization) = partition("alice", 1);
    let mut slot = slot(&directory, &cx, &key, &authorization, None);
    let create = slot.prepare_replace(&cx, &authorization, None, b"protected fixture\0\xff").unwrap();
    let intent = SlotCommitIntent::from_trusted_bytes(&create.intent().to_bytes()).unwrap();
    assert_eq!(intent.previous(), None);
    assert_eq!(intent.proposed().generation(), 1);
    let commit = slot.commit(&cx, &authorization, create).unwrap();
    let first = commit.revision();
    assert!(commit.into_consumed().is_none());
    assert_eq!(slot.load(&cx, &authorization).unwrap(), Some(b"protected fixture\0\xff".to_vec()));

    let take = slot.prepare_take(&cx, &authorization, first).unwrap();
    let taken_intent = take.intent();
    assert_eq!(taken_intent.previous(), Some(first));
    let commit = slot.commit(&cx, &authorization, take).unwrap();
    let tombstone = commit.revision();
    assert_eq!(tombstone.generation(), 2);
    assert_eq!(commit.into_consumed(), Some(b"protected fixture\0\xff".to_vec()));
    assert_eq!(slot.load(&cx, &authorization).unwrap(), None);
    assert!(!fs::read(directory.file("credential")).unwrap().windows(9).any(|bytes| bytes == b"protected"));
    drop(slot);

    let trusted = SlotRevision::from_trusted_bytes(&tombstone.to_bytes()).unwrap();
    let mut reopened = self::slot(&directory, &cx, &key, &authorization, Some(trusted));
    assert_eq!(reopened.load(&cx, &authorization).unwrap(), None);
    assert_eq!(reopened.prepare_take(&cx, &authorization, tombstone).err(), Some(CredentialSlotError::Empty));
    let replacement = reopened.prepare_replace(&cx, &authorization, Some(tombstone), b"successor").unwrap();
    assert_eq!(reopened.commit(&cx, &authorization, replacement).unwrap().revision().generation(), 3);
    assert_eq!(reopened.prepare_take(&cx, &authorization, first).err(), Some(CredentialSlotError::RevisionMismatch));
    assert_eq!(reopened.load(&cx, &authorization).unwrap(), Some(b"successor".to_vec()));
}

#[test]
fn preparing_or_dropping_a_take_does_not_consume_the_file() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let (key, authorization) = partition("alice", 1);
    let mut slot = slot(&directory, &cx, &key, &authorization, None);
    let create = slot.prepare_replace(&cx, &authorization, None, b"retained").unwrap();
    let first = slot.commit(&cx, &authorization, create).unwrap().revision();
    let original = fs::read(directory.file("credential")).unwrap();
    let take = slot.prepare_take(&cx, &authorization, first).unwrap();
    assert_eq!(fs::read(directory.file("credential")).unwrap(), original);
    drop(take);
    assert_eq!(slot.load(&cx, &authorization).unwrap(), Some(b"retained".to_vec()));
    assert_eq!(slot.revision(), Some(first));
}

#[test]
fn only_one_of_two_prepared_mutations_can_commit() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let (key, authorization) = partition("alice", 1);
    let mut slot = slot(&directory, &cx, &key, &authorization, None);
    let first = slot.prepare_replace(&cx, &authorization, None, b"winner").unwrap();
    let stale = slot.prepare_replace(&cx, &authorization, None, b"loser").unwrap();
    let winner = slot.commit(&cx, &authorization, first).unwrap().revision();
    assert_eq!(slot.commit(&cx, &authorization, stale).err(), Some(CredentialSlotError::RevisionMismatch));
    assert_eq!(slot.revision(), Some(winner));
    assert_eq!(slot.load(&cx, &authorization).unwrap(), Some(b"winner".to_vec()));
}

#[test]
fn wrong_current_authorization_cannot_read_prepare_or_commit() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let (key, authorization) = partition("alice", 1);
    let (_, changed_policy) = partition("alice", 2);
    let mut slot = slot(&directory, &cx, &key, &authorization, None);
    let create = slot.prepare_replace(&cx, &authorization, None, b"private").unwrap();
    let first = slot.commit(&cx, &authorization, create).unwrap().revision();
    let before = fs::read(directory.file("credential")).unwrap();
    assert_eq!(slot.load(&cx, &changed_policy).err(), Some(CredentialSlotError::BindingMismatch));
    assert_eq!(slot.prepare_replace(&cx, &changed_policy, Some(first), b"other").err(), Some(CredentialSlotError::BindingMismatch));
    let take = slot.prepare_take(&cx, &authorization, first).unwrap();
    assert_eq!(slot.commit(&cx, &changed_policy, take).err(), Some(CredentialSlotError::BindingMismatch));
    assert_eq!(fs::read(directory.file("credential")).unwrap(), before);
    assert_eq!(slot.load(&cx, &authorization).unwrap(), Some(b"private".to_vec()));
}

#[test]
fn cross_partition_record_and_prepared_mutation_substitution_are_refused() {
    let a = TestDirectory::new();
    let b = TestDirectory::new();
    let cx = Cx::for_testing();
    let (alice_key, alice_auth) = partition("alice", 1);
    let (bob_key, bob_auth) = partition("bob", 1);
    let mut alice = slot(&a, &cx, &alice_key, &alice_auth, None);
    let mut bob = slot(&b, &cx, &bob_key, &bob_auth, None);
    let substituted = alice.prepare_replace(&cx, &alice_auth, None, b"alice").unwrap();
    assert_eq!(bob.commit(&cx, &bob_auth, substituted).err(), Some(CredentialSlotError::BindingMismatch));
    assert!(!b.file("credential").exists());
    let create = alice.prepare_replace(&cx, &alice_auth, None, b"alice").unwrap();
    let revision = alice.commit(&cx, &alice_auth, create).unwrap().revision();
    drop(alice);
    assert_eq!(
        DurableCredentialSlot::open(&cx, a.open(&cx, 4096), &bob_key, &bob_auth, Some(revision)).err(),
        Some(CredentialSlotError::BindingMismatch),
    );
    assert_eq!(self::slot(&a, &cx, &alice_key, &alice_auth, Some(revision)).load(&cx, &alice_auth).unwrap(), Some(b"alice".to_vec()));
}

#[test]
fn restored_backup_and_absent_anchor_cannot_reset_a_consumed_generation() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let (key, authorization) = partition("alice", 1);
    let mut slot = slot(&directory, &cx, &key, &authorization, None);
    let create = slot.prepare_replace(&cx, &authorization, None, b"old").unwrap();
    let first = slot.commit(&cx, &authorization, create).unwrap().revision();
    let backup = fs::read(directory.file("credential")).unwrap();
    let take = slot.prepare_take(&cx, &authorization, first).unwrap();
    let latest = slot.commit(&cx, &authorization, take).unwrap().revision();
    drop(slot);
    assert_eq!(
        DurableCredentialSlot::open(&cx, directory.open(&cx, 4096), &key, &authorization, None).err(),
        Some(CredentialSlotError::RevisionMismatch),
    );
    // Restore only the untrusted data volume; retain the independent latest anchor.
    fs::write(directory.file("credential"), &backup).unwrap();
    assert_eq!(
        DurableCredentialSlot::open(&cx, directory.open(&cx, 4096), &key, &authorization, Some(latest)).err(),
        Some(CredentialSlotError::RevisionMismatch),
    );
    assert_eq!(fs::read(directory.file("credential")).unwrap(), backup);
}

#[test]
fn intent_recovery_distinguishes_not_started_from_exact_committed_replacement() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let (key, authorization) = partition("alice", 1);
    let slot = slot(&directory, &cx, &key, &authorization, None);
    let prepared = slot.prepare_replace(&cx, &authorization, None, b"next").unwrap();
    let trusted_intent = SlotCommitIntent::from_trusted_bytes(&prepared.intent().to_bytes()).unwrap();
    drop(slot);
    let (mut recovered, outcome) = DurableCredentialSlot::recover(
        &cx, directory.open(&cx, 4096), &key, &authorization, trusted_intent,
    ).unwrap();
    assert_eq!(outcome, SlotRecoveryOutcome::NotCommitted(None));
    let committed = recovered.commit(&cx, &authorization, prepared).unwrap().revision();
    drop(recovered);
    let (recovered, outcome) = DurableCredentialSlot::recover(
        &cx, directory.open(&cx, 4096), &key, &authorization, trusted_intent,
    ).unwrap();
    assert_eq!(outcome, SlotRecoveryOutcome::Committed(committed));
    assert_eq!(recovered.load(&cx, &authorization).unwrap(), Some(b"next".to_vec()));
}

#[test]
fn recovery_refuses_a_different_commit_at_the_same_generation() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let (key, authorization) = partition("alice", 1);
    let mut slot = slot(&directory, &cx, &key, &authorization, None);
    let proposed = slot.prepare_replace(&cx, &authorization, None, b"proposed").unwrap();
    let intent = proposed.intent();
    let other = slot.prepare_replace(&cx, &authorization, None, b"other").unwrap();
    let winner = slot.commit(&cx, &authorization, other).unwrap().revision();
    assert_eq!(winner.generation(), intent.proposed().generation());
    assert_ne!(winner, intent.proposed());
    drop(slot);
    assert_eq!(
        DurableCredentialSlot::recover(&cx, directory.open(&cx, 4096), &key, &authorization, intent).err(),
        Some(CredentialSlotError::RevisionMismatch),
    );
    assert_eq!(self::slot(&directory, &cx, &key, &authorization, Some(winner)).load(&cx, &authorization).unwrap(), Some(b"other".to_vec()));
}

#[test]
fn recovered_take_never_redelivers_its_old_payload() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let (key, authorization) = partition("alice", 1);
    let mut slot = slot(&directory, &cx, &key, &authorization, None);
    let create = slot.prepare_replace(&cx, &authorization, None, b"once").unwrap();
    let first = slot.commit(&cx, &authorization, create).unwrap().revision();
    let take = slot.prepare_take(&cx, &authorization, first).unwrap();
    let intent = take.intent();
    assert_eq!(slot.commit(&cx, &authorization, take).unwrap().into_consumed(), Some(b"once".to_vec()));
    drop(slot);
    let (recovered, outcome) = DurableCredentialSlot::recover(
        &cx, directory.open(&cx, 4096), &key, &authorization, intent,
    ).unwrap();
    assert_eq!(outcome, SlotRecoveryOutcome::Committed(intent.proposed()));
    assert_eq!(recovered.load(&cx, &authorization).unwrap(), None);
    assert_eq!(recovered.prepare_take(&cx, &authorization, intent.proposed()).err(), Some(CredentialSlotError::Empty));
}

#[test]
fn prepared_take_cancellation_preserves_the_old_payload_and_revision() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let (key, authorization) = partition("alice", 1);
    let mut slot = slot(&directory, &cx, &key, &authorization, None);
    let create = slot.prepare_replace(&cx, &authorization, None, b"retained").unwrap();
    let first = slot.commit(&cx, &authorization, create).unwrap().revision();
    let take = slot.prepare_take(&cx, &authorization, first).unwrap();
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert_eq!(slot.commit(&cancelled, &authorization, take).err(), Some(CredentialSlotError::Storage(AtomicFileError::Cancelled)));
    assert_eq!(slot.revision(), Some(first));
    assert_eq!(slot.load(&cx, &authorization).unwrap(), Some(b"retained".to_vec()));
    assert_eq!(slot.prepare_take(&expired(), &authorization, first).err(), Some(CredentialSlotError::Storage(AtomicFileError::TimedOut)));
}

#[test]
fn empty_payload_is_distinct_from_a_tombstone_and_payload_limit_excludes_framing() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let (key, authorization) = partition("alice", 1);
    let mut slot = DurableCredentialSlot::open(&cx, directory.open(&cx, 128), &key, &authorization, None).unwrap();
    let empty = slot.prepare_replace(&cx, &authorization, None, b"").unwrap();
    let first = slot.commit(&cx, &authorization, empty).unwrap().revision();
    assert_eq!(slot.load(&cx, &authorization).unwrap(), Some(Vec::new()));
    let take = slot.prepare_take(&cx, &authorization, first).unwrap();
    let commit = slot.commit(&cx, &authorization, take).unwrap();
    let tombstone = commit.revision();
    assert_eq!(commit.into_consumed(), Some(Vec::new()));
    assert_eq!(slot.load(&cx, &authorization).unwrap(), None);
    let maximum = slot.maximum_payload_bytes();
    assert!(maximum < 128);
    assert_eq!(slot.prepare_replace(&cx, &authorization, Some(tombstone), &vec![1; maximum + 1]).err(), Some(CredentialSlotError::Storage(AtomicFileError::TooLarge)));
    let boundary = slot.prepare_replace(&cx, &authorization, Some(tombstone), &vec![2; maximum]).unwrap();
    slot.commit(&cx, &authorization, boundary).unwrap();
    assert_eq!(fs::metadata(directory.file("credential")).unwrap().len(), 128);
    assert_eq!(slot.load(&cx, &authorization).unwrap(), Some(vec![2; maximum]));
}

#[test]
fn invalid_slot_framing_and_trusted_anchor_encodings_fail_closed() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let (key, authorization) = partition("alice", 1);
    let mut slot = slot(&directory, &cx, &key, &authorization, None);
    let prepared = slot.prepare_replace(&cx, &authorization, None, b"exact").unwrap();
    let intent = prepared.intent();
    let revision = slot.commit(&cx, &authorization, prepared).unwrap().revision();
    let original = fs::read(directory.file("credential")).unwrap();
    drop(slot);
    for malformed in [b"".to_vec(), b"FCPSLOT\0".to_vec(), {
        let mut bytes = original.clone();
        bytes[82] = 2; // Invalid kind, not an empty record.
        bytes
    }, {
        let mut bytes = original.clone();
        bytes.push(0); // Trailing bytes disagree with the exact payload length.
        bytes
    }] {
        fs::write(directory.file("credential"), &malformed).unwrap();
        assert_eq!(
            DurableCredentialSlot::open(&cx, directory.open(&cx, 4096), &key, &authorization, Some(revision)).err(),
            Some(CredentialSlotError::InvalidRecord),
        );
        assert_eq!(fs::read(directory.file("credential")).unwrap(), malformed);
    }
    assert_eq!(SlotRevision::from_trusted_bytes(&[0; SLOT_REVISION_BYTES]).err(), Some(CredentialSlotError::InvalidRecord));
    assert_eq!(SlotRevision::from_trusted_bytes(&revision.to_bytes()[..39]).err(), Some(CredentialSlotError::InvalidRecord));
    assert_eq!(SlotCommitIntent::from_trusted_bytes(&[0; SLOT_INTENT_BYTES]).err(), Some(CredentialSlotError::InvalidRecord));
    let mut invalid_intent = intent.to_bytes();
    invalid_intent[72] = 2;
    assert_eq!(SlotCommitIntent::from_trusted_bytes(&invalid_intent).err(), Some(CredentialSlotError::InvalidRecord));
    assert_eq!(SlotCommitIntent::from_trusted_bytes(&intent.to_bytes()).unwrap(), intent);
}

#[test]
fn exhausted_generation_cannot_wrap_or_modify_the_existing_record() {
    let directory = TestDirectory::new();
    let cx = Cx::for_testing();
    let (key, authorization) = partition("alice", 1);
    let mut slot = slot(&directory, &cx, &key, &authorization, None);
    let create = slot.prepare_replace(&cx, &authorization, None, b"last").unwrap();
    slot.commit(&cx, &authorization, create).unwrap();
    drop(slot);
    let mut bytes = fs::read(directory.file("credential")).unwrap();
    bytes[74..82].copy_from_slice(&u64::MAX.to_be_bytes());
    fs::write(directory.file("credential"), &bytes).unwrap();
    let digest = fastmcp_core::crypto::sha256_bounded(&bytes, 4096).unwrap();
    let mut anchor = [0; SLOT_REVISION_BYTES];
    anchor[..8].copy_from_slice(&u64::MAX.to_be_bytes());
    anchor[8..].copy_from_slice(digest.as_bytes());
    let revision = SlotRevision::from_trusted_bytes(&anchor).unwrap();
    let slot = self::slot(&directory, &cx, &key, &authorization, Some(revision));
    assert_eq!(slot.prepare_replace(&cx, &authorization, Some(revision), b"wrap").err(), Some(CredentialSlotError::GenerationExhausted));
    assert_eq!(slot.prepare_take(&cx, &authorization, revision).err(), Some(CredentialSlotError::GenerationExhausted));
    assert_eq!(slot.load(&cx, &authorization).unwrap(), Some(b"last".to_vec()));
    assert_eq!(fs::read(directory.file("credential")).unwrap(), bytes);
}
