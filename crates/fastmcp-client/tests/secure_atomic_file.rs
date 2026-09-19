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
