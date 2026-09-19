//! Linux descriptor-relative atomic storage for protected credential blobs.
//!
//! The caller supplies an already-open, owner-private directory. No ambient
//! home directory, pathname traversal, runtime, key, or plaintext fallback is
//! introduced. All namespace operations are relative to that retained handle.
//! The fixed lock file is never removed: replacing a lock inode would let two
//! independent writers both believe they own the same slot.
//!
//! This is the filesystem portion of FND-07/AUTH-05, **not encryption**. Callers
//! must protect secrets with their admitted credential-envelope provider before
//! passing bytes here. The SHA-256 revision is a compare-and-swap identity, not
//! authentication or an anti-rollback anchor. No OAuth token is automatically
//! serialized or persisted by this module.
//!
//! These are synchronous, bounded-size filesystem operations. The caller must
//! run them in its owned blocking-I/O lane. Checkpoints prevent starting another
//! operation after cancellation, but cannot preempt a syscall already executing.
//! After rename, directory synchronization is completed even if cancellation
//! arrives: reporting a retryable cancellation then would conceal a commit.
//! Local filesystem rename/fsync/locking semantics are required; distributed
//! filesystems, hostile same-UID processes, inherited handles after fork, and
//! macOS ACLs, and Windows DACL/reparse behavior are outside this implementation's
//! boundary. The API is absent on those platforms rather than inferring private
//! access from Unix mode bits where extended ACLs can independently grant it.

use std::fmt;
use std::fs::{File, Metadata, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use asupersync::Cx;
use fastmcp_core::crypto::{draw_security_identifier, sha256_bounded};
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, flock, openat, renameat, statat, unlinkat};
use rustix::io::Errno;

/// Hard allocation and on-disk payload ceiling. A store can choose a lower one.
pub const MAX_ATOMIC_FILE_BYTES: usize = 1024 * 1024;
const MAX_LEAF_BYTES: usize = 96;

/// Opaque identity of the complete bytes observed in one slot.
///
/// Equality detects a stale snapshot, not malicious replacement or ABA. A
/// higher-level credential record must bind its own authenticated generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicFileVersion([u8; 32]);

/// A bounded read of one complete file. Diagnostic output never includes bytes.
pub struct AtomicFileSnapshot {
    version: AtomicFileVersion,
    bytes: Vec<u8>,
}

impl AtomicFileSnapshot {
    pub fn version(&self) -> AtomicFileVersion {
        self.version
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Debug for AtomicFileSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AtomicFileSnapshot")
            .field("version", &self.version)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

/// Sanitized storage refusals. No path, blob, credential, or OS error text is
/// retained. `CommitUncertain` is deliberately different from a precommit error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicFileError {
    InvalidName,
    InvalidLimit,
    UnsafeDirectory,
    UnsafeFile,
    LockReplaced,
    Busy,
    TooLarge,
    Conflict,
    RandomUnavailable,
    EntropyUnavailable,
    Cancelled,
    TimedOut,
    Io,
    RecoveryRequired,
    /// Rename happened, but directory durability could not be established.
    /// Do not repeat the operation blindly. Use `reconcile` under the same lock.
    CommitUncertain { attempted: AtomicFileVersion },
}

impl fmt::Display for AtomicFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidName => "atomic file requires one bounded ASCII leaf name",
            Self::InvalidLimit => "atomic file byte limit is invalid",
            Self::UnsafeDirectory => "atomic file directory is not owner-private",
            Self::UnsafeFile => "atomic file is not an owner-private single-link regular file",
            Self::LockReplaced => "atomic file lock identity changed",
            Self::Busy => "atomic file is owned by another writer",
            Self::TooLarge => "atomic file exceeds its configured byte limit",
            Self::Conflict => "atomic file changed since the supplied snapshot",
            Self::RandomUnavailable => "atomic file temporary-name randomness unavailable",
            Self::EntropyUnavailable => "atomic file caller lacks entropy authority",
            Self::Cancelled => "atomic file operation cancelled before commit",
            Self::TimedOut => "atomic file operation deadline exceeded before commit",
            Self::Io => "atomic file filesystem operation failed",
            Self::RecoveryRequired => "atomic file requires explicit commit reconciliation",
            Self::CommitUncertain { .. } => "atomic file rename completed but durability is uncertain",
        })
    }
}

impl std::error::Error for AtomicFileError {}

/// Exclusive, owner-private storage of a single bounded opaque blob.
///
/// The directory and advisory writer lock are retained for this handle's
/// lifetime. Another independently opened handle receives `Busy`, without
/// blocking an executor thread. Dropping the handle releases the lock but never
/// unlinks its inode. Access is confined to `leaf` and this slot's private
/// lock/temporary names; callers cannot supply absolute or relative paths.
pub struct SecureAtomicFile {
    directory: File,
    lock: File,
    leaf: String,
    lock_leaf: String,
    maximum_bytes: usize,
    recovery_required: bool,
}

impl SecureAtomicFile {
    /// Opens a slot relative to a caller-owned directory handle. The directory
    /// must belong to the effective user and have exactly mode 0700. Existing
    /// files must have mode 0600, one link, and that same owner. Symlinks and
    /// special files are refused; a FIFO cannot block the type check.
    pub fn open(
        cx: &Cx,
        directory: File,
        leaf: &str,
        maximum_bytes: usize,
    ) -> Result<Self, AtomicFileError> {
        checkpoint(cx)?;
        validate_name(leaf)?;
        if maximum_bytes == 0 || maximum_bytes > MAX_ATOMIC_FILE_BYTES {
            return Err(AtomicFileError::InvalidLimit);
        }
        validate_directory(&directory)?;
        let lock_leaf = format!(".{leaf}.lock");
        let (lock, created) = match openat(
            &directory,
            lock_leaf.as_str(),
            private_open_flags() | OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => (File::from(fd), true),
            Err(Errno::EXIST) => (
                File::from(openat(
                    &directory,
                    lock_leaf.as_str(),
                    private_open_flags() | OFlags::RDWR,
                    Mode::empty(),
                ).map_err(|_| AtomicFileError::UnsafeFile)?),
                false,
            ),
            Err(_) => return Err(AtomicFileError::Io),
        };
        if created {
            // Defeat an unusually restrictive umask only on our new inode.
            // Existing permissions are inspected, never silently repaired.
            lock.set_permissions(Permissions::from_mode(0o600))
                .map_err(|_| AtomicFileError::Io)?;
        }
        validate_regular(&lock.metadata().map_err(|_| AtomicFileError::Io)?)?;
        checkpoint(cx)?;
        match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(Errno::WOULDBLOCK) => return Err(AtomicFileError::Busy),
            Err(_) => return Err(AtomicFileError::Io),
        }
        let store = Self {
            directory,
            lock,
            leaf: leaf.to_owned(),
            lock_leaf,
            maximum_bytes,
            recovery_required: false,
        };
        store.validate_authority()?;
        // Persist creation of the stable lock inode before a payload can commit.
        // A pre-existing lock may have been left by an interrupted first opener.
        checkpoint(cx)?;
        store.lock.sync_all().map_err(|_| AtomicFileError::Io)?;
        checkpoint(cx)?;
        store.directory.sync_all().map_err(|_| AtomicFileError::Io)?;
        store.read_current(cx)?;
        Ok(store)
    }

    pub fn maximum_bytes(&self) -> usize {
        self.maximum_bytes
    }

    /// Reads the entire bounded file through a no-follow descriptor. Absence is
    /// distinct from an empty file, an unsafe file, or an I/O error.
    pub fn load(&self, cx: &Cx) -> Result<Option<AtomicFileSnapshot>, AtomicFileError> {
        self.admit(cx)?;
        self.read_current(cx)
    }

    /// Atomically replaces exactly the supplied version. `None` requires an
    /// absent target. Every ordinary error occurs before rename and leaves the
    /// previous target unchanged. A successfully synchronized rename is returned
    /// as success even if the caller cancels during final synchronization.
    pub fn replace(
        &mut self,
        cx: &Cx,
        expected: Option<AtomicFileVersion>,
        bytes: &[u8],
    ) -> Result<AtomicFileVersion, AtomicFileError> {
        self.admit(cx)?;
        if bytes.len() > self.maximum_bytes {
            return Err(AtomicFileError::TooLarge);
        }
        self.check_expected(cx, expected)?;
        let version = version(bytes)?;
        if !cx.capabilities().entropy {
            return Err(AtomicFileError::EntropyUnavailable);
        }
        let mut temporary = self.create_temporary(cx)?;
        write_bounded(cx, &mut temporary.file, bytes)?;
        checkpoint(cx)?;
        temporary.file.sync_all().map_err(|_| AtomicFileError::Io)?;
        // Recheck both namespace authority and target identity at the commit
        // boundary. A caller must not silently adopt a replaced lock or target.
        self.validate_authority()?;
        self.check_expected(cx, expected)?;
        checkpoint(cx)?;
        renameat(
            &self.directory,
            temporary.leaf.as_str(),
            &self.directory,
            self.leaf.as_str(),
        ).map_err(|_| AtomicFileError::Io)?;
        temporary.renamed = true;
        drop(temporary);
        // No cancellation checkpoint is legal between rename and this durability
        // result: the visible mutation has already happened.
        if self.directory.sync_all().is_err() {
            self.recovery_required = true;
            return Err(AtomicFileError::CommitUncertain { attempted: version });
        }
        Ok(version)
    }

    /// Resolves an uncertain commit by rereading the actual target and syncing
    /// its directory while retaining the writer lock. It does not guess whether
    /// the attempted or previous value won. The caller must compare the returned
    /// version to its retained intent before deciding what to do next.
    pub fn reconcile(&mut self, cx: &Cx) -> Result<Option<AtomicFileSnapshot>, AtomicFileError> {
        checkpoint(cx)?;
        self.validate_authority()?;
        let current = self.read_current(cx)?;
        checkpoint(cx)?;
        self.directory.sync_all().map_err(|_| AtomicFileError::RecoveryRequired)?;
        self.recovery_required = false;
        Ok(current)
    }

    fn admit(&self, cx: &Cx) -> Result<(), AtomicFileError> {
        checkpoint(cx)?;
        if self.recovery_required {
            return Err(AtomicFileError::RecoveryRequired);
        }
        self.validate_authority()
    }

    fn validate_authority(&self) -> Result<(), AtomicFileError> {
        validate_directory(&self.directory)?;
        let held = self.lock.metadata().map_err(|_| AtomicFileError::Io)?;
        validate_regular(&held)?;
        let named = statat(&self.directory, self.lock_leaf.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| AtomicFileError::LockReplaced)?;
        if named.st_dev != held.dev() || named.st_ino != held.ino() {
            return Err(AtomicFileError::LockReplaced);
        }
        Ok(())
    }

    fn check_expected(&self, cx: &Cx, expected: Option<AtomicFileVersion>) -> Result<(), AtomicFileError> {
        let observed = self.read_current(cx)?.map(|snapshot| snapshot.version);
        if observed != expected {
            return Err(AtomicFileError::Conflict);
        }
        Ok(())
    }

    fn read_current(&self, cx: &Cx) -> Result<Option<AtomicFileSnapshot>, AtomicFileError> {
        checkpoint(cx)?;
        let mut file = match openat(
            &self.directory,
            self.leaf.as_str(),
            private_open_flags() | OFlags::RDONLY,
            Mode::empty(),
        ) {
            Ok(fd) => File::from(fd),
            Err(Errno::NOENT) => return Ok(None),
            Err(Errno::LOOP) => return Err(AtomicFileError::UnsafeFile),
            Err(_) => return Err(AtomicFileError::Io),
        };
        let metadata = file.metadata().map_err(|_| AtomicFileError::Io)?;
        validate_regular(&metadata)?;
        if metadata.len() > self.maximum_bytes as u64 {
            return Err(AtomicFileError::TooLarge);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        let mut buffer = [0_u8; 8192];
        loop {
            checkpoint(cx)?;
            // One extra byte detects growth without allowing an unbounded read.
            let remaining = self.maximum_bytes - bytes.len();
            let read_limit = buffer.len().min(remaining.saturating_add(1));
            let count = match file.read(&mut buffer[..read_limit]) {
                Ok(0) => break,
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(AtomicFileError::Io),
            };
            if count > remaining {
                return Err(AtomicFileError::TooLarge);
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        checkpoint(cx)?;
        let after = file.metadata().map_err(|_| AtomicFileError::Io)?;
        validate_regular(&after)?;
        if after.len() != bytes.len() as u64 || metadata.len() != after.len() {
            return Err(AtomicFileError::Conflict);
        }
        Ok(Some(AtomicFileSnapshot { version: version(&bytes)?, bytes }))
    }

    fn create_temporary<'a>(&'a self, cx: &Cx) -> Result<Temporary<'a>, AtomicFileError> {
        for _ in 0..4 {
            checkpoint(cx)?;
            let random = draw_security_identifier().map_err(|_| AtomicFileError::RandomUnavailable)?;
            let mut leaf = format!(".{}.tmp-", self.leaf);
            for byte in random.as_bytes() {
                use std::fmt::Write as _;
                write!(&mut leaf, "{byte:02x}").map_err(|_| AtomicFileError::Io)?;
            }
            match openat(
                &self.directory,
                leaf.as_str(),
                private_open_flags() | OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(fd) => {
                    let temporary = Temporary {
                        directory: &self.directory,
                        file: File::from(fd),
                        leaf,
                        renamed: false,
                    };
                    temporary.file.set_permissions(Permissions::from_mode(0o600))
                        .map_err(|_| AtomicFileError::Io)?;
                    validate_regular(&temporary.file.metadata().map_err(|_| AtomicFileError::Io)?)?;
                    return Ok(temporary);
                }
                Err(Errno::EXIST) => continue,
                Err(_) => return Err(AtomicFileError::Io),
            }
        }
        Err(AtomicFileError::RandomUnavailable)
    }
}

struct Temporary<'a> {
    directory: &'a File,
    file: File,
    leaf: String,
    renamed: bool,
}

impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        if !self.renamed {
            // Only our exact temporary inode may be removed. Never clean up by
            // prefix, and never delete a recovered or another writer's file.
            if let (Ok(held), Ok(named)) = (
                self.file.metadata(),
                statat(self.directory, self.leaf.as_str(), AtFlags::SYMLINK_NOFOLLOW),
            ) {
                if named.st_dev == held.dev() && named.st_ino == held.ino() {
                    let _ = unlinkat(self.directory, self.leaf.as_str(), AtFlags::empty());
                }
            }
        }
    }
}

fn private_open_flags() -> OFlags {
    OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK
}

fn validate_name(name: &str) -> Result<(), AtomicFileError> {
    if name.is_empty() || name.len() > MAX_LEAF_BYTES
        || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AtomicFileError::InvalidName);
    }
    Ok(())
}

fn validate_directory(directory: &File) -> Result<(), AtomicFileError> {
    let metadata = directory.metadata().map_err(|_| AtomicFileError::Io)?;
    if !metadata.is_dir() || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(AtomicFileError::UnsafeDirectory);
    }
    Ok(())
}

fn validate_regular(metadata: &Metadata) -> Result<(), AtomicFileError> {
    if !metadata.is_file() || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600 || metadata.nlink() != 1
    {
        return Err(AtomicFileError::UnsafeFile);
    }
    Ok(())
}

fn version(bytes: &[u8]) -> Result<AtomicFileVersion, AtomicFileError> {
    sha256_bounded(bytes, MAX_ATOMIC_FILE_BYTES)
        .map(|digest| AtomicFileVersion(digest.into_bytes()))
        .map_err(|_| AtomicFileError::TooLarge)
}

fn write_bounded(cx: &Cx, file: &mut File, mut bytes: &[u8]) -> Result<(), AtomicFileError> {
    while !bytes.is_empty() {
        checkpoint(cx)?;
        match file.write(bytes) {
            Ok(0) => return Err(AtomicFileError::Io),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(AtomicFileError::Io),
        }
    }
    Ok(())
}

fn checkpoint(cx: &Cx) -> Result<(), AtomicFileError> {
    cx.checkpoint().map_err(|error| {
        use asupersync::{CancelKind, error::ErrorKind};
        match cx.cancel_reason().map(|reason| reason.kind) {
            Some(CancelKind::Deadline | CancelKind::Timeout) => AtomicFileError::TimedOut,
            Some(_) => AtomicFileError::Cancelled,
            None => match error.kind() {
                ErrorKind::DeadlineExceeded | ErrorKind::CancelTimeout => AtomicFileError::TimedOut,
                _ => AtomicFileError::Cancelled,
            },
        }
    })
}
