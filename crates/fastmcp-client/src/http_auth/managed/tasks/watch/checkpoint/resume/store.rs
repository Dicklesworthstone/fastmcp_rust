//! Bounded atomic storage of caller-protected Task resume records.
//!
//! This is a durable FILE adapter, not a bundled key-custody provider. The host
//! must install a reviewed restart-capable authenticated-encryption provider;
//! no plaintext/default/ephemeral protector is supplied. The provider binds
//! the complete manifest to the expected owner/configuration associated data.
//!
//! All methods are synchronous and must execute in the caller's owned blocking
//! I/O lane, just like SecureAtomicFile. No runtime or detached worker is made.
//! A successful mutation follows file and directory synchronization. Uncertain
//! rename outcomes quarantine this owner until exact-version reconciliation.
//! Removal writes an authenticated empty/updated manifest, never unlinks the
//! lock. Valid old checkpoints are NOT independent anti-rollback evidence:
//! restart must always reauthorize and read current remote Task state.

use std::collections::BTreeMap;
use std::fmt;

use asupersync::Cx;
use fastmcp_core::runtime::ProcessBoundToken;
use crate::http_auth::secure_file::{AtomicFileError, AtomicFileSnapshot, AtomicFileVersion, SecureAtomicFile};

use super::{
    Reader, TaskResumeBinding, TaskResumeError, TaskResumeKey, TaskResumeRecord,
    MAX_TASK_RESUME_RECORD_BYTES, checkpoint, timestamp_nanos, wall_now,
};

const STORE_MAGIC: &[u8; 8] = b"FMTRST01";
const MAX_RECORDS: usize = 128;
const MAX_BYTES: usize = 1024 * 1024;

/// Host-supplied durable authenticated encryption and key custody.
///
/// Implementations must authenticate BOTH the ciphertext and `associated_data`,
/// enforce purpose separation, bound all work/output, support reopening after
/// process restart and refuse unavailable/revoked keys. `profile` is the
/// deployment's pinned provider/configuration identity, not an attestation.
/// Its correctness and confidentiality are provider qualification obligations;
/// merely implementing this trait cannot prove them. Checkpoints never carry
/// encryption keys. A provider failure never enables a plaintext fallback.
pub trait TaskResumeProtector: Send {
    fn profile(&self) -> [u8; 32];
    fn seal(
        &mut self, cx: &Cx, associated_data: &[u8; 32], plaintext: &[u8], maximum_output: usize,
    ) -> Result<Vec<u8>, TaskResumeError>;
    fn open(
        &mut self, cx: &Cx, associated_data: &[u8; 32], ciphertext: &[u8], maximum_output: usize,
    ) -> Result<Vec<u8>, TaskResumeError>;
}

#[derive(Clone, Copy, Debug)]
pub struct TaskResumeStoreLimits { records: usize, plaintext_bytes: usize }
impl Default for TaskResumeStoreLimits {
    fn default() -> Self { Self { records: 128, plaintext_bytes: 512 * 1024 } }
}
impl TaskResumeStoreLimits {
    pub fn new(records: usize, plaintext_bytes: usize) -> Result<Self, TaskResumeError> {
        if !(1..=MAX_RECORDS).contains(&records) || !(64..=MAX_BYTES).contains(&plaintext_bytes) {
            return Err(TaskResumeError::Capacity);
        }
        Ok(Self { records, plaintext_bytes })
    }
}

#[derive(Debug)]
pub enum TaskResumeStoreError {
    Resume(TaskResumeError),
    Storage(AtomicFileError),
}
impl fmt::Display for TaskResumeStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::Resume(error) => error.fmt(f), Self::Storage(error) => error.fmt(f) }
    }
}
impl std::error::Error for TaskResumeStoreError {}
impl From<TaskResumeError> for TaskResumeStoreError {
    fn from(error: TaskResumeError) -> Self { Self::Resume(error) }
}
impl From<AtomicFileError> for TaskResumeStoreError {
    fn from(error: AtomicFileError) -> Self { Self::Storage(error) }
}

/// Opaque cursor bound to this authenticated manifest generation. Mutation
/// invalidates it; pagination cannot silently switch to a different snapshot.
#[derive(Clone)]
pub struct TaskResumeCursor { binding: [u8; 32], generation: u64, after: TaskResumeKey }

pub struct TaskResumePage {
    pub keys: Vec<TaskResumeKey>,
    pub next: Option<TaskResumeCursor>,
}

#[derive(Clone, Default)]
struct Manifest { generation: u64, records: BTreeMap<TaskResumeKey, TaskResumeRecord> }

impl Manifest {
    fn encode(&self, binding: &TaskResumeBinding, limits: TaskResumeStoreLimits) -> Result<Vec<u8>, TaskResumeError> {
        if self.generation == 0 || self.records.len() > limits.records { return Err(TaskResumeError::Capacity); }
        let mut bytes = STORE_MAGIC.to_vec();
        bytes.extend_from_slice(&binding.digest);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&(self.records.len() as u16).to_be_bytes());
        for (key, record) in &self.records {
            if record.binding != binding.digest || *key != record.key() { return Err(TaskResumeError::Unavailable); }
            let encoded = record.encode()?;
            let needed = bytes.len().checked_add(36).and_then(|n| n.checked_add(encoded.len()))
                .ok_or(TaskResumeError::TooLarge)?;
            if needed > limits.plaintext_bytes { return Err(TaskResumeError::TooLarge); }
            bytes.extend_from_slice(key.as_bytes());
            bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&encoded);
        }
        if bytes.len() > limits.plaintext_bytes { return Err(TaskResumeError::TooLarge); }
        Ok(bytes)
    }

    fn decode(bytes: &[u8], binding: &TaskResumeBinding, limits: TaskResumeStoreLimits) -> Result<Self, TaskResumeError> {
        if bytes.len() > limits.plaintext_bytes { return Err(TaskResumeError::TooLarge); }
        let mut reader = Reader(bytes);
        if reader.take(8)? != STORE_MAGIC { return Err(TaskResumeError::InvalidRecord); }
        if reader.take(32)? != binding.digest { return Err(TaskResumeError::Unavailable); }
        let generation = u64::from_be_bytes(reader.take(8)?.try_into().map_err(|_| TaskResumeError::InvalidRecord)?);
        if generation == 0 { return Err(TaskResumeError::InvalidRecord); }
        let count = usize::from(reader.u16()?);
        if count > limits.records { return Err(TaskResumeError::Capacity); }
        let mut records = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let key = TaskResumeKey(reader.take(32)?.try_into().map_err(|_| TaskResumeError::InvalidRecord)?);
            if previous.is_some_and(|previous| previous >= key) { return Err(TaskResumeError::InvalidRecord); }
            let length = u32::from_be_bytes(reader.take(4)?.try_into().map_err(|_| TaskResumeError::InvalidRecord)?);
            let length = usize::try_from(length).map_err(|_| TaskResumeError::TooLarge)?;
            if length > MAX_TASK_RESUME_RECORD_BYTES { return Err(TaskResumeError::TooLarge); }
            let record = TaskResumeRecord::decode(reader.take(length)?)?;
            if record.binding != binding.digest || record.key() != key { return Err(TaskResumeError::Unavailable); }
            records.insert(key, record);
            previous = Some(key);
        }
        if !reader.0.is_empty() { return Err(TaskResumeError::InvalidRecord); }
        Ok(Self { generation, records })
    }

    // Absence means no physical manifest slot, not get()'s filtered view.
    // Expired records must not turn a repeated initial write into an upsert.
    fn insert(&self, record: TaskResumeRecord, now: i128, limits: TaskResumeStoreLimits) -> Result<Self, TaskResumeError> {
        if self.records.contains_key(&record.key()) { return Err(TaskResumeError::ConflictingSnapshot); }
        self.put(record, now, limits)
    }

    fn put(&self, mut record: TaskResumeRecord, now: i128, limits: TaskResumeStoreLimits) -> Result<Self, TaskResumeError> {
        let key = record.key();
        if let Some(previous) = self.records.get(&key) {
            if previous.task_id != record.task_id || previous.binding != record.binding
                || timestamp_nanos(&previous.created_at)? != timestamp_nanos(&record.created_at)?
                || previous.ttl_ms != record.ttl_ms
            { return Err(TaskResumeError::ConflictingSnapshot); }
            let old_time = timestamp_nanos(&previous.updated_at)?;
            let new_time = timestamp_nanos(&record.updated_at)?;
            if new_time < old_time { return Err(TaskResumeError::StaleSnapshot); }
            if new_time == old_time && (previous.status != record.status || previous.poll_interval_ms != record.poll_interval_ms) {
                return Err(TaskResumeError::ConflictingSnapshot);
            }
            // A keepalive/update cannot silently refresh an existing record's
            // original retention budget, even for a null-TTL remote Task.
            record.retain_until = record.retain_until.min(previous.retain_until);
            if now >= record.retain_until { return Err(TaskResumeError::Unavailable); }
        }
        let mut next = self.clone();
        next.records.retain(|_, record| now < record.retain_until);
        if !next.records.contains_key(&key) && next.records.len() >= limits.records { return Err(TaskResumeError::Capacity); }
        next.records.insert(key, record);
        Ok(next)
    }
}

/// One exclusive, bounded manifest of protected Task checkpoints.
///
/// The caller passes an already-open SecureAtomicFile, process-generation
/// authority and a restart-capable protector. Its directory remains under the
/// caller's filesystem custody. Only opaque TaskResumeKey values select records;
/// a raw Task ID is never used as a filename or provider key.
///
/// Opening decodes the whole bounded manifest, not an unbounded directory scan.
/// Quotas include expired records until pruning/another mutation commits. No
/// stored result or record can initiate a tool call, input update or cancellation.
pub struct TaskResumeStore<P> {
    file: SecureAtomicFile,
    process: ProcessBoundToken,
    protector: P,
    binding: TaskResumeBinding,
    limits: TaskResumeStoreLimits,
    manifest: Manifest,
    revision: Option<AtomicFileVersion>,
    uncertain: Option<(Option<AtomicFileVersion>, AtomicFileVersion)>,
}

impl<P: TaskResumeProtector> TaskResumeStore<P> {
    pub fn open(
        cx: &Cx, process: ProcessBoundToken, file: SecureAtomicFile,
        mut protector: P, binding: TaskResumeBinding, limits: TaskResumeStoreLimits,
    ) -> Result<Self, TaskResumeStoreError> {
        checkpoint(cx)?;
        process.verify().map_err(|_| TaskResumeError::ProcessChanged)?;
        if protector.profile() != binding.protection_profile { return Err(TaskResumeError::Protection.into()); }
        if file.maximum_bytes() > MAX_BYTES { return Err(TaskResumeError::TooLarge.into()); }
        let snapshot = file.load(cx)?;
        let (revision, manifest) = decode_file(cx, &mut protector, &binding, limits, snapshot)?;
        checkpoint(cx)?;
        Ok(Self { file, process, protector, binding, limits, manifest, revision, uncertain: None })
    }

    fn admit(&self, cx: &Cx, current: &TaskResumeBinding) -> Result<(), TaskResumeStoreError> {
        checkpoint(cx)?;
        self.process.verify().map_err(|_| TaskResumeError::ProcessChanged)?;
        if self.binding.digest != current.digest { return Err(TaskResumeError::Unavailable.into()); }
        if self.uncertain.is_some() { return Err(TaskResumeError::RecoveryRequired.into()); }
        Ok(())
    }

    /// The caller supplies current verified binding BEFORE any record lookup.
    /// Expired or absent keys both return None; wrong binding reveals no record.
    pub fn get(&self, cx: &Cx, current: &TaskResumeBinding, key: TaskResumeKey)
        -> Result<Option<TaskResumeRecord>, TaskResumeStoreError>
    {
        self.admit(cx, current)?;
        Ok(self.manifest.records.get(&key).filter(|record| wall_now() < record.retain_until).cloned())
    }

    /// Insert a newly accepted Task only when its manifest slot is absent.
    /// Even an identical or expired-but-unpruned record is a conflict, before
    /// protection or filesystem mutation. This is NOT an idempotent retry API.
    /// Quotas, process authority and uncertain-commit quarantine are unchanged.
    /// A successful return follows the same synchronized write as put().
    pub fn insert(&mut self, cx: &Cx, current: &TaskResumeBinding, record: TaskResumeRecord)
        -> Result<TaskResumeKey, TaskResumeStoreError>
    {
        self.admit(cx, current)?;
        let now = wall_now();
        record.validate()?;
        record.admit_at(current, now)?;
        let key = record.key();
        let next = self.manifest.insert(record, now, self.limits)?;
        self.commit(cx, next)?;
        Ok(key)
    }

    /// Atomically persists the complete protected manifest. A returned key is
    /// durable only after the existing file primitive has synchronized it.
    pub fn put(&mut self, cx: &Cx, current: &TaskResumeBinding, record: TaskResumeRecord)
        -> Result<TaskResumeKey, TaskResumeStoreError>
    {
        self.admit(cx, current)?;
        let now = wall_now();
        record.validate()?;
        record.admit_at(current, now)?;
        let key = record.key();
        let next = self.manifest.put(record, now, self.limits)?;
        self.commit(cx, next)?;
        Ok(key)
    }

    /// Terminal, not-found, expired or explicitly discarded checkpoints are
    /// removed by a synchronized manifest replacement, not by unlinking a slot.
    pub fn remove(&mut self, cx: &Cx, current: &TaskResumeBinding, key: TaskResumeKey)
        -> Result<bool, TaskResumeStoreError>
    {
        self.admit(cx, current)?;
        if !self.manifest.records.contains_key(&key) { return Ok(false); }
        let mut next = self.manifest.clone();
        next.records.remove(&key);
        self.commit(cx, next)?;
        Ok(true)
    }

    pub fn prune_expired(&mut self, cx: &Cx, current: &TaskResumeBinding) -> Result<usize, TaskResumeStoreError> {
        self.admit(cx, current)?;
        let mut next = self.manifest.clone();
        let now = wall_now();
        next.records.retain(|_, record| now < record.retain_until);
        let removed = self.manifest.records.len() - next.records.len();
        if removed != 0 { self.commit(cx, next)?; }
        Ok(removed)
    }

    pub fn page(
        &self, cx: &Cx, current: &TaskResumeBinding, cursor: Option<&TaskResumeCursor>, limit: usize,
    ) -> Result<TaskResumePage, TaskResumeStoreError> {
        self.admit(cx, current)?;
        if !(1..=MAX_RECORDS).contains(&limit) { return Err(TaskResumeError::Capacity.into()); }
        if cursor.is_some_and(|cursor| cursor.binding != current.digest || cursor.generation != self.manifest.generation) {
            return Err(TaskResumeError::StaleCursor.into());
        }
        let mut keys = Vec::with_capacity(limit.min(self.manifest.records.len()));
        let mut more = false;
        let now = wall_now();
        for (key, record) in &self.manifest.records {
            if cursor.is_some_and(|cursor| *key <= cursor.after) || now >= record.retain_until { continue; }
            if keys.len() == limit { more = true; break; }
            keys.push(*key);
        }
        let next = if more {
            keys.last().copied().map(|after| TaskResumeCursor { binding: current.digest, generation: self.manifest.generation, after })
        } else { None };
        Ok(TaskResumePage { keys, next })
    }

    fn commit(&mut self, cx: &Cx, mut next: Manifest) -> Result<(), TaskResumeStoreError> {
        next.generation = self.manifest.generation.checked_add(1).ok_or(TaskResumeError::GenerationExhausted)?;
        // Count and complete encoded-byte admission precede the protector and
        // filesystem mutation. Providers receive the same finite output cap.
        let plaintext = next.encode(&self.binding, self.limits)?;
        checkpoint(cx)?;
        let ciphertext = self.protector.seal(cx, &self.binding.digest, &plaintext, self.file.maximum_bytes())
            .map_err(|_| TaskResumeError::Protection)?;
        if ciphertext.is_empty() || ciphertext.len() > self.file.maximum_bytes() { return Err(TaskResumeError::Protection.into()); }
        checkpoint(cx)?;
        let revision = match self.file.replace(cx, self.revision, &ciphertext) {
            Ok(revision) => revision,
            Err(error @ AtomicFileError::CommitUncertain { attempted }) => {
                self.uncertain = Some((self.revision, attempted));
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        };
        // No post-commit cancellation rewrite: committed storage is committed.
        self.revision = Some(revision);
        self.manifest = next;
        Ok(())
    }

    /// Reconciles ONLY the exact previous or attempted ciphertext identity.
    /// A third version, provider failure or malformed manifest stays quarantined.
    /// This does not retry the mutation or claim an independent rollback anchor.
    pub fn reconcile(&mut self, cx: &Cx, current: &TaskResumeBinding) -> Result<(), TaskResumeStoreError> {
        checkpoint(cx)?;
        self.process.verify().map_err(|_| TaskResumeError::ProcessChanged)?;
        if self.binding.digest != current.digest { return Err(TaskResumeError::Unavailable.into()); }
        let Some((previous, attempted)) = self.uncertain else { return Ok(()); };
        let snapshot = self.file.reconcile(cx)?;
        let observed = snapshot.as_ref().map(AtomicFileSnapshot::version);
        if observed != previous && observed != Some(attempted) { return Err(TaskResumeError::RecoveryRequired.into()); }
        let (revision, manifest) = decode_file(cx, &mut self.protector, current, self.limits, snapshot)?;
        checkpoint(cx)?;
        self.revision = revision;
        self.manifest = manifest;
        self.uncertain = None;
        Ok(())
    }
}

fn decode_file<P: TaskResumeProtector>(
    cx: &Cx, protector: &mut P, binding: &TaskResumeBinding, limits: TaskResumeStoreLimits,
    snapshot: Option<AtomicFileSnapshot>,
) -> Result<(Option<AtomicFileVersion>, Manifest), TaskResumeStoreError> {
    let Some(snapshot) = snapshot else { return Ok((None, Manifest::default())); };
    if snapshot.bytes().is_empty() { return Err(TaskResumeError::InvalidRecord.into()); }
    let plaintext = protector.open(cx, &binding.digest, snapshot.bytes(), limits.plaintext_bytes)
        .map_err(|_| TaskResumeError::Protection)?;
    checkpoint(cx)?;
    let manifest = Manifest::decode(&plaintext, binding, limits)?;
    Ok((Some(snapshot.version()), manifest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests::{binding, now, record};

    fn populated() -> Manifest {
        let record = record();
        Manifest { generation: 1, records: BTreeMap::from([(record.key(), record)]) }
    }

    #[test]
    fn initial_insert_cannot_overwrite_even_identical_or_expired_slots() {
        let original = populated();
        let limits = TaskResumeStoreLimits::default();
        let before = original.encode(&binding(1), limits).unwrap();
        for instant in [now(), record().retain_until, record().retain_until + 1] {
            assert!(matches!(original.insert(record(), instant, limits), Err(TaskResumeError::ConflictingSnapshot)));
        }
        assert_eq!(original.encode(&binding(1), limits).unwrap(), before);
        let inserted = Manifest::default().insert(record(), now(), limits).unwrap();
        assert_eq!(inserted.records.get(&record().key()), Some(&record()));
    }

    #[test]
    fn manifest_roundtrip_and_empty_tombstone_preserve_generation() {
        let limits = TaskResumeStoreLimits::default();
        let original = populated();
        let bytes = original.encode(&binding(1), limits).unwrap();
        let decoded = Manifest::decode(&bytes, &binding(1), limits).unwrap();
        assert_eq!(decoded.generation, 1);
        assert!(decoded.records == original.records);
        let empty = Manifest { generation: 2, records: BTreeMap::new() };
        let decoded = Manifest::decode(&empty.encode(&binding(1), limits).unwrap(), &binding(1), limits).unwrap();
        assert_eq!(decoded.generation, 2);
        assert!(decoded.records.is_empty());
    }

    #[test]
    fn manifest_rejects_wrong_binding_corrupt_key_and_trailing_bytes() {
        let limits = TaskResumeStoreLimits::default();
        let bytes = populated().encode(&binding(1), limits).unwrap();
        assert!(matches!(Manifest::decode(&bytes, &binding(2), limits), Err(TaskResumeError::Unavailable)));
        let mut changed = bytes.clone();
        changed[50] ^= 1;
        assert!(matches!(Manifest::decode(&changed, &binding(1), limits), Err(TaskResumeError::Unavailable)));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Manifest::decode(&trailing, &binding(1), limits).is_err());
        for end in 0..bytes.len() { assert!(Manifest::decode(&bytes[..end], &binding(1), limits).is_err()); }
    }

    #[test]
    fn duplicate_records_and_declared_count_overflow_fail_before_collection_growth() {
        let limits = TaskResumeStoreLimits::default();
        let mut bytes = populated().encode(&binding(1), limits).unwrap();
        let encoded_record = bytes[50..].to_vec();
        bytes[48..50].copy_from_slice(&2_u16.to_be_bytes());
        bytes.extend_from_slice(&encoded_record);
        assert!(matches!(Manifest::decode(&bytes, &binding(1), limits), Err(TaskResumeError::InvalidRecord)));
        bytes[48..50].copy_from_slice(&129_u16.to_be_bytes());
        assert!(matches!(Manifest::decode(&bytes, &binding(1), limits), Err(TaskResumeError::Capacity)));
    }

    #[test]
    fn timestamp_regression_and_conflicting_same_time_leave_manifest_unchanged() {
        let original = populated();
        let limits = TaskResumeStoreLimits::default();
        let baseline = original.encode(&binding(1), limits).unwrap();
        let mut changed = record();
        changed.updated_at = fastmcp_protocol::tasks_extension::TaskTimestamp::parse("2026-09-21T00:00:00Z").unwrap();
        assert!(matches!(original.put(changed, now(), limits), Err(TaskResumeError::StaleSnapshot)));
        let mut changed = record();
        changed.poll_interval_ms = Some(1);
        assert!(matches!(original.put(changed, now(), limits), Err(TaskResumeError::ConflictingSnapshot)));
        assert_eq!(original.encode(&binding(1), limits).unwrap(), baseline);
        assert!(original.put(record(), now(), limits).is_ok());
    }

    #[test]
    fn retention_cannot_be_refreshed_and_complete_manifest_bytes_are_bounded() {
        let original = populated();
        let mut later = record();
        later.retain_until += 10;
        let next = original.put(later, now(), TaskResumeStoreLimits::default()).unwrap();
        assert_eq!(next.records.values().next().unwrap().retain_until, record().retain_until);
        let size = original.encode(&binding(1), TaskResumeStoreLimits::default()).unwrap().len();
        assert!(original.encode(&binding(1), TaskResumeStoreLimits::new(1, size).unwrap()).is_ok());
        assert!(matches!(original.encode(&binding(1), TaskResumeStoreLimits::new(1, size - 1).unwrap()), Err(TaskResumeError::TooLarge)));
    }
}
