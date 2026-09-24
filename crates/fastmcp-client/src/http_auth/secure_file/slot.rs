//! Generation-preserving custody of caller-protected credential blobs.
//!
//! This module consumes `SecureAtomicFile`; it is not an encryption provider.
//! Payloads must already be authenticated/encrypted for the credential partition
//! by the caller's admitted provider. Partition keys are not authorization: each
//! operation also requires the current verified `PartitionAuthorization`.
//!
//! The prepare/commit split lets the owner durably record an intent in an
//! **independent trusted rollback anchor before committing this file**. On restart,
//! opening requires the exact trusted revision, not a revision learned from the
//! file being checked. Recovery admits only the old or proposed bytes named by
//! that intent. This is an anchor consumer, not an implementation of that anchor.
//! Without independent anchor custody it cannot detect restoring both together.
//!
//! `prepare_take` retains the old protected payload privately. `commit` releases
//! it only after an atomic, synchronized tombstone replaces the file. A process
//! crash after that point may lose the handoff, but cannot recover the old value
//! through this slot. This deliberately favors at-most-once custody over an
//! unsafe retry of a potentially consumed refresh token. Tombstones retain the
//! generation, so removing and recreating an entry does not permit ABA.

use std::fmt;

use asupersync::Cx;
use fastmcp_core::partition::{CredentialStoreKey, PartitionAuthorization};

use super::{AtomicFileError, AtomicFileSnapshot, AtomicFileVersion, SecureAtomicFile, checkpoint, version};

/// Enforced independent-anchor transaction ordering and restart reconciliation.
pub mod coordinator;

const MAGIC: &[u8; 8] = b"FCPSLOT\0";
const HEADER_BYTES: usize = 8 + 2 + 32 + 32 + 8 + 1 + 4;
const FORMAT_VERSION: u16 = 1;
/// Exact size of a revision's non-secret trusted-anchor encoding.
pub const SLOT_REVISION_BYTES: usize = 40;
/// Exact size of a prepared intent's non-secret trusted-anchor encoding.
pub const SLOT_INTENT_BYTES: usize = 8 + 32 + 32 + 1 + SLOT_REVISION_BYTES * 2;

/// Full record identity, including its monotonically increasing generation.
/// This is not a MAC or a source of authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotRevision {
    generation: u64,
    file_version: AtomicFileVersion,
}

impl SlotRevision {
    pub fn generation(self) -> u64 { self.generation }

    pub fn to_bytes(self) -> [u8; SLOT_REVISION_BYTES] {
        let mut bytes = [0; SLOT_REVISION_BYTES];
        bytes[..8].copy_from_slice(&self.generation.to_be_bytes());
        bytes[8..].copy_from_slice(&self.file_version.0);
        bytes
    }

    /// Decode only from the owner's independently authenticated anchor. Reading
    /// these bytes beside the credential file does not establish rollback safety.
    pub fn from_trusted_bytes(bytes: &[u8]) -> Result<Self, CredentialSlotError> {
        if bytes.len() != SLOT_REVISION_BYTES { return Err(CredentialSlotError::InvalidRecord); }
        let generation = u64::from_be_bytes(bytes[..8].try_into().map_err(|_| CredentialSlotError::InvalidRecord)?);
        if generation == 0 { return Err(CredentialSlotError::InvalidRecord); }
        let digest = bytes[8..].try_into().map_err(|_| CredentialSlotError::InvalidRecord)?;
        Ok(Self { generation, file_version: AtomicFileVersion(digest) })
    }
}

/// An exact two-outcome recovery intent. It contains no credential payload.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SlotCommitIntent {
    key: [u8; 32],
    authorization: [u8; 32],
    previous: Option<SlotRevision>,
    proposed: SlotRevision,
}

impl fmt::Debug for SlotCommitIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlotCommitIntent")
            .field("previous", &self.previous)
            .field("proposed", &self.proposed)
            .finish_non_exhaustive()
    }
}

impl SlotCommitIntent {
    pub fn previous(self) -> Option<SlotRevision> { self.previous }
    pub fn proposed(self) -> SlotRevision { self.proposed }

    pub fn to_bytes(self) -> [u8; SLOT_INTENT_BYTES] {
        let mut bytes = [0; SLOT_INTENT_BYTES];
        bytes[..8].copy_from_slice(b"FCPSINT1");
        bytes[8..40].copy_from_slice(&self.key);
        bytes[40..72].copy_from_slice(&self.authorization);
        if let Some(previous) = self.previous {
            bytes[72] = 1;
            bytes[73..113].copy_from_slice(&previous.to_bytes());
        }
        bytes[113..].copy_from_slice(&self.proposed.to_bytes());
        bytes
    }

    /// Restores an intent from independently trusted custody, never from peer
    /// input or an unauthenticated sidecar in the same rollback domain.
    pub fn from_trusted_bytes(bytes: &[u8]) -> Result<Self, CredentialSlotError> {
        if bytes.len() != SLOT_INTENT_BYTES || &bytes[..8] != b"FCPSINT1" {
            return Err(CredentialSlotError::InvalidRecord);
        }
        let previous = match bytes[72] {
            0 if bytes[73..113].iter().all(|byte| *byte == 0) => None,
            1 => Some(SlotRevision::from_trusted_bytes(&bytes[73..113])?),
            _ => return Err(CredentialSlotError::InvalidRecord),
        };
        let proposed = SlotRevision::from_trusted_bytes(&bytes[113..])?;
        if next_generation(previous)? != proposed.generation { return Err(CredentialSlotError::InvalidRecord); }
        Ok(Self {
            key: bytes[8..40].try_into().map_err(|_| CredentialSlotError::InvalidRecord)?,
            authorization: bytes[40..72].try_into().map_err(|_| CredentialSlotError::InvalidRecord)?,
            previous,
            proposed,
        })
    }
}

/// An opaque prepared mutation. It exposes the intent, never a pending consumed
/// payload; it is neither Clone nor serializable nor diagnostically printable.
pub struct PreparedSlotMutation {
    intent: SlotCommitIntent,
    record: Vec<u8>,
    consumed: Option<Vec<u8>>,
}

impl PreparedSlotMutation {
    pub fn intent(&self) -> SlotCommitIntent { self.intent }
}

/// A durably committed mutation. A take's payload becomes available only here.
pub struct SlotCommit {
    revision: SlotRevision,
    consumed: Option<Vec<u8>>,
}

impl SlotCommit {
    pub fn revision(&self) -> SlotRevision { self.revision }
    pub fn into_consumed(self) -> Option<Vec<u8>> { self.consumed }
}

/// Recovery does not redeliver a consumed payload, even when the proposed
/// tombstone is found. The original caller may already have used that payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotRecoveryOutcome {
    Committed(SlotRevision),
    NotCommitted(Option<SlotRevision>),
}

/// Storage diagnostics never retain credential bytes, paths, or peer errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialSlotError {
    Storage(AtomicFileError),
    InvalidRecord,
    BindingMismatch,
    RevisionMismatch,
    Empty,
    GenerationExhausted,
    /// The commit's durability is unknown. Carries only what identifies WHICH
    /// commit is in doubt -- deliberately not a `SlotCommitIntent`.
    ///
    /// Reconciliation takes its intent from independently retained custody, as
    /// `recover` documents and `SlotCommitIntent::from_trusted_bytes` requires:
    /// the caller persists `PreparedSlotMutation::intent()` BEFORE committing.
    /// An intent rebuilt from this in-memory error would be a sidecar in the
    /// same rollback domain, which is the one source that rule excludes. So the
    /// binding key and authorization are not restated here; the caller supplied
    /// both to open the slot and still holds them.
    CommitUncertain {
        previous: Option<SlotRevision>,
        proposed: SlotRevision,
    },
}

impl fmt::Display for CredentialSlotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => error.fmt(f),
            Self::InvalidRecord => f.write_str("protected credential slot record is invalid"),
            Self::BindingMismatch => f.write_str("protected credential slot binding mismatch"),
            Self::RevisionMismatch => f.write_str("protected credential slot revision disagrees with trusted custody"),
            Self::Empty => f.write_str("protected credential slot has no payload"),
            Self::GenerationExhausted => f.write_str("protected credential slot generation exhausted"),
            Self::CommitUncertain { .. } => f.write_str("protected credential slot commit requires intent reconciliation"),
        }
    }
}

impl std::error::Error for CredentialSlotError {}

/// The size this error is allowed to reach, enforced by the compiler rather than
/// by arithmetic. `CredentialSlotError` is returned by 31 functions across this
/// subtree, so one oversized variant sets every one of their `Result` layouts.
///
/// 128 is clippy's `large-error-threshold`. Before this bound existed the type
/// was ~152 bytes, driven by `CommitUncertain` carrying a whole
/// `SlotCommitIntent` (`SLOT_INTENT_BYTES` = 153).
///
/// Measured by `rustc` on the exact shapes, not computed: 152 before, 88 after.
///
/// The assert exists because I predicted that replacement size twice by hand and
/// was wrong both times -- 81 by forgetting that `Option<SlotRevision>` is 48 and
/// not 41 (neither `u64` nor `[u8; 32]` offers a niche for the discriminant), then
/// 96 by adding a discriminant byte the variant layout does not need. The true 88
/// came from `size_of`. Only the 152 was ever reliable, and only because
/// `SLOT_INTENT_BYTES` = 153 corroborated it independently. A layout number with
/// no corroboration does not get to be load-bearing, so this one is the
/// compiler's rather than mine.
const _: () = assert!(core::mem::size_of::<CredentialSlotError>() <= 128);

/// `Copy` preservation, proven by the compiler rather than by reading derive lists.
///
/// This is the ENTIRE argument for reshaping the variant instead of boxing it. A
/// `Box` anywhere inside removes `Copy` from all five of these types, and consumer
/// code doing `let a = e; use(e);` stops compiling — a far wider break than the
/// pattern-match adjustment that reshaping costs. Until now that argument lived only
/// in prose, which is the same defect the size bound above was added to fix, sitting
/// one argument over.
///
/// The guard is not a no-op: instantiated with a non-`Copy` type it fails with
/// E0277, which was checked in both directions before this landed.
const fn assert_copy<T: Copy>() {}
const _: () = assert_copy::<SlotRevision>();
const _: () = assert_copy::<SlotCommitIntent>();
const _: () = assert_copy::<CredentialSlotError>();
const _: () = assert_copy::<coordinator::CredentialAnchorState>();
const _: () = assert_copy::<coordinator::CredentialAnchorSnapshot>();
const _: () = assert_copy::<coordinator::CoordinatedSlotError>();

/// The on-disk trusted-anchor encoding is unchanged by the variant reshape.
///
/// `SLOT_INTENT_BYTES` is what `SlotCommitIntent::to_bytes` writes and
/// `from_trusted_bytes` validates, so it IS the persisted format: an intent written
/// before a crash must still parse after one. Pinning it here means a change to
/// `SLOT_REVISION_BYTES` or to the header/flag layout fails the build instead of
/// silently invalidating every retained intent in the field.
///
/// Deliberately NOT pinned: `size_of::<SlotCommitIntent>()`. That is an in-memory
/// layout, not a format, and it can move for reasons that harm nobody — a niche
/// optimisation in a future compiler would break the build while the persisted bytes
/// stayed identical. Pinning it would assert something this crate does not promise.
const _: () = assert!(SLOT_REVISION_BYTES == 40);
const _: () = assert!(SLOT_INTENT_BYTES == 153);

impl From<AtomicFileError> for CredentialSlotError {
    fn from(error: AtomicFileError) -> Self { Self::Storage(error) }
}

/// One exclusively owned, partition-bound credential slot. The filesystem lock
/// remains held until this value drops. This low-level API is for the trusted
/// credential owner; server-facing non-oracular authorization/error mapping and
/// current-provider revalidation remain the caller's responsibility.
pub struct DurableCredentialSlot {
    file: SecureAtomicFile,
    key: [u8; 32],
    authorization: [u8; 32],
    current: Option<SlotRevision>,
}

impl DurableCredentialSlot {
    /// Opens only the exact independently trusted revision. `None` means the
    /// file must be absent, not "adopt whatever is there". A tombstone is still
    /// a record and cannot be silently treated as a new generation-zero store.
    pub fn open(
        cx: &Cx,
        file: SecureAtomicFile,
        key: &CredentialStoreKey,
        authorization: &PartitionAuthorization,
        trusted_revision: Option<SlotRevision>,
    ) -> Result<Self, CredentialSlotError> {
        let slot = Self::new(file, key, authorization)?;
        let record = slot.read(cx)?;
        if record.as_ref().map(|record| record.revision) != trusted_revision {
            return Err(CredentialSlotError::RevisionMismatch);
        }
        Ok(Self { current: trusted_revision, ..slot })
    }

    /// Reconciles after a crash/uncertain commit against an independently
    /// retained intent. Only its exact old or proposed full record may survive.
    /// No arbitrary newer generation is adopted as a successful operation.
    pub fn recover(
        cx: &Cx,
        file: SecureAtomicFile,
        key: &CredentialStoreKey,
        authorization: &PartitionAuthorization,
        intent: SlotCommitIntent,
    ) -> Result<(Self, SlotRecoveryOutcome), CredentialSlotError> {
        let mut slot = Self::new(file, key, authorization)?;
        slot.check_intent_binding(&intent)?;
        // Explicit reconciliation establishes durability before declaring either
        // outcome; normal load remains unavailable after uncertain file commit.
        let record = slot.file.reconcile(cx)?.map(|raw| slot.decode(raw)).transpose()?;
        let actual = record.as_ref().map(|record| record.revision);
        let outcome = if actual == Some(intent.proposed) {
            SlotRecoveryOutcome::Committed(intent.proposed)
        } else if actual == intent.previous {
            SlotRecoveryOutcome::NotCommitted(actual)
        } else {
            return Err(CredentialSlotError::RevisionMismatch);
        };
        slot.current = actual;
        Ok((slot, outcome))
    }

    pub fn revision(&self) -> Option<SlotRevision> { self.current }
    pub fn maximum_payload_bytes(&self) -> usize { self.file.maximum_bytes() - HEADER_BYTES }

    /// Reads only under the current matching authorization and the last trusted
    /// full revision. Callers must verify the protected envelope before using it.
    pub fn load(&self, cx: &Cx, authorization: &PartitionAuthorization) -> Result<Option<Vec<u8>>, CredentialSlotError> {
        self.check_authorization(authorization)?;
        Ok(self.read_current(cx)?.and_then(|record| record.payload))
    }

    pub fn prepare_replace(
        &self,
        cx: &Cx,
        authorization: &PartitionAuthorization,
        expected: Option<SlotRevision>,
        protected_payload: &[u8],
    ) -> Result<PreparedSlotMutation, CredentialSlotError> {
        self.check_authorization(authorization)?;
        checkpoint(cx)?;
        if expected != self.current { return Err(CredentialSlotError::RevisionMismatch); }
        self.read_current(cx)?;
        if protected_payload.len() > self.maximum_payload_bytes() {
            return Err(AtomicFileError::TooLarge.into());
        }
        self.prepare(Some(protected_payload), None)
    }

    /// Prepares a generation-advancing tombstone without exposing its current
    /// payload. Persist `mutation.intent()` independently before calling commit.
    pub fn prepare_take(
        &self,
        cx: &Cx,
        authorization: &PartitionAuthorization,
        expected: SlotRevision,
    ) -> Result<PreparedSlotMutation, CredentialSlotError> {
        self.check_authorization(authorization)?;
        checkpoint(cx)?;
        if Some(expected) != self.current { return Err(CredentialSlotError::RevisionMismatch); }
        let payload = self.read_current(cx)?.and_then(|record| record.payload)
            .ok_or(CredentialSlotError::Empty)?;
        self.prepare(None, Some(payload))
    }

    /// Commits an already-prepared mutation against the exact old generation.
    /// The owner must have retained its intent before entering this method.
    /// On uncertain durability no consumed payload is released. Drop this slot
    /// and use `recover` with that intent and a fresh SecureAtomicFile handle.
    pub fn commit(
        &mut self,
        cx: &Cx,
        authorization: &PartitionAuthorization,
        mutation: PreparedSlotMutation,
    ) -> Result<SlotCommit, CredentialSlotError> {
        self.check_authorization(authorization)?;
        self.check_intent_binding(&mutation.intent)?;
        checkpoint(cx)?;
        if mutation.intent.previous != self.current { return Err(CredentialSlotError::RevisionMismatch); }
        match self.file.replace(cx, self.current.map(|current| current.file_version), &mutation.record) {
            Ok(file_version) => {
                // The record was hashed before external intent custody; the
                // exact same bytes are what the atomic-file operation committed.
                debug_assert_eq!(file_version, mutation.intent.proposed.file_version);
                self.current = Some(mutation.intent.proposed);
                Ok(SlotCommit { revision: mutation.intent.proposed, consumed: mutation.consumed })
            }
            Err(AtomicFileError::CommitUncertain { .. }) => {
                Err(CredentialSlotError::CommitUncertain {
                    previous: mutation.intent.previous,
                    proposed: mutation.intent.proposed,
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    fn new(file: SecureAtomicFile, key: &CredentialStoreKey, authorization: &PartitionAuthorization) -> Result<Self, CredentialSlotError> {
        if file.maximum_bytes() < HEADER_BYTES { return Err(AtomicFileError::InvalidLimit.into()); }
        Ok(Self { file, key: *key.as_bytes(), authorization: *authorization.as_bytes(), current: None })
    }

    fn check_authorization(&self, authorization: &PartitionAuthorization) -> Result<(), CredentialSlotError> {
        if self.authorization != *authorization.as_bytes() { return Err(CredentialSlotError::BindingMismatch); }
        Ok(())
    }

    fn check_intent_binding(&self, intent: &SlotCommitIntent) -> Result<(), CredentialSlotError> {
        if self.key != intent.key || self.authorization != intent.authorization {
            return Err(CredentialSlotError::BindingMismatch);
        }
        Ok(())
    }

    fn read(&self, cx: &Cx) -> Result<Option<Record>, CredentialSlotError> {
        self.file.load(cx)?.map(|raw| self.decode(raw)).transpose()
    }

    fn read_current(&self, cx: &Cx) -> Result<Option<Record>, CredentialSlotError> {
        let record = self.read(cx)?;
        if record.as_ref().map(|record| record.revision) != self.current {
            return Err(CredentialSlotError::RevisionMismatch);
        }
        Ok(record)
    }

    fn prepare(&self, payload: Option<&[u8]>, consumed: Option<Vec<u8>>) -> Result<PreparedSlotMutation, CredentialSlotError> {
        let generation = next_generation(self.current)?;
        let payload_len = payload.map_or(0, <[u8]>::len);
        let mut record = Vec::with_capacity(HEADER_BYTES + payload_len);
        record.extend_from_slice(MAGIC);
        record.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        record.extend_from_slice(&self.key);
        record.extend_from_slice(&self.authorization);
        record.extend_from_slice(&generation.to_be_bytes());
        record.push(u8::from(payload.is_some()));
        record.extend_from_slice(&(payload_len as u32).to_be_bytes());
        if let Some(payload) = payload { record.extend_from_slice(payload); }
        let proposed = SlotRevision { generation, file_version: version(&record)? };
        Ok(PreparedSlotMutation {
            intent: SlotCommitIntent { key: self.key, authorization: self.authorization, previous: self.current, proposed },
            record,
            consumed,
        })
    }

    fn decode(&self, raw: AtomicFileSnapshot) -> Result<Record, CredentialSlotError> {
        let bytes = raw.bytes();
        if bytes.len() < HEADER_BYTES || &bytes[..8] != MAGIC
            || bytes[8..10] != FORMAT_VERSION.to_be_bytes()
        { return Err(CredentialSlotError::InvalidRecord); }
        if bytes[10..42] != self.key || bytes[42..74] != self.authorization {
            return Err(CredentialSlotError::BindingMismatch);
        }
        let generation = u64::from_be_bytes(bytes[74..82].try_into().map_err(|_| CredentialSlotError::InvalidRecord)?);
        let length = u32::from_be_bytes(bytes[83..87].try_into().map_err(|_| CredentialSlotError::InvalidRecord)?) as usize;
        if generation == 0 || length != bytes.len() - HEADER_BYTES || bytes[82] > 1
            || (bytes[82] == 0 && length != 0)
        { return Err(CredentialSlotError::InvalidRecord); }
        let revision = SlotRevision { generation, file_version: raw.version() };
        let payload = (bytes[82] == 1).then(|| bytes[HEADER_BYTES..].to_vec());
        Ok(Record { revision, payload })
    }
}

struct Record { revision: SlotRevision, payload: Option<Vec<u8>> }

fn next_generation(current: Option<SlotRevision>) -> Result<u64, CredentialSlotError> {
    current.map_or(0, |current| current.generation).checked_add(1)
        .ok_or(CredentialSlotError::GenerationExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests::{PrivateDirectory, failing_directory_sync};
    use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};

    fn identity() -> (CredentialStoreKey, PartitionAuthorization) {
        let descriptor = PartitionDescriptor::from_verified_facts(
            "fixture-provider", 1, "https://issuer.example", "https://resource.example/mcp",
            "fixture-tenant", "fixture-subject", "native-client", 1, 1, &[b"fixture-audience"],
        ).unwrap();
        let owner = DurableOwnerKey::derive(&descriptor, 1).unwrap();
        (
            CredentialStoreKey::derive(&descriptor, "fixture-store", "refresh-family", "stable-lineage")
                .unwrap(),
            PartitionAuthorization::current(&descriptor, &owner),
        )
    }

    #[test]
    fn an_uncertain_file_commit_is_the_slots_commit_uncertain() {
        let cx = Cx::for_testing();
        let directory = PrivateDirectory::new();
        let (key, authorization) = identity();
        let mut slot =
            DurableCredentialSlot::open(&cx, directory.open(&cx), &key, &authorization, None).unwrap();
        let mutation = slot.prepare_replace(&cx, &authorization, None, b"protected").unwrap();
        let intent = mutation.intent();
        slot.file.directory_sync = failing_directory_sync;

        assert_eq!(
            slot.commit(&cx, &authorization, mutation).err(),
            Some(CredentialSlotError::CommitUncertain {
                previous: intent.previous(),
                proposed: intent.proposed(),
            }),
        );
        assert_eq!(slot.revision(), None, "an uncertain commit must not advance the trusted revision");

        // Recovery takes a fresh handle and the independently retained intent.
        drop(slot);
        let (_, outcome) =
            DurableCredentialSlot::recover(&cx, directory.open(&cx), &key, &authorization, intent).unwrap();
        assert_eq!(outcome, SlotRecoveryOutcome::Committed(intent.proposed()));
    }

    /// Planted negative: identical except the post-rename directory sync
    /// succeeds, so the commit is certain and the revision advances.
    #[test]
    fn a_certain_file_commit_is_the_slots_commit() {
        let cx = Cx::for_testing();
        let directory = PrivateDirectory::new();
        let (key, authorization) = identity();
        let mut slot =
            DurableCredentialSlot::open(&cx, directory.open(&cx), &key, &authorization, None).unwrap();
        let mutation = slot.prepare_replace(&cx, &authorization, None, b"protected").unwrap();
        let intent = mutation.intent();

        let commit = slot.commit(&cx, &authorization, mutation).unwrap();
        assert_eq!(commit.revision(), intent.proposed());
        assert_eq!(slot.revision(), Some(intent.proposed()));
    }
}
