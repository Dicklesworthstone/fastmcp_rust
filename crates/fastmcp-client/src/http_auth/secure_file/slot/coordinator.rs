//! Ordered credential-file transactions against an independent trusted anchor.
//!
//! The coordinator, not application call sites, persists an intent before the
//! data mutation and finalizes the anchor before releasing a consumed payload.
//! Restart reconciles exactly the old/proposed record and never redelivers a
//! take. An uncertain provider response quarantines the handle; it cannot cause
//! a second mutation, an automatic retry, or adoption of an arbitrary revision.
//!
//! A deployment supplies the complete `CredentialCommitAnchor` implementation.
//! It must keep linearizable durable state outside the data store's rollback
//! domain, authenticate its configured service, and enforce finite `Cx`-bounded
//! operations. There is no same-directory sidecar or in-memory production
//! fallback. A conforming Rust implementation cannot prove an external service
//! tells the truth: provider qualification and independent custody remain part
//! of the deployment's trusted computing base.
//!
//! This single-slot transaction consumer does not implement FND-08's deployment
//! restore-epoch authority, epoch migration, encryption, or OAuth serialization.
//! Inputs remain caller-protected blobs. Synchronous storage/provider work must
//! run in the caller's owned blocking-I/O lane, not on a runtime polling thread.

use std::fmt;

use asupersync::Cx;
use fastmcp_core::crypto::sha256_bounded;
use fastmcp_core::partition::{CredentialStoreKey, PartitionAuthorization};

use super::{
    CredentialSlotError, DurableCredentialSlot, PreparedSlotMutation, SlotCommit,
    SlotCommitIntent, SlotRecoveryOutcome, SlotRevision,
};
use super::super::{SecureAtomicFile, checkpoint};

const MAX_NAMESPACE_BYTES: usize = 128;
const BINDING_DOMAIN: &[u8] = b"fastmcp/credential-anchor/v1\0";

/// Fixed identity presented to the configured anchor. It binds the credential
/// partition, current authorization, and an explicit deployment/store namespace.
/// It is not a token or authorization grant and cannot choose a provider route.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CredentialAnchorBinding {
    key: [u8; 32],
    authorization: [u8; 32],
    digest: [u8; 32],
}

impl CredentialAnchorBinding {
    /// A provider uses this opaque digest as its exact, already-provisioned key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Derives the non-authorizing identity used for explicit, out-of-band
    /// anchor provisioning. This performs no provider or filesystem operation.
    pub fn for_store(
        namespace: &str,
        key: &CredentialStoreKey,
        authorization: &PartitionAuthorization,
    ) -> Result<Self, CoordinatedSlotError> {
        if namespace.is_empty()
            || namespace.len() > MAX_NAMESPACE_BYTES
            || !namespace.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
            })
        {
            return Err(CoordinatedSlotError::InvalidNamespace);
        }
        let mut input = Vec::with_capacity(BINDING_DOMAIN.len() + 2 + namespace.len() + 64);
        input.extend_from_slice(BINDING_DOMAIN);
        input.extend_from_slice(&(namespace.len() as u16).to_be_bytes());
        input.extend_from_slice(namespace.as_bytes());
        input.extend_from_slice(key.as_bytes());
        input.extend_from_slice(authorization.as_bytes());
        let digest = sha256_bounded(&input, BINDING_DOMAIN.len() + 2 + MAX_NAMESPACE_BYTES + 64)
            .map_err(|_| CoordinatedSlotError::InvalidNamespace)?;
        Ok(Self {
            key: *key.as_bytes(),
            authorization: *authorization.as_bytes(),
            digest: digest.into_bytes(),
        })
    }

    fn accepts(self, state: CredentialAnchorState) -> bool {
        match state {
            CredentialAnchorState::Stable(_) => true,
            CredentialAnchorState::Pending(intent) => {
                intent.key == self.key && intent.authorization == self.authorization
            }
        }
    }
}

impl fmt::Debug for CredentialAnchorBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialAnchorBinding").finish_non_exhaustive()
    }
}

/// Exactly one settled revision or one unresolved, exact two-outcome intent.
/// `Stable(None)` is an explicitly provisioned empty slot, never a missing-key
/// fallback. Tombstones retain their nonzero revision in `Stable(Some(...))`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialAnchorState {
    Stable(Option<SlotRevision>),
    Pending(SlotCommitIntent),
}

/// A provider response. The coordinator validates its identity, state and
/// sequence; those checks do not attest the provider's actual disk durability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialAnchorSnapshot {
    binding: CredentialAnchorBinding,
    sequence: u64,
    state: CredentialAnchorState,
}

impl CredentialAnchorSnapshot {
    /// Provider-side response construction. Sequence zero may represent an
    /// explicitly provisioned initial state. Every successful CAS increments
    /// it exactly once; it must never reset after deletion or restart.
    pub fn new(
        binding: CredentialAnchorBinding,
        sequence: u64,
        state: CredentialAnchorState,
    ) -> Self {
        Self { binding, sequence, state }
    }

    pub fn binding(self) -> CredentialAnchorBinding { self.binding }
    pub fn sequence(self) -> u64 { self.sequence }
    pub fn state(self) -> CredentialAnchorState { self.state }
}

/// Closed, non-secret provider failures. An error from a mutation is never
/// interpreted as proof that it was not dispatched, even when it is Conflict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialAnchorError {
    NotProvisioned,
    Unavailable,
    Conflict,
    Uncertain,
}

/// Deployment-owned durable anchor, separate from replaceable credential data.
///
/// These operations address only an authenticated, preconfigured route. They
/// must be finite and observe `cx`; no method may spawn detached work. `current`
/// is an authoritative read, not a stale cache. Absence MUST return
/// `NotProvisioned`, never synthesize `Stable(None)`. Provisioning and restore
/// administration are deliberately outside this runtime interface.
///
/// `compare_exchange` atomically compares the complete snapshot (binding,
/// sequence, state), persists `next`, and advances sequence by exactly one.
/// A successful response is issued only after durable linearization. Pending
/// intents must survive provider/client restart until their exact resolution.
/// Uncertain dispatch must remain discoverable through `current`; this caller
/// never blindly resubmits the CAS. Providers must refuse sequence exhaustion.
/// Implementing this trait alone is not a provider conformance certificate.
pub trait CredentialCommitAnchor: Send {
    fn current(
        &mut self,
        cx: &Cx,
        binding: &CredentialAnchorBinding,
    ) -> Result<CredentialAnchorSnapshot, CredentialAnchorError>;

    fn compare_exchange(
        &mut self,
        cx: &Cx,
        expected: &CredentialAnchorSnapshot,
        next: CredentialAnchorState,
    ) -> Result<CredentialAnchorSnapshot, CredentialAnchorError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatedSlotError {
    InvalidNamespace,
    Slot(CredentialSlotError),
    Anchor(CredentialAnchorError),
    InvalidAnchorResponse,
    AnchorChanged,
    SequenceExhausted,
    RecoveryRequired,
    /// Both stores committed, but cancellation/deadline prevented payload
    /// delivery. The revision is settled; a take must not be repeated.
    CommittedWithoutDelivery(SlotRevision),
}

impl fmt::Display for CoordinatedSlotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNamespace => f.write_str("invalid credential-anchor namespace"),
            Self::Slot(error) => error.fmt(f),
            Self::Anchor(_) => f.write_str("credential-anchor operation failed"),
            Self::InvalidAnchorResponse => f.write_str("credential-anchor response failed correlation"),
            Self::AnchorChanged => f.write_str("credential anchor changed outside the active owner"),
            Self::SequenceExhausted => f.write_str("credential-anchor sequence exhausted"),
            Self::RecoveryRequired => f.write_str("credential transaction requires reopen and reconciliation"),
            Self::CommittedWithoutDelivery(_) => f.write_str("credential transaction committed without payload delivery"),
        }
    }
}

impl std::error::Error for CoordinatedSlotError {}

impl From<CredentialSlotError> for CoordinatedSlotError {
    fn from(error: CredentialSlotError) -> Self { Self::Slot(error) }
}

impl From<CredentialAnchorError> for CoordinatedSlotError {
    fn from(error: CredentialAnchorError) -> Self { Self::Anchor(error) }
}

/// Enforces prepare-anchor -> commit-file -> settle-anchor -> deliver.
/// No public accessor exposes the inner slot, provider, or prepared mutation.
/// The retained file lock serializes local mutation and recovery. An external
/// anchor must serialize its own writers independently.
pub struct CoordinatedCredentialSlot<A> {
    slot: DurableCredentialSlot,
    anchor: A,
    binding: CredentialAnchorBinding,
    snapshot: CredentialAnchorSnapshot,
    quarantined: bool,
}

impl<A: CredentialCommitAnchor> CoordinatedCredentialSlot<A> {
    /// Opens only the independently anchored revision. A pending transaction
    /// is reconciled under the retained file lock before this returns. Recovery
    /// settles the anchor but never replays or returns a previous take payload.
    ///
    /// `namespace` must uniquely name this configured deployment/store. It is
    /// not derived from peer input, an access token, or a local pathname.
    pub fn open(
        cx: &Cx,
        file: SecureAtomicFile,
        key: &CredentialStoreKey,
        authorization: &PartitionAuthorization,
        namespace: &str,
        mut anchor: A,
    ) -> Result<(Self, Option<SlotRecoveryOutcome>), CoordinatedSlotError> {
        check(cx)?;
        let binding = CredentialAnchorBinding::for_store(namespace, key, authorization)?;
        let mut snapshot = anchor.current(cx, &binding)?;
        validate_snapshot(binding, snapshot)?;
        check(cx)?;
        let (slot, recovery) = match snapshot.state {
            CredentialAnchorState::Stable(revision) => {
                (DurableCredentialSlot::open(cx, file, key, authorization, revision)?, None)
            }
            CredentialAnchorState::Pending(intent) => {
                let (slot, outcome) = DurableCredentialSlot::recover(cx, file, key, authorization, intent)?;
                let next = CredentialAnchorState::Stable(slot.revision());
                snapshot = transition(cx, &mut anchor, snapshot, next)?;
                (slot, Some(outcome))
            }
        };
        // No payload has been handed out, so cancellation after a recovery
        // settlement can safely fail open; a new open observes the settled state.
        check(cx)?;
        Ok((Self { slot, anchor, binding, snapshot, quarantined: false }, recovery))
    }

    pub fn revision(&self) -> Option<SlotRevision> { self.slot.revision() }
    pub fn requires_recovery(&self) -> bool { self.quarantined }
    pub fn maximum_payload_bytes(&self) -> usize { self.slot.maximum_payload_bytes() }

    /// Requires fresh matching anchor state before reading any protected value.
    pub fn load(
        &mut self,
        cx: &Cx,
        authorization: &PartitionAuthorization,
    ) -> Result<Option<Vec<u8>>, CoordinatedSlotError> {
        self.admit(cx, authorization)?;
        let result = self.slot.load(cx, authorization);
        if result.is_err() { self.quarantined = true; }
        Ok(result?)
    }

    /// Persists an exact intent before the data replacement. An expected
    /// revision mismatch or oversized payload cannot mutate the anchor.
    pub fn replace(
        &mut self,
        cx: &Cx,
        authorization: &PartitionAuthorization,
        expected: Option<SlotRevision>,
        protected_payload: &[u8],
    ) -> Result<SlotRevision, CoordinatedSlotError> {
        self.admit(cx, authorization)?;
        let mutation = self.slot.prepare_replace(cx, authorization, expected, protected_payload)?;
        Ok(self.commit(cx, authorization, mutation)?.revision())
    }

    /// Durably tombstones and settles the trusted anchor before returning a
    /// consumed protected value. Cancellation or any uncertain outcome releases
    /// no payload. Restart may retire a completed take but never redelivers it.
    pub fn take(
        &mut self,
        cx: &Cx,
        authorization: &PartitionAuthorization,
        expected: SlotRevision,
    ) -> Result<SlotCommit, CoordinatedSlotError> {
        self.admit(cx, authorization)?;
        let mutation = self.slot.prepare_take(cx, authorization, expected)?;
        self.commit(cx, authorization, mutation)
    }

    fn admit(&mut self, cx: &Cx, authorization: &PartitionAuthorization) -> Result<(), CoordinatedSlotError> {
        // A different caller must not even query the original owner's anchor.
        self.slot.check_authorization(authorization)?;
        check(cx)?;
        if self.quarantined { return Err(CoordinatedSlotError::RecoveryRequired); }
        let observed = match self.anchor.current(cx, &self.binding) {
            Ok(observed) => observed,
            Err(error) => {
                self.quarantined = true;
                return Err(error.into());
            }
        };
        if validate_snapshot(self.binding, observed).is_err() {
            self.quarantined = true;
            return Err(CoordinatedSlotError::InvalidAnchorResponse);
        }
        if observed != self.snapshot {
            self.quarantined = true;
            return Err(CoordinatedSlotError::AnchorChanged);
        }
        check(cx)
    }

    fn commit(
        &mut self,
        cx: &Cx,
        authorization: &PartitionAuthorization,
        mutation: PreparedSlotMutation,
    ) -> Result<SlotCommit, CoordinatedSlotError> {
        // Reserve both sequence increments before any effect; a pending state
        // must never be stranded merely because its settlement cannot increment.
        self.snapshot.sequence.checked_add(2).ok_or(CoordinatedSlotError::SequenceExhausted)?;
        check(cx)?;
        let intent = mutation.intent();
        self.quarantined = true;
        self.snapshot = transition(cx, &mut self.anchor, self.snapshot, CredentialAnchorState::Pending(intent))?;
        let committed = self.slot.commit(cx, authorization, mutation)?;
        self.snapshot = transition(
            cx, &mut self.anchor, self.snapshot,
            CredentialAnchorState::Stable(Some(committed.revision())),
        )?;
        self.quarantined = false;
        if check(cx).is_err() {
            // The full transaction is known committed; ordinary Cancelled would
            // falsely imply no effect. Drop the retained handoff rather than
            // releasing it to a cancelled owner or making it recoverable again.
            return Err(CoordinatedSlotError::CommittedWithoutDelivery(committed.revision()));
        }
        Ok(committed)
    }
}

fn check(cx: &Cx) -> Result<(), CoordinatedSlotError> {
    checkpoint(cx).map_err(|error| CoordinatedSlotError::Slot(CredentialSlotError::Storage(error)))
}

fn validate_snapshot(binding: CredentialAnchorBinding, snapshot: CredentialAnchorSnapshot) -> Result<(), CoordinatedSlotError> {
    if snapshot.binding != binding || !binding.accepts(snapshot.state) {
        return Err(CoordinatedSlotError::InvalidAnchorResponse);
    }
    Ok(())
}

fn transition<A: CredentialCommitAnchor>(
    cx: &Cx,
    anchor: &mut A,
    previous: CredentialAnchorSnapshot,
    next: CredentialAnchorState,
) -> Result<CredentialAnchorSnapshot, CoordinatedSlotError> {
    let sequence = previous.sequence.checked_add(1).ok_or(CoordinatedSlotError::SequenceExhausted)?;
    check(cx)?;
    let actual = anchor.compare_exchange(cx, &previous, next)?;
    validate_snapshot(previous.binding, actual)?;
    if actual.sequence != sequence || actual.state != next {
        return Err(CoordinatedSlotError::InvalidAnchorResponse);
    }
    Ok(actual)
}
