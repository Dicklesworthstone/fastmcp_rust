//! Protected persistent blobs through a complete external envelope provider.
//!
//! This is a real insert/compare-and-replace/read consumer of FND-08's restore
//! write protocol. The external envelope backend owns ALL persistent key,
//! nonce, rotation and AEAD custody; there is no raw-key or process-key bridge.
//! The independent blob backend must atomically compare the exact prior record,
//! compare the durable restore fence, and persist the operation ID, logical
//! intent digest and ciphertext transaction digest with the new record.
//!
//! These public traits are deployment extension points, not qualification.
//! The named envelope provider, durable blob store and external restore authority
//! remain trusted computing base components. Their receipts are structural
//! claims until the authority verifies the independently durable store proof.
//! No in-memory adapter, OIDC flow, MCP authorization, latest-record discovery,
//! epoch migration or persistent-provider support claim is supplied here.
//!
//! Callers retain each returned revision in trusted control state, including
//! across restart. Reads require that exact revision; store-returned metadata
//! can never select its own expected AAD. The sole purpose/section in this
//! increment is ProtectedBlob/Payload, with no untyped application AAD.

use std::collections::BTreeSet;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use asupersync::channel::oneshot;
use asupersync::cx::cap::CapMask;
use asupersync::time::Sleep;
use asupersync::{Cx, Time};
use zeroize::Zeroizing;

use crate::crypto::{draw_security_identifier, sha256_bounded};
use crate::restore::{
    DurableRestoreCommitReceipt, DurableRestoreNonCommitReceipt, DurableRestoreResolution,
    RegisteredRestoreStore, RestoreDispatch, RestoreEpochBinding, RestoreError, RestoreWriteFence,
};
use crate::runtime::{ProcessBoundToken, ProcessGenerationGuard, ambient_capability_ceiling};

mod codec;
#[cfg(test)]
mod tests;

pub use codec::{CanonicalEnvelope, PersistentEnvelopeHeader};

const MIB: usize = 1024 * 1024;
const MAX_PLAINTEXT: usize = 48 * MIB;
const MAX_ENVELOPE: usize = 50 * MIB;
const MAX_AAD: usize = 256 * 1024;
const MAX_CONTROL: usize = 4096;
const CONTROL_RESERVE: usize = 4 * MAX_CONTROL;
const REVISION_BYTES: usize = 98;

/// Redacted, bounded failures. No provider message or protected bytes survive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistentEnvelopeError {
    InvalidConfiguration,
    InvalidEnvelope,
    InvalidReceipt,
    InvalidRevision,
    TooLarge,
    CapacityExceeded,
    CapabilityUnavailable,
    Cancelled,
    DeadlineExceeded,
    ProcessChanged,
    RandomSourceUnavailable,
    ProviderUnavailable,
    Conflict,
    Uncertain,
    Quarantined,
    Restore(RestoreError),
}

impl fmt::Display for PersistentEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid persistent envelope configuration",
            Self::InvalidEnvelope => "persistent envelope was refused",
            Self::InvalidReceipt => "persistent operation receipt does not match",
            Self::InvalidRevision => "persistent record revision was refused",
            Self::TooLarge => "persistent protected state exceeds its bound",
            Self::CapacityExceeded => "persistent protected-state capacity exhausted",
            Self::CapabilityUnavailable => "persistent operation effects unavailable",
            Self::Cancelled => "persistent protected-state operation cancelled",
            Self::DeadlineExceeded => "persistent protected-state deadline exceeded",
            Self::ProcessChanged => "persistent facade process generation changed",
            Self::RandomSourceUnavailable => "persistent operation randomness unavailable",
            Self::ProviderUnavailable => "persistent provider unavailable",
            Self::Conflict => "persistent record compare-and-replace conflicted",
            Self::Uncertain => "persistent operation disposition is uncertain",
            Self::Quarantined => "persistent facade requires reconciliation",
            Self::Restore(_) => "persistent restore-authority operation failed",
        })
    }
}
impl std::error::Error for PersistentEnvelopeError {}
impl From<RestoreError> for PersistentEnvelopeError {
    fn from(error: RestoreError) -> Self {
        Self::Restore(error)
    }
}

/// Finite limits for one facade. Providers must additionally enforce their
/// qualified provider/deployment-wide limits across all facade instances.
#[derive(Clone, Copy, Debug)]
pub struct PersistentEnvelopeLimits {
    pub plaintext_bytes: usize,
    pub envelope_bytes: usize,
    pub aad_bytes: usize,
    pub active_operations: usize,
    pub in_flight_bytes: usize,
    pub call_timeout: Duration,
}
impl Default for PersistentEnvelopeLimits {
    fn default() -> Self {
        Self {
            plaintext_bytes: 12 * MIB,
            envelope_bytes: 13 * MIB,
            aad_bytes: 64 * 1024,
            active_operations: 2,
            in_flight_bytes: 64 * MIB,
            call_timeout: Duration::from_secs(10),
        }
    }
}
impl PersistentEnvelopeLimits {
    fn validate(self) -> Result<(), PersistentEnvelopeError> {
        if !(1..=MAX_PLAINTEXT).contains(&self.plaintext_bytes)
            || !(256..=MAX_ENVELOPE).contains(&self.envelope_bytes)
            || !(1024..=MAX_AAD).contains(&self.aad_bytes)
            || !(1..=16).contains(&self.active_operations)
            || !(1024..=256 * MIB).contains(&self.in_flight_bytes)
            || self.call_timeout.is_zero()
            || self.call_timeout > Duration::from_secs(60)
            || self.plaintext_bytes.checked_add(199).is_none_or(|n| n > self.envelope_bytes)
            || self.envelope_bytes.checked_add(self.plaintext_bytes)
                .and_then(|n| n.checked_add(self.aad_bytes))
                .and_then(|n| n.checked_add(CONTROL_RESERVE))
                .is_none_or(|n| n > self.in_flight_bytes)
        {
            return Err(PersistentEnvelopeError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// One finite, preconfigured route. It is not a key or an arbitrary KMS URL.
#[derive(Clone)]
pub struct PersistentKeyGeneration {
    pub key_id: String,
    pub generation: u64,
    pub sealing: bool,
}

/// Immutable identity of the complete configured envelope provider and ring.
/// Exactly one admitted generation seals; up to seven others may open.
#[derive(Clone)]
pub struct PersistentEnvelopeConfiguration {
    pub artifact: String,
    pub artifact_digest: [u8; 32],
    pub configuration_fingerprint: [u8; 32],
    pub ring_generation: u64,
    pub keys: Vec<PersistentKeyGeneration>,
    pub limits: PersistentEnvelopeLimits,
}
impl PersistentEnvelopeConfiguration {
    fn validate(&self) -> Result<(), PersistentEnvelopeError> {
        self.limits.validate()?;
        if !identifier(&self.artifact) || self.ring_generation == 0
            || self.keys.is_empty() || self.keys.len() > 8
            || self.keys.iter().filter(|key| key.sealing).count() != 1
        {
            return Err(PersistentEnvelopeError::InvalidConfiguration);
        }
        let mut unique = BTreeSet::new();
        for key in &self.keys {
            if !codec::key_identifier(&key.key_id) || key.generation == 0
                || !unique.insert((&key.key_id, key.generation))
            {
                return Err(PersistentEnvelopeError::InvalidConfiguration);
            }
        }
        Ok(())
    }
    fn admits(&self, header: &PersistentEnvelopeHeader, sealing: bool) -> bool {
        self.keys.iter().any(|key| key.key_id == header.key_id()
            && key.generation == header.generation() && (!sealing || key.sealing))
    }
}

/// Independently pinned identity of the durable blob store implementation.
/// Matching the restore store ID alone is not enough to select a backend.
#[derive(Clone)]
pub struct PersistentBlobBackendConfiguration {
    pub artifact: String,
    pub artifact_digest: [u8; 32],
    pub configuration_fingerprint: [u8; 32],
    pub generation: u64,
}
impl PersistentBlobBackendConfiguration {
    fn validate(&self) -> Result<(), PersistentEnvelopeError> {
        if !identifier(&self.artifact) || self.generation == 0 {
            return Err(PersistentEnvelopeError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Exclusive bounded secret owner. No Clone, Debug, Serialize or ordinary Vec
/// extraction. A provider decrypts in place inside a zeroizing allocation.
pub struct BoundedPlaintext {
    bytes: Zeroizing<Vec<u8>>,
    admission: Option<ByteLease>,
}
impl BoundedPlaintext {
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Result<Self, PersistentEnvelopeError> {
        if bytes.len() > MAX_PLAINTEXT || bytes.capacity() > MAX_PLAINTEXT {
            return Err(PersistentEnvelopeError::TooLarge);
        }
        Ok(Self { bytes, admission: None })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn allocated_bytes(&self) -> usize {
        self.bytes.capacity()
    }
    /// Explicit caller extraction transfers the still-zeroizing allocation out
    /// of the facade's byte reservation; the caller then owns its admission.
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

/// Nonsecret locator of ONE exact committed version. Persist these bytes in
/// trusted application control state. Decoding validates shape, not authority
/// or freshness; a forged or old reference grants no MCP authorization.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PersistentBlobRevision {
    namespace: [u8; 32],
    record_id: [u8; 16],
    generation: u64,
    envelope_digest: [u8; 32],
}
impl PersistentBlobRevision {
    pub const fn namespace_digest(&self) -> [u8; 32] { self.namespace }
    pub const fn record_id(&self) -> [u8; 16] { self.record_id }
    pub const fn generation(&self) -> u64 { self.generation }
    pub const fn envelope_digest(&self) -> [u8; 32] { self.envelope_digest }
    pub fn encode(&self) -> [u8; REVISION_BYTES] {
        let mut out = [0; REVISION_BYTES];
        out[..10].copy_from_slice(b"FMCPBLR\0\0\x01");
        out[10..42].copy_from_slice(&self.namespace);
        out[42..58].copy_from_slice(&self.record_id);
        out[58..66].copy_from_slice(&self.generation.to_be_bytes());
        out[66..].copy_from_slice(&self.envelope_digest);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, PersistentEnvelopeError> {
        if bytes.len() != REVISION_BYTES || bytes[..10] != *b"FMCPBLR\0\0\x01" {
            return Err(PersistentEnvelopeError::InvalidRevision);
        }
        let generation = u64::from_be_bytes(bytes[58..66].try_into()
            .map_err(|_| PersistentEnvelopeError::InvalidRevision)?);
        if generation == 0 { return Err(PersistentEnvelopeError::InvalidRevision); }
        Ok(Self {
            namespace: bytes[10..42].try_into().map_err(|_| PersistentEnvelopeError::InvalidRevision)?,
            record_id: bytes[42..58].try_into().map_err(|_| PersistentEnvelopeError::InvalidRevision)?,
            generation,
            envelope_digest: bytes[66..].try_into().map_err(|_| PersistentEnvelopeError::InvalidRevision)?,
        })
    }
}

#[derive(Clone, Copy)]
struct BlobIndex {
    namespace: [u8; 32],
    record_id: [u8; 16],
    generation: u64,
}
impl BlobIndex {
    fn from_revision(revision: &PersistentBlobRevision) -> Self {
        Self { namespace: revision.namespace, record_id: revision.record_id, generation: revision.generation }
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.namespace);
        out.extend_from_slice(&self.record_id);
        out.extend_from_slice(&self.generation.to_be_bytes());
    }
}

/// Framework-constructed expected context. Only the blob consumer can create
/// one; neither provider headers nor callers can supply an epoch or AAD map.
pub struct ExpectedEnvelopeContext<'a> {
    binding: &'a RestoreEpochBinding,
    deployment_uuid: [u8; 16],
    store_set_digest: [u8; 32],
    index: BlobIndex,
    blob_artifact_digest: [u8; 32],
    blob_configuration_fingerprint: [u8; 32],
    blob_generation: u64,
    aad_limit: usize,
}
impl ExpectedEnvelopeContext<'_> {
    pub fn restore_binding(&self) -> &RestoreEpochBinding { self.binding }
    pub const fn deployment_uuid(&self) -> [u8; 16] { self.deployment_uuid }
    pub const fn namespace_digest(&self) -> [u8; 32] { self.index.namespace }
    pub const fn record_id(&self) -> [u8; 16] { self.index.record_id }
    pub const fn record_generation(&self) -> u64 { self.index.generation }
    pub const fn store_set_digest(&self) -> [u8; 32] { self.store_set_digest }
    pub const fn blob_artifact_digest(&self) -> [u8; 32] { self.blob_artifact_digest }
    pub const fn blob_configuration_fingerprint(&self) -> [u8; 32] { self.blob_configuration_fingerprint }
    pub const fn blob_generation(&self) -> u64 { self.blob_generation }
    /// Shared canonical FMCPENV v1 encoder. The sole purpose is ProtectedBlob
    /// (1), section is Payload, and lifetime discriminator is Persistent (2).
    pub fn canonical_aad(&self, header: &PersistentEnvelopeHeader) -> Result<Vec<u8>, PersistentEnvelopeError> {
        codec::aad(self, header)
    }
}

/// Immutable provider request. The backend uses only its preconfigured route;
/// configuration metadata never authorizes endpoint discovery or key import.
pub struct PersistentEnvelopeRequest<'a> {
    operation_id: [u8; 16],
    request_digest: [u8; 32],
    deadline: Time,
    configuration: &'a PersistentEnvelopeConfiguration,
    context: ExpectedEnvelopeContext<'a>,
    plaintext_bytes: usize,
}
impl PersistentEnvelopeRequest<'_> {
    pub const fn version(&self) -> u16 { 1 }
    pub const fn operation_id(&self) -> [u8; 16] { self.operation_id }
    pub const fn request_digest(&self) -> [u8; 32] { self.request_digest }
    pub const fn deadline(&self) -> Time { self.deadline }
    pub fn configuration(&self) -> &PersistentEnvelopeConfiguration { self.configuration }
    pub fn context(&self) -> &ExpectedEnvelopeContext<'_> { &self.context }
    pub const fn plaintext_bytes(&self) -> usize { self.plaintext_bytes }
}

/// Provider attestation/correlation, not independent cryptographic proof.
pub struct PersistentEnvelopeReceipt {
    pub operation_id: [u8; 16],
    pub request_digest: [u8; 32],
    pub configuration_fingerprint: [u8; 32],
    pub ring_generation: u64,
    pub key_generation: u64,
    pub envelope_digest: [u8; 32],
    pub dispatch: RestoreDispatch,
}
impl PersistentEnvelopeReceipt {
    /// Convenience for provider implementations; truthful AEAD and durable nonce
    /// allocation still require provider qualification.
    pub fn for_request(request: &PersistentEnvelopeRequest<'_>, envelope: &CanonicalEnvelope) -> Result<Self, PersistentEnvelopeError> {
        let header = envelope.header()?;
        Ok(Self {
            operation_id: request.operation_id,
            request_digest: request.request_digest,
            configuration_fingerprint: request.configuration.configuration_fingerprint,
            ring_generation: request.configuration.ring_generation,
            key_generation: header.generation(),
            envelope_digest: digest(envelope.as_bytes(), MAX_ENVELOPE)?,
            dispatch: RestoreDispatch::Dispatched,
        })
    }
}
pub struct PersistentSealResult {
    pub envelope: CanonicalEnvelope,
    pub receipt: PersistentEnvelopeReceipt,
}
pub struct PersistentOpenResult {
    pub plaintext: BoundedPlaintext,
    pub receipt: PersistentEnvelopeReceipt,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistentBackendFailureKind { Unavailable, AuthenticationFailed, Conflict }
pub struct PersistentBackendFailure {
    pub dispatch: RestoreDispatch,
    pub kind: PersistentBackendFailureKind,
}
pub type PersistentBackendFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, PersistentBackendFailure>> + Send + 'a>>;

/// Complete external persistent crypto custody. Implementers own rollback-safe
/// nonce domains/ranges, key protection, XC20P AEAD, rotation and late-result
/// wiping. They MUST authenticate the shared canonical AAD and cannot return
/// plaintext before authentication. Blocking work requires the caller-owned
/// admitted executor; spawning an independent runtime/queue is not permitted.
/// Dropping a future is not permission to leak buffers or reuse a nonce.
pub trait PersistentEnvelopeBackend: Send + Sync + 'static {
    fn seal<'a>(
        &'a self, cx: &'a Cx, request: &'a PersistentEnvelopeRequest<'a>, plaintext: BoundedPlaintext,
    ) -> PersistentBackendFuture<'a, PersistentSealResult>;
    fn open<'a>(
        &'a self, cx: &'a Cx, request: &'a PersistentEnvelopeRequest<'a>, envelope: &'a CanonicalEnvelope,
    ) -> PersistentBackendFuture<'a, PersistentOpenResult>;
}

/// Store request correlation is independent of the envelope provider's receipt.
pub struct PersistentBlobReceipt {
    pub operation_id: [u8; 16],
    pub request_digest: [u8; 32],
    pub artifact_digest: [u8; 32],
    pub configuration_fingerprint: [u8; 32],
    pub backend_generation: u64,
    pub dispatch: RestoreDispatch,
}
pub struct PersistentBlobReadRequest<'a> {
    operation_id: [u8; 16],
    request_digest: [u8; 32],
    configuration: &'a PersistentBlobBackendConfiguration,
    store_id: &'a str,
    store_set_digest: [u8; 32],
    binding_digest: [u8; 32],
    store_fence_generation: u64,
    expected: PersistentBlobRevision,
    envelope_bytes: usize,
    deadline: Time,
}
impl PersistentBlobReadRequest<'_> {
    pub const fn operation_id(&self) -> [u8; 16] { self.operation_id }
    pub const fn request_digest(&self) -> [u8; 32] { self.request_digest }
    pub fn configuration(&self) -> &PersistentBlobBackendConfiguration { self.configuration }
    pub fn store_id(&self) -> &str { self.store_id }
    pub const fn store_set_digest(&self) -> [u8; 32] { self.store_set_digest }
    pub const fn binding_digest(&self) -> [u8; 32] { self.binding_digest }
    pub const fn store_fence_generation(&self) -> u64 { self.store_fence_generation }
    pub const fn expected_revision(&self) -> PersistentBlobRevision { self.expected }
    pub const fn max_envelope_bytes(&self) -> usize { self.envelope_bytes }
    pub const fn deadline(&self) -> Time { self.deadline }
    pub fn receipt(&self) -> PersistentBlobReceipt {
        blob_receipt(self.operation_id, self.request_digest, self.configuration)
    }
}
pub struct PersistentBlobReadResult {
    pub envelope: CanonicalEnvelope,
    pub receipt: PersistentBlobReceipt,
}

pub struct PersistentBlobCommitRequest<'a> {
    request_digest: [u8; 32],
    configuration: &'a PersistentBlobBackendConfiguration,
    fence: &'a RestoreWriteFence,
    expected: Option<PersistentBlobRevision>,
    next: PersistentBlobRevision,
    envelope: &'a CanonicalEnvelope,
    commit_digest: [u8; 32],
    deadline: Time,
}
impl PersistentBlobCommitRequest<'_> {
    pub fn operation_id(&self) -> [u8; 16] { self.fence.operation_id() }
    pub const fn request_digest(&self) -> [u8; 32] { self.request_digest }
    pub fn configuration(&self) -> &PersistentBlobBackendConfiguration { self.configuration }
    pub fn write_fence(&self) -> &RestoreWriteFence { self.fence }
    pub const fn expected_revision(&self) -> Option<PersistentBlobRevision> { self.expected }
    pub const fn next_revision(&self) -> PersistentBlobRevision { self.next }
    pub fn envelope(&self) -> &CanonicalEnvelope { self.envelope }
    /// Ciphertext transaction digest, deliberately different from the pre-seal
    /// logical record digest in write_fence(). The durable proof binds BOTH.
    pub const fn commit_digest(&self) -> [u8; 32] { self.commit_digest }
    pub const fn deadline(&self) -> Time { self.deadline }
    pub fn receipt(&self) -> PersistentBlobReceipt {
        blob_receipt(self.operation_id(), self.request_digest, self.configuration)
    }
}
pub enum PersistentBlobCommitOutcome {
    Committed(DurableRestoreCommitReceipt),
    /// A failed CAS is settled only with an independently verified durable fence
    /// that proves this operation can never commit later.
    FencedConflict(DurableRestoreNonCommitReceipt),
}
pub struct PersistentBlobCommitResult {
    pub receipt: PersistentBlobReceipt,
    pub outcome: PersistentBlobCommitOutcome,
}

/// External transactional store, distinct from the envelope provider. commit
/// MUST perform insert-if-absent or full expected-revision CAS, restore-fence
/// CAS, and persist op ID + logical digest + exact ciphertext commit digest in
/// ONE durable transaction. Its proof must be independently verifiable by the
/// configured restore authority. Read must verify the requested binding and
/// durable restore-fence generation in the SAME consistent read as loading the
/// exact current revision. It cannot substitute a historical or latest revision.
/// Unknown commit outcomes are retained for reconciliation, never retried with
/// a fresh operation ID. Implementers also own bounded durable indexes/cleanup.
pub trait PersistentBlobBackend: Send + Sync + 'static {
    fn read<'a>(&'a self, cx: &'a Cx, request: &'a PersistentBlobReadRequest<'a>)
        -> PersistentBackendFuture<'a, PersistentBlobReadResult>;
    fn commit<'a>(&'a self, cx: &'a Cx, request: &'a PersistentBlobCommitRequest<'a>)
        -> PersistentBackendFuture<'a, PersistentBlobCommitResult>;
}

/// Sealed transaction consumer. Every write prepares its restore intent BEFORE
/// sealing and returns only after the exact durable store receipt is completed.
/// All calls are caller-owned, bounded and cancellation-aware.
pub struct PersistentBlobStore {
    restore: RegisteredRestoreStore,
    configuration: PersistentEnvelopeConfiguration,
    blob_configuration: PersistentBlobBackendConfiguration,
    crypto: Arc<dyn PersistentEnvelopeBackend>,
    blobs: Arc<dyn PersistentBlobBackend>,
    process: ProcessBoundToken,
    quarantined: AtomicBool,
    active: AtomicUsize,
    bytes: Arc<AtomicUsize>,
}
impl PersistentBlobStore {
    pub fn new(
        restore: RegisteredRestoreStore,
        configuration: PersistentEnvelopeConfiguration,
        blob_configuration: PersistentBlobBackendConfiguration,
        crypto: Arc<dyn PersistentEnvelopeBackend>,
        blobs: Arc<dyn PersistentBlobBackend>,
    ) -> Result<Self, PersistentEnvelopeError> {
        configuration.validate()?;
        blob_configuration.validate()?;
        let process = ProcessGenerationGuard::installed()
            .ok_or(PersistentEnvelopeError::ProcessChanged)?.token();
        process.verify().map_err(|_| PersistentEnvelopeError::ProcessChanged)?;
        if restore.is_quarantined() { return Err(PersistentEnvelopeError::Quarantined); }
        Ok(Self {
            restore, configuration, blob_configuration, crypto, blobs, process,
            quarantined: AtomicBool::new(false), active: AtomicUsize::new(0),
            bytes: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn is_quarantined(&self) -> bool {
        self.quarantined.load(Ordering::Acquire) || self.restore.is_quarantined()
    }

    /// Insert a framework-selected random record ID only if absent.
    pub async fn create(&self, cx: &Cx, plaintext: BoundedPlaintext, deadline: Time)
        -> Result<PersistentBlobRevision, PersistentEnvelopeError>
    {
        self.scoped(cx, self.create_inner(cx, plaintext, deadline)).await
    }

    /// Compare the complete trusted prior revision and commit its successor.
    pub async fn replace(&self, cx: &Cx, expected: &PersistentBlobRevision,
        plaintext: BoundedPlaintext, deadline: Time)
        -> Result<PersistentBlobRevision, PersistentEnvelopeError>
    {
        self.scoped(cx, self.replace_inner(cx, expected, plaintext, deadline)).await
    }

    /// Read exactly the caller-retained revision; never infer AAD from storage.
    pub async fn read(&self, cx: &Cx, expected: &PersistentBlobRevision, deadline: Time)
        -> Result<BoundedPlaintext, PersistentEnvelopeError>
    {
        self.scoped(cx, self.read_inner(cx, expected, deadline)).await
    }

    async fn create_inner(&self, cx: &Cx, plaintext: BoundedPlaintext, deadline: Time)
        -> Result<PersistentBlobRevision, PersistentEnvelopeError>
    {
        let deadline = self.deadline(cx, deadline)?;
        let index = BlobIndex {
            namespace: self.restore.namespace_digest(),
            record_id: operation_id(cx)?,
            generation: 1,
        };
        self.write(cx, None, index, plaintext, deadline).await
    }

    async fn replace_inner(&self, cx: &Cx, expected: &PersistentBlobRevision,
        plaintext: BoundedPlaintext, deadline: Time)
        -> Result<PersistentBlobRevision, PersistentEnvelopeError>
    {
        self.admit_revision(expected)?;
        let deadline = self.deadline(cx, deadline)?;
        let index = BlobIndex {
            namespace: expected.namespace, record_id: expected.record_id,
            generation: expected.generation.checked_add(1)
                .ok_or(PersistentEnvelopeError::InvalidRevision)?,
        };
        self.write(cx, Some(*expected), index, plaintext, deadline).await
    }

    async fn write(&self, cx: &Cx, expected: Option<PersistentBlobRevision>,
        index: BlobIndex, plaintext: BoundedPlaintext, deadline: Time)
        -> Result<PersistentBlobRevision, PersistentEnvelopeError>
    {
        let length = plaintext.as_bytes().len();
        if length > self.configuration.limits.plaintext_bytes
            || plaintext.allocated_bytes() > self.configuration.limits.plaintext_bytes
        {
            return Err(PersistentEnvelopeError::TooLarge);
        }
        let _active = ActiveLease::acquire(&self.active, self.configuration.limits.active_operations)?;
        let reserved = plaintext.allocated_bytes().checked_add(self.configuration.limits.envelope_bytes)
            .and_then(|n| n.checked_add(self.configuration.limits.aad_bytes))
            .and_then(|n| n.checked_add(CONTROL_RESERVE))
            .ok_or(PersistentEnvelopeError::TooLarge)?;
        let _bytes = ByteLease::acquire(Arc::clone(&self.bytes), reserved, self.configuration.limits.in_flight_bytes)?;
        let logical = self.logical_digest(expected, index, length)?;
        let fence = self.restore.prepare_write(cx, logical, deadline).await?;
        fence.check(cx)?;
        let deadline = deadline.min(fence.expires_at());
        let context = self.context(fence.binding(), index);
        let request = self.envelope_request(cx, context, length, None, deadline)?;
        let caller = self.caller(cx, deadline)?;
        let future = with_caller(&caller, || self.crypto.seal(&caller, &request, plaintext));
        let sealed = self.within(&caller, deadline, future).await?.map_err(backend_error)?;
        fence.check(cx)?;
        self.admit_envelope_result(&request, &sealed.envelope, &sealed.receipt, true)?;
        let header = sealed.envelope.header()?;
        if header.sealed_bytes() != length.checked_add(16).ok_or(PersistentEnvelopeError::TooLarge)? {
            return self.invalid_receipt();
        }
        let next = PersistentBlobRevision {
            namespace: index.namespace, record_id: index.record_id, generation: index.generation,
            envelope_digest: digest(sealed.envelope.as_bytes(), self.configuration.limits.envelope_bytes)?,
        };
        let commit_digest = self.commit_digest(&fence, expected, next)?;
        let request_digest = self.store_request_digest(
            fence.operation_id(), 2, fence.binding_digest(), fence.store_fence_generation(),
            &commit_digest, deadline,
        )?;
        let commit = PersistentBlobCommitRequest {
            request_digest, configuration: &self.blob_configuration, fence: &fence,
            expected, next, envelope: &sealed.envelope, commit_digest, deadline,
        };
        fence.check(cx)?;
        let caller = self.caller(cx, deadline)?;
        let future = with_caller(&caller, || self.blobs.commit(&caller, &commit));
        let result = self.within(&caller, deadline, future).await?.map_err(backend_error)?;
        fence.check(cx)?;
        self.admit_blob_receipt(&result.receipt, fence.operation_id(), request_digest)?;
        match result.outcome {
            PersistentBlobCommitOutcome::Committed(receipt) => {
                if receipt.commit_digest() != commit_digest { return self.invalid_receipt(); }
                self.restore.complete_write(cx, fence, receipt, deadline).await?;
                self.caller(cx, deadline)?;
                Ok(next)
            }
            PersistentBlobCommitOutcome::FencedConflict(receipt) => {
                self.restore.reconcile_write(
                    cx, fence, DurableRestoreResolution::FencedNotCommitted(receipt), deadline,
                ).await?;
                self.caller(cx, deadline)?;
                Err(PersistentEnvelopeError::Conflict)
            }
        }
    }

    async fn read_inner(&self, cx: &Cx, expected: &PersistentBlobRevision, deadline: Time)
        -> Result<BoundedPlaintext, PersistentEnvelopeError>
    {
        self.admit_revision(expected)?;
        let deadline = self.deadline(cx, deadline)?;
        let _active = ActiveLease::acquire(&self.active, self.configuration.limits.active_operations)?;
        let reserved = self.configuration.limits.envelope_bytes
            + self.configuration.limits.plaintext_bytes + self.configuration.limits.aad_bytes
            + CONTROL_RESERVE;
        let mut bytes = ByteLease::acquire(Arc::clone(&self.bytes), reserved, self.configuration.limits.in_flight_bytes)?;
        let observation = self.restore.current_binding(cx, deadline).await?;
        observation.check(cx)?;
        let deadline = deadline.min(observation.expires_at());
        let id = operation_id(cx)?;
        let request_digest = self.store_request_digest(
            id, 1, observation.binding().digest(), observation.store_fence_generation(),
            &expected.encode(), deadline,
        )?;
        let request = PersistentBlobReadRequest {
            operation_id: id, request_digest, configuration: &self.blob_configuration,
            store_id: self.restore.store_id(), store_set_digest: self.restore.store_set_digest(),
            binding_digest: observation.binding().digest(),
            store_fence_generation: observation.store_fence_generation(),
            expected: *expected, envelope_bytes: self.configuration.limits.envelope_bytes, deadline,
        };
        let caller = self.caller(cx, deadline)?;
        let future = with_caller(&caller, || self.blobs.read(&caller, &request));
        let stored = self.within(&caller, deadline, future).await?.map_err(backend_error)?;
        observation.check(cx)?;
        self.admit_blob_receipt(&stored.receipt, id, request_digest)?;
        if stored.envelope.as_bytes().len() > self.configuration.limits.envelope_bytes
            || stored.envelope.allocated_bytes() > self.configuration.limits.envelope_bytes
        {
            return Err(PersistentEnvelopeError::TooLarge);
        }
        // Full structural/suite/key admission happens before crypto dispatch.
        let header = stored.envelope.header()?;
        if !self.configuration.admits(&header, false) {
            return Err(PersistentEnvelopeError::InvalidEnvelope);
        }
        let envelope_digest = digest(stored.envelope.as_bytes(), self.configuration.limits.envelope_bytes)?;
        if envelope_digest != expected.envelope_digest {
            return Err(PersistentEnvelopeError::InvalidRevision);
        }
        let length = header.sealed_bytes() - 16;
        if length > self.configuration.limits.plaintext_bytes {
            return Err(PersistentEnvelopeError::TooLarge);
        }
        let context = self.context(observation.binding(), BlobIndex::from_revision(expected));
        let open = self.envelope_request(cx, context, length, Some(envelope_digest), deadline)?;
        let caller = self.caller(cx, deadline)?;
        let future = with_caller(&caller, || self.crypto.open(&caller, &open, &stored.envelope));
        let mut result = self.within(&caller, deadline, future).await?.map_err(open_backend_error)?;
        observation.check(cx)?;
        self.admit_envelope_result(&open, &stored.envelope, &result.receipt, false)?;
        if result.plaintext.as_bytes().len() != length
            || result.plaintext.allocated_bytes() > self.configuration.limits.plaintext_bytes
        {
            return self.invalid_receipt();
        }
        self.caller(cx, deadline)?;
        bytes.shrink(result.plaintext.allocated_bytes());
        result.plaintext.admission = Some(bytes);
        Ok(result.plaintext)
    }

    fn context<'a>(&self, binding: &'a RestoreEpochBinding, index: BlobIndex) -> ExpectedEnvelopeContext<'a> {
        ExpectedEnvelopeContext {
            binding, deployment_uuid: self.restore.configuration().deployment_uuid,
            store_set_digest: self.restore.store_set_digest(), index,
            blob_artifact_digest: self.blob_configuration.artifact_digest,
            blob_configuration_fingerprint: self.blob_configuration.configuration_fingerprint,
            blob_generation: self.blob_configuration.generation,
            aad_limit: self.configuration.limits.aad_bytes,
        }
    }

    fn envelope_request<'a>(&'a self, cx: &Cx, context: ExpectedEnvelopeContext<'a>,
        length: usize, envelope_digest: Option<[u8; 32]>, deadline: Time)
        -> Result<PersistentEnvelopeRequest<'a>, PersistentEnvelopeError>
    {
        let id = operation_id(cx)?;
        let mut encoded = b"FMCPERQ\0\0\x01".to_vec();
        encoded.extend_from_slice(&id);
        encoded.push(u8::from(envelope_digest.is_some()));
        encode_bytes(&mut encoded, self.configuration.artifact.as_bytes());
        encoded.extend_from_slice(&self.configuration.artifact_digest);
        encoded.extend_from_slice(&self.configuration.configuration_fingerprint);
        encoded.extend_from_slice(&self.configuration.ring_generation.to_be_bytes());
        encoded.extend_from_slice(&context.binding.digest());
        encoded.extend_from_slice(&context.deployment_uuid);
        encoded.extend_from_slice(&context.store_set_digest);
        encoded.extend_from_slice(&context.blob_artifact_digest);
        encoded.extend_from_slice(&context.blob_configuration_fingerprint);
        encoded.extend_from_slice(&context.blob_generation.to_be_bytes());
        context.index.encode(&mut encoded);
        encoded.extend_from_slice(&(length as u64).to_be_bytes());
        encoded.extend_from_slice(&deadline.as_nanos().to_be_bytes());
        if let Some(digest) = envelope_digest { encoded.extend_from_slice(&digest); }
        Ok(PersistentEnvelopeRequest {
            operation_id: id, request_digest: digest(&encoded, MAX_CONTROL)?, deadline,
            configuration: &self.configuration, context, plaintext_bytes: length,
        })
    }

    fn logical_digest(&self, expected: Option<PersistentBlobRevision>, index: BlobIndex, length: usize)
        -> Result<[u8; 32], PersistentEnvelopeError>
    {
        let mut bytes = b"FMCPLIN\0\0\x01".to_vec();
        bytes.extend_from_slice(&self.restore.store_set_digest());
        bytes.extend_from_slice(&self.blob_configuration.configuration_fingerprint);
        bytes.extend_from_slice(&self.blob_configuration.generation.to_be_bytes());
        index.encode(&mut bytes);
        bytes.extend_from_slice(&(length as u64).to_be_bytes());
        bytes.push(u8::from(expected.is_some()));
        if let Some(expected) = expected { bytes.extend_from_slice(&expected.encode()); }
        digest(&bytes, MAX_CONTROL)
    }

    fn commit_digest(&self, fence: &RestoreWriteFence, expected: Option<PersistentBlobRevision>, next: PersistentBlobRevision)
        -> Result<[u8; 32], PersistentEnvelopeError>
    {
        let mut bytes = b"FMCPCMT\0\0\x01".to_vec();
        bytes.extend_from_slice(&fence.operation_id());
        bytes.extend_from_slice(&fence.binding_digest());
        bytes.extend_from_slice(&fence.store_set_digest());
        bytes.extend_from_slice(&fence.store_fence_generation().to_be_bytes());
        bytes.extend_from_slice(&fence.record_digest());
        bytes.extend_from_slice(&self.blob_configuration.artifact_digest);
        bytes.extend_from_slice(&self.blob_configuration.configuration_fingerprint);
        bytes.extend_from_slice(&self.blob_configuration.generation.to_be_bytes());
        bytes.push(u8::from(expected.is_some()));
        if let Some(expected) = expected { bytes.extend_from_slice(&expected.encode()); }
        bytes.extend_from_slice(&next.encode());
        digest(&bytes, MAX_CONTROL)
    }

    fn store_request_digest(&self, id: [u8; 16], operation: u8, binding: [u8; 32], fence: u64,
        input: &[u8], deadline: Time) -> Result<[u8; 32], PersistentEnvelopeError>
    {
        let mut bytes = b"FMCPBRQ\0\0\x01".to_vec();
        bytes.extend_from_slice(&id);
        bytes.push(operation);
        encode_bytes(&mut bytes, self.blob_configuration.artifact.as_bytes());
        bytes.extend_from_slice(&self.blob_configuration.artifact_digest);
        bytes.extend_from_slice(&self.blob_configuration.configuration_fingerprint);
        bytes.extend_from_slice(&self.blob_configuration.generation.to_be_bytes());
        encode_bytes(&mut bytes, self.restore.store_id().as_bytes());
        bytes.extend_from_slice(&self.restore.store_set_digest());
        bytes.extend_from_slice(&binding);
        bytes.extend_from_slice(&fence.to_be_bytes());
        bytes.extend_from_slice(&deadline.as_nanos().to_be_bytes());
        encode_bytes(&mut bytes, input);
        digest(&bytes, MAX_CONTROL)
    }

    fn admit_envelope_result(&self, request: &PersistentEnvelopeRequest<'_>, envelope: &CanonicalEnvelope,
        receipt: &PersistentEnvelopeReceipt, sealing: bool) -> Result<(), PersistentEnvelopeError>
    {
        if envelope.as_bytes().len() > self.configuration.limits.envelope_bytes
            || envelope.allocated_bytes() > self.configuration.limits.envelope_bytes
        {
            return self.invalid_receipt();
        }
        let header = envelope.header()?;
        if !self.configuration.admits(&header, sealing)
            || receipt.operation_id != request.operation_id
            || receipt.request_digest != request.request_digest
            || receipt.configuration_fingerprint != self.configuration.configuration_fingerprint
            || receipt.ring_generation != self.configuration.ring_generation
            || receipt.key_generation != header.generation()
            || receipt.envelope_digest != digest(envelope.as_bytes(), self.configuration.limits.envelope_bytes)?
            || receipt.dispatch != RestoreDispatch::Dispatched
        {
            return self.invalid_receipt();
        }
        // Reconstruct/validate the exact bounded AAD even though authenticity of
        // a well-formed external backend remains a provider TCB obligation.
        drop(request.context.canonical_aad(&header)?);
        Ok(())
    }
    fn admit_blob_receipt(&self, receipt: &PersistentBlobReceipt, id: [u8; 16], request: [u8; 32])
        -> Result<(), PersistentEnvelopeError>
    {
        if receipt.operation_id != id || receipt.request_digest != request
            || receipt.artifact_digest != self.blob_configuration.artifact_digest
            || receipt.configuration_fingerprint != self.blob_configuration.configuration_fingerprint
            || receipt.backend_generation != self.blob_configuration.generation
            || receipt.dispatch != RestoreDispatch::Dispatched
        { return self.invalid_receipt(); }
        Ok(())
    }
    fn admit_revision(&self, revision: &PersistentBlobRevision) -> Result<(), PersistentEnvelopeError> {
        self.check()?;
        if revision.namespace != self.restore.namespace_digest() || revision.generation == 0 {
            return Err(PersistentEnvelopeError::InvalidRevision);
        }
        Ok(())
    }
    fn invalid_receipt<T>(&self) -> Result<T, PersistentEnvelopeError> {
        self.quarantined.store(true, Ordering::Release);
        Err(PersistentEnvelopeError::InvalidReceipt)
    }
    fn check(&self) -> Result<(), PersistentEnvelopeError> {
        self.process.verify().map_err(|_| PersistentEnvelopeError::ProcessChanged)?;
        if self.is_quarantined() { return Err(PersistentEnvelopeError::Quarantined); }
        Ok(())
    }
    fn deadline(&self, cx: &Cx, deadline: Time) -> Result<Time, PersistentEnvelopeError> {
        self.check()?;
        with_caller(cx, || {
            let active = Cx::current().ok_or(PersistentEnvelopeError::CapabilityUnavailable)?;
            require_caller(&active)?;
            active.checkpoint().map_err(|_| PersistentEnvelopeError::Cancelled)?;
            let timeout = u64::try_from(self.configuration.limits.call_timeout.as_nanos())
                .map_err(|_| PersistentEnvelopeError::InvalidConfiguration)?;
            let timeout = active.now().as_nanos().checked_add(timeout)
                .map(Time::from_nanos).ok_or(PersistentEnvelopeError::DeadlineExceeded)?;
            let deadline = deadline.min(timeout);
            let deadline = active.budget().deadline.map_or(deadline, |parent| parent.min(deadline));
            if active.now() >= deadline { return Err(PersistentEnvelopeError::DeadlineExceeded); }
            Ok(deadline)
        })
    }
    fn caller(&self, cx: &Cx, deadline: Time) -> Result<Cx, PersistentEnvelopeError> {
        self.check()?;
        with_caller(cx, || {
            let active = Cx::current().ok_or(PersistentEnvelopeError::CapabilityUnavailable)?;
            require_caller(&active)?;
            active.checkpoint().map_err(|_| PersistentEnvelopeError::Cancelled)?;
            if active.now() >= deadline { return Err(PersistentEnvelopeError::DeadlineExceeded); }
            Ok(active)
        })
    }

    // One retained ceiling covers the WHOLE transaction, including authority
    // awaits and transitions between separate backend calls.
    async fn scoped<F, T>(&self, cx: &Cx, future: F) -> Result<T, PersistentEnvelopeError>
    where F: Future<Output = Result<T, PersistentEnvelopeError>>
    {
        let mut future = CallerFuture {
            cx, ceiling: ambient_capability_ceiling(), future: Some(Box::pin(future)),
        };
        poll_fn(|task| {
            future.ceiling = future.ceiling.intersect(ambient_capability_ceiling());
            let _caller = Cx::set_current(Some(cx.clone()));
            let _restriction = Cx::push_restriction(future.ceiling);
            let active = Cx::current().ok_or(PersistentEnvelopeError::CapabilityUnavailable)?;
            self.check()?;
            require_caller(&active)?;
            active.checkpoint().map_err(|_| PersistentEnvelopeError::Cancelled)?;
            let result = future.future.as_mut().expect("transaction future is owned").as_mut().poll(task);
            match result {
                Poll::Ready(Ok(value)) => {
                    self.check()?;
                    active.checkpoint().map_err(|_| PersistentEnvelopeError::Cancelled)?;
                    Poll::Ready(Ok(value))
                }
                other => other,
            }
        }).await
    }

    async fn within<F: Future>(&self, cx: &Cx, deadline: Time, future: F)
        -> Result<F::Output, PersistentEnvelopeError>
    {
        let mut future = CallerFuture {
            cx, ceiling: ambient_capability_ceiling(), future: Some(Box::pin(future)),
        };
        let mut sleep = std::pin::pin!(Sleep::new(deadline));
        let (_sender, mut receiver) = oneshot::channel::<()>();
        let mut cancelled = std::pin::pin!(receiver.recv(cx));
        poll_fn(|task| {
            future.ceiling = future.ceiling.intersect(ambient_capability_ceiling());
            let _caller = Cx::set_current(Some(cx.clone()));
            let _restriction = Cx::push_restriction(future.ceiling);
            let active = Cx::current().ok_or(PersistentEnvelopeError::CapabilityUnavailable)?;
            self.check()?;
            require_caller(&active)?;
            active.checkpoint().map_err(|_| PersistentEnvelopeError::Cancelled)?;
            if active.now() >= deadline { return Poll::Ready(Err(PersistentEnvelopeError::DeadlineExceeded)); }
            if cancelled.as_mut().poll(task).is_ready() { return Poll::Ready(Err(PersistentEnvelopeError::Cancelled)); }
            if sleep.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(if active.is_cancel_requested() {
                    PersistentEnvelopeError::Cancelled
                } else { PersistentEnvelopeError::DeadlineExceeded }));
            }
            let result = future.future.as_mut().expect("provider future is owned").as_mut().poll(task);
            self.check()?;
            if active.is_cancel_requested() { return Poll::Ready(Err(PersistentEnvelopeError::Cancelled)); }
            if active.now() >= deadline { return Poll::Ready(Err(PersistentEnvelopeError::DeadlineExceeded)); }
            result.map(Ok)
        }).await
    }
}

fn blob_receipt(id: [u8; 16], request_digest: [u8; 32], configuration: &PersistentBlobBackendConfiguration) -> PersistentBlobReceipt {
    PersistentBlobReceipt {
        operation_id: id, request_digest, artifact_digest: configuration.artifact_digest,
        configuration_fingerprint: configuration.configuration_fingerprint,
        backend_generation: configuration.generation, dispatch: RestoreDispatch::Dispatched,
    }
}
fn backend_error(failure: PersistentBackendFailure) -> PersistentEnvelopeError {
    if failure.dispatch != RestoreDispatch::NotDispatched {
        PersistentEnvelopeError::Uncertain
    } else {
        // A conflict string is not a durable noncommit proof. Only the verified
        // FencedConflict result above can release a live write intent normally.
        PersistentEnvelopeError::ProviderUnavailable
    }
}
fn open_backend_error(failure: PersistentBackendFailure) -> PersistentEnvelopeError {
    // Crypto open is nonmutating record access. A completed authentication
    // refusal can share the same redacted error as structural envelope refusal.
    if failure.dispatch == RestoreDispatch::Unknown {
        PersistentEnvelopeError::Uncertain
    } else if failure.kind == PersistentBackendFailureKind::AuthenticationFailed {
        PersistentEnvelopeError::InvalidEnvelope
    } else {
        PersistentEnvelopeError::ProviderUnavailable
    }
}
fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(|c| c.is_control() || c.is_whitespace())
}
fn digest(bytes: &[u8], maximum: usize) -> Result<[u8; 32], PersistentEnvelopeError> {
    sha256_bounded(bytes, maximum).map(|digest| *digest.as_bytes()).map_err(|_| PersistentEnvelopeError::TooLarge)
}
fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn operation_id(cx: &Cx) -> Result<[u8; 16], PersistentEnvelopeError> {
    with_caller(cx, || {
        let active = Cx::current().ok_or(PersistentEnvelopeError::CapabilityUnavailable)?;
        require_caller(&active)?;
        active.checkpoint().map_err(|_| PersistentEnvelopeError::Cancelled)?;
        let id = draw_security_identifier().map_err(|_| PersistentEnvelopeError::RandomSourceUnavailable)?;
        let mut out = [0; 16];
        out.copy_from_slice(&id.as_bytes()[..16]);
        Ok(out)
    })
}
fn with_caller<T>(cx: &Cx, action: impl FnOnce() -> T) -> T {
    let ceiling = ambient_capability_ceiling();
    let _caller = Cx::set_current(Some(cx.clone()));
    let _restriction = Cx::push_restriction(ceiling);
    action()
}
fn require_caller(cx: &Cx) -> Result<(), PersistentEnvelopeError> {
    let effects = cx.capabilities();
    if !effects.time || !effects.entropy || !effects.io || !effects.remote || cx.timer_driver().is_none() {
        return Err(PersistentEnvelopeError::CapabilityUnavailable);
    }
    Ok(())
}
struct CallerFuture<'a, F> {
    cx: &'a Cx,
    ceiling: CapMask,
    future: Option<Pin<Box<F>>>,
}
impl<F> Drop for CallerFuture<'_, F> {
    fn drop(&mut self) {
        let ceiling = self.ceiling.intersect(ambient_capability_ceiling());
        let _caller = Cx::set_current(Some(self.cx.clone()));
        let _restriction = Cx::push_restriction(ceiling);
        drop(self.future.take());
    }
}
struct ActiveLease<'a> { counter: &'a AtomicUsize }
impl<'a> ActiveLease<'a> {
    fn acquire(counter: &'a AtomicUsize, maximum: usize) -> Result<Self, PersistentEnvelopeError> {
        counter.try_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < maximum).then_some(n + 1))
            .map_err(|_| PersistentEnvelopeError::CapacityExceeded)?;
        Ok(Self { counter })
    }
}
impl Drop for ActiveLease<'_> {
    fn drop(&mut self) { self.counter.fetch_sub(1, Ordering::AcqRel); }
}
struct ByteLease { counter: Arc<AtomicUsize>, bytes: usize }
impl ByteLease {
    fn acquire(counter: Arc<AtomicUsize>, bytes: usize, maximum: usize) -> Result<Self, PersistentEnvelopeError> {
        counter.try_update(Ordering::AcqRel, Ordering::Acquire, |old| old.checked_add(bytes).filter(|n| *n <= maximum))
            .map_err(|_| PersistentEnvelopeError::CapacityExceeded)?;
        Ok(Self { counter, bytes })
    }
    fn shrink(&mut self, bytes: usize) {
        debug_assert!(bytes <= self.bytes);
        self.counter.fetch_sub(self.bytes - bytes, Ordering::AcqRel);
        self.bytes = bytes;
    }
}
impl Drop for ByteLease {
    fn drop(&mut self) { self.counter.fetch_sub(self.bytes, Ordering::AcqRel); }
}
