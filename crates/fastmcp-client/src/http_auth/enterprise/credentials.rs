//! Protected confidential-client credential custody for the native exchanges.
//!
//! A trusted embedding provisions a versioned record through its registered
//! protected blob store, retains the exact committed revision independently,
//! and selects that revision here. Neither a token response nor the blob backend
//! can choose a role, endpoint, client, authentication method or newer revision.
//! The native driver is the only consumer of decrypted secret bytes. This
//! component does not attest the deployment or activate complete enterprise
//! authorization; the external envelope, blob and restore providers remain
//! deployment trust boundaries.

#[cfg(test)]
pub(super) mod tests;

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::persistent::{
    BoundedPlaintext, PersistentBlobRevision, PersistentBlobStore, PersistentEnvelopeError,
};
use fastmcp_core::restore::RestoreError;
use fastmcp_core::runtime::{ProcessBoundToken, ProcessGenerationGuard};
use fastmcp_core::{McpRequestCancellation, Sha256Digest, sha256_bounded};

use super::identity::{EnterpriseIdentitySnapshotKey, profile_digest};
use super::policy::EnterpriseProfile;
use super::response::EnterpriseClientSecret;

const RECORD_PREFIX: &[u8] = b"FMCPENTCRED\0\x01";
const RECORD_HEADER: usize = RECORD_PREFIX.len() + 32 + 8 + 2;
const MAX_SECRET_BYTES: usize = 4_096;
const MAX_RECORD_BYTES: usize = RECORD_HEADER + MAX_SECRET_BYTES;
// In-place authenticated decryption may truncate its tag while retaining the
// ciphertext allocation. Keep that finite allocation separate from wire size.
const MAX_RECORD_ALLOCATION: usize = MAX_RECORD_BYTES * 2;
const MAX_BINDING_BYTES: usize = 4_096;

/// The two independently registered confidential-client roles. The IdP role
/// serves code redemption and ID-JAG exchange; the resource-AS role serves only
/// final JWT-bearer redemption. Shared backend storage never merges these roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseCredentialRole {
    Idp,
    ResourceAuthorizationServer,
}

/// Fixed diagnostics never contain record bytes, endpoints, clients or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseCredentialError {
    InvalidConfiguration,
    BindingMismatch,
    InvalidRecord,
    RevisionMismatch,
    GenerationRollback,
    Revoked,
    Expired,
    ProcessChanged,
    StoreUnavailable,
    Cancelled,
    TimedOut,
}

impl fmt::Display for EnterpriseCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid enterprise credential configuration",
            Self::BindingMismatch => "enterprise credential authority does not match",
            Self::InvalidRecord => "protected enterprise credential record was refused",
            Self::RevisionMismatch => "enterprise credential revision does not match",
            Self::GenerationRollback => "enterprise credential generation did not advance",
            Self::Revoked => "enterprise credential generation was revoked",
            Self::Expired => "enterprise credential generation expired",
            Self::ProcessChanged => "enterprise credential process generation changed",
            Self::StoreUnavailable => "protected enterprise credential store unavailable",
            Self::Cancelled => "enterprise credential acquisition cancelled",
            Self::TimedOut => "enterprise credential acquisition exceeded its deadline",
        })
    }
}

impl std::error::Error for EnterpriseCredentialError {}

/// Independently selected complete profile, reviewed mapping snapshot and role.
/// The profile binds both issuers, exact token endpoints, client registrations,
/// authentication methods, policy/key generations, source document digests and
/// scope allowances. No metadata from a stored record can replace these values.
pub struct EnterpriseCredentialBinding {
    profile: EnterpriseProfile,
    snapshot: EnterpriseIdentitySnapshotKey,
    role: EnterpriseCredentialRole,
    digest: Sha256Digest,
}

impl EnterpriseCredentialBinding {
    pub fn new(
        profile: EnterpriseProfile,
        snapshot: EnterpriseIdentitySnapshotKey,
        role: EnterpriseCredentialRole,
    ) -> Result<Self, EnterpriseCredentialError> {
        let profile_hash = profile_digest(&profile)
            .map_err(|_| EnterpriseCredentialError::InvalidConfiguration)?;
        let mut encoded = b"fastmcp-enterprise-credential-binding-v1".to_vec();
        encoded.extend_from_slice(profile_hash.as_bytes());
        encoded.extend_from_slice(&(snapshot.id().len() as u64).to_be_bytes());
        encoded.extend_from_slice(snapshot.id().as_bytes());
        encoded.extend_from_slice(&snapshot.generation().to_be_bytes());
        encoded.extend_from_slice(snapshot.digest().as_bytes());
        encoded.push(match role {
            EnterpriseCredentialRole::Idp => 1,
            EnterpriseCredentialRole::ResourceAuthorizationServer => 2,
        });
        let digest = sha256_bounded(&encoded, MAX_BINDING_BYTES)
            .map_err(|_| EnterpriseCredentialError::InvalidConfiguration)?;
        Ok(Self {
            profile,
            snapshot,
            role,
            digest,
        })
    }

    /// Encodes a trusted provisioning secret into an exclusively owned,
    /// zeroizing protected-store payload. Persist it with `create` or `replace`
    /// and retain the resulting exact revision in trusted configuration.
    /// This provisioning codec performs no exchange and grants no deployment
    /// authority. Native provider paths never accept this plaintext directly.
    pub fn encode_record(
        &self,
        secret: EnterpriseClientSecret,
        generation: u64,
    ) -> Result<BoundedPlaintext, EnterpriseCredentialError> {
        if generation == 0 {
            return Err(EnterpriseCredentialError::InvalidConfiguration);
        }
        let secret = secret.as_str();
        let mut bytes =
            BoundedPlaintext::new(Vec::with_capacity(RECORD_HEADER + secret.len()).into())
                .map_err(map_store_error)?
                .into_zeroizing();
        bytes.extend_from_slice(RECORD_PREFIX);
        bytes.extend_from_slice(self.digest.as_bytes());
        bytes.extend_from_slice(&generation.to_be_bytes());
        bytes.extend_from_slice(&(secret.len() as u16).to_be_bytes());
        bytes.extend_from_slice(secret.as_bytes());
        BoundedPlaintext::new(bytes).map_err(map_store_error)
    }
}

struct CredentialGeneration {
    revision: PersistentBlobRevision,
    generation: u64,
    valid_until: Instant,
    cancellation: McpRequestCancellation,
}

/// Concrete restore-fenced protected-blob credential provider.
///
/// Selection is an exact trusted revision, never a backend's "latest" record.
/// Reads authenticate the protected envelope through `PersistentBlobStore` and
/// verify the closed credential record before the sealed native serializer can
/// access its secret. Rotation and revocation invalidate acquired generations
/// immediately, including reads and HTTP exchanges already waiting on I/O.
pub struct EnterpriseClientCredentialProvider {
    binding: EnterpriseCredentialBinding,
    store: Arc<PersistentBlobStore>,
    current: Mutex<Arc<CredentialGeneration>>,
    active_generation: Arc<AtomicU64>,
    process: ProcessBoundToken,
}

impl EnterpriseClientCredentialProvider {
    pub fn new(
        binding: EnterpriseCredentialBinding,
        store: Arc<PersistentBlobStore>,
        revision: PersistentBlobRevision,
        generation: u64,
        valid_until: Instant,
    ) -> Result<Self, EnterpriseCredentialError> {
        validate_generation(generation, valid_until)?;
        if store.is_quarantined() {
            return Err(EnterpriseCredentialError::StoreUnavailable);
        }
        let process = ProcessGenerationGuard::installed()
            .ok_or(EnterpriseCredentialError::ProcessChanged)?
            .token();
        process
            .verify()
            .map_err(|_| EnterpriseCredentialError::ProcessChanged)?;
        Ok(Self {
            binding,
            store,
            current: Mutex::new(Arc::new(CredentialGeneration {
                revision,
                generation,
                valid_until,
                cancellation: McpRequestCancellation::new(),
            })),
            active_generation: Arc::new(AtomicU64::new(generation)),
            process,
        })
    }

    /// Selects a separately committed replacement of the same protected record.
    /// Both the durable revision and credential generation must advance. No
    /// backend write is attempted here; failed selection leaves the old owner
    /// unchanged. A revoked provider cannot be reactivated by rotation.
    pub fn rotate(
        &self,
        expected: &PersistentBlobRevision,
        next: PersistentBlobRevision,
        generation: u64,
        valid_until: Instant,
    ) -> Result<(), EnterpriseCredentialError> {
        validate_generation(generation, valid_until)?;
        self.process
            .verify()
            .map_err(|_| EnterpriseCredentialError::ProcessChanged)?;
        if self.store.is_quarantined() {
            return Err(EnterpriseCredentialError::StoreUnavailable);
        }
        let previous = {
            let mut current = self
                .current
                .lock()
                .map_err(|_| EnterpriseCredentialError::StoreUnavailable)?;
            if self.active_generation.load(Ordering::Acquire) == 0 {
                return Err(EnterpriseCredentialError::Revoked);
            }
            if current.revision != *expected
                || next.namespace_digest() != expected.namespace_digest()
                || next.record_id() != expected.record_id()
            {
                return Err(EnterpriseCredentialError::RevisionMismatch);
            }
            if generation <= current.generation || next.generation() <= expected.generation() {
                return Err(EnterpriseCredentialError::GenerationRollback);
            }
            let replacement = Arc::new(CredentialGeneration {
                revision: next,
                generation,
                valid_until,
                cancellation: McpRequestCancellation::new(),
            });
            let previous = std::mem::replace(&mut *current, replacement);
            // Publish revocation before releasing the lock; notifications are
            // delivered afterwards so a user waker cannot reenter this lock.
            self.active_generation.store(generation, Ordering::Release);
            previous
        };
        previous.cancellation.cancel();
        Ok(())
    }

    /// Irreversibly revokes this provider and wakes its pending acquisitions or
    /// exchanges. It never cancels the caller's shared context or other roles.
    pub fn revoke(&self) {
        // Revocation is the fail-closed path: even a poisoned generation lock
        // must not strand an already-admitted reader waiting for cancellation.
        // Keep the generation fence and token snapshot serialized with rotate;
        // ordinary select/rotate still refuse poisoned state.
        let current = match self.current.lock() {
            Ok(current) => current,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.active_generation.store(0, Ordering::Release);
        let cancellation = current.cancellation.clone();
        drop(current);
        // Wake callbacks only after releasing the mutex.
        cancellation.cancel();
    }

    pub(super) fn select(
        &self,
        profile: &EnterpriseProfile,
        snapshot: &EnterpriseIdentitySnapshotKey,
        role: EnterpriseCredentialRole,
    ) -> Result<PendingEnterpriseCredential, EnterpriseCredentialError> {
        if profile != &self.binding.profile
            || snapshot != &self.binding.snapshot
            || role != self.binding.role
        {
            return Err(EnterpriseCredentialError::BindingMismatch);
        }
        let generation = {
            let current = self
                .current
                .lock()
                .map_err(|_| EnterpriseCredentialError::StoreUnavailable)?;
            Arc::clone(&*current)
        };
        let pending = PendingEnterpriseCredential {
            generation,
            active_generation: Arc::clone(&self.active_generation),
            store: Arc::clone(&self.store),
            process: self.process,
            binding_digest: self.binding.digest,
        };
        pending.check()?;
        Ok(pending)
    }
}

impl Drop for EnterpriseClientCredentialProvider {
    fn drop(&mut self) {
        self.revoke();
    }
}

pub(super) struct PendingEnterpriseCredential {
    generation: Arc<CredentialGeneration>,
    active_generation: Arc<AtomicU64>,
    store: Arc<PersistentBlobStore>,
    process: ProcessBoundToken,
    binding_digest: Sha256Digest,
}

impl PendingEnterpriseCredential {
    pub(super) fn valid_until(&self) -> Instant {
        self.generation.valid_until
    }

    pub(super) fn check(&self) -> Result<(), EnterpriseCredentialError> {
        if self.active_generation.load(Ordering::Acquire) != self.generation.generation
            || self.generation.cancellation.is_cancel_requested()
        {
            return Err(EnterpriseCredentialError::Revoked);
        }
        self.process
            .verify()
            .map_err(|_| EnterpriseCredentialError::ProcessChanged)?;
        if Instant::now() >= self.generation.valid_until {
            return Err(EnterpriseCredentialError::Expired);
        }
        if self.store.is_quarantined() {
            return Err(EnterpriseCredentialError::StoreUnavailable);
        }
        Ok(())
    }

    pub(super) async fn revoked(&self) {
        self.generation.cancellation.cancelled().await;
    }

    pub(super) async fn read(
        &self,
        cx: &Cx,
        deadline: Time,
    ) -> Result<EnterpriseCredentialLease, EnterpriseCredentialError> {
        self.check()?;
        let record = self
            .store
            .read(cx, &self.generation.revision, deadline)
            .await
            .map_err(map_store_error)?;
        self.check()?;
        validate_record(&record, self.binding_digest, self.generation.generation)?;
        Ok(EnterpriseCredentialLease {
            record,
            authority: PendingEnterpriseCredential {
                generation: Arc::clone(&self.generation),
                active_generation: Arc::clone(&self.active_generation),
                store: Arc::clone(&self.store),
                process: self.process,
                binding_digest: self.binding_digest,
            },
        })
    }
}

/// Exclusive plaintext stays behind the sealed native Basic/form serializer.
/// Deliberately no Clone, Debug, serialization or public byte accessor.
pub(super) struct EnterpriseCredentialLease {
    record: BoundedPlaintext,
    authority: PendingEnterpriseCredential,
}

impl EnterpriseCredentialLease {
    pub(super) fn check(&self) -> Result<(), EnterpriseCredentialError> {
        self.authority.check()
    }

    pub(super) async fn revoked(&self) {
        self.authority.revoked().await;
    }

    pub(super) fn as_str(&self) -> Result<&str, EnterpriseCredentialError> {
        self.check()?;
        std::str::from_utf8(&self.record.as_bytes()[RECORD_HEADER..])
            .map_err(|_| EnterpriseCredentialError::InvalidRecord)
    }
}

fn validate_generation(
    generation: u64,
    valid_until: Instant,
) -> Result<(), EnterpriseCredentialError> {
    if generation == 0 {
        return Err(EnterpriseCredentialError::InvalidConfiguration);
    }
    if Instant::now() >= valid_until {
        return Err(EnterpriseCredentialError::Expired);
    }
    Ok(())
}

fn validate_record(
    record: &BoundedPlaintext,
    binding: Sha256Digest,
    generation: u64,
) -> Result<(), EnterpriseCredentialError> {
    let bytes = record.as_bytes();
    if bytes.len() <= RECORD_HEADER
        || bytes.len() > MAX_RECORD_BYTES
        || record.allocated_bytes() > MAX_RECORD_ALLOCATION
        || !bytes.starts_with(RECORD_PREFIX)
        || bytes[RECORD_PREFIX.len()..RECORD_PREFIX.len() + 32] != *binding.as_bytes()
        || bytes[RECORD_PREFIX.len() + 32..RECORD_HEADER - 2] != generation.to_be_bytes()
    {
        return Err(EnterpriseCredentialError::InvalidRecord);
    }
    let length = u16::from_be_bytes([bytes[RECORD_HEADER - 2], bytes[RECORD_HEADER - 1]]) as usize;
    let secret = &bytes[RECORD_HEADER..];
    if length != secret.len()
        || secret.iter().any(|byte| *byte < 0x20 || *byte == 0x7f)
        || std::str::from_utf8(secret).is_err()
    {
        return Err(EnterpriseCredentialError::InvalidRecord);
    }
    Ok(())
}

fn map_store_error(error: PersistentEnvelopeError) -> EnterpriseCredentialError {
    match error {
        PersistentEnvelopeError::Cancelled
        | PersistentEnvelopeError::Restore(RestoreError::Cancelled) => {
            EnterpriseCredentialError::Cancelled
        }
        PersistentEnvelopeError::DeadlineExceeded
        | PersistentEnvelopeError::Restore(RestoreError::DeadlineExceeded) => {
            EnterpriseCredentialError::TimedOut
        }
        PersistentEnvelopeError::ProcessChanged
        | PersistentEnvelopeError::Restore(RestoreError::ProcessChanged) => {
            EnterpriseCredentialError::ProcessChanged
        }
        _ => EnterpriseCredentialError::StoreUnavailable,
    }
}
