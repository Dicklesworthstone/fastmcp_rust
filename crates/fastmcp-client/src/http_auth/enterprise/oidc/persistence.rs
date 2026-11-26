//! Restore-fenced custody for the local OIDC pending-challenge codec.
//!
//! Preparation commits protected state, nonce and PKCE bytes before exposing
//! the authorization URL. Resume reads only an independently retained exact
//! revision. Callback admission first replaces that revision with a secret-free
//! consumed record, so competing workers and resumed owners cannot both redeem.
//! A crash after that CAS requires a fresh authorization flow.
//!
//! This is not browser-launch or callback-origin attestation, the complete
//! enterprise activation state machine, or a built-in storage deployment. The
//! embedding supplies qualified blob/envelope/restore providers, bounded record
//! retention and cleanup, and a trusted current wall-clock sample on resume.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use asupersync::Cx;
use asupersync::security::SecretString;
use asupersync::types::Time;
use fastmcp_core::persistent::{
    BoundedPlaintext, PersistentBlobRevision, PersistentBlobStore, PersistentEnvelopeError,
};
use fastmcp_core::restore::RestoreError;
use fastmcp_core::runtime::{ProcessBoundToken, ProcessGenerationGuard};

use super::super::identity::{EnterpriseIdentitySnapshotKey, EnterpriseOidcSubjectType, profile_digest};
use super::{
    ConfiguredTenant, MAX_FLOW_LIFETIME, OidcCallbackOutcome, OidcCodeFlowConfiguration,
    OidcCodeFlowError, PreparedOidcAuthorization, digest, live,
};

#[cfg(test)]
mod tests;

const PREFIX: &[u8] = b"FMCPOIDCFLOW\0\x01";
const PENDING: u8 = 1;
const CONSUMED: u8 = 2;
const CHALLENGE_BYTES: usize = 43;
const RECORD_BYTES: usize = PREFIX.len() + 1 + 32 + 24 + 64 + 3 * CHALLENGE_BYTES;
const MAX_RECORD_ALLOCATION: usize = 2 * RECORD_BYTES;
const MAX_BINDING_BYTES: usize = 16 * 1024;

/// Redacted errors never contain protected records, callbacks or provider text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcPendingFlowError {
    InvalidConfiguration,
    BindingMismatch,
    InvalidRecord,
    ConsumedOrChanged,
    StoreUnavailable,
    Uncertain,
    ProcessChanged,
    Cancelled,
    TimedOut,
    Expired,
    CodeFlow(OidcCodeFlowError),
}

impl fmt::Display for OidcPendingFlowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidConfiguration => "invalid protected OIDC flow configuration",
            Self::BindingMismatch => "protected OIDC flow authority does not match",
            Self::InvalidRecord => "protected OIDC flow record was refused",
            Self::ConsumedOrChanged => "protected OIDC flow was consumed or changed",
            Self::StoreUnavailable => "protected OIDC flow store is unavailable",
            Self::Uncertain => "protected OIDC flow commit is uncertain",
            Self::ProcessChanged => "protected OIDC flow process generation changed",
            Self::Cancelled => "protected OIDC flow operation was cancelled",
            Self::TimedOut => "protected OIDC flow operation exceeded its deadline",
            Self::Expired => "protected OIDC flow expired",
            Self::CodeFlow(error) => return fmt::Display::fmt(error, formatter),
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OidcPendingFlowError {}

impl From<OidcCodeFlowError> for OidcPendingFlowError {
    fn from(error: OidcCodeFlowError) -> Self {
        Self::CodeFlow(error)
    }
}

/// One independently selected configuration, identity snapshot and protected
/// store. Stored bytes cannot replace these authorities or select a newer
/// revision. Reconstruct this owner with current trusted inputs after restart.
pub struct OidcPendingFlowStore {
    configuration: OidcCodeFlowConfiguration,
    binding: [u8; 32],
    snapshot: EnterpriseIdentitySnapshotKey,
    store: Arc<PersistentBlobStore>,
    process: ProcessBoundToken,
}

impl OidcPendingFlowStore {
    pub fn new(
        configuration: OidcCodeFlowConfiguration,
        snapshot: EnterpriseIdentitySnapshotKey,
        store: Arc<PersistentBlobStore>,
    ) -> Result<Self, OidcPendingFlowError> {
        let binding = configuration_binding(&configuration, &snapshot)?;
        let process = ProcessGenerationGuard::installed()
            .ok_or(OidcPendingFlowError::ProcessChanged)?
            .token();
        process
            .verify()
            .map_err(|_| OidcPendingFlowError::ProcessChanged)?;
        if store.is_quarantined() {
            return Err(OidcPendingFlowError::StoreUnavailable);
        }
        Ok(Self {
            configuration,
            binding,
            snapshot,
            store,
            process,
        })
    }

    /// Generates independent challenges and commits them before returning any
    /// launch bytes. Storage work consumes the original finite flow lifetime;
    /// neither the commit nor a later resume restarts it.
    pub async fn prepare(
        &self,
        cx: &Cx,
        now: SystemTime,
        lifetime: Duration,
        deadline: Time,
    ) -> Result<PersistedOidcAuthorization, OidcPendingFlowError> {
        check_runtime(cx)?;
        let clock = FlowClock::new(now);
        let pending = self.configuration.prepare(cx, now, lifetime)?;
        let custody = self.custody(&clock, pending.created_at, pending.expires_at)?;
        let record = encode_pending(&pending, self.binding)?;
        let deadline = custody.deadline(cx, deadline)?;
        let revision = self.store.create(cx, record, deadline).await.map_err(store_error)?;
        check_runtime(cx)?;
        custody.check()?;
        Ok(PersistedOidcAuthorization {
            pending,
            revision,
            binding: self.binding,
            custody,
        })
    }

    /// Restores only the caller-retained complete revision. The protected record
    /// must match every current policy/profile/snapshot input, retain canonical
    /// challenges and reproduce the exact originally committed GET digests.
    pub async fn resume(
        &self,
        cx: &Cx,
        revision: PersistentBlobRevision,
        now: SystemTime,
        deadline: Time,
    ) -> Result<PersistedOidcAuthorization, OidcPendingFlowError> {
        check_runtime(cx)?;
        self.process
            .verify()
            .map_err(|_| OidcPendingFlowError::ProcessChanged)?;
        let clock = FlowClock::new(now);
        let record = self.store.read(cx, &revision, deadline).await.map_err(store_error)?;
        let pending = decode_pending(&record, self.binding, &self.configuration)?;
        let custody = self.custody(&clock, pending.created_at, pending.expires_at)?;
        check_runtime(cx)?;
        custody.check()?;
        Ok(PersistedOidcAuthorization {
            pending,
            revision,
            binding: self.binding,
            custody,
        })
    }

    fn custody(
        &self,
        clock: &FlowClock,
        created_at: SystemTime,
        expires_at: SystemTime,
    ) -> Result<OidcFlowCustodyGuard, OidcPendingFlowError> {
        live(created_at, expires_at, clock.now()?)?;
        let remaining = expires_at
            .duration_since(clock.wall)
            .map_err(|_| OidcPendingFlowError::Expired)?;
        let valid_until = clock
            .monotonic
            .checked_add(remaining)
            .ok_or(OidcPendingFlowError::Expired)?;
        Ok(OidcFlowCustodyGuard {
            store: Arc::clone(&self.store),
            process: self.process,
            snapshot: self.snapshot.clone(),
            valid_until,
        })
    }
}

/// A committed or resumed challenge owner. It deliberately has no Clone, Debug
/// or serialization implementation. Retain revision() separately from storage
/// to resume; never replace it with an untrusted backend's latest revision.
pub struct PersistedOidcAuthorization {
    pending: PreparedOidcAuthorization,
    revision: PersistentBlobRevision,
    binding: [u8; 32],
    custody: OidcFlowCustodyGuard,
}

impl PersistedOidcAuthorization {
    pub const fn revision(&self) -> PersistentBlobRevision {
        self.revision
    }

    pub fn authorization_url(&self) -> Result<&str, OidcPendingFlowError> {
        self.custody.check()?;
        Ok(self.pending.authorization_url())
    }

    pub fn request_target(&self) -> Result<&str, OidcPendingFlowError> {
        self.custody.check()?;
        Ok(self.pending.request_target())
    }

    pub fn expires_at(&self) -> SystemTime {
        self.pending.expires_at()
    }

    /// Atomically consumes the exact pending revision BEFORE interpreting the
    /// callback, including malformed/denied callbacks. Only the winning CAS can
    /// return a code grant. A failed or ambiguous commit returns no grant; there
    /// is no fallback to the in-memory challenge. Cancellation after commit can
    /// lose the flow but cannot authorize a second redemption.
    ///
    /// This performs the existing local callback codec checks, not a browser
    /// launch or callback-origin attestation. The returned grant retains store,
    /// process and original monotonic-expiry checks through native redemption.
    pub async fn admit_callback(
        self,
        cx: &Cx,
        callback_uri: &str,
        received_at: SystemTime,
        deadline: Time,
    ) -> Result<OidcCallbackOutcome, OidcPendingFlowError> {
        let clock = FlowClock::new(received_at);
        self.consume(cx, deadline).await?;
        let mut outcome = self.pending.admit_callback(callback_uri, clock.now()?)?;
        self.custody.check()?;
        if let OidcCallbackOutcome::Code(grant) = &mut outcome {
            grant.persistent_custody = Some(self.custody);
        }
        Ok(outcome)
    }

    /// Discards a live pending challenge through the same one-use CAS.
    pub async fn discard(
        self,
        cx: &Cx,
        deadline: Time,
    ) -> Result<(), OidcPendingFlowError> {
        self.consume(cx, deadline).await
    }

    async fn consume(&self, cx: &Cx, deadline: Time) -> Result<(), OidcPendingFlowError> {
        let deadline = self.custody.deadline(cx, deadline)?;
        let record = consumed_record(self.binding)?;
        self.custody
            .store
            .replace(cx, &self.revision, record, deadline)
            .await
            .map_err(store_error)?;
        check_runtime(cx)?;
        self.custody.check()?;
        Ok(())
    }
}

/// Retained by code/response owners so quarantining storage or changing process
/// generation cannot turn an already decoded challenge into unfenced authority.
pub(super) struct OidcFlowCustodyGuard {
    store: Arc<PersistentBlobStore>,
    process: ProcessBoundToken,
    snapshot: EnterpriseIdentitySnapshotKey,
    valid_until: Instant,
}

impl OidcFlowCustodyGuard {
    pub(super) fn admit_snapshot(
        &self,
        snapshot: Option<&EnterpriseIdentitySnapshotKey>,
    ) -> Result<(), OidcCodeFlowError> {
        self.check()?;
        if snapshot != Some(&self.snapshot) {
            return Err(OidcCodeFlowError::PersistentCustodyUnavailable);
        }
        Ok(())
    }

    pub(super) fn valid_until(&self) -> Instant {
        self.valid_until
    }

    pub(super) fn check(&self) -> Result<(), OidcCodeFlowError> {
        if self.store.is_quarantined() || self.process.verify().is_err() {
            return Err(OidcCodeFlowError::PersistentCustodyUnavailable);
        }
        if Instant::now() >= self.valid_until {
            return Err(OidcCodeFlowError::InvalidLifetime);
        }
        Ok(())
    }

    fn deadline(&self, cx: &Cx, requested: Time) -> Result<Time, OidcPendingFlowError> {
        self.check()?;
        let caller = check_runtime(cx)?;
        let remaining = self.valid_until
            .checked_duration_since(Instant::now())
            .ok_or(OidcPendingFlowError::Expired)?;
        let nanos = u64::try_from(remaining.as_nanos())
            .map_err(|_| OidcPendingFlowError::Expired)?;
        let deadline = requested.min(caller.now().saturating_add_nanos(nanos));
        let deadline = caller.budget().deadline.map_or(deadline, |limit| limit.min(deadline));
        if caller.now() >= deadline {
            return Err(OidcPendingFlowError::TimedOut);
        }
        Ok(deadline)
    }
}

struct FlowClock {
    wall: SystemTime,
    monotonic: Instant,
}

impl FlowClock {
    fn new(wall: SystemTime) -> Self {
        Self { wall, monotonic: Instant::now() }
    }

    fn now(&self) -> Result<SystemTime, OidcPendingFlowError> {
        self.wall.checked_add(self.monotonic.elapsed()).ok_or(OidcPendingFlowError::Expired)
    }
}

fn check_runtime(cx: &Cx) -> Result<Cx, OidcPendingFlowError> {
    crate::http_auth::caller::with_caller(cx, || {
        let caller = Cx::current().ok_or(OidcPendingFlowError::StoreUnavailable)?;
        if caller.checkpoint().is_err() {
            return Err(OidcPendingFlowError::Cancelled);
        }
        if !caller.capabilities().time {
            return Err(OidcPendingFlowError::StoreUnavailable);
        }
        if caller.budget().deadline.is_some_and(|limit| caller.now() >= limit) {
            return Err(OidcPendingFlowError::TimedOut);
        }
        Ok(caller)
    })
}

fn store_error(error: PersistentEnvelopeError) -> OidcPendingFlowError {
    match error {
        PersistentEnvelopeError::Cancelled
        | PersistentEnvelopeError::Restore(RestoreError::Cancelled) => OidcPendingFlowError::Cancelled,
        PersistentEnvelopeError::DeadlineExceeded
        | PersistentEnvelopeError::Restore(RestoreError::DeadlineExceeded) => OidcPendingFlowError::TimedOut,
        PersistentEnvelopeError::ProcessChanged
        | PersistentEnvelopeError::Restore(RestoreError::ProcessChanged) => OidcPendingFlowError::ProcessChanged,
        PersistentEnvelopeError::Conflict => OidcPendingFlowError::ConsumedOrChanged,
        PersistentEnvelopeError::Uncertain => OidcPendingFlowError::Uncertain,
        _ => OidcPendingFlowError::StoreUnavailable,
    }
}

fn configuration_binding(
    configuration: &OidcCodeFlowConfiguration,
    snapshot: &EnterpriseIdentitySnapshotKey,
) -> Result<[u8; 32], OidcPendingFlowError> {
    let profile = profile_digest(&configuration.profile)
        .map_err(|_| OidcPendingFlowError::InvalidConfiguration)?;
    let mut bytes = b"fastmcp-protected-oidc-pending-v1".to_vec();
    bytes.extend_from_slice(profile.as_bytes());
    bytes.extend_from_slice(&configuration.metadata_digest);
    bytes.extend_from_slice(&configuration.registration_digest);
    for value in [
        configuration.authorization_endpoint.as_str(),
        &configuration.redirect_uri,
        configuration.subject_namespace.issuer(),
        configuration.subject_namespace.sector_host().unwrap_or(""),
    ] {
        append_text(&mut bytes, value)?;
    }
    bytes.push(match configuration.subject_namespace.subject_type() {
        EnterpriseOidcSubjectType::Public => 1,
        EnterpriseOidcSubjectType::Pairwise => 2,
    });
    bytes.extend_from_slice(
        &configuration.subject_namespace.registration_generation().unwrap_or(0).to_be_bytes(),
    );
    match configuration.subject_namespace.sector_review_digest() {
        Some(review) => { bytes.push(1); bytes.extend_from_slice(review.as_bytes()); }
        None => bytes.push(0),
    }
    match &configuration.tenant {
        ConfiguredTenant::SingleTenant => bytes.push(0),
        ConfiguredTenant::Exact(tenant) => { bytes.push(1); append_text(&mut bytes, tenant)?; }
    }
    bytes.push(u8::from(configuration.require_callback_issuer));
    for duration in configuration.response_policy.binding_durations() {
        append_duration(&mut bytes, duration);
    }
    match configuration.maximum_authentication_age {
        None => bytes.push(0),
        Some(age) => { bytes.push(1); append_duration(&mut bytes, age); }
    }
    append_text(&mut bytes, snapshot.id())?;
    bytes.extend_from_slice(&snapshot.generation().to_be_bytes());
    bytes.extend_from_slice(snapshot.digest().as_bytes());
    digest(&bytes, MAX_BINDING_BYTES).map_err(|_| OidcPendingFlowError::InvalidConfiguration)
}

fn append_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), OidcPendingFlowError> {
    if bytes.len().saturating_add(8).saturating_add(value.len()) > MAX_BINDING_BYTES {
        return Err(OidcPendingFlowError::InvalidConfiguration);
    }
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn append_duration(bytes: &mut Vec<u8>, duration: Duration) {
    bytes.extend_from_slice(&duration.as_secs().to_be_bytes());
    bytes.extend_from_slice(&duration.subsec_nanos().to_be_bytes());
}

fn encode_pending(
    pending: &PreparedOidcAuthorization,
    binding: [u8; 32],
) -> Result<BoundedPlaintext, OidcPendingFlowError> {
    let mut bytes = BoundedPlaintext::new(Vec::with_capacity(RECORD_BYTES).into())
        .map_err(store_error)?.into_zeroizing();
    bytes.extend_from_slice(PREFIX);
    bytes.push(PENDING);
    bytes.extend_from_slice(&binding);
    for time in [pending.created_at, pending.expires_at] {
        let duration = time.duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| OidcPendingFlowError::InvalidRecord)?;
        append_duration(&mut bytes, duration);
    }
    bytes.extend_from_slice(&pending.url_digest);
    bytes.extend_from_slice(&pending.target_digest);
    for secret in [&pending.state, &pending.nonce, &pending.verifier] {
        if !canonical_challenge(secret.as_str().as_bytes()) {
            return Err(OidcPendingFlowError::InvalidRecord);
        }
        bytes.extend_from_slice(secret.as_str().as_bytes());
    }
    BoundedPlaintext::new(bytes).map_err(store_error)
}

fn consumed_record(binding: [u8; 32]) -> Result<BoundedPlaintext, OidcPendingFlowError> {
    let mut bytes = BoundedPlaintext::new(Vec::with_capacity(PREFIX.len() + 1 + 32).into())
        .map_err(store_error)?.into_zeroizing();
    bytes.extend_from_slice(PREFIX);
    bytes.push(CONSUMED);
    bytes.extend_from_slice(&binding);
    BoundedPlaintext::new(bytes).map_err(store_error)
}

fn decode_pending(
    record: &BoundedPlaintext,
    binding: [u8; 32],
    configuration: &OidcCodeFlowConfiguration,
) -> Result<PreparedOidcAuthorization, OidcPendingFlowError> {
    let bytes = record.as_bytes();
    if bytes.len() != RECORD_BYTES || record.allocated_bytes() > MAX_RECORD_ALLOCATION
        || !bytes.starts_with(PREFIX) || bytes[PREFIX.len()] != PENDING
    {
        return Err(OidcPendingFlowError::InvalidRecord);
    }
    let mut offset = PREFIX.len() + 1;
    if bytes[offset..offset + 32] != binding {
        return Err(OidcPendingFlowError::BindingMismatch);
    }
    offset += 32;
    let created_at = read_time(bytes, &mut offset)?;
    let expires_at = read_time(bytes, &mut offset)?;
    let lifetime = expires_at.duration_since(created_at)
        .map_err(|_| OidcPendingFlowError::InvalidRecord)?;
    if lifetime.is_zero() || lifetime > MAX_FLOW_LIFETIME {
        return Err(OidcPendingFlowError::InvalidRecord);
    }
    let url_digest = &bytes[offset..offset + 32];
    offset += 32;
    let target_digest = &bytes[offset..offset + 32];
    offset += 32;
    let state = read_challenge(bytes, &mut offset)?;
    let nonce = read_challenge(bytes, &mut offset)?;
    let verifier = read_challenge(bytes, &mut offset)?;
    let pending = configuration.prepare_from_challenges(state, nonce, verifier, created_at, expires_at)?;
    if pending.url_digest.as_slice() != url_digest || pending.target_digest.as_slice() != target_digest {
        return Err(OidcPendingFlowError::InvalidRecord);
    }
    Ok(pending)
}

fn read_time(bytes: &[u8], offset: &mut usize) -> Result<SystemTime, OidcPendingFlowError> {
    let seconds = u64::from_be_bytes(bytes[*offset..*offset + 8].try_into()
        .map_err(|_| OidcPendingFlowError::InvalidRecord)?);
    *offset += 8;
    let nanos = u32::from_be_bytes(bytes[*offset..*offset + 4].try_into()
        .map_err(|_| OidcPendingFlowError::InvalidRecord)?);
    *offset += 4;
    if nanos >= 1_000_000_000 {
        return Err(OidcPendingFlowError::InvalidRecord);
    }
    SystemTime::UNIX_EPOCH.checked_add(Duration::new(seconds, nanos))
        .ok_or(OidcPendingFlowError::InvalidRecord)
}

fn canonical_challenge(bytes: &[u8]) -> bool {
    bytes.len() == CHALLENGE_BYTES
        && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
        && b"AEIMQUYcgkosw048".contains(&bytes[CHALLENGE_BYTES - 1])
}

fn read_challenge(bytes: &[u8], offset: &mut usize) -> Result<SecretString, OidcPendingFlowError> {
    let field = &bytes[*offset..*offset + CHALLENGE_BYTES];
    *offset += CHALLENGE_BYTES;
    if !canonical_challenge(field) {
        return Err(OidcPendingFlowError::InvalidRecord);
    }
    let text = std::str::from_utf8(field).map_err(|_| OidcPendingFlowError::InvalidRecord)?;
    Ok(SecretString::from_string(text.to_owned()))
}
