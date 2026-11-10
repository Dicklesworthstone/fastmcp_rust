//! External-store consumption for durable enterprise identity-assertion replay.
//!
//! A consumed, signature-verified assertion produces every active/previous MAC
//! alias, one immutable reservation record, and a registered restore write
//! intent. The store must reserve the entire alias set atomically. An assertion
//! owner is returned only after the independent restore authority accepts the
//! exact durable commit. Cancellation, an unknown write, a mismatched receipt,
//! or an abandoned future never releases an alias or retries a transaction.
//!
//! This consumes named external providers; it is not a durability or custody
//! attestation. Its store adapter belongs to the deployment's trusted computing
//! base and must prove atomicity, persistence, ring acknowledgement, and receipt
//! verification separately. Flow evidence is local correlation, not the missing
//! sealed browser/acquisition receipt. Reserving an assertion does not activate
//! EMA, expose its compact bytes, or authorize HTTP dispatch.

#[cfg(test)]
mod tests;

use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};
use asupersync::time::Sleep;
use asupersync::types::Time;
use fastmcp_core::Sha256Digest;
use fastmcp_core::crypto::sha256_bounded;
use fastmcp_core::replay::{PersistentReplayAliasSet, PersistentReplayDigest};
use fastmcp_core::restore::{
    CompletedRestoreWrite, DurableRestoreCommitReceipt, RegisteredRestoreStore, RestoreWriteFence,
};
use fastmcp_core::runtime::{ProcessBoundToken, ProcessGenerationGuard};
use fastmcp_protocol::jose::enterprise::{MAX_ENTERPRISE_CLOCK_SKEW, VerifiedOidcIdToken};

use super::policy::EnterpriseProfile;
use super::response::EnterpriseIdentityAssertion;
use crate::http_auth::caller;

/// Persistent MAC provider contracts available through the enterprise client facade.
pub use fastmcp_core::replay as persistent_mac;
/// External restore-authority contracts available through the enterprise client facade.
pub use fastmcp_core::restore as restore_authority;

/// A complete reservation, including all providers, has one finite caller budget.
pub const MAX_ASSERTION_RESERVATION_DURATION: Duration = Duration::from_secs(30);
/// Includes calls awaiting the MAC provider, authority, or atomic store.
pub const MAX_PENDING_ASSERTION_RESERVATIONS: usize = 64;
const MAX_PROFILE_BINDING_BYTES: usize = 128 * 1024;
const MAX_RECORD_BYTES: usize = 8 * 1024;
const MAX_STORE_ID_BYTES: usize = 256;
const MAX_STORE_ADAPTER_BYTES: usize = 128;
const MAX_STORE_IDENTITY_BYTES: usize = 256;

/// Fixed diagnostics never contain tokens, aliases, identifiers or provider errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityAssertionReplayError {
    InvalidConfiguration,
    InvalidAssertion,
    InvalidLifetime,
    RuntimeUnavailable,
    ProcessChanged,
    Cancelled,
    TimedOut,
    Saturated,
    DigestUnavailable,
    RestoreUnavailable,
    StoreUnavailable,
    UnknownStoreOutcome,
    InvalidReceipt,
    AlreadyReserved,
}

impl fmt::Display for IdentityAssertionReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid enterprise assertion replay configuration",
            Self::InvalidAssertion => "enterprise assertion does not match the current profile",
            Self::InvalidLifetime => "enterprise assertion replay lifetime is invalid",
            Self::RuntimeUnavailable => "enterprise replay requires the caller's bounded runtime",
            Self::ProcessChanged => "enterprise assertion replay process generation changed",
            Self::Cancelled => "enterprise assertion reservation was cancelled",
            Self::TimedOut => "enterprise assertion reservation deadline elapsed",
            Self::Saturated => "enterprise assertion reservation capacity exhausted",
            Self::DigestUnavailable => "enterprise persistent replay aliases are unavailable",
            Self::RestoreUnavailable => "enterprise replay restore authority is unavailable",
            Self::StoreUnavailable => "enterprise assertion use store is unavailable",
            Self::UnknownStoreOutcome => "enterprise assertion reservation outcome is unknown",
            Self::InvalidReceipt => "enterprise assertion reservation receipt does not match",
            Self::AlreadyReserved => "enterprise identity assertion has already been reserved",
        })
    }
}
impl std::error::Error for IdentityAssertionReplayError {}

/// Immutable identity of the configured store adapter and its deployed artifact.
///
/// The adapter name includes its version. Artifact and configuration digests
/// name independently trusted deployment inputs; this identity is configuration,
/// not an attestation, persistence proof, or permission to reset a store.
#[derive(Clone, Eq, PartialEq)]
pub struct IdentityAssertionStoreIdentity {
    adapter: String,
    artifact: Sha256Digest,
    configuration: Sha256Digest,
    digest: Sha256Digest,
}
impl IdentityAssertionStoreIdentity {
    pub fn new(
        adapter: &str,
        artifact: Sha256Digest,
        configuration: Sha256Digest,
    ) -> Result<Self, IdentityAssertionReplayError> {
        if adapter.is_empty()
            || adapter.len() > MAX_STORE_ADAPTER_BYTES
            || !adapter.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(IdentityAssertionReplayError::InvalidConfiguration);
        }
        let mut bytes = b"FMCPIASI\0\x00\x01".to_vec();
        put_field(&mut bytes, adapter.as_bytes(), MAX_STORE_IDENTITY_BYTES)?;
        bytes.extend_from_slice(artifact.as_bytes());
        bytes.extend_from_slice(configuration.as_bytes());
        let digest = sha256_bounded(&bytes, MAX_STORE_IDENTITY_BYTES)
            .map_err(|_| IdentityAssertionReplayError::InvalidConfiguration)?;
        Ok(Self {
            adapter: adapter.to_owned(),
            artifact,
            configuration,
            digest,
        })
    }
    pub fn adapter(&self) -> &str {
        &self.adapter
    }
    pub const fn artifact_digest(&self) -> Sha256Digest {
        self.artifact
    }
    pub const fn configuration_digest(&self) -> Sha256Digest {
        self.configuration
    }
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Opaque local correlation recorded with a reservation, never a replay-key partition.
///
/// Supplying these identifiers does not prove a browser session or acquisition
/// flow. A future native exchange owner must separately require those sealed
/// receipts. Different values here never permit the same assertion to re-enter.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IdentityAssertionFlowEvidence {
    flow_id: [u8; 32],
    browser_session_digest: [u8; 32],
}
impl IdentityAssertionFlowEvidence {
    pub fn new(
        flow_id: [u8; 32],
        browser_session_digest: [u8; 32],
    ) -> Result<Self, IdentityAssertionReplayError> {
        if flow_id == [0; 32] || browser_session_digest == [0; 32] {
            return Err(IdentityAssertionReplayError::InvalidConfiguration);
        }
        Ok(Self {
            flow_id,
            browser_session_digest,
        })
    }
    pub const fn flow_id(&self) -> &[u8; 32] {
        &self.flow_id
    }
    pub const fn browser_session_digest(&self) -> &[u8; 32] {
        &self.browser_session_digest
    }
}
impl fmt::Debug for IdentityAssertionFlowEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityAssertionFlowEvidence")
            .finish_non_exhaustive()
    }
}

/// Immutable evidence stored alongside keyed aliases. It contains no compact
/// assertion, unkeyed assertion digest, subject, nonce, or access token.
pub struct IdentityAssertionReservationEvidence {
    flow: IdentityAssertionFlowEvidence,
    idp_client_id: String,
    idp_registration_generation: u64,
    policy_generation: u64,
    oidc_key_generation: u64,
    profile_digest: Sha256Digest,
    assertion_expires_at: SystemTime,
    retain_until: SystemTime,
}
impl IdentityAssertionReservationEvidence {
    pub const fn flow(&self) -> &IdentityAssertionFlowEvidence {
        &self.flow
    }
    pub fn idp_client_id(&self) -> &str {
        &self.idp_client_id
    }
    pub const fn idp_registration_generation(&self) -> u64 {
        self.idp_registration_generation
    }
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }
    pub const fn oidc_key_generation(&self) -> u64 {
        self.oidc_key_generation
    }
    pub const fn profile_digest(&self) -> Sha256Digest {
        self.profile_digest
    }
    pub const fn assertion_expires_at(&self) -> SystemTime {
        self.assertion_expires_at
    }
    /// Signed expiration plus the immutable global maximum positive clock skew.
    /// A narrower current policy never shortens this tombstone retention.
    pub const fn retain_until(&self) -> SystemTime {
        self.retain_until
    }
}

/// One complete transaction request. Only the framework can construct it.
/// Adapters may persist the keyed aliases and bounded evidence, never raw tokens.
pub struct IdentityAssertionReservationRequest<'a> {
    store_identity: &'a IdentityAssertionStoreIdentity,
    aliases: &'a PersistentReplayAliasSet,
    evidence: &'a IdentityAssertionReservationEvidence,
    ring_acknowledgement_digest: Sha256Digest,
    fence: &'a RestoreWriteFence,
    deadline: Time,
}
impl IdentityAssertionReservationRequest<'_> {
    pub const fn store_identity(&self) -> &IdentityAssertionStoreIdentity {
        self.store_identity
    }
    pub const fn aliases(&self) -> &PersistentReplayAliasSet {
        self.aliases
    }
    pub const fn evidence(&self) -> &IdentityAssertionReservationEvidence {
        self.evidence
    }
    pub const fn ring_acknowledgement_digest(&self) -> Sha256Digest {
        self.ring_acknowledgement_digest
    }
    pub const fn fence(&self) -> &RestoreWriteFence {
        self.fence
    }
    pub const fn deadline(&self) -> Time {
        self.deadline
    }

    /// The store's durable commit must bind this exact closed outcome digest.
    /// AlreadyReserved also journals the outcome under this write intent.
    pub fn commit_digest(&self, decision: IdentityAssertionReservationDecision) -> [u8; 32] {
        commit_digest(self.fence.record_digest(), decision)
    }
}

/// A committed store decision. Both outcomes require an acknowledged durable receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityAssertionReservationDecision {
    Reserved,
    AlreadyReserved,
}

/// Untrusted external-store output; it cannot construct a reserved assertion.
pub enum IdentityAssertionStoreResult {
    Committed {
        decision: IdentityAssertionReservationDecision,
        receipt: DurableRestoreCommitReceipt,
    },
    /// No retry or alias release is licensed by this outcome.
    Unknown,
}

/// Bounded, redacted backend failures. Neither implies that no write occurred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityAssertionStoreError {
    Unavailable,
    Rejected,
}

/// Deployment-owned durable, atomic assertion-use storage.
///
/// The named adapter verifies its exact registered store, namespace, restore
/// binding, fencing generation, operation ID, and current deployment-wide MAC
/// ring acknowledgement before changing state. It atomically checks EVERY
/// supplied active/previous alias and reserves ALL of them in one transaction,
/// or returns AlreadyReserved without reopening an existing record. Client,
/// flow, session, policy, and expiration are evidence, never key partitions.
/// Every successful decision durably journals the exact operation/outcome and
/// returns a commit receipt verifiable by the independent restore authority.
///
/// Retention is at least evidence.retain_until() across policy changes, restart,
/// backups and independently writable clones. No in-memory, partial-write,
/// active-key-only, unauthenticated, or ordinary snapshot fallback satisfies the
/// production contract. This public trait does not attest those properties.
///
/// Work uses only the supplied caller's runtime and deadline, bounds all queues
/// and replies before allocation, and has no hidden blocking work, detached
/// tasks, automatic retry, release, or cleanup on future drop. Cancellation and
/// unknown outcomes retain the transaction for external reconciliation.
pub trait IdentityAssertionUseStore: Send + Sync + 'static {
    /// The exact store ID previously admitted by the restore authority.
    fn store_id(&self) -> &str;
    /// Exact named adapter, artifact and configuration pinned by the consumer.
    fn identity(&self) -> &IdentityAssertionStoreIdentity;

    fn reserve_all<'a>(
        &'a self,
        cx: &'a Cx,
        request: IdentityAssertionReservationRequest<'a>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<IdentityAssertionStoreResult, IdentityAssertionStoreError>>
                + Send
                + 'a,
        >,
    >;
}

/// Composes the MAC provider, registered restore store, and atomic use-store adapter.
/// No raw epoch or caller-asserted authorization boolean can construct this owner.
pub struct IdentityAssertionReplay {
    process: ProcessBoundToken,
    store_identity: IdentityAssertionStoreIdentity,
    digests: Arc<PersistentReplayDigest>,
    restore: RegisteredRestoreStore,
    backend: Arc<dyn IdentityAssertionUseStore>,
    store_id: String,
    ring_acknowledgement_digest: Sha256Digest,
    pending: AtomicUsize,
}
impl IdentityAssertionReplay {
    /// Pins the deployment's existing ring acknowledgement identity. The digest
    /// is trusted configuration, not proof by itself: the named store adapter
    /// must verify the acknowledged exact ring under its registered authority.
    pub fn new(
        digests: Arc<PersistentReplayDigest>,
        restore: RegisteredRestoreStore,
        backend: Arc<dyn IdentityAssertionUseStore>,
        ring_acknowledgement_digest: Sha256Digest,
        expected_store_identity: IdentityAssertionStoreIdentity,
    ) -> Result<Self, IdentityAssertionReplayError> {
        let process = ProcessGenerationGuard::installed()
            .ok_or(IdentityAssertionReplayError::ProcessChanged)?
            .token();
        process
            .verify()
            .map_err(|_| IdentityAssertionReplayError::ProcessChanged)?;
        let store_id = restore.store_id();
        if store_id.is_empty()
            || store_id.len() > MAX_STORE_ID_BYTES
            || backend.store_id() != store_id
            || backend.identity() != &expected_store_identity
            || ring_acknowledgement_digest.as_bytes() == &[0; 32]
        {
            return Err(IdentityAssertionReplayError::InvalidConfiguration);
        }
        Ok(Self {
            process,
            store_identity: expected_store_identity,
            store_id: store_id.to_owned(),
            digests,
            restore,
            backend,
            ring_acknowledgement_digest,
            pending: AtomicUsize::new(0),
        })
    }

    /// Consumes an already verified protected assertion on EVERY outcome.
    ///
    /// All aliases are derived internally from the exact verified issuer and
    /// compact digest. Callers cannot inject or truncate the alias set. The
    /// returned owner proves only this local provider/receipt choreography;
    /// browser custody, distinct-assertion recovery, credential custody and
    /// native dispatch are separate prerequisites. There is no retry/release
    /// method and no conversion back to an unreserved assertion. The supplied
    /// wall time must come from the caller's trusted clock. The durable adapter
    /// independently enforces signed expiry and immutable tombstone retention;
    /// caller time is never permission to shorten or delete stored evidence.
    pub async fn reserve(
        &self,
        cx: &Cx,
        profile: &EnterpriseProfile,
        assertion: EnterpriseIdentityAssertion,
        flow: IdentityAssertionFlowEvidence,
        now: SystemTime,
        deadline: Time,
    ) -> Result<ReservedIdentityAssertion, IdentityAssertionReplayError> {
        self.process
            .verify()
            .map_err(|_| IdentityAssertionReplayError::ProcessChanged)?;
        let cx = caller::with_caller(cx, Cx::current)
            .ok_or(IdentityAssertionReplayError::RuntimeUnavailable)?;
        let mut deadline = admit_deadline(&cx, deadline)?;
        if self.backend.store_id() != self.store_id
            || self.restore.store_id() != self.store_id
            || self.backend.identity() != &self.store_identity
        {
            return Err(IdentityAssertionReplayError::InvalidConfiguration);
        }
        if self.restore.is_quarantined() {
            return Err(IdentityAssertionReplayError::RestoreUnavailable);
        }
        let evidence = evidence(profile, assertion.identity(), flow, now)?;
        // A slow provider cannot return a reservation after the assertion's
        // remaining signed lifetime. Cap the entire caller-owned operation.
        let remaining = assertion
            .identity()
            .expires_at()
            .duration_since(now)
            .map_err(|_| IdentityAssertionReplayError::InvalidLifetime)?
            .min(MAX_ASSERTION_RESERVATION_DURATION);
        let expires = cx
            .now()
            .as_nanos()
            .checked_add(remaining.as_nanos() as u64)
            .ok_or(IdentityAssertionReplayError::InvalidLifetime)?;
        deadline = deadline.min(Time::from_nanos(expires));
        check_context(&cx, deadline)?;
        let _permit = ReservationPermit::new(&self.pending)?;
        within(&cx, &self.process, deadline, async {
            let aliases = self
                .digests
                .derive_identity_assertion(
                    &cx,
                    assertion.identity().issuer(),
                    &assertion.identity().compact_digest(),
                    deadline,
                )
                .await
                .map_err(|_| IdentityAssertionReplayError::DigestUnavailable)?;
            let record_digest = record_digest(
                &self.store_id,
                &self.store_identity,
                &aliases,
                self.ring_acknowledgement_digest,
                &evidence,
            )?;
            let fence = self
                .restore
                .prepare_write(&cx, record_digest, deadline)
                .await
                .map_err(|_| IdentityAssertionReplayError::RestoreUnavailable)?;
            // A store transaction cannot outlive its independently issued
            // write fence, even when the caller's overall budget is longer.
            let store_deadline = deadline.min(fence.expires_at());
            check_context(&cx, store_deadline)?;
            let request = IdentityAssertionReservationRequest {
                store_identity: &self.store_identity,
                aliases: &aliases,
                evidence: &evidence,
                ring_acknowledgement_digest: self.ring_acknowledgement_digest,
                fence: &fence,
                deadline: store_deadline,
            };
            let result = within(&cx, &self.process, store_deadline, async {
                check_context(&cx, store_deadline)?;
                self.process
                    .verify()
                    .map_err(|_| IdentityAssertionReplayError::ProcessChanged)?;
                self.backend
                    .reserve_all(&cx, request)
                    .await
                    .map_err(|_| IdentityAssertionReplayError::StoreUnavailable)
            })
            .await?;
            check_context(&cx, store_deadline)?;
            let IdentityAssertionStoreResult::Committed { decision, receipt } = result else {
                return Err(IdentityAssertionReplayError::UnknownStoreOutcome);
            };
            let expected_commit = commit_digest(record_digest, decision);
            if receipt.commit_digest() != expected_commit {
                return Err(IdentityAssertionReplayError::InvalidReceipt);
            }
            let completed = self
                .restore
                .complete_write(&cx, fence, receipt, deadline)
                .await
                .map_err(|_| IdentityAssertionReplayError::RestoreUnavailable)?;
            check_context(&cx, deadline)?;
            if completed.commit_digest() != expected_commit {
                return Err(IdentityAssertionReplayError::InvalidReceipt);
            }
            match decision {
                IdentityAssertionReservationDecision::AlreadyReserved => {
                    Err(IdentityAssertionReplayError::AlreadyReserved)
                }
                IdentityAssertionReservationDecision::Reserved => Ok(ReservedIdentityAssertion {
                    assertion,
                    evidence,
                    aliases,
                    completed,
                    store_identity: self.store_identity.clone(),
                    ring_acknowledgement_digest: self.ring_acknowledgement_digest,
                }),
            }
        })
        .await
    }
}

/// Exclusive protected assertion with a completed durable reservation.
/// No Clone, Debug, Serialize, raw-token getter, release, or HTTP conversion exists.
/// Dropping this owner destroys local assertion custody and retains the tombstone.
pub struct ReservedIdentityAssertion {
    store_identity: IdentityAssertionStoreIdentity,
    assertion: EnterpriseIdentityAssertion,
    evidence: IdentityAssertionReservationEvidence,
    aliases: PersistentReplayAliasSet,
    completed: CompletedRestoreWrite,
    ring_acknowledgement_digest: Sha256Digest,
}
impl ReservedIdentityAssertion {
    pub const fn store_identity(&self) -> &IdentityAssertionStoreIdentity {
        &self.store_identity
    }
    pub fn identity(&self) -> &VerifiedOidcIdToken {
        self.assertion.identity()
    }
    pub const fn evidence(&self) -> &IdentityAssertionReservationEvidence {
        &self.evidence
    }
    pub fn alias_set_digest(&self) -> Sha256Digest {
        self.aliases.digest()
    }
    pub const fn ring_acknowledgement_digest(&self) -> Sha256Digest {
        self.ring_acknowledgement_digest
    }
    pub fn restore_binding_digest(&self) -> [u8; 32] {
        self.completed.binding_digest()
    }
    pub fn operation_id(&self) -> [u8; 16] {
        self.completed.operation_id()
    }
    pub fn commit_digest(&self) -> [u8; 32] {
        self.completed.commit_digest()
    }
}

struct ReservationPermit<'a>(&'a AtomicUsize);
impl<'a> ReservationPermit<'a> {
    fn new(pending: &'a AtomicUsize) -> Result<Self, IdentityAssertionReplayError> {
        pending
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                (value < MAX_PENDING_ASSERTION_RESERVATIONS).then(|| value + 1)
            })
            .map_err(|_| IdentityAssertionReplayError::Saturated)?;
        Ok(Self(pending))
    }
}
impl Drop for ReservationPermit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn evidence(
    profile: &EnterpriseProfile,
    identity: &VerifiedOidcIdToken,
    flow: IdentityAssertionFlowEvidence,
    now: SystemTime,
) -> Result<IdentityAssertionReservationEvidence, IdentityAssertionReplayError> {
    if identity.issuer() != profile.idp_issuer()
        || identity.client_id() != profile.idp_client_id()
        || identity.generation() != profile.oidc_key_generation()
    {
        return Err(IdentityAssertionReplayError::InvalidAssertion);
    }
    // Positive verifier skew never manufactures extra time for a new dispatch.
    // Retention, independently, always includes the immutable maximum skew.
    if now >= identity.expires_at()
        || now
            .checked_add(MAX_ENTERPRISE_CLOCK_SKEW)
            .is_none_or(|latest| identity.issued_at() > latest)
    {
        return Err(IdentityAssertionReplayError::InvalidLifetime);
    }
    let retain_until = identity
        .expires_at()
        .checked_add(MAX_ENTERPRISE_CLOCK_SKEW)
        .ok_or(IdentityAssertionReplayError::InvalidLifetime)?;
    let _ = timestamp(now)?;
    let _ = timestamp(retain_until)?;
    Ok(IdentityAssertionReservationEvidence {
        flow,
        idp_client_id: profile.idp_client_id().to_owned(),
        idp_registration_generation: profile.idp_registration_generation(),
        policy_generation: profile.policy_generation(),
        oidc_key_generation: profile.oidc_key_generation(),
        profile_digest: profile_digest(profile)?,
        assertion_expires_at: identity.expires_at(),
        retain_until,
    })
}

fn profile_digest(
    profile: &EnterpriseProfile,
) -> Result<Sha256Digest, IdentityAssertionReplayError> {
    let mut bytes = b"FMCPIAPF\x01".to_vec();
    for field in [
        profile.idp_issuer(),
        profile.idp_token_endpoint(),
        profile.idp_authorization_endpoint(),
        profile.idp_client_id(),
        profile.idp_authentication().as_str(),
        profile.resource_as_issuer(),
        profile.resource_as_token_endpoint(),
        profile.resource_as_client_id(),
        profile.resource_as_authentication().as_str(),
        profile.resource().as_str(),
        profile.oidc_jwks_uri(),
        profile.id_jag_jwks_uri(),
    ] {
        put_field(&mut bytes, field.as_bytes(), MAX_PROFILE_BINDING_BYTES)?;
    }
    bytes.extend_from_slice(&(profile.requested_scopes().as_slice().len() as u32).to_be_bytes());
    for scope in profile.requested_scopes().as_slice() {
        put_field(&mut bytes, scope.as_bytes(), MAX_PROFILE_BINDING_BYTES)?;
    }
    for generation in [
        profile.oidc_key_generation(),
        profile.id_jag_key_generation(),
        profile.id_jag_policy_generation(),
        profile.policy_generation(),
        profile.idp_metadata_generation(),
        profile.resource_as_metadata_generation(),
        profile.idp_registration_generation(),
        profile.resource_as_registration_generation(),
        profile.aggregate_registration_generation(),
    ] {
        bytes.extend_from_slice(&generation.to_be_bytes());
    }
    bytes.push(u8::from(profile.permits_oidc_openid()));
    sha256_bounded(&bytes, MAX_PROFILE_BINDING_BYTES)
        .map_err(|_| IdentityAssertionReplayError::InvalidConfiguration)
}

fn record_digest(
    store_id: &str,
    store_identity: &IdentityAssertionStoreIdentity,
    aliases: &PersistentReplayAliasSet,
    acknowledgement: Sha256Digest,
    evidence: &IdentityAssertionReservationEvidence,
) -> Result<[u8; 32], IdentityAssertionReplayError> {
    let mut bytes = b"FMCPIARS\x01".to_vec();
    put_field(&mut bytes, store_id.as_bytes(), MAX_RECORD_BYTES)?;
    bytes.extend_from_slice(store_identity.digest().as_bytes());
    bytes.extend_from_slice(aliases.digest().as_bytes());
    bytes.extend_from_slice(aliases.ring_digest().as_bytes());
    bytes.extend_from_slice(acknowledgement.as_bytes());
    bytes.extend_from_slice(evidence.flow.flow_id());
    bytes.extend_from_slice(evidence.flow.browser_session_digest());
    put_field(
        &mut bytes,
        evidence.idp_client_id.as_bytes(),
        MAX_RECORD_BYTES,
    )?;
    for generation in [
        evidence.idp_registration_generation,
        evidence.policy_generation,
        evidence.oidc_key_generation,
    ] {
        bytes.extend_from_slice(&generation.to_be_bytes());
    }
    bytes.extend_from_slice(evidence.profile_digest.as_bytes());
    bytes.extend_from_slice(&timestamp(evidence.assertion_expires_at)?);
    bytes.extend_from_slice(&timestamp(evidence.retain_until)?);
    sha256_bounded(&bytes, MAX_RECORD_BYTES)
        .map(Sha256Digest::into_bytes)
        .map_err(|_| IdentityAssertionReplayError::InvalidConfiguration)
}

fn timestamp(value: SystemTime) -> Result<[u8; 12], IdentityAssertionReplayError> {
    let value = value
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IdentityAssertionReplayError::InvalidLifetime)?;
    let mut encoded = [0; 12];
    encoded[..8].copy_from_slice(&value.as_secs().to_be_bytes());
    encoded[8..].copy_from_slice(&value.subsec_nanos().to_be_bytes());
    Ok(encoded)
}

fn put_field(
    bytes: &mut Vec<u8>,
    field: &[u8],
    maximum: usize,
) -> Result<(), IdentityAssertionReplayError> {
    let length = u32::try_from(field.len())
        .map_err(|_| IdentityAssertionReplayError::InvalidConfiguration)?;
    if bytes
        .len()
        .checked_add(4)
        .and_then(|n| n.checked_add(field.len()))
        .is_none_or(|length| length > maximum)
    {
        return Err(IdentityAssertionReplayError::InvalidConfiguration);
    }
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(field);
    Ok(())
}

fn commit_digest(record: [u8; 32], decision: IdentityAssertionReservationDecision) -> [u8; 32] {
    let mut bytes = [0; 42];
    bytes[..9].copy_from_slice(b"FMCPIARC\x01");
    bytes[9..41].copy_from_slice(&record);
    bytes[41] = match decision {
        IdentityAssertionReservationDecision::Reserved => 1,
        IdentityAssertionReservationDecision::AlreadyReserved => 2,
    };
    // The array length is fixed and exactly equals the admitted bound.
    sha256_bounded(&bytes, bytes.len())
        .expect("fixed reservation commit digest bound")
        .into_bytes()
}

fn admit_deadline(cx: &Cx, requested: Time) -> Result<Time, IdentityAssertionReplayError> {
    require_runtime(cx)?;
    let limit = cx
        .now()
        .as_nanos()
        .checked_add(MAX_ASSERTION_RESERVATION_DURATION.as_nanos() as u64)
        .ok_or(IdentityAssertionReplayError::InvalidConfiguration)?;
    if requested.as_nanos() > limit {
        return Err(IdentityAssertionReplayError::InvalidConfiguration);
    }
    let deadline = cx
        .budget()
        .deadline
        .map_or(requested, |parent| parent.min(requested));
    check_context(cx, deadline)?;
    Ok(deadline)
}

fn check_context(cx: &Cx, deadline: Time) -> Result<(), IdentityAssertionReplayError> {
    cx.checkpoint()
        .map_err(|_| IdentityAssertionReplayError::Cancelled)?;
    if cx.now() >= deadline {
        return Err(IdentityAssertionReplayError::TimedOut);
    }
    Ok(())
}

fn require_runtime(cx: &Cx) -> Result<(), IdentityAssertionReplayError> {
    let capabilities = cx.capabilities();
    if !capabilities.io
        || !capabilities.remote
        || !capabilities.time
        || !capabilities.entropy
        || cx.timer_driver().is_none()
    {
        return Err(IdentityAssertionReplayError::RuntimeUnavailable);
    }
    Ok(())
}

// Retain the tightest ambient ceiling observed by any poll. An external
// provider's Drop must not regain effects removed while it was suspended.
struct CallerFuture<'a, F> {
    cx: &'a Cx,
    ceiling: CapMask,
    future: Option<Pin<Box<F>>>,
}
impl<F> Drop for CallerFuture<'_, F> {
    fn drop(&mut self) {
        let ceiling = self.ceiling.intersect(ambient_ceiling());
        let _caller = Cx::set_current(Some(self.cx.clone()));
        let _restriction = Cx::push_restriction(ceiling);
        drop(self.future.take());
    }
}

fn ambient_ceiling() -> CapMask {
    let Some(active) = Cx::current() else {
        return CapMask::all();
    };
    let capabilities = active.capabilities();
    let mut ceiling = CapMask::all();
    for (allowed, without) in [
        (
            capabilities.spawn,
            CapSet::<false, true, true, true, true>::MASK,
        ),
        (
            capabilities.time,
            CapSet::<true, false, true, true, true>::MASK,
        ),
        (
            capabilities.entropy,
            CapSet::<true, true, false, true, true>::MASK,
        ),
        (
            capabilities.io,
            CapSet::<true, true, true, false, true>::MASK,
        ),
        (
            capabilities.remote,
            CapSet::<true, true, true, true, false>::MASK,
        ),
    ] {
        if !allowed {
            ceiling = ceiling.intersect(without);
        }
    }
    ceiling
}

async fn within<T>(
    cx: &Cx,
    process: &ProcessBoundToken,
    deadline: Time,
    future: impl Future<Output = Result<T, IdentityAssertionReplayError>>,
) -> Result<T, IdentityAssertionReplayError> {
    process
        .verify()
        .map_err(|_| IdentityAssertionReplayError::ProcessChanged)?;
    let mut sleep = std::pin::pin!(Sleep::new(deadline));
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancelled = std::pin::pin!(receiver.recv(cx));
    let mut future = CallerFuture {
        cx,
        ceiling: ambient_ceiling(),
        future: Some(Box::pin(future)),
    };
    poll_fn(|task| {
        process
            .verify()
            .map_err(|_| IdentityAssertionReplayError::ProcessChanged)?;
        future.ceiling = future.ceiling.intersect(ambient_ceiling());
        let _caller = Cx::set_current(Some(cx.clone()));
        let _restriction = Cx::push_restriction(future.ceiling);
        let active = Cx::current().ok_or(IdentityAssertionReplayError::RuntimeUnavailable)?;
        require_runtime(&active)?;
        check_context(&active, deadline)?;
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(IdentityAssertionReplayError::Cancelled));
        }
        if sleep.as_mut().poll(task).is_ready() {
            // Sleep can also resolve during a cancellation race. Preserve the
            // caller's cancellation classification before reporting a timeout.
            check_context(&active, deadline)?;
            return Poll::Ready(Err(IdentityAssertionReplayError::TimedOut));
        }
        let result = future
            .future
            .as_mut()
            .expect("reservation future remains owned")
            .as_mut()
            .poll(task);
        process
            .verify()
            .map_err(|_| IdentityAssertionReplayError::ProcessChanged)?;
        check_context(&active, deadline)?;
        result
    })
    .await
}
