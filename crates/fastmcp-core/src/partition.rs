//! AUTH-00 B: security-partition admission and non-oracular lookup.
//!
//! This module owns the second AUTH-00 capability slice: deriving the
//! purpose-specific partition keys from verified security facts, admitting
//! quota and revalidation work against frozen concurrency and attempt-rate
//! floors, and serving lookups that leak nothing across tenants.
//!
//! # The authorization rule
//!
//! Possessing a partition key is **not** authorization. Every record slot is
//! identified by `(purpose, partition key, durable owner)`, so a caller who
//! somehow obtains another principal's partition key names a slot in their own
//! owner space, which is empty. The foreign read is therefore
//! [`LookupOutcome::Absent`] — byte-identical to a genuine miss — and the
//! victim's record, counters, quota reservations and revalidation flight are
//! untouched. There is no code path on which a caller learns that a record
//! exists in a partition they do not currently own.
//!
//! Quota is admission-only. [`QuotaPartitionKey`] gates how much work a
//! principal may consume; it never authorizes a lookup, and no lookup
//! entrypoint accepts one. Two descriptors that differ only in issuer derive
//! the *same* quota key but *different* [`DurableOwnerKey`]s, so quota-key
//! equality provably does not imply lookup authority.
//!
//! # Identity stability under rotation
//!
//! [`DurableOwnerKey`] and [`QuotaPartitionKey`] are derived from stable
//! principal facts only — no token instance, no effective grants — so ordinary
//! token rotation and scope churn preserve durable-owner and quota identity.
//! [`CachePartitionKey`], [`ContinuationPartitionKey`] and
//! [`SubscriptionPartitionKey`] bind the result-affecting facts (effective
//! grants, token instance, audience-policy revision), so any change that can
//! alter a result also changes the partition the result is stored under.
//!
//! # No-claim boundary
//!
//! This leaf proves partition admission and non-oracular lookup from a
//! verified descriptor. It does **not** prove AUTH-00 A's ingress
//! construction: [`PartitionDescriptor`] is the input contract this module
//! consumes, and AUTH-00 A owns the only production producer of those verified
//! facts. It does not prove the AUTH-00 aggregate or aggregate MCP capability.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::limits::{SealedAdmissionKeyError, opaque_admission_digest, require_admission_field};

/// Default concurrent revalidations allowed per verified partition.
pub const DEFAULT_REVALIDATIONS_PER_PARTITION: usize = 2;
/// Hard ceiling on concurrent revalidations per verified partition.
pub const HARD_REVALIDATIONS_PER_PARTITION: usize = 16;
/// Default concurrent revalidations allowed per provider.
pub const DEFAULT_REVALIDATIONS_PER_PROVIDER: usize = 32;
/// Hard ceiling on concurrent revalidations per provider.
pub const HARD_REVALIDATIONS_PER_PROVIDER: usize = 256;
/// Default concurrent revalidations allowed per deployment.
pub const DEFAULT_REVALIDATIONS_PER_DEPLOYMENT: usize = 256;
/// Hard ceiling on concurrent revalidations per deployment.
pub const HARD_REVALIDATIONS_PER_DEPLOYMENT: usize = 4_096;
/// Default revalidation attempts per minute per verified partition.
pub const DEFAULT_ATTEMPTS_PER_MINUTE_PER_PARTITION: u32 = 120;
/// Hard ceiling on revalidation attempts per minute per verified partition.
pub const HARD_ATTEMPTS_PER_MINUTE_PER_PARTITION: u32 = 6_000;
/// Default revalidation attempts per minute per provider.
pub const DEFAULT_ATTEMPTS_PER_MINUTE_PER_PROVIDER: u32 = 10_000;
/// Hard ceiling on revalidation attempts per minute per provider.
pub const HARD_ATTEMPTS_PER_MINUTE_PER_PROVIDER: u32 = 100_000;

/// The attempt-rate accounting window.
pub const ATTEMPT_RATE_WINDOW: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Verified descriptor
// ---------------------------------------------------------------------------

/// The immutable verified security facts every partition key is derived from.
///
/// AUTH-00 A owns the only production producer of these facts. This type is
/// the input contract AUTH-00 B consumes; constructing one here asserts the
/// facts are already verified, it does not verify them.
#[derive(Clone, PartialEq, Eq)]
pub struct PartitionDescriptor {
    provider: String,
    configuration_generation: u64,
    issuer: String,
    canonical_resource: String,
    tenant: String,
    subject: String,
    client: String,
    trust_generation: u64,
    audience_policy_revision: u64,
    identity: [u8; 32],
}

impl fmt::Debug for PartitionDescriptor {
    /// Redacts every identity field; only the opaque identity digest is shown.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PartitionDescriptor")
            .finish_non_exhaustive()
    }
}

impl PartitionDescriptor {
    /// Builds a descriptor from already-verified provider output.
    ///
    /// Every string field must be nonempty and within the sealed-key field
    /// bound. No field may be a request-supplied identifier; AUTH-00 A is
    /// responsible for that guarantee upstream.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_facts(
        provider: &str,
        configuration_generation: u64,
        issuer: &str,
        canonical_resource: &str,
        tenant: &str,
        subject: &str,
        client: &str,
        trust_generation: u64,
        audience_policy_revision: u64,
    ) -> Result<Self, SealedAdmissionKeyError> {
        let identity = opaque_admission_digest(&[
            b"auth-00-partition-descriptor-v1",
            require_admission_field(provider)?,
            &configuration_generation.to_be_bytes(),
            require_admission_field(issuer)?,
            require_admission_field(canonical_resource)?,
            require_admission_field(tenant)?,
            require_admission_field(subject)?,
            require_admission_field(client)?,
            &trust_generation.to_be_bytes(),
            &audience_policy_revision.to_be_bytes(),
        ]);
        Ok(Self {
            provider: provider.to_owned(),
            configuration_generation,
            issuer: issuer.to_owned(),
            canonical_resource: canonical_resource.to_owned(),
            tenant: tenant.to_owned(),
            subject: subject.to_owned(),
            client: client.to_owned(),
            trust_generation,
            audience_policy_revision,
            identity,
        })
    }

    /// The verifying provider.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// The provider configuration generation these facts were verified under.
    #[must_use]
    pub const fn configuration_generation(&self) -> u64 {
        self.configuration_generation
    }

    /// The verified token issuer.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The canonical resource the principal was verified against.
    #[must_use]
    pub fn canonical_resource(&self) -> &str {
        &self.canonical_resource
    }

    /// The verified tenant.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The verified subject or principal.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The verified authorized party or client.
    #[must_use]
    pub fn client(&self) -> &str {
        &self.client
    }

    /// The trust generation in force when these facts were verified.
    #[must_use]
    pub const fn trust_generation(&self) -> u64 {
        self.trust_generation
    }

    /// The audience-policy revision in force when these facts were verified.
    #[must_use]
    pub const fn audience_policy_revision(&self) -> u64 {
        self.audience_policy_revision
    }

    /// The opaque identity digest over every verified field.
    #[must_use]
    pub const fn identity(&self) -> &[u8; 32] {
        &self.identity
    }
}

/// Declares an opaque 32-byte partition key newtype with a redacting `Debug`.
macro_rules! opaque_partition_key {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name {
            digest: [u8; 32],
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl $name {
            /// The opaque digest.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.digest
            }
        }
    };
}

opaque_partition_key! {
    /// Response-cache partition: binds the descriptor plus every
    /// result-affecting fact, so a grant, token or audience-policy change
    /// moves the result to a different partition.
    CachePartitionKey
}

opaque_partition_key! {
    /// Continuation/cursor partition: binds the descriptor, the grant
    /// snapshot, the method parameter binding and the capability fingerprint.
    ContinuationPartitionKey
}

opaque_partition_key! {
    /// Durable ownership identity. Derived from stable principal facts only,
    /// so it survives ordinary token rotation and scope churn.
    DurableOwnerKey
}

opaque_partition_key! {
    /// Subscription partition: result-affecting, like the cache partition.
    SubscriptionPartitionKey
}

opaque_partition_key! {
    /// Credential-store partition.
    CredentialStoreKey
}

opaque_partition_key! {
    /// Quota admission identity. Admission-only: it never authorizes a lookup.
    /// Derived without issuer or configuration generation, so principals that
    /// differ only in issuer share a quota identity while remaining distinct
    /// durable owners.
    QuotaPartitionKey
}

opaque_partition_key! {
    /// Singleflight identity for one revalidation purpose in one partition.
    RevalidationFlightKey
}

opaque_partition_key! {
    /// Replay-reservation identity for one alias in one partition.
    ReplayReservationKey
}

/// Encodes an ordered grant set into stable, length-prefixed canonical bytes.
fn encode_grants(grants: &[&str]) -> Result<Vec<u8>, SealedAdmissionKeyError> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&(grants.len() as u64).to_be_bytes());
    for grant in grants {
        let field = require_admission_field(grant)?;
        encoded.extend_from_slice(&(field.len() as u64).to_be_bytes());
        encoded.extend_from_slice(field);
    }
    Ok(encoded)
}

impl CachePartitionKey {
    /// Derives the cache partition for one representation of one result.
    pub fn derive(
        descriptor: &PartitionDescriptor,
        effective_grants: &[&str],
        token_instance: &str,
        representation_policy: &str,
        cache_domain: &str,
    ) -> Result<Self, SealedAdmissionKeyError> {
        let grants = encode_grants(effective_grants)?;
        Ok(Self {
            digest: opaque_admission_digest(&[
                b"auth-00-cache-partition-v1",
                descriptor.identity(),
                &grants,
                require_admission_field(token_instance)?,
                &descriptor.audience_policy_revision().to_be_bytes(),
                require_admission_field(representation_policy)?,
                require_admission_field(cache_domain)?,
            ]),
        })
    }
}

impl ContinuationPartitionKey {
    /// Derives the continuation partition for one cursor lineage.
    pub fn derive(
        descriptor: &PartitionDescriptor,
        grant_snapshot: &[&str],
        method_parameter_binding: &str,
        capability_fingerprint: &str,
        continuation_policy: &str,
        domain: &str,
    ) -> Result<Self, SealedAdmissionKeyError> {
        let grants = encode_grants(grant_snapshot)?;
        Ok(Self {
            digest: opaque_admission_digest(&[
                b"auth-00-continuation-partition-v1",
                descriptor.identity(),
                &grants,
                require_admission_field(method_parameter_binding)?,
                require_admission_field(capability_fingerprint)?,
                require_admission_field(continuation_policy)?,
                require_admission_field(domain)?,
            ]),
        })
    }
}

impl DurableOwnerKey {
    /// Derives the durable owner identity for one ownership epoch.
    ///
    /// Token instance and effective grants are deliberately not inputs, so
    /// rotation and scope churn preserve ownership.
    pub fn derive(
        descriptor: &PartitionDescriptor,
        ownership_epoch: u64,
    ) -> Result<Self, SealedAdmissionKeyError> {
        Ok(Self {
            digest: opaque_admission_digest(&[
                b"auth-00-durable-owner-v1",
                require_admission_field(descriptor.issuer())?,
                require_admission_field(descriptor.tenant())?,
                require_admission_field(descriptor.subject())?,
                require_admission_field(descriptor.client())?,
                require_admission_field(descriptor.canonical_resource())?,
                require_admission_field(descriptor.provider())?,
                &ownership_epoch.to_be_bytes(),
            ]),
        })
    }
}

/// The caller's **current** verified authorization for a partition.
///
/// Binds the durable owner to the descriptor identity in force right now, so
/// a trust-generation or audience-policy bump relocates every record the
/// principal could previously reach. Ordinary token rotation and scope churn
/// do not change it: neither the token instance nor the effective grants are
/// descriptor fields.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PartitionAuthorization {
    binding: [u8; 32],
}

impl fmt::Debug for PartitionAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PartitionAuthorization")
            .finish_non_exhaustive()
    }
}

impl PartitionAuthorization {
    /// Derives the authorization in force for this descriptor and owner.
    #[must_use]
    pub fn current(descriptor: &PartitionDescriptor, owner: &DurableOwnerKey) -> Self {
        Self {
            binding: opaque_admission_digest(&[
                b"auth-00-partition-authorization-v1",
                descriptor.identity(),
                owner.as_bytes(),
            ]),
        }
    }

    /// The opaque binding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.binding
    }
}

impl SubscriptionPartitionKey {
    /// Derives the subscription partition for one topic and delivery policy.
    pub fn derive(
        descriptor: &PartitionDescriptor,
        effective_grants: &[&str],
        token_instance: &str,
        subscription_topic: &str,
        delivery_policy: &str,
    ) -> Result<Self, SealedAdmissionKeyError> {
        let grants = encode_grants(effective_grants)?;
        Ok(Self {
            digest: opaque_admission_digest(&[
                b"auth-00-subscription-partition-v1",
                descriptor.identity(),
                &grants,
                require_admission_field(token_instance)?,
                require_admission_field(subscription_topic)?,
                require_admission_field(delivery_policy)?,
            ]),
        })
    }
}

impl CredentialStoreKey {
    /// Derives the credential-store partition for one credential class.
    pub fn derive(
        descriptor: &PartitionDescriptor,
        store_domain: &str,
        credential_class: &str,
        token_instance: &str,
    ) -> Result<Self, SealedAdmissionKeyError> {
        Ok(Self {
            digest: opaque_admission_digest(&[
                b"auth-00-credential-store-v1",
                descriptor.identity(),
                require_admission_field(store_domain)?,
                require_admission_field(credential_class)?,
                require_admission_field(token_instance)?,
            ]),
        })
    }
}

impl QuotaPartitionKey {
    /// Derives the admission-only quota identity for one quota epoch.
    ///
    /// Issuer and configuration generation are deliberately not inputs.
    pub fn derive(
        descriptor: &PartitionDescriptor,
        quota_epoch: u64,
    ) -> Result<Self, SealedAdmissionKeyError> {
        Ok(Self {
            digest: opaque_admission_digest(&[
                b"auth-00-quota-partition-v1",
                require_admission_field(descriptor.provider())?,
                require_admission_field(descriptor.canonical_resource())?,
                require_admission_field(descriptor.tenant())?,
                require_admission_field(descriptor.subject())?,
                require_admission_field(descriptor.client())?,
                &quota_epoch.to_be_bytes(),
            ]),
        })
    }
}

impl RevalidationFlightKey {
    /// Derives the singleflight identity for one revalidation purpose.
    pub fn derive(
        descriptor: &PartitionDescriptor,
        purpose: &str,
    ) -> Result<Self, SealedAdmissionKeyError> {
        Ok(Self {
            digest: opaque_admission_digest(&[
                b"auth-00-revalidation-flight-v1",
                descriptor.identity(),
                require_admission_field(purpose)?,
            ]),
        })
    }
}

impl ReplayReservationKey {
    /// Derives the replay-reservation identity for one alias.
    pub fn derive(
        descriptor: &PartitionDescriptor,
        replay_alias: &str,
        purpose: &str,
    ) -> Result<Self, SealedAdmissionKeyError> {
        Ok(Self {
            digest: opaque_admission_digest(&[
                b"auth-00-replay-reservation-v1",
                descriptor.identity(),
                require_admission_field(replay_alias)?,
                require_admission_field(purpose)?,
            ]),
        })
    }
}

// ---------------------------------------------------------------------------
// Lookup surface
// ---------------------------------------------------------------------------

/// The purpose-specific partition a record lives in.
///
/// There is deliberately no quota variant: a quota key never names a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LookupPurpose {
    /// A cached result representation.
    Cache,
    /// A continuation/cursor lineage.
    Continuation,
    /// A subscription registration.
    Subscription,
    /// A stored credential reference.
    CredentialStore,
}

/// The partition key naming a record, paired with its purpose.
///
/// Each variant carries only a key type whose derivation includes the full
/// descriptor identity, so slots in different partitions can never alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionSlot {
    /// A cache slot.
    Cache(CachePartitionKey),
    /// A continuation slot.
    Continuation(ContinuationPartitionKey),
    /// A subscription slot.
    Subscription(SubscriptionPartitionKey),
    /// A credential-store slot.
    CredentialStore(CredentialStoreKey),
}

impl PartitionSlot {
    /// The purpose this slot belongs to.
    #[must_use]
    pub const fn purpose(&self) -> LookupPurpose {
        match self {
            Self::Cache(_) => LookupPurpose::Cache,
            Self::Continuation(_) => LookupPurpose::Continuation,
            Self::Subscription(_) => LookupPurpose::Subscription,
            Self::CredentialStore(_) => LookupPurpose::CredentialStore,
        }
    }

    const fn key_bytes(&self) -> &[u8; 32] {
        match self {
            Self::Cache(key) => key.as_bytes(),
            Self::Continuation(key) => key.as_bytes(),
            Self::Subscription(key) => key.as_bytes(),
            Self::CredentialStore(key) => key.as_bytes(),
        }
    }
}

/// The result of a non-oracular lookup.
///
/// A caller who does not currently own the named partition observes exactly
/// [`Self::Absent`], which is byte-identical to a genuine miss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupOutcome {
    /// The record exists and the caller currently owns its partition.
    Present(Vec<u8>),
    /// No record is visible to this caller. Indistinguishable between a
    /// genuine miss and a record owned by another principal.
    Absent,
}

impl LookupOutcome {
    /// Whether a record was returned.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        matches!(self, Self::Present(_))
    }

    /// Whether nothing was visible to this caller.
    #[must_use]
    pub const fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }
}

// ---------------------------------------------------------------------------
// Admission limits and errors
// ---------------------------------------------------------------------------

/// A refused limits configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevalidationLimitsError {
    /// A configured concurrency row was zero.
    ZeroConcurrency,
    /// A configured attempt-rate row was zero.
    ZeroAttemptRate,
    /// A configured row exceeded its documented hard ceiling.
    ExceedsHardCeiling,
}

impl fmt::Display for RevalidationLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroConcurrency => {
                formatter.write_str("revalidation concurrency must be positive")
            }
            Self::ZeroAttemptRate => {
                formatter.write_str("revalidation attempt rate must be positive")
            }
            Self::ExceedsHardCeiling => {
                formatter.write_str("revalidation limit exceeds its hard ceiling")
            }
        }
    }
}

impl std::error::Error for RevalidationLimitsError {}

/// The frozen revalidation concurrency and attempt-rate floors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevalidationLimits {
    per_partition: usize,
    per_provider: usize,
    per_deployment: usize,
    partition_attempts_per_minute: u32,
    provider_attempts_per_minute: u32,
}

impl Default for RevalidationLimits {
    fn default() -> Self {
        Self {
            per_partition: DEFAULT_REVALIDATIONS_PER_PARTITION,
            per_provider: DEFAULT_REVALIDATIONS_PER_PROVIDER,
            per_deployment: DEFAULT_REVALIDATIONS_PER_DEPLOYMENT,
            partition_attempts_per_minute: DEFAULT_ATTEMPTS_PER_MINUTE_PER_PARTITION,
            provider_attempts_per_minute: DEFAULT_ATTEMPTS_PER_MINUTE_PER_PROVIDER,
        }
    }
}

impl RevalidationLimits {
    /// Builds a limits row set, refusing any value outside its hard ceiling.
    pub fn new(
        per_partition: usize,
        per_provider: usize,
        per_deployment: usize,
        partition_attempts_per_minute: u32,
        provider_attempts_per_minute: u32,
    ) -> Result<Self, RevalidationLimitsError> {
        if per_partition == 0 || per_provider == 0 || per_deployment == 0 {
            return Err(RevalidationLimitsError::ZeroConcurrency);
        }
        if partition_attempts_per_minute == 0 || provider_attempts_per_minute == 0 {
            return Err(RevalidationLimitsError::ZeroAttemptRate);
        }
        if per_partition > HARD_REVALIDATIONS_PER_PARTITION
            || per_provider > HARD_REVALIDATIONS_PER_PROVIDER
            || per_deployment > HARD_REVALIDATIONS_PER_DEPLOYMENT
            || partition_attempts_per_minute > HARD_ATTEMPTS_PER_MINUTE_PER_PARTITION
            || provider_attempts_per_minute > HARD_ATTEMPTS_PER_MINUTE_PER_PROVIDER
        {
            return Err(RevalidationLimitsError::ExceedsHardCeiling);
        }
        Ok(Self {
            per_partition,
            per_provider,
            per_deployment,
            partition_attempts_per_minute,
            provider_attempts_per_minute,
        })
    }

    /// Concurrent revalidations allowed per verified partition.
    #[must_use]
    pub const fn per_partition(&self) -> usize {
        self.per_partition
    }

    /// Concurrent revalidations allowed per provider.
    #[must_use]
    pub const fn per_provider(&self) -> usize {
        self.per_provider
    }

    /// Concurrent revalidations allowed per deployment.
    #[must_use]
    pub const fn per_deployment(&self) -> usize {
        self.per_deployment
    }

    /// Revalidation attempts per minute allowed per verified partition.
    #[must_use]
    pub const fn partition_attempts_per_minute(&self) -> u32 {
        self.partition_attempts_per_minute
    }

    /// Revalidation attempts per minute allowed per provider.
    #[must_use]
    pub const fn provider_attempts_per_minute(&self) -> u32 {
        self.provider_attempts_per_minute
    }
}

/// A typed admission or authorization denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionAdmissionError {
    /// A quota reserve requested zero units.
    ZeroUnits,
    /// A quota constructor received a zero capacity.
    ZeroCapacity,
    /// The quota partition has no room for the requested units.
    QuotaExhausted {
        /// Units requested.
        requested: usize,
        /// Units already reserved in this quota partition.
        in_use: usize,
        /// Configured per-quota-partition ceiling.
        limit: usize,
    },
    /// A second settle was attempted on a released quota reservation.
    QuotaAlreadySettled,
    /// The same revalidation purpose is already in flight for this partition.
    RevalidationAlreadyInFlight,
    /// The per-partition revalidation concurrency ceiling is reached.
    PartitionRevalidationLimitExceeded {
        /// Flights currently open for this partition.
        in_flight: usize,
        /// Configured per-partition ceiling.
        limit: usize,
    },
    /// The per-provider revalidation concurrency ceiling is reached.
    ProviderRevalidationLimitExceeded {
        /// Flights currently open for this provider.
        in_flight: usize,
        /// Configured per-provider ceiling.
        limit: usize,
    },
    /// The deployment-wide revalidation concurrency ceiling is reached.
    DeploymentRevalidationLimitExceeded {
        /// Flights currently open across the deployment.
        in_flight: usize,
        /// Configured deployment ceiling.
        limit: usize,
    },
    /// The per-partition attempt rate for the current window is exhausted.
    PartitionAttemptRateExceeded {
        /// Attempts already recorded in the current window.
        attempts: u32,
        /// Configured per-minute ceiling.
        limit: u32,
    },
    /// The per-provider attempt rate for the current window is exhausted.
    ProviderAttemptRateExceeded {
        /// Attempts already recorded in the current window.
        attempts: u32,
        /// Configured per-minute ceiling.
        limit: u32,
    },
    /// A revalidation flight was closed twice.
    RevalidationAlreadyFinished,
    /// This replay alias is already reserved in this partition.
    ReplayAliasAlreadyReserved,
}

impl fmt::Display for PartitionAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroUnits => formatter.write_str("quota reserve requires a positive unit count"),
            Self::ZeroCapacity => formatter.write_str("quota capacity must be positive"),
            Self::QuotaExhausted {
                requested,
                in_use,
                limit,
            } => write!(
                formatter,
                "quota partition capacity {limit} exceeded (in_use {in_use}, requested {requested})"
            ),
            Self::QuotaAlreadySettled => formatter.write_str("quota reservation already settled"),
            Self::RevalidationAlreadyInFlight => {
                formatter.write_str("revalidation is already in flight for this partition purpose")
            }
            Self::PartitionRevalidationLimitExceeded { in_flight, limit } => write!(
                formatter,
                "partition revalidation concurrency {limit} exceeded (in_flight {in_flight})"
            ),
            Self::ProviderRevalidationLimitExceeded { in_flight, limit } => write!(
                formatter,
                "provider revalidation concurrency {limit} exceeded (in_flight {in_flight})"
            ),
            Self::DeploymentRevalidationLimitExceeded { in_flight, limit } => write!(
                formatter,
                "deployment revalidation concurrency {limit} exceeded (in_flight {in_flight})"
            ),
            Self::PartitionAttemptRateExceeded { attempts, limit } => write!(
                formatter,
                "partition revalidation attempt rate {limit}/min exceeded (attempts {attempts})"
            ),
            Self::ProviderAttemptRateExceeded { attempts, limit } => write!(
                formatter,
                "provider revalidation attempt rate {limit}/min exceeded (attempts {attempts})"
            ),
            Self::RevalidationAlreadyFinished => {
                formatter.write_str("revalidation flight is already finished")
            }
            Self::ReplayAliasAlreadyReserved => {
                formatter.write_str("replay alias is already reserved in this partition")
            }
        }
    }
}

impl std::error::Error for PartitionAdmissionError {}

// ---------------------------------------------------------------------------
// Controller state
// ---------------------------------------------------------------------------

/// A record slot: the purpose, the partition key, and the durable owner.
///
/// Binding the owner into the slot identity is what makes lookup non-oracular:
/// a caller who holds another principal's partition key still names a slot in
/// their own owner space, and that slot is empty.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct RecordSlot {
    purpose: LookupPurpose,
    key: [u8; 32],
    authorization: [u8; 32],
}

#[derive(Clone, Copy)]
struct AttemptWindow {
    started: Instant,
    attempts: u32,
}

#[derive(Default)]
struct PartitionState {
    records: HashMap<RecordSlot, Vec<u8>>,
    quota_in_use: HashMap<[u8; 32], usize>,
    quota_live: HashMap<u64, ([u8; 32], usize)>,
    next_quota_id: u64,
    open_flights: HashMap<[u8; 32], u64>,
    flight_owner: HashMap<u64, ([u8; 32], [u8; 32], [u8; 32])>,
    next_flight_id: u64,
    partition_flights: HashMap<[u8; 32], usize>,
    provider_flights: HashMap<[u8; 32], usize>,
    deployment_flights: usize,
    partition_attempts: HashMap<[u8; 32], AttemptWindow>,
    provider_attempts: HashMap<[u8; 32], AttemptWindow>,
    replay_reservations: HashMap<[u8; 32], [u8; 32]>,
    denial_count: usize,
}

fn lock_state(state: &Mutex<PartitionState>) -> MutexGuard<'_, PartitionState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn provider_bucket(descriptor: &PartitionDescriptor) -> [u8; 32] {
    opaque_admission_digest(&[
        b"auth-00-provider-bucket-v1",
        descriptor.provider().as_bytes(),
    ])
}

/// Security-partition admission, record storage, and non-oracular lookup.
#[derive(Clone)]
pub struct PartitionAdmissionController {
    limits: RevalidationLimits,
    quota_capacity: usize,
    inner: Arc<Mutex<PartitionState>>,
}

impl fmt::Debug for PartitionAdmissionController {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PartitionAdmissionController")
            .field("limits", &self.limits)
            .field("quota_capacity", &self.quota_capacity)
            .finish_non_exhaustive()
    }
}

impl PartitionAdmissionController {
    /// Builds a controller with the given revalidation limits and per-quota
    /// partition capacity.
    pub fn new(
        limits: RevalidationLimits,
        quota_capacity: usize,
    ) -> Result<Self, PartitionAdmissionError> {
        if quota_capacity == 0 {
            return Err(PartitionAdmissionError::ZeroCapacity);
        }
        Ok(Self {
            limits,
            quota_capacity,
            inner: Arc::new(Mutex::new(PartitionState::default())),
        })
    }

    /// The configured revalidation limits.
    #[must_use]
    pub const fn limits(&self) -> &RevalidationLimits {
        &self.limits
    }

    /// The configured per-quota-partition capacity.
    #[must_use]
    pub const fn quota_capacity(&self) -> usize {
        self.quota_capacity
    }

    // -- records -----------------------------------------------------------

    /// Stores a record in the caller's own owner space.
    ///
    /// A caller can only ever write into a slot bound to their own current
    /// verified authorization, so this can neither overwrite nor reveal
    /// another principal's record.
    pub fn store(
        &self,
        authorization: &PartitionAuthorization,
        slot: &PartitionSlot,
        value: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let record = RecordSlot {
            purpose: slot.purpose(),
            key: *slot.key_bytes(),
            authorization: *authorization.as_bytes(),
        };
        lock_state(&self.inner).records.insert(record, value)
    }

    /// Looks a record up under the caller's current verified authorization.
    ///
    /// The lookup is authorized by the purpose-specific partition key **and**
    /// the durable owner derived from the caller's current descriptor. A
    /// caller who does not own the partition observes [`LookupOutcome::Absent`]
    /// and no state changes.
    #[must_use]
    pub fn lookup(
        &self,
        authorization: &PartitionAuthorization,
        slot: &PartitionSlot,
    ) -> LookupOutcome {
        let record = RecordSlot {
            purpose: slot.purpose(),
            key: *slot.key_bytes(),
            authorization: *authorization.as_bytes(),
        };
        lock_state(&self.inner)
            .records
            .get(&record)
            .map_or(LookupOutcome::Absent, |value| {
                LookupOutcome::Present(value.clone())
            })
    }

    /// Number of stored records across every owner space.
    #[must_use]
    pub fn record_count(&self) -> usize {
        lock_state(&self.inner).records.len()
    }

    // -- quota (admission only) -------------------------------------------

    /// Reserves quota units against a quota partition.
    ///
    /// This is admission only. The returned reservation never authorizes a
    /// lookup, and no lookup entrypoint accepts a [`QuotaPartitionKey`].
    pub fn reserve_quota(
        &self,
        key: &QuotaPartitionKey,
        units: usize,
    ) -> Result<QuotaReservation, PartitionAdmissionError> {
        if units == 0 {
            return Err(PartitionAdmissionError::ZeroUnits);
        }
        let bucket = *key.as_bytes();
        let mut state = lock_state(&self.inner);
        let in_use = state.quota_in_use.get(&bucket).copied().unwrap_or(0);
        let next = in_use
            .checked_add(units)
            .ok_or(PartitionAdmissionError::QuotaExhausted {
                requested: units,
                in_use,
                limit: self.quota_capacity,
            })?;
        if next > self.quota_capacity {
            state.denial_count = state.denial_count.saturating_add(1);
            return Err(PartitionAdmissionError::QuotaExhausted {
                requested: units,
                in_use,
                limit: self.quota_capacity,
            });
        }
        let id = state.next_quota_id;
        state.next_quota_id = state.next_quota_id.saturating_add(1);
        state.quota_in_use.insert(bucket, next);
        state.quota_live.insert(id, (bucket, units));
        drop(state);
        Ok(QuotaReservation {
            inner: Arc::clone(&self.inner),
            id,
            live: true,
        })
    }

    /// Units currently reserved in one quota partition.
    #[must_use]
    pub fn quota_in_use(&self, key: &QuotaPartitionKey) -> usize {
        lock_state(&self.inner)
            .quota_in_use
            .get(key.as_bytes())
            .copied()
            .unwrap_or(0)
    }

    // -- revalidation singleflight ----------------------------------------

    /// Opens a revalidation flight, collapsing duplicates by singleflight.
    ///
    /// Checks, in order: singleflight, attempt rate per partition, attempt
    /// rate per provider, then concurrency per partition, per provider and per
    /// deployment. Every refusal leaves all counters unchanged, including the
    /// attempt windows.
    pub fn begin_revalidation(
        &self,
        descriptor: &PartitionDescriptor,
        flight: &RevalidationFlightKey,
    ) -> Result<RevalidationFlight, PartitionAdmissionError> {
        let flight_key = *flight.as_bytes();
        let partition = *descriptor.identity();
        let provider = provider_bucket(descriptor);
        let now = Instant::now();

        let mut state = lock_state(&self.inner);

        if state.open_flights.contains_key(&flight_key) {
            state.denial_count = state.denial_count.saturating_add(1);
            return Err(PartitionAdmissionError::RevalidationAlreadyInFlight);
        }

        let partition_attempts = window_attempts(&state.partition_attempts, &partition, now);
        if partition_attempts >= self.limits.partition_attempts_per_minute {
            state.denial_count = state.denial_count.saturating_add(1);
            return Err(PartitionAdmissionError::PartitionAttemptRateExceeded {
                attempts: partition_attempts,
                limit: self.limits.partition_attempts_per_minute,
            });
        }
        let provider_attempts = window_attempts(&state.provider_attempts, &provider, now);
        if provider_attempts >= self.limits.provider_attempts_per_minute {
            state.denial_count = state.denial_count.saturating_add(1);
            return Err(PartitionAdmissionError::ProviderAttemptRateExceeded {
                attempts: provider_attempts,
                limit: self.limits.provider_attempts_per_minute,
            });
        }

        let partition_in_flight = state
            .partition_flights
            .get(&partition)
            .copied()
            .unwrap_or(0);
        if partition_in_flight >= self.limits.per_partition {
            state.denial_count = state.denial_count.saturating_add(1);
            return Err(
                PartitionAdmissionError::PartitionRevalidationLimitExceeded {
                    in_flight: partition_in_flight,
                    limit: self.limits.per_partition,
                },
            );
        }
        let provider_in_flight = state.provider_flights.get(&provider).copied().unwrap_or(0);
        if provider_in_flight >= self.limits.per_provider {
            state.denial_count = state.denial_count.saturating_add(1);
            return Err(PartitionAdmissionError::ProviderRevalidationLimitExceeded {
                in_flight: provider_in_flight,
                limit: self.limits.per_provider,
            });
        }
        if state.deployment_flights >= self.limits.per_deployment {
            state.denial_count = state.denial_count.saturating_add(1);
            return Err(
                PartitionAdmissionError::DeploymentRevalidationLimitExceeded {
                    in_flight: state.deployment_flights,
                    limit: self.limits.per_deployment,
                },
            );
        }

        // Admitted: record the attempt and open the flight.
        charge_attempt(&mut state.partition_attempts, partition, now);
        charge_attempt(&mut state.provider_attempts, provider, now);

        let id = state.next_flight_id;
        state.next_flight_id = state.next_flight_id.saturating_add(1);
        state.open_flights.insert(flight_key, id);
        state
            .flight_owner
            .insert(id, (flight_key, partition, provider));
        state
            .partition_flights
            .insert(partition, partition_in_flight.saturating_add(1));
        state
            .provider_flights
            .insert(provider, provider_in_flight.saturating_add(1));
        state.deployment_flights = state.deployment_flights.saturating_add(1);
        drop(state);

        Ok(RevalidationFlight {
            inner: Arc::clone(&self.inner),
            id,
            live: true,
        })
    }

    /// Open revalidation flights for one verified partition.
    #[must_use]
    pub fn partition_flights(&self, descriptor: &PartitionDescriptor) -> usize {
        lock_state(&self.inner)
            .partition_flights
            .get(descriptor.identity())
            .copied()
            .unwrap_or(0)
    }

    /// Open revalidation flights for one provider.
    #[must_use]
    pub fn provider_flights(&self, descriptor: &PartitionDescriptor) -> usize {
        lock_state(&self.inner)
            .provider_flights
            .get(&provider_bucket(descriptor))
            .copied()
            .unwrap_or(0)
    }

    /// Open revalidation flights across the deployment.
    #[must_use]
    pub fn deployment_flights(&self) -> usize {
        lock_state(&self.inner).deployment_flights
    }

    /// Attempts recorded in the current window for one verified partition.
    #[must_use]
    pub fn partition_attempts(&self, descriptor: &PartitionDescriptor) -> u32 {
        let state = lock_state(&self.inner);
        window_attempts(
            &state.partition_attempts,
            descriptor.identity(),
            Instant::now(),
        )
    }

    /// Attempts recorded in the current window for one provider.
    #[must_use]
    pub fn provider_attempts(&self, descriptor: &PartitionDescriptor) -> u32 {
        let state = lock_state(&self.inner);
        window_attempts(
            &state.provider_attempts,
            &provider_bucket(descriptor),
            Instant::now(),
        )
    }

    // -- replay reservations ----------------------------------------------

    /// Reserves a replay alias in the caller's own partition.
    ///
    /// The reservation is scoped to the reserving partition, so the same alias
    /// in a different partition is a distinct reservation and one principal
    /// can never observe or block another's alias.
    pub fn reserve_replay(
        &self,
        descriptor: &PartitionDescriptor,
        replay: &ReplayReservationKey,
    ) -> Result<(), PartitionAdmissionError> {
        let alias = *replay.as_bytes();
        let partition = *descriptor.identity();
        let mut state = lock_state(&self.inner);
        if state.replay_reservations.contains_key(&alias) {
            state.denial_count = state.denial_count.saturating_add(1);
            return Err(PartitionAdmissionError::ReplayAliasAlreadyReserved);
        }
        state.replay_reservations.insert(alias, partition);
        Ok(())
    }

    /// Whether a replay alias is currently reserved.
    #[must_use]
    pub fn replay_reserved(&self, replay: &ReplayReservationKey) -> bool {
        lock_state(&self.inner)
            .replay_reservations
            .contains_key(replay.as_bytes())
    }

    /// Number of live replay reservations.
    #[must_use]
    pub fn replay_reservation_count(&self) -> usize {
        lock_state(&self.inner).replay_reservations.len()
    }

    /// Number of typed admission denials recorded.
    #[must_use]
    pub fn denial_count(&self) -> usize {
        lock_state(&self.inner).denial_count
    }
}

fn window_attempts(
    windows: &HashMap<[u8; 32], AttemptWindow>,
    bucket: &[u8; 32],
    now: Instant,
) -> u32 {
    windows.get(bucket).map_or(0, |window| {
        if now.duration_since(window.started) >= ATTEMPT_RATE_WINDOW {
            0
        } else {
            window.attempts
        }
    })
}

fn charge_attempt(windows: &mut HashMap<[u8; 32], AttemptWindow>, bucket: [u8; 32], now: Instant) {
    let entry = windows.entry(bucket).or_insert(AttemptWindow {
        started: now,
        attempts: 0,
    });
    if now.duration_since(entry.started) >= ATTEMPT_RATE_WINDOW {
        entry.started = now;
        entry.attempts = 0;
    }
    entry.attempts = entry.attempts.saturating_add(1);
}

/// One live quota charge. Admission only; never a lookup capability.
pub struct QuotaReservation {
    inner: Arc<Mutex<PartitionState>>,
    id: u64,
    live: bool,
}

impl fmt::Debug for QuotaReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuotaReservation")
            .finish_non_exhaustive()
    }
}

impl QuotaReservation {
    /// Releases the charge exactly once.
    pub fn release(&mut self) -> Result<(), PartitionAdmissionError> {
        if !self.live {
            return Err(PartitionAdmissionError::QuotaAlreadySettled);
        }
        self.live = false;
        let mut state = lock_state(&self.inner);
        let Some((bucket, units)) = state.quota_live.remove(&self.id) else {
            return Err(PartitionAdmissionError::QuotaAlreadySettled);
        };
        let remaining = state
            .quota_in_use
            .get(&bucket)
            .copied()
            .unwrap_or(0)
            .saturating_sub(units);
        if remaining == 0 {
            state.quota_in_use.remove(&bucket);
        } else {
            state.quota_in_use.insert(bucket, remaining);
        }
        Ok(())
    }
}

impl Drop for QuotaReservation {
    fn drop(&mut self) {
        if self.live {
            let _ = self.release();
        }
    }
}

/// One open revalidation flight. Closing it frees every concurrency counter.
pub struct RevalidationFlight {
    inner: Arc<Mutex<PartitionState>>,
    id: u64,
    live: bool,
}

impl fmt::Debug for RevalidationFlight {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RevalidationFlight")
            .finish_non_exhaustive()
    }
}

impl RevalidationFlight {
    /// Closes the flight exactly once, releasing all three concurrency rows.
    ///
    /// The attempt-window charge is deliberately not refunded: an attempt was
    /// genuinely made.
    pub fn finish(&mut self) -> Result<(), PartitionAdmissionError> {
        if !self.live {
            return Err(PartitionAdmissionError::RevalidationAlreadyFinished);
        }
        self.live = false;
        let mut state = lock_state(&self.inner);
        let Some((flight_key, partition, provider)) = state.flight_owner.remove(&self.id) else {
            return Ok(());
        };
        state.open_flights.remove(&flight_key);
        let partition_remaining = state
            .partition_flights
            .get(&partition)
            .copied()
            .unwrap_or(0)
            .saturating_sub(1);
        if partition_remaining == 0 {
            state.partition_flights.remove(&partition);
        } else {
            state
                .partition_flights
                .insert(partition, partition_remaining);
        }
        let provider_remaining = state
            .provider_flights
            .get(&provider)
            .copied()
            .unwrap_or(0)
            .saturating_sub(1);
        if provider_remaining == 0 {
            state.provider_flights.remove(&provider);
        } else {
            state.provider_flights.insert(provider, provider_remaining);
        }
        state.deployment_flights = state.deployment_flights.saturating_sub(1);
        Ok(())
    }
}

impl Drop for RevalidationFlight {
    fn drop(&mut self) {
        if self.live {
            let _ = self.finish();
        }
    }
}
