//! Purpose-separated replay aliases from a configured persistent MAC service.
//!
//! The facade constructs exact canonical inputs and requests every active and
//! previous generation. It imports no key and never publishes a partial set.
//! The backend is a deployment trust boundary: receipt correlation cannot
//! establish honest key use, durable custody, restore safety or cluster agreement.
//! A returned set still requires an atomic durable replay-store transaction.
//! Ring configuration digests are identities, not acknowledgement certificates.

use crate::combinator::BoxFuture;
use crate::crypto::{Sha256Digest, draw_security_identifier, sha256_bounded};
pub use crate::ingress::ReplayPurpose;
use crate::runtime::{ProcessBoundToken, ProcessGenerationGuard, ambient_capability_ceiling};
use asupersync::channel::oneshot;
use asupersync::cx::cap::CapMask;
use asupersync::time::Sleep;
use asupersync::{Cx, Time};
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use zeroize::Zeroizing;

const CONTEXT_MAGIC: &[u8; 8] = b"FMCPSCX\0";
const REPLAY_MAGIC: &[u8; 8] = b"FMCPRPL\0";
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_ISSUER_BYTES: usize = 16 * 1024;
const MAX_JTI_BYTES: usize = 16 * 1024;
const MAX_GENERATIONS: usize = 8;
const MAX_CONTEXT_BYTES: usize = 256 * 1024;
const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_ACTIVE_OPERATIONS: usize = 256;
const MAX_RESERVED_BYTES: usize = 128 * 1024 * 1024;
const MAX_CALL_TIMEOUT: Duration = Duration::from_secs(60);
const CONTEXT_FRAMING: usize = 12 + 7 + 7;
const MAC_FRAMING: usize = 26;
const OPERATION_OVERHEAD: usize = 4096;

/// Closed errors never contain an issuer, assertion, jti, provider body or tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDigestError {
    InvalidConfiguration,
    InvalidLimits,
    InvalidTuple,
    InputTooLarge,
    AllocationFailed,
    CapacityExceeded,
    AdmissionUnavailable,
    ProcessChanged,
    EntropyUnavailable,
    CapabilityUnavailable,
    Cancelled,
    DeadlineExceeded,
    ReceiptMismatch,
    ProviderRejected(PersistentMacDispatch),
    UnknownGeneration,
    PurposeMismatch,
    VerificationRejected,
}
impl fmt::Display for ReplayDigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid persistent replay MAC configuration",
            Self::InvalidLimits => "invalid persistent replay MAC limits",
            Self::InvalidTuple => "invalid bounded replay tuple",
            Self::InputTooLarge => "replay MAC input exceeds its admitted bounds",
            Self::AllocationFailed => "replay MAC storage could not be reserved",
            Self::CapacityExceeded => "replay MAC admission capacity exhausted",
            Self::AdmissionUnavailable => "replay MAC admission state is unavailable",
            Self::ProcessChanged => "replay MAC process generation changed",
            Self::EntropyUnavailable => "replay MAC operation entropy is unavailable",
            Self::CapabilityUnavailable => {
                "replay MAC requires caller time and entropy capabilities"
            }
            Self::Cancelled => "replay MAC operation cancelled",
            Self::DeadlineExceeded => "replay MAC operation deadline exceeded",
            Self::ReceiptMismatch => "replay MAC receipt did not match its operation",
            Self::ProviderRejected(_) => "replay MAC provider did not complete the operation",
            Self::UnknownGeneration => "replay MAC generation is not configured",
            Self::PurposeMismatch => "replay MAC purpose does not match its tuple",
            Self::VerificationRejected => "replay MAC verification was rejected",
        })
    }
}
impl std::error::Error for ReplayDigestError {}

/// Provider dispatch is reported separately from its result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistentMacDispatch {
    NotDispatched,
    Dispatched,
    Unknown,
}

/// Immutable configured adapter/artifact/configuration identity, not attestation.
#[derive(Clone)]
pub struct PersistentMacProviderIdentity {
    adapter: String,
    artifact: Sha256Digest,
    configuration: Sha256Digest,
    digest: Sha256Digest,
}
impl PersistentMacProviderIdentity {
    pub fn new(
        adapter: &str,
        artifact: Sha256Digest,
        configuration: Sha256Digest,
    ) -> Result<Self, ReplayDigestError> {
        if !valid_identifier(adapter) {
            return Err(ReplayDigestError::InvalidConfiguration);
        }
        let mut bytes = bounded_vec(8 + 2 + 2 + adapter.len() + 64)?;
        bytes.extend_from_slice(b"FMCPRPM\0");
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        put_bytes_u16(&mut bytes, adapter.as_bytes())?;
        bytes.extend_from_slice(artifact.as_bytes());
        bytes.extend_from_slice(configuration.as_bytes());
        let digest = digest(&bytes)?;
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

/// A bounded preconfigured key selector; no key material is accepted.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct PersistentMacKeyGeneration {
    key_id: String,
    generation: u64,
}
impl PersistentMacKeyGeneration {
    pub fn new(key_id: &str, generation: u64) -> Result<Self, ReplayDigestError> {
        if !valid_identifier(key_id) {
            return Err(ReplayDigestError::InvalidConfiguration);
        }
        Ok(Self {
            key_id: key_id.to_owned(),
            generation,
        })
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Canonical finite ring, including all verifiable previous generations.
/// Construction validates configuration only. Fenced cluster expansion,
/// acknowledgement and retirement remain the durable store's responsibility.
/// This type intentionally has no caller-supplied acknowledgement boolean.
pub struct PersistentReplayConfiguration {
    provider: PersistentMacProviderIdentity,
    revision: u64,
    active: PersistentMacKeyGeneration,
    generations: Vec<PersistentMacKeyGeneration>,
    digest: Sha256Digest,
}
impl PersistentReplayConfiguration {
    pub fn new(
        provider: PersistentMacProviderIdentity,
        revision: u64,
        active: PersistentMacKeyGeneration,
        previous: Vec<PersistentMacKeyGeneration>,
    ) -> Result<Self, ReplayDigestError> {
        if revision == 0 || previous.len() >= MAX_GENERATIONS {
            return Err(ReplayDigestError::InvalidConfiguration);
        }
        let mut generations = Vec::new();
        generations
            .try_reserve_exact(previous.len() + 1)
            .map_err(|_| ReplayDigestError::AllocationFailed)?;
        generations.push(active.clone());
        generations.extend(previous);
        generations.sort();
        if generations.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ReplayDigestError::InvalidConfiguration);
        }
        let mut bytes = bounded_vec(OPERATION_OVERHEAD)?;
        bytes.extend_from_slice(b"FMCPRNG\0");
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(provider.digest().as_bytes());
        bytes.extend_from_slice(&revision.to_be_bytes());
        put_generation(&mut bytes, &active)?;
        bytes.extend_from_slice(&(generations.len() as u16).to_be_bytes());
        for generation in &generations {
            put_generation(&mut bytes, generation)?;
        }
        let digest = digest(&bytes)?;
        Ok(Self {
            provider,
            revision,
            active,
            generations,
            digest,
        })
    }
    pub fn provider(&self) -> &PersistentMacProviderIdentity {
        &self.provider
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub fn active(&self) -> &PersistentMacKeyGeneration {
        &self.active
    }
    pub fn generations(&self) -> &[PersistentMacKeyGeneration] {
        &self.generations
    }
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Bounds for an explicitly shared provider admission domain. Saturation
/// refuses before retaining input or dispatch; there is no hidden queue.
#[derive(Clone, Copy, Debug)]
pub struct ReplayDigestLimits {
    context_bytes: usize,
    input_bytes: usize,
    generations: usize,
    active_operations: usize,
    reserved_bytes: usize,
    call_timeout: Duration,
}
impl Default for ReplayDigestLimits {
    fn default() -> Self {
        Self {
            context_bytes: 64 * 1024,
            input_bytes: 512 * 1024,
            generations: 3,
            active_operations: 32,
            reserved_bytes: 16 * 1024 * 1024,
            call_timeout: Duration::from_secs(10),
        }
    }
}
impl ReplayDigestLimits {
    pub fn new(
        context_bytes: usize,
        input_bytes: usize,
        generations: usize,
        active_operations: usize,
        reserved_bytes: usize,
        call_timeout: Duration,
    ) -> Result<Self, ReplayDigestError> {
        let framed = context_bytes
            .checked_add(MAC_FRAMING + MAX_KEY_ID_BYTES)
            .ok_or(ReplayDigestError::InvalidLimits)?;
        if !(CONTEXT_FRAMING + 33..=MAX_CONTEXT_BYTES).contains(&context_bytes)
            || input_bytes < framed
            || input_bytes > MAX_INPUT_BYTES
            || !(1..=MAX_GENERATIONS).contains(&generations)
            || !(1..=MAX_ACTIVE_OPERATIONS).contains(&active_operations)
            || !(OPERATION_OVERHEAD..=MAX_RESERVED_BYTES).contains(&reserved_bytes)
            || call_timeout.is_zero()
            || call_timeout > MAX_CALL_TIMEOUT
        {
            return Err(ReplayDigestError::InvalidLimits);
        }
        Ok(Self {
            context_bytes,
            input_bytes,
            generations,
            active_operations,
            reserved_bytes,
            call_timeout,
        })
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReplayMacSnapshot {
    pub active_operations: usize,
    pub reserved_input_bytes: usize,
}

/// Share one lane across all facades in its admission domain. Framework
/// operation/scratch reservations remain charged through provider destruction.
/// Backend-owned work must remain bounded and owned by the caller's region.
pub struct ReplayMacLane {
    process: ProcessBoundToken,
    limits: ReplayDigestLimits,
    state: Mutex<ReplayMacSnapshot>,
}
impl ReplayMacLane {
    pub fn new(limits: ReplayDigestLimits) -> Result<Self, ReplayDigestError> {
        let process = ProcessGenerationGuard::install()
            .map_err(|_| ReplayDigestError::EntropyUnavailable)?
            .token();
        Ok(Self {
            process,
            limits,
            state: Mutex::new(ReplayMacSnapshot::default()),
        })
    }
    pub fn snapshot(&self) -> Result<ReplayMacSnapshot, ReplayDigestError> {
        self.live()?;
        self.state
            .lock()
            .map(|state| *state)
            .map_err(|_| ReplayDigestError::AdmissionUnavailable)
    }
    fn live(&self) -> Result<(), ReplayDigestError> {
        self.process
            .verify()
            .map_err(|_| ReplayDigestError::ProcessChanged)
    }
    fn reserve(&self, bytes: usize) -> Result<ReplayMacLease<'_>, ReplayDigestError> {
        self.live()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReplayDigestError::AdmissionUnavailable)?;
        let active = state
            .active_operations
            .checked_add(1)
            .ok_or(ReplayDigestError::CapacityExceeded)?;
        let reserved = state
            .reserved_input_bytes
            .checked_add(bytes)
            .ok_or(ReplayDigestError::CapacityExceeded)?;
        if active > self.limits.active_operations || reserved > self.limits.reserved_bytes {
            return Err(ReplayDigestError::CapacityExceeded);
        }
        state.active_operations = active;
        state.reserved_input_bytes = reserved;
        Ok(ReplayMacLease { lane: self, bytes })
    }
}
struct ReplayMacLease<'a> {
    lane: &'a ReplayMacLane,
    bytes: usize,
}
impl Drop for ReplayMacLease<'_> {
    fn drop(&mut self) {
        let mut state = self
            .lane
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active_operations -= 1;
        state.reserved_input_bytes -= self.bytes;
    }
}

/// Framework-constructed operation; input storage is zeroized on all drops.
/// The backend must not log or persist this canonical replay tuple.
pub struct PersistentMacRequest {
    operation_id: [u8; 16],
    provider: PersistentMacProviderIdentity,
    ring_digest: Sha256Digest,
    key: PersistentMacKeyGeneration,
    purpose: ReplayPurpose,
    input: Zeroizing<Vec<u8>>,
    input_digest: Sha256Digest,
}
impl PersistentMacRequest {
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }
    pub fn provider(&self) -> &PersistentMacProviderIdentity {
        &self.provider
    }
    pub const fn ring_digest(&self) -> Sha256Digest {
        self.ring_digest
    }
    pub fn key_id(&self) -> &str {
        self.key.key_id()
    }
    pub const fn generation(&self) -> u64 {
        self.key.generation()
    }
    pub const fn purpose(&self) -> ReplayPurpose {
        self.purpose
    }
    pub fn input(&self) -> &[u8] {
        &self.input
    }
    pub const fn input_digest(&self) -> Sha256Digest {
        self.input_digest
    }
}

/// The adapter's report, not independently verifiable attestation. Every field
/// must correlate with the outstanding request before an alias is released.
pub struct PersistentMacReceipt {
    operation_id: [u8; 16],
    provider_digest: Sha256Digest,
    ring_digest: Sha256Digest,
    key: PersistentMacKeyGeneration,
    purpose: ReplayPurpose,
    input_digest: Sha256Digest,
    dispatch: PersistentMacDispatch,
}
impl PersistentMacReceipt {
    /// Admits bounded receipt fields returned by the configured service.
    pub fn new(
        operation_id: [u8; 16],
        provider_digest: Sha256Digest,
        ring_digest: Sha256Digest,
        key: PersistentMacKeyGeneration,
        purpose: ReplayPurpose,
        input_digest: Sha256Digest,
        dispatch: PersistentMacDispatch,
    ) -> Self {
        Self {
            operation_id,
            provider_digest,
            ring_digest,
            key,
            purpose,
            input_digest,
            dispatch,
        }
    }
    /// Reports completion for a locally correlated request. An adapter that
    /// receives an independent remote receipt must validate that receipt first;
    /// copying request fields cannot authenticate the remote service's report.
    pub fn reported_for(request: &PersistentMacRequest, dispatch: PersistentMacDispatch) -> Self {
        Self {
            operation_id: request.operation_id,
            provider_digest: request.provider.digest(),
            ring_digest: request.ring_digest,
            key: request.key.clone(),
            purpose: request.purpose,
            input_digest: request.input_digest,
            dispatch,
        }
    }
    pub const fn dispatch(&self) -> PersistentMacDispatch {
        self.dispatch
    }
}
/// A full-width tag and correlated adapter report.
pub struct PersistentMacReply {
    receipt: PersistentMacReceipt,
    tag: [u8; 32],
}
impl PersistentMacReply {
    pub const fn new(receipt: PersistentMacReceipt, tag: [u8; 32]) -> Self {
        Self { receipt, tag }
    }
}
/// Backend constant-time verification verdict and correlated report.
pub struct PersistentMacVerification {
    receipt: PersistentMacReceipt,
    verified: bool,
}
impl PersistentMacVerification {
    pub const fn new(receipt: PersistentMacReceipt, verified: bool) -> Self {
        Self { receipt, verified }
    }
}
/// A failure carries the same operation correlation as success.
pub struct PersistentMacFailure {
    receipt: PersistentMacReceipt,
}
impl PersistentMacFailure {
    pub const fn new(receipt: PersistentMacReceipt) -> Self {
        Self { receipt }
    }
}

/// Public deployment boundary for the complete persistent HMAC service.
///
/// No method accepts a key, arbitrary endpoint, algorithm or unbounded request.
/// Every configured generation must use distinct protected key bytes. Providers
/// own durable key custody, rollback/clone resistance, truthful dispatch and
/// constant-time full-tag verification. They must not block an async poll;
/// blocking operations use the caller's admitted executor. Construction, poll
/// and drop run under the caller's effect ceiling. Dropped futures dispose of
/// late results, retain outstanding work in the caller-owned region, and never
/// launch detached unbounded jobs or retain plaintext inputs. Implementing this
/// trait is not provider qualification or enterprise-profile activation.
pub trait PersistentHmacSha256Backend: Send + Sync + 'static {
    fn mac<'a>(
        &'a self,
        cx: &'a Cx,
        request: PersistentMacRequest,
        deadline: Time,
    ) -> BoxFuture<'a, Result<PersistentMacReply, PersistentMacFailure>>;
    fn verify<'a>(
        &'a self,
        cx: &'a Cx,
        request: PersistentMacRequest,
        tag: [u8; 32],
        deadline: Time,
    ) -> BoxFuture<'a, Result<PersistentMacVerification, PersistentMacFailure>>;
}

/// A keyed alias, not a reservation. No Clone, Debug or Serialize is provided.
pub struct PersistentReplayAlias {
    purpose: ReplayPurpose,
    key: PersistentMacKeyGeneration,
    tag: [u8; 32],
}
impl PersistentReplayAlias {
    /// Parses untrusted storage fields. Only facade verification authenticates
    /// this alias; only an atomic durable store transaction can reserve it.
    pub fn from_persisted(
        purpose: ReplayPurpose,
        key_id: &str,
        generation: u64,
        tag: [u8; 32],
    ) -> Result<Self, ReplayDigestError> {
        Ok(Self {
            purpose,
            key: PersistentMacKeyGeneration::new(key_id, generation)?,
            tag,
        })
    }
    pub const fn purpose(&self) -> ReplayPurpose {
        self.purpose
    }
    pub fn key_id(&self) -> &str {
        self.key.key_id()
    }
    pub const fn generation(&self) -> u64 {
        self.key.generation()
    }
    pub const fn tag(&self) -> &[u8; 32] {
        &self.tag
    }
}
/// Nonconstructible complete alias set. Its digest binds the purpose, configured
/// ring and every canonical alias, and never contains a raw replay tuple.
pub struct PersistentReplayAliasSet {
    purpose: ReplayPurpose,
    provider: PersistentMacProviderIdentity,
    ring_digest: Sha256Digest,
    aliases: Vec<PersistentReplayAlias>,
    digest: Sha256Digest,
}
impl PersistentReplayAliasSet {
    pub const fn purpose(&self) -> ReplayPurpose {
        self.purpose
    }
    pub fn provider(&self) -> &PersistentMacProviderIdentity {
        &self.provider
    }
    pub const fn ring_digest(&self) -> Sha256Digest {
        self.ring_digest
    }
    pub fn aliases(&self) -> &[PersistentReplayAlias] {
        &self.aliases
    }
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// Immutable shared facade. Partial all-generation results never escape.
pub struct PersistentReplayDigest {
    configuration: PersistentReplayConfiguration,
    backend: Arc<dyn PersistentHmacSha256Backend>,
    lane: Arc<ReplayMacLane>,
}
impl PersistentReplayDigest {
    pub fn new(
        configuration: PersistentReplayConfiguration,
        backend: Arc<dyn PersistentHmacSha256Backend>,
        lane: Arc<ReplayMacLane>,
    ) -> Result<Self, ReplayDigestError> {
        lane.live()?;
        if configuration.generations.len() > lane.limits.generations {
            return Err(ReplayDigestError::InvalidConfiguration);
        }
        Ok(Self {
            configuration,
            backend,
            lane,
        })
    }
    pub fn provider(&self) -> &PersistentMacProviderIdentity {
        &self.configuration.provider
    }
    pub const fn ring_digest(&self) -> Sha256Digest {
        self.configuration.digest
    }
    /// Uses exact preserved issuer bytes and SHA-256 of the exact compact ID
    /// Token. A consuming client derives both from its verified assertion owner.
    pub async fn derive_identity_assertion(
        &self,
        cx: &Cx,
        issuer: &str,
        compact_digest: &Sha256Digest,
        deadline: Time,
    ) -> Result<PersistentReplayAliasSet, ReplayDigestError> {
        self.derive(
            cx,
            ReplayTuple::IdentityAssertion(issuer, compact_digest),
            deadline,
        )
        .await
    }
    pub async fn derive_id_jag_jti(
        &self,
        cx: &Cx,
        issuer: &str,
        jti: &[u8],
        deadline: Time,
    ) -> Result<PersistentReplayAliasSet, ReplayDigestError> {
        self.derive(cx, ReplayTuple::IdJagJti(issuer, jti), deadline)
            .await
    }
    pub async fn verify_identity_assertion_alias(
        &self,
        cx: &Cx,
        issuer: &str,
        compact_digest: &Sha256Digest,
        alias: &PersistentReplayAlias,
        deadline: Time,
    ) -> Result<(), ReplayDigestError> {
        self.verify(
            cx,
            ReplayTuple::IdentityAssertion(issuer, compact_digest),
            alias,
            deadline,
        )
        .await
    }
    pub async fn verify_id_jag_jti_alias(
        &self,
        cx: &Cx,
        issuer: &str,
        jti: &[u8],
        alias: &PersistentReplayAlias,
        deadline: Time,
    ) -> Result<(), ReplayDigestError> {
        self.verify(cx, ReplayTuple::IdJagJti(issuer, jti), alias, deadline)
            .await
    }
    async fn derive(
        &self,
        cx: &Cx,
        tuple: ReplayTuple<'_>,
        deadline: Time,
    ) -> Result<PersistentReplayAliasSet, ReplayDigestError> {
        let deadline = self.admit_deadline(cx, deadline)?;
        let context_len = tuple.length(self.lane.limits.context_bytes)?;
        let _lease = self.lane.reserve(self.reservation_bytes(context_len)?)?;
        let context = tuple.encode(context_len)?;
        let mut aliases = Vec::new();
        aliases
            .try_reserve_exact(self.configuration.generations.len())
            .map_err(|_| ReplayDigestError::AllocationFailed)?;
        for key in &self.configuration.generations {
            self.live(cx, deadline)?;
            let request = self.request(cx, tuple.purpose(), key, &context)?;
            let expected =
                PersistentMacReceipt::reported_for(&request, PersistentMacDispatch::Dispatched);
            let provider_cx = with_caller(cx, || {
                Cx::current().ok_or(ReplayDigestError::CapabilityUnavailable)
            })?;
            let result = within(&self.lane.process, &provider_cx, deadline, || {
                self.backend.mac(&provider_cx, request, deadline)
            })
            .await?;
            let reply = match result {
                Ok(reply) => reply,
                Err(failure) => {
                    check_receipt(&expected, &failure.receipt, false)?;
                    return Err(ReplayDigestError::ProviderRejected(
                        failure.receipt.dispatch,
                    ));
                }
            };
            check_receipt(&expected, &reply.receipt, true)?;
            self.live(cx, deadline)?;
            aliases.push(PersistentReplayAlias {
                purpose: tuple.purpose(),
                key: key.clone(),
                tag: reply.tag,
            });
        }
        let digest = alias_set_digest(tuple.purpose(), self.ring_digest(), &aliases)?;
        self.live(cx, deadline)?;
        Ok(PersistentReplayAliasSet {
            purpose: tuple.purpose(),
            provider: self.provider().clone(),
            ring_digest: self.ring_digest(),
            aliases,
            digest,
        })
    }
    async fn verify(
        &self,
        cx: &Cx,
        tuple: ReplayTuple<'_>,
        alias: &PersistentReplayAlias,
        deadline: Time,
    ) -> Result<(), ReplayDigestError> {
        let deadline = self.admit_deadline(cx, deadline)?;
        if alias.purpose != tuple.purpose() {
            return Err(ReplayDigestError::PurposeMismatch);
        }
        let key = self
            .configuration
            .generations
            .iter()
            .find(|key| *key == &alias.key)
            .ok_or(ReplayDigestError::UnknownGeneration)?;
        let context_len = tuple.length(self.lane.limits.context_bytes)?;
        let _lease = self.lane.reserve(self.reservation_bytes(context_len)?)?;
        let context = tuple.encode(context_len)?;
        let request = self.request(cx, tuple.purpose(), key, &context)?;
        let expected =
            PersistentMacReceipt::reported_for(&request, PersistentMacDispatch::Dispatched);
        let provider_cx = with_caller(cx, || {
            Cx::current().ok_or(ReplayDigestError::CapabilityUnavailable)
        })?;
        let result = within(&self.lane.process, &provider_cx, deadline, || {
            self.backend
                .verify(&provider_cx, request, alias.tag, deadline)
        })
        .await?;
        let reply = match result {
            Ok(reply) => reply,
            Err(failure) => {
                check_receipt(&expected, &failure.receipt, false)?;
                return Err(ReplayDigestError::ProviderRejected(
                    failure.receipt.dispatch,
                ));
            }
        };
        check_receipt(&expected, &reply.receipt, true)?;
        self.live(cx, deadline)?;
        if !reply.verified {
            return Err(ReplayDigestError::VerificationRejected);
        }
        Ok(())
    }
    fn admit_deadline(&self, cx: &Cx, requested: Time) -> Result<Time, ReplayDigestError> {
        self.lane.live()?;
        let deadline = requested.min(
            cx.now()
                .saturating_add_nanos(self.lane.limits.call_timeout.as_nanos() as u64),
        );
        let deadline = cx
            .budget()
            .deadline
            .map_or(deadline, |parent| parent.min(deadline));
        self.live(cx, deadline)?;
        with_caller(cx, || {
            require_time(cx)?;
            if !Cx::current().is_some_and(|active| active.capabilities().entropy) {
                return Err(ReplayDigestError::CapabilityUnavailable);
            }
            Ok(deadline)
        })
    }
    fn live(&self, cx: &Cx, deadline: Time) -> Result<(), ReplayDigestError> {
        self.lane.live()?;
        checkpoint(cx, deadline)
    }
    fn reservation_bytes(&self, context_len: usize) -> Result<usize, ReplayDigestError> {
        let input = context_len
            .checked_add(MAC_FRAMING + MAX_KEY_ID_BYTES)
            .ok_or(ReplayDigestError::InputTooLarge)?;
        if input > self.lane.limits.input_bytes {
            return Err(ReplayDigestError::InputTooLarge);
        }
        context_len
            .checked_add(input)
            .and_then(|n| n.checked_add(OPERATION_OVERHEAD))
            .ok_or(ReplayDigestError::InputTooLarge)
    }
    fn request(
        &self,
        cx: &Cx,
        purpose: ReplayPurpose,
        key: &PersistentMacKeyGeneration,
        context: &[u8],
    ) -> Result<PersistentMacRequest, ReplayDigestError> {
        let operation_id = with_caller(cx, || {
            if !Cx::current().is_some_and(|active| active.capabilities().entropy) {
                return Err(ReplayDigestError::CapabilityUnavailable);
            }
            let draw =
                draw_security_identifier().map_err(|_| ReplayDigestError::EntropyUnavailable)?;
            let mut operation = [0_u8; 16];
            operation.copy_from_slice(&draw.as_bytes()[..16]);
            Ok(operation)
        })?;
        let input = encode_mac(purpose, key, context, self.lane.limits.input_bytes)?;
        let input_digest = digest(&input)?;
        Ok(PersistentMacRequest {
            operation_id,
            provider: self.provider().clone(),
            ring_digest: self.ring_digest(),
            key: key.clone(),
            purpose,
            input,
            input_digest,
        })
    }
}

#[derive(Clone, Copy)]
enum ReplayTuple<'a> {
    IdentityAssertion(&'a str, &'a Sha256Digest),
    IdJagJti(&'a str, &'a [u8]),
}
impl<'a> ReplayTuple<'a> {
    fn purpose(self) -> ReplayPurpose {
        match self {
            Self::IdentityAssertion(..) => ReplayPurpose::EnterpriseIdentityAssertionReplay,
            Self::IdJagJti(..) => ReplayPurpose::EnterpriseIdJagJtiReplay,
        }
    }
    fn fields(self) -> (&'a str, &'a [u8]) {
        match self {
            Self::IdentityAssertion(issuer, hash) => (issuer, hash.as_bytes()),
            Self::IdJagJti(issuer, jti) => (issuer, jti),
        }
    }
    fn length(self, maximum: usize) -> Result<usize, ReplayDigestError> {
        let (issuer, value) = self.fields();
        if issuer.is_empty()
            || issuer.len() > MAX_ISSUER_BYTES
            || issuer.chars().any(char::is_control)
            || value.is_empty()
            || value.len() > MAX_JTI_BYTES
        {
            return Err(ReplayDigestError::InvalidTuple);
        }
        let size = CONTEXT_FRAMING
            .checked_add(issuer.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(ReplayDigestError::InputTooLarge)?;
        if size > maximum {
            return Err(ReplayDigestError::InputTooLarge);
        }
        Ok(size)
    }
    fn encode(self, size: usize) -> Result<Zeroizing<Vec<u8>>, ReplayDigestError> {
        let (issuer, value) = self.fields();
        let mut out = Zeroizing::new(bounded_vec(size)?);
        out.extend_from_slice(CONTEXT_MAGIC);
        out.extend_from_slice(&1_u16.to_be_bytes());
        out.extend_from_slice(&2_u16.to_be_bytes());
        // Frozen v1 registry: tag 1 UTF-8 issuer; tag 2 raw compact-token
        // SHA-256 for purpose 1, or exact jti bytes for purpose 2.
        put_field(&mut out, 1, 0x02, issuer.as_bytes())?;
        put_field(&mut out, 2, 0x01, value)?;
        Ok(out)
    }
}
fn purpose_id(purpose: ReplayPurpose) -> u16 {
    match purpose {
        ReplayPurpose::EnterpriseIdentityAssertionReplay => 1,
        ReplayPurpose::EnterpriseIdJagJtiReplay => 2,
    }
}
fn encode_mac(
    purpose: ReplayPurpose,
    key: &PersistentMacKeyGeneration,
    context: &[u8],
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, ReplayDigestError> {
    let size = MAC_FRAMING
        .checked_add(key.key_id.len())
        .and_then(|n| n.checked_add(context.len()))
        .ok_or(ReplayDigestError::InputTooLarge)?;
    if size > maximum {
        return Err(ReplayDigestError::InputTooLarge);
    }
    let mut out = Zeroizing::new(bounded_vec(size)?);
    out.extend_from_slice(REPLAY_MAGIC);
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&purpose_id(purpose).to_be_bytes());
    put_generation(&mut out, key)?;
    let length = u32::try_from(context.len()).map_err(|_| ReplayDigestError::InputTooLarge)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(context);
    Ok(out)
}
fn alias_set_digest(
    purpose: ReplayPurpose,
    ring: Sha256Digest,
    aliases: &[PersistentReplayAlias],
) -> Result<Sha256Digest, ReplayDigestError> {
    let size = aliases.iter().try_fold(46_usize, |size, alias| {
        size.checked_add(42 + alias.key_id().len())
            .ok_or(ReplayDigestError::InputTooLarge)
    })?;
    let mut bytes = bounded_vec(size)?;
    bytes.extend_from_slice(b"FMCPRAS\0");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&purpose_id(purpose).to_be_bytes());
    bytes.extend_from_slice(ring.as_bytes());
    bytes.extend_from_slice(&(aliases.len() as u16).to_be_bytes());
    for alias in aliases {
        put_generation(&mut bytes, &alias.key)?;
        bytes.extend_from_slice(&alias.tag);
    }
    digest(&bytes)
}
fn check_receipt(
    expected: &PersistentMacReceipt,
    actual: &PersistentMacReceipt,
    success: bool,
) -> Result<(), ReplayDigestError> {
    if expected.operation_id != actual.operation_id
        || expected.provider_digest != actual.provider_digest
        || expected.ring_digest != actual.ring_digest
        || expected.key != actual.key
        || expected.purpose != actual.purpose
        || expected.input_digest != actual.input_digest
    {
        return Err(ReplayDigestError::ReceiptMismatch);
    }
    if success && actual.dispatch != PersistentMacDispatch::Dispatched {
        return Err(ReplayDigestError::ProviderRejected(actual.dispatch));
    }
    Ok(())
}
fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_KEY_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}
fn bounded_vec(size: usize) -> Result<Vec<u8>, ReplayDigestError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| ReplayDigestError::AllocationFailed)?;
    Ok(bytes)
}
fn digest(bytes: &[u8]) -> Result<Sha256Digest, ReplayDigestError> {
    sha256_bounded(bytes, MAX_INPUT_BYTES).map_err(|_| ReplayDigestError::InputTooLarge)
}
fn put_bytes_u16(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ReplayDigestError> {
    let len = u16::try_from(bytes.len()).map_err(|_| ReplayDigestError::InputTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn put_generation(
    out: &mut Vec<u8>,
    key: &PersistentMacKeyGeneration,
) -> Result<(), ReplayDigestError> {
    put_bytes_u16(out, key.key_id.as_bytes())?;
    out.extend_from_slice(&key.generation.to_be_bytes());
    Ok(())
}
fn put_field(out: &mut Vec<u8>, tag: u16, kind: u8, bytes: &[u8]) -> Result<(), ReplayDigestError> {
    let len = u32::try_from(bytes.len()).map_err(|_| ReplayDigestError::InputTooLarge)?;
    out.extend_from_slice(&tag.to_be_bytes());
    out.push(kind);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn with_caller<T>(cx: &Cx, run: impl FnOnce() -> T) -> T {
    let ceiling = ambient_capability_ceiling();
    let _caller = Cx::set_current(Some(cx.clone()));
    let _restriction = Cx::push_restriction(ceiling);
    run()
}
fn require_time(cx: &Cx) -> Result<(), ReplayDigestError> {
    if cx.timer_driver().is_none()
        || !Cx::current().is_some_and(|active| active.capabilities().time)
    {
        return Err(ReplayDigestError::CapabilityUnavailable);
    }
    Ok(())
}
fn checkpoint(cx: &Cx, deadline: Time) -> Result<(), ReplayDigestError> {
    if cx.now() >= deadline
        || cx
            .budget()
            .deadline
            .is_some_and(|parent| cx.now() >= parent)
    {
        return Err(ReplayDigestError::DeadlineExceeded);
    }
    cx.checkpoint().map_err(|_| ReplayDigestError::Cancelled)
}

// Preserve the tightest observed ceiling through provider construction, every
// poll and destruction, including panic, cancellation and owner abandonment.
struct ScopedProvider<'a, T> {
    cx: &'a Cx,
    ceiling: CapMask,
    future: Option<BoxFuture<'a, T>>,
}
impl<T> Future for ScopedProvider<'_, T> {
    type Output = T;
    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<T> {
        let this = self.get_mut();
        this.ceiling = this.ceiling.intersect(ambient_capability_ceiling());
        let _caller = Cx::set_current(Some(this.cx.clone()));
        let _restriction = Cx::push_restriction(this.ceiling);
        this.future
            .as_mut()
            .expect("provider exists until drop")
            .as_mut()
            .poll(task)
    }
}
impl<T> Drop for ScopedProvider<'_, T> {
    fn drop(&mut self) {
        let ceiling = self.ceiling.intersect(ambient_capability_ceiling());
        let _caller = Cx::set_current(Some(self.cx.clone()));
        let _restriction = Cx::push_restriction(ceiling);
        drop(self.future.take());
    }
}
async fn within<'a, T: 'a>(
    process: &ProcessBoundToken,
    cx: &'a Cx,
    deadline: Time,
    factory: impl FnOnce() -> BoxFuture<'a, T>,
) -> Result<T, ReplayDigestError> {
    process
        .verify()
        .map_err(|_| ReplayDigestError::ProcessChanged)?;
    checkpoint(cx, deadline)?;
    let ceiling = ambient_capability_ceiling();
    let future = with_caller(cx, || {
        require_time(cx)?;
        Ok::<_, ReplayDigestError>(factory())
    })?;
    let mut provider = ScopedProvider {
        cx,
        ceiling,
        future: Some(future),
    };
    let mut timer = Sleep::new(deadline);
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancelled = pin!(receiver.recv(cx));
    poll_fn(|task| {
        with_caller(cx, || {
            process
                .verify()
                .map_err(|_| ReplayDigestError::ProcessChanged)?;
            checkpoint(cx, deadline)?;
            require_time(cx)?;
            if cancelled.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(ReplayDigestError::Cancelled));
            }
            if Pin::new(&mut timer).poll(task).is_ready() {
                checkpoint(cx, deadline)?;
                return Poll::Ready(Err(ReplayDigestError::DeadlineExceeded));
            }
            let result = Pin::new(&mut provider).poll(task);
            process
                .verify()
                .map_err(|_| ReplayDigestError::ProcessChanged)?;
            checkpoint(cx, deadline)?;
            result.map(Ok)
        })
    })
    .await
}

#[cfg(test)]
mod tests;
