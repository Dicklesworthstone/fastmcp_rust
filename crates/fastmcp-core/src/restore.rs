//! External restore-authority registration and the live-write intent protocol.
//!
//! A deployment registers its complete store set before obtaining any store
//! handle. Each write then reads the external authority, prepares an intent,
//! commits through the store's durable fence CAS, and completes the SAME intent
//! with the store's receipt. An unfinished fence quarantines the shared facade;
//! dropping a future never means that an external mutation did not happen.
//!
//! This implements the ordinary-write subset of FND-08. Administrative epoch
//! advance, migration, snapshot reconciliation, persistent encryption, and
//! provider qualification are separate, not implemented here. In particular a
//! quarantined facade has no reset or reopen method. Recreating one is safe only
//! if the external authority refuses unresolved/closed registrations as required
//! by its contract. An ordinary database or in-memory implementation is NOT an
//! external rollback/clone authority. The named adapter and its independent
//! persistence service remain part of the deployment's trusted computing base.

use std::collections::BTreeSet;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use asupersync::channel::oneshot;
use asupersync::cx::cap::CapMask;
use asupersync::time::Sleep;
use asupersync::{Cx, Time};

use crate::crypto::{draw_security_identifier, sha256_bounded};
use crate::runtime::{ProcessBoundToken, ProcessGenerationGuard, ambient_capability_ceiling};

#[cfg(test)]
mod tests;

const MAX_IDENTIFIER: usize = 128;
const MAX_BINDING: usize = 128 * 1024;
const MAX_CERTIFICATE: usize = 64 * 1024;
const MAX_COMMIT_PROOF: usize = 16 * 1024;
const MAX_REQUEST: usize = 256 * 1024;

/// Only these three dispositions exist. An error is not proof of no dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreDispatch {
    NotDispatched,
    Dispatched,
    Unknown,
}

/// Fixed diagnostics never retain provider responses, identifiers or proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreError {
    InvalidConfiguration,
    InvalidBinding,
    InvalidReceipt,
    CapacityExceeded,
    CapabilityUnavailable,
    Cancelled,
    DeadlineExceeded,
    ProcessChanged,
    RandomSourceUnavailable,
    ProviderUnavailable,
    Uncertain,
    Quarantined,
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid restore-authority configuration",
            Self::InvalidBinding => "restore binding was refused",
            Self::InvalidReceipt => "restore receipt does not match its operation",
            Self::CapacityExceeded => "restore-authority capacity exhausted",
            Self::CapabilityUnavailable => "restore-authority caller effects are unavailable",
            Self::Cancelled => "restore-authority operation cancelled",
            Self::DeadlineExceeded => "restore-authority deadline exceeded",
            Self::ProcessChanged => "restore-authority process generation changed",
            Self::RandomSourceUnavailable => "restore operation randomness unavailable",
            Self::ProviderUnavailable => "restore authority unavailable",
            Self::Uncertain => "restore mutation disposition is uncertain",
            Self::Quarantined => "restore deployment requires external reconciliation",
        })
    }
}
impl std::error::Error for RestoreError {}

/// The selected certificate mode is itself bound by configuration fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StableCertificateMode {
    Forbidden,
    Required,
}

/// Finite per-deployment limits. There is no hidden queue or worker runtime.
#[derive(Clone, Copy, Debug)]
pub struct RestoreLimits {
    pub stores: usize,
    pub active_calls: usize,
    pub active_reads: usize,
    pub active_intents: usize,
    pub call_timeout: Duration,
    pub observation_freshness: Duration,
    pub intent_lifetime: Duration,
    pub binding_bytes: usize,
    pub certificate_bytes: usize,
}

impl Default for RestoreLimits {
    fn default() -> Self {
        Self {
            stores: 16,
            active_calls: 32,
            active_reads: 2,
            active_intents: 1024,
            call_timeout: Duration::from_secs(10),
            observation_freshness: Duration::from_secs(1),
            intent_lifetime: Duration::from_secs(300),
            binding_bytes: 32 * 1024,
            certificate_bytes: 16 * 1024,
        }
    }
}

impl RestoreLimits {
    fn validate(self) -> Result<(), RestoreError> {
        if !(1..=128).contains(&self.stores)
            || !(1..=256).contains(&self.active_calls)
            || !(1..=16).contains(&self.active_reads)
            || !(1..=16_384).contains(&self.active_intents)
            || !duration_between(self.call_timeout, 60)
            || !duration_between(self.observation_freshness, 30)
            || !duration_between(self.intent_lifetime, 1800)
            || !(256..=MAX_BINDING).contains(&self.binding_bytes)
            || self.certificate_bytes > MAX_CERTIFICATE
            || self.certificate_bytes.checked_add(256).is_none_or(|n| n > self.binding_bytes)
        {
            return Err(RestoreError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Trusted route configuration, not evidence that a provider obeys its contract.
#[derive(Clone)]
pub struct RestoreEpochConfiguration {
    pub authority_id: String,
    pub provider_artifact: String,
    pub provider_artifact_digest: [u8; 32],
    pub configuration_fingerprint: [u8; 32],
    pub authority_generation: u64,
    pub deployment_uuid: [u8; 16],
    pub store_set_generation: u64,
    pub policy_generation: u64,
    pub certificate_mode: StableCertificateMode,
    pub limits: RestoreLimits,
}

impl RestoreEpochConfiguration {
    fn validate(&self) -> Result<(), RestoreError> {
        self.limits.validate()?;
        if !identifier(&self.authority_id)
            || !identifier(&self.provider_artifact)
            || self.authority_generation == 0
            || self.store_set_generation == 0
            || self.policy_generation == 0
            || (self.certificate_mode == StableCertificateMode::Required
                && self.limits.certificate_bytes == 0)
        {
            return Err(RestoreError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// One predeclared store. The namespace identifies its external persistence domain.
#[derive(Clone, PartialEq, Eq)]
pub struct RestoreStoreDeclaration {
    pub id: String,
    pub namespace_digest: [u8; 32],
}

/// Provider-side stable certificate fields. This value is NOT a sealed binding.
/// Only a correlated authority response can produce [`RestoreEpochBinding`].
pub struct CertifiedRestoreEpoch {
    pub authority_id: String,
    pub configuration_fingerprint: [u8; 32],
    pub authority_generation: u64,
    pub deployment_uuid: [u8; 16],
    pub namespace_digest: [u8; 32],
    pub epoch: u128,
    pub stable_certificate: Option<Vec<u8>>,
}

impl CertifiedRestoreEpoch {
    /// Canonical FMCPEPC v1 bytes for an external provider response. This does
    /// not attest the fields or authorize a store operation.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RestoreError> {
        if !identifier(&self.authority_id) || self.authority_generation == 0 || self.epoch == 0
            || self.stable_certificate.as_ref().is_some_and(|c| c.is_empty() || c.len() > MAX_CERTIFICATE)
        {
            return Err(RestoreError::InvalidBinding);
        }
        let size = 12 + 6 * 7 + self.authority_id.len() + 32 + 8 + 16 + 32 + 16
            + self.stable_certificate.as_ref().map_or(0, |c| 7 + c.len());
        if size > MAX_BINDING { return Err(RestoreError::InvalidBinding); }
        let mut out = Vec::new();
        out.try_reserve_exact(size).map_err(|_| RestoreError::CapacityExceeded)?;
        out.extend_from_slice(b"FMCPEPC\0");
        out.extend_from_slice(&1_u16.to_be_bytes());
        out.extend_from_slice(&(if self.stable_certificate.is_some() { 7_u16 } else { 6 }).to_be_bytes());
        field(&mut out, 2, 1, self.authority_id.as_bytes());
        field(&mut out, 1, 2, &self.configuration_fingerprint);
        field(&mut out, 3, 3, &self.authority_generation.to_be_bytes());
        field(&mut out, 1, 4, &self.deployment_uuid);
        field(&mut out, 1, 5, &self.namespace_digest);
        field(&mut out, 4, 6, &self.epoch.to_be_bytes());
        if let Some(certificate) = &self.stable_certificate { field(&mut out, 1, 7, certificate); }
        Ok(out)
    }
}

/// Sealed stable identity. Transient operation IDs, timestamps and receipts are
/// deliberately absent from its digest and canonical certified bytes.
pub struct RestoreEpochBinding {
    digest: [u8; 32],
    epoch: u128,
    namespace: [u8; 32],
}

impl RestoreEpochBinding {
    pub const fn digest(&self) -> [u8; 32] { self.digest }
    pub const fn epoch(&self) -> u128 { self.epoch }
    pub const fn namespace_digest(&self) -> [u8; 32] { self.namespace }
}

/// The closed ordinary-write operations. Administrative operations are not
/// exposed by this subset and cannot be smuggled in through arbitrary bytes.
pub enum RestoreAuthorityOperation {
    RegisterStoreSet { stores: Vec<RestoreStoreDeclaration> },
    Current { store: RestoreStoreDeclaration },
    PrepareWrite {
        store: RestoreStoreDeclaration,
        binding_digest: [u8; 32],
        store_fence_generation: u64,
        record_digest: [u8; 32],
        intent_lifetime: Duration,
    },
    CompleteWrite {
        store: RestoreStoreDeclaration,
        intent_operation_id: [u8; 16],
        receipt: DurableRestoreCommitReceipt,
    },
}

impl RestoreAuthorityOperation {
    fn tag(&self) -> u8 {
        match self { Self::RegisterStoreSet { .. } => 1, Self::Current { .. } => 2,
            Self::PrepareWrite { .. } => 3, Self::CompleteWrite { .. } => 4 }
    }
}

/// Immutable framework request to a preconfigured external authority route.
/// Repeated operation IDs MUST be idempotent only for byte-identical requests.
pub struct RestoreAuthorityRequest {
    operation_id: [u8; 16],
    request_digest: [u8; 32],
    store_set_digest: [u8; 32],
    configuration: Arc<RestoreEpochConfiguration>,
    deadline: Time,
    operation: RestoreAuthorityOperation,
}

impl RestoreAuthorityRequest {
    pub const fn operation_id(&self) -> [u8; 16] { self.operation_id }
    pub const fn request_digest(&self) -> [u8; 32] { self.request_digest }
    pub const fn store_set_digest(&self) -> [u8; 32] { self.store_set_digest }
    pub fn configuration(&self) -> &RestoreEpochConfiguration { &self.configuration }
    pub const fn deadline(&self) -> Time { self.deadline }
    pub fn operation(&self) -> &RestoreAuthorityOperation { &self.operation }
}

/// Bounded provider output; its certificate bytes remain untrusted until parsed.
pub enum RestoreAuthorityOutcome {
    Registered { store_set_digest: [u8; 32] },
    Current { certified_binding: Vec<u8>, store_fence_generation: u64 },
    Prepared { binding_digest: [u8; 32], store_fence_generation: u64 },
    Completed { intent_operation_id: [u8; 16], commit_digest: [u8; 32] },
}

pub struct RestoreAuthorityResponse {
    pub operation_id: [u8; 16],
    pub request_digest: [u8; 32],
    pub dispatch: RestoreDispatch,
    pub outcome: RestoreAuthorityOutcome,
}

impl RestoreAuthorityResponse {
    /// Adapter convenience, not an attestation or an authorization constructor.
    pub fn for_request(request: &RestoreAuthorityRequest, outcome: RestoreAuthorityOutcome) -> Self {
        Self { operation_id: request.operation_id, request_digest: request.request_digest,
            dispatch: RestoreDispatch::Dispatched, outcome }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RestoreAuthorityFailure {
    pub dispatch: RestoreDispatch,
}

pub type RestoreAuthorityFuture<'a> = Pin<Box<dyn Future<Output = Result<RestoreAuthorityResponse, RestoreAuthorityFailure>> + Send + 'a>>;

/// Implemented by a named external, independently persistent authority adapter.
///
/// Registration atomically admits the EXACT complete store set, fails on an
/// unresolved previous operation/closed deployment, and never silently resets
/// an epoch. Current reads and all mutations are durably linearized across all
/// writers. Prepare persists its intent before returning; completion verifies
/// the exact durable store CAS/commit proof before settling that intent. The
/// authority must retain uncertain intents across crashes and refuse epoch
/// advance until they have been reconciled. Operations and Drop must not block
/// the caller's executor; any offloaded work retains its own admission until
/// settlement. No provider endpoint, clock or retry policy comes from token data.
///
/// A truthful implementation and its external failure domain are deployment
/// requirements, not properties Rust can prove by checking these receipts.
pub trait RestoreEpochAuthority: Send + Sync + 'static {
    fn execute<'a>(&'a self, cx: &'a Cx, request: &'a RestoreAuthorityRequest) -> RestoreAuthorityFuture<'a>;
}

struct Shared {
    configuration: Arc<RestoreEpochConfiguration>,
    backend: Arc<dyn RestoreEpochAuthority>,
    store_set_digest: [u8; 32],
    process: ProcessBoundToken,
    quarantined: AtomicBool,
    calls: AtomicUsize,
    reads: AtomicUsize,
    intents: AtomicUsize,
}

/// Registered deployment. Store handles cannot be added after construction.
pub struct RestoreEpochFacade {
    stores: Vec<RegisteredRestoreStore>,
}

impl RestoreEpochFacade {
    pub async fn register(
        cx: &Cx,
        configuration: RestoreEpochConfiguration,
        mut stores: Vec<RestoreStoreDeclaration>,
        backend: Arc<dyn RestoreEpochAuthority>,
        deadline: Time,
    ) -> Result<Self, RestoreError> {
        configuration.validate()?;
        if stores.is_empty() || stores.len() > configuration.limits.stores {
            return Err(RestoreError::InvalidConfiguration);
        }
        stores.sort_by(|a, b| a.id.cmp(&b.id));
        let mut namespaces = BTreeSet::new();
        for (index, store) in stores.iter().enumerate() {
            if !identifier(&store.id) || (index > 0 && stores[index - 1].id == store.id)
                || !namespaces.insert(store.namespace_digest)
            { return Err(RestoreError::InvalidConfiguration); }
        }
        let mut encoded = b"FMCPRSS\0\0\x01".to_vec();
        encoded.extend_from_slice(&configuration.store_set_generation.to_be_bytes());
        encoded.extend_from_slice(&(stores.len() as u16).to_be_bytes());
        for store in &stores { encode_store(&mut encoded, store); }
        let store_set_digest = hash(&encoded)?;
        let process = ProcessGenerationGuard::installed().ok_or(RestoreError::ProcessChanged)?.token();
        process.verify().map_err(|_| RestoreError::ProcessChanged)?;
        let shared = Arc::new(Shared {
            configuration: Arc::new(configuration), backend, store_set_digest, process,
            quarantined: AtomicBool::new(false), calls: AtomicUsize::new(0),
            reads: AtomicUsize::new(0), intents: AtomicUsize::new(0),
        });
        let request = shared.request(cx, RestoreAuthorityOperation::RegisterStoreSet { stores: stores.clone() }, deadline)?;
        let mut uncertain = UncertainMutation::new(Arc::clone(&shared));
        let response = shared.call(cx, &request, Some(&mut uncertain)).await?;
        match response.outcome {
            RestoreAuthorityOutcome::Registered { store_set_digest: echoed } if echoed == store_set_digest => {}
            _ => return Err(RestoreError::InvalidReceipt),
        }
        uncertain.settled = true;
        Ok(Self { stores: stores.into_iter().map(|declaration| RegisteredRestoreStore {
            shared: Arc::clone(&shared), declaration: Arc::new(declaration),
            stable: Arc::new(Mutex::new(None)),
        }).collect() })
    }

    pub fn store(&self, id: &str) -> Option<RegisteredRestoreStore> {
        self.stores.binary_search_by(|store| store.declaration.id.as_str().cmp(id))
            .ok().map(|index| self.stores[index].clone())
    }

    pub fn is_quarantined(&self) -> bool { self.stores[0].is_quarantined() }
}

/// One member of the atomically registered store union. Clones share quarantine,
/// admission and the pinned stable binding; they do not create a new namespace.
#[derive(Clone)]
pub struct RegisteredRestoreStore {
    shared: Arc<Shared>,
    declaration: Arc<RestoreStoreDeclaration>,
    stable: Arc<Mutex<Option<([u8; 32], u128)>>>,
}

impl RegisteredRestoreStore {
    pub fn store_id(&self) -> &str { &self.declaration.id }
    pub fn namespace_digest(&self) -> [u8; 32] { self.declaration.namespace_digest }
    pub fn store_set_digest(&self) -> [u8; 32] { self.shared.store_set_digest }
    pub fn configuration(&self) -> &RestoreEpochConfiguration { &self.shared.configuration }
    pub fn is_quarantined(&self) -> bool { self.shared.quarantined.load(Ordering::Acquire) }

    /// Read and independently admit the exact certified epoch. No provider
    /// timestamp establishes freshness; the received instant stays transient.
    async fn current(&self, cx: &Cx, deadline: Time) -> Result<(RestoreEpochBinding, u64, Time), RestoreError> {
        let _read = CounterLease::acquire(&self.shared.reads, self.shared.configuration.limits.active_reads)?;
        let request = self.shared.request(cx, RestoreAuthorityOperation::Current { store: (*self.declaration).clone() }, deadline)?;
        let response = self.shared.call(cx, &request, None).await?;
        let (bytes, generation) = match response.outcome {
            RestoreAuthorityOutcome::Current { certified_binding, store_fence_generation } if store_fence_generation != 0 => (certified_binding, store_fence_generation),
            _ => { self.shared.quarantine(); return Err(RestoreError::InvalidReceipt); }
        };
        let binding = parse_binding(&bytes, &self.shared.configuration, &self.declaration)
            .inspect_err(|_| self.shared.quarantine())?;
        let mut pinned = self.stable.lock().map_err(|_| { self.shared.quarantine(); RestoreError::Quarantined })?;
        if pinned.as_ref().is_some_and(|old| old.0 != binding.digest || old.1 != binding.epoch) {
            self.shared.quarantine();
            return Err(RestoreError::Quarantined);
        }
        *pinned = Some((binding.digest, binding.epoch));
        Ok((binding, generation, cx.now()))
    }

    /// Register a durable intent BEFORE dispatching a store mutation. The
    /// caller must commit the returned operation ID, record digest and fence
    /// generation atomically with its own durable restore-fence CAS.
    pub async fn prepare_write(&self, cx: &Cx, record_digest: [u8; 32], deadline: Time) -> Result<RestoreWriteFence, RestoreError> {
        self.shared.check()?;
        let intent = OwnedIntentLease::acquire(Arc::clone(&self.shared))?;
        let (binding, generation, observed_at) = self.current(cx, deadline).await?;
        let fresh_until = add_time(observed_at, self.shared.configuration.limits.observation_freshness)?;
        let expires_at = add_time(cx.now(), self.shared.configuration.limits.intent_lifetime)?;
        let request = self.shared.request(cx, RestoreAuthorityOperation::PrepareWrite {
            store: (*self.declaration).clone(), binding_digest: binding.digest,
            store_fence_generation: generation, record_digest,
            intent_lifetime: self.shared.configuration.limits.intent_lifetime,
        }, deadline.min(fresh_until).min(expires_at))?;
        let mut uncertain = UncertainMutation::new(Arc::clone(&self.shared));
        let response = self.shared.call(cx, &request, Some(&mut uncertain)).await?;
        match response.outcome {
            RestoreAuthorityOutcome::Prepared { binding_digest, store_fence_generation }
                if binding_digest == binding.digest && store_fence_generation == generation => {}
            _ => return Err(RestoreError::InvalidReceipt),
        }
        let fence = RestoreWriteFence {
            store: self.clone(), binding, operation_id: request.operation_id,
            generation, record_digest, expires_at, settled: false, _intent: intent,
        };
        uncertain.settled = true;
        Ok(fence)
    }

    /// Admit the store's durable commit proof, then settle the exact authority
    /// intent. A timeout or malformed receipt retains the intent externally and
    /// quarantines this deployment; it never releases a replay reservation.
    pub async fn complete_write(&self, cx: &Cx, mut fence: RestoreWriteFence, receipt: DurableRestoreCommitReceipt, deadline: Time) -> Result<CompletedRestoreWrite, RestoreError> {
        self.shared.check()?;
        if !Arc::ptr_eq(&self.shared, &fence.store.shared)
            || self.declaration.as_ref() != fence.store.declaration.as_ref()
            || receipt.operation_id != fence.operation_id
            || receipt.binding_digest != fence.binding.digest
            || receipt.fence_generation != fence.generation
            || receipt.record_digest != fence.record_digest
        { return Err(RestoreError::InvalidReceipt); }
        let commit_digest = receipt.commit_digest;
        let request = self.shared.request(cx, RestoreAuthorityOperation::CompleteWrite {
            store: (*self.declaration).clone(), intent_operation_id: fence.operation_id, receipt,
        }, deadline.min(fence.expires_at))?;
        let mut uncertain = UncertainMutation::new(Arc::clone(&self.shared));
        let response = self.shared.call(cx, &request, Some(&mut uncertain)).await?;
        match response.outcome {
            RestoreAuthorityOutcome::Completed { intent_operation_id, commit_digest: echoed }
                if intent_operation_id == fence.operation_id && echoed == commit_digest => {}
            _ => return Err(RestoreError::InvalidReceipt),
        }
        uncertain.settled = true;
        fence.settled = true;
        Ok(CompletedRestoreWrite { operation_id: fence.operation_id,
            binding_digest: fence.binding.digest, commit_digest })
    }
}

/// Non-Clone write intent. Dropping it without a correlated completion closes
/// the entire registered deployment to new writes. Its external intent persists.
#[must_use = "an unresolved write fence requires external reconciliation"]
pub struct RestoreWriteFence {
    store: RegisteredRestoreStore,
    binding: RestoreEpochBinding,
    operation_id: [u8; 16],
    generation: u64,
    record_digest: [u8; 32],
    expires_at: Time,
    settled: bool,
    _intent: OwnedIntentLease,
}

impl RestoreWriteFence {
    pub const fn operation_id(&self) -> [u8; 16] { self.operation_id }
    pub const fn binding_digest(&self) -> [u8; 32] { self.binding.digest }
    pub const fn store_fence_generation(&self) -> u64 { self.generation }
    pub fn store_set_digest(&self) -> [u8; 32] { self.store.store_set_digest() }
    pub fn namespace_digest(&self) -> [u8; 32] { self.store.namespace_digest() }
    pub fn store_id(&self) -> &str { self.store.store_id() }
    pub const fn record_digest(&self) -> [u8; 32] { self.record_digest }
    pub const fn expires_at(&self) -> Time { self.expires_at }
}

impl Drop for RestoreWriteFence {
    fn drop(&mut self) { if !self.settled { self.store.shared.quarantine(); } }
}

/// Untrusted external store evidence. Construction only checks size/shape;
/// authority completion must verify the real durable transaction proof.
pub struct DurableRestoreCommitReceipt {
    operation_id: [u8; 16],
    binding_digest: [u8; 32],
    fence_generation: u64,
    record_digest: [u8; 32],
    commit_digest: [u8; 32],
    proof: Vec<u8>,
}

impl DurableRestoreCommitReceipt {
    pub fn new(operation_id: [u8; 16], binding_digest: [u8; 32], fence_generation: u64,
        record_digest: [u8; 32], commit_digest: [u8; 32], proof: Vec<u8>) -> Result<Self, RestoreError> {
        if fence_generation == 0 || proof.is_empty() || proof.len() > MAX_COMMIT_PROOF {
            return Err(RestoreError::InvalidReceipt);
        }
        Ok(Self { operation_id, binding_digest, fence_generation, record_digest, commit_digest, proof })
    }
    pub const fn operation_id(&self) -> [u8; 16] { self.operation_id }
    pub const fn binding_digest(&self) -> [u8; 32] { self.binding_digest }
    pub const fn store_fence_generation(&self) -> u64 { self.fence_generation }
    pub const fn record_digest(&self) -> [u8; 32] { self.record_digest }
    pub const fn commit_digest(&self) -> [u8; 32] { self.commit_digest }
    pub fn proof(&self) -> &[u8] { &self.proof }
}

/// Returned only after both the store commit and authority settlement correlate.
pub struct CompletedRestoreWrite {
    operation_id: [u8; 16],
    binding_digest: [u8; 32],
    commit_digest: [u8; 32],
}

impl CompletedRestoreWrite {
    pub const fn operation_id(&self) -> [u8; 16] { self.operation_id }
    pub const fn binding_digest(&self) -> [u8; 32] { self.binding_digest }
    pub const fn commit_digest(&self) -> [u8; 32] { self.commit_digest }
}

impl Shared {
    fn quarantine(&self) { self.quarantined.store(true, Ordering::Release); }
    fn check(&self) -> Result<(), RestoreError> {
        self.process.verify().map_err(|_| RestoreError::ProcessChanged)?;
        if self.quarantined.load(Ordering::Acquire) { Err(RestoreError::Quarantined) } else { Ok(()) }
    }

    fn request(&self, cx: &Cx, operation: RestoreAuthorityOperation, deadline: Time) -> Result<RestoreAuthorityRequest, RestoreError> {
        self.check()?;
        let deadline = with_caller(cx, || {
            let active = Cx::current().ok_or(RestoreError::CapabilityUnavailable)?;
            require_caller(&active)?;
            active.checkpoint().map_err(|_| RestoreError::Cancelled)?;
            let deadline = deadline.min(add_time(active.now(), self.configuration.limits.call_timeout)?);
            let deadline = active.budget().deadline.map_or(deadline, |parent| parent.min(deadline));
            if active.now() >= deadline { return Err(RestoreError::DeadlineExceeded); }
            Ok(deadline)
        })?;
        let id = with_caller(cx, || draw_security_identifier().map_err(|_| RestoreError::RandomSourceUnavailable))?;
        let mut operation_id = [0; 16];
        operation_id.copy_from_slice(&id.as_bytes()[..16]);
        let mut bytes = b"FMCPROP\0\0\x01".to_vec();
        bytes.extend_from_slice(&operation_id);
        encode_bytes(&mut bytes, self.configuration.authority_id.as_bytes());
        encode_bytes(&mut bytes, self.configuration.provider_artifact.as_bytes());
        bytes.extend_from_slice(&self.configuration.provider_artifact_digest);
        bytes.extend_from_slice(&self.configuration.configuration_fingerprint);
        bytes.extend_from_slice(&self.configuration.authority_generation.to_be_bytes());
        bytes.extend_from_slice(&self.configuration.deployment_uuid);
        bytes.extend_from_slice(&self.configuration.store_set_generation.to_be_bytes());
        bytes.extend_from_slice(&self.configuration.policy_generation.to_be_bytes());
        bytes.extend_from_slice(&self.store_set_digest);
        bytes.extend_from_slice(&deadline.as_nanos().to_be_bytes());
        bytes.push(operation.tag());
        match &operation {
            RestoreAuthorityOperation::RegisterStoreSet { stores } => {
                bytes.extend_from_slice(&(stores.len() as u16).to_be_bytes());
                for store in stores { encode_store(&mut bytes, store); }
            }
            RestoreAuthorityOperation::Current { store } => encode_store(&mut bytes, store),
            RestoreAuthorityOperation::PrepareWrite { store, binding_digest, store_fence_generation, record_digest, intent_lifetime } => {
                encode_store(&mut bytes, store); bytes.extend_from_slice(binding_digest);
                bytes.extend_from_slice(&store_fence_generation.to_be_bytes());
                bytes.extend_from_slice(record_digest);
                bytes.extend_from_slice(&intent_lifetime.as_nanos().to_be_bytes());
            }
            RestoreAuthorityOperation::CompleteWrite { store, intent_operation_id, receipt } => {
                encode_store(&mut bytes, store); bytes.extend_from_slice(intent_operation_id);
                bytes.extend_from_slice(&receipt.operation_id); bytes.extend_from_slice(&receipt.binding_digest);
                bytes.extend_from_slice(&receipt.fence_generation.to_be_bytes());
                bytes.extend_from_slice(&receipt.record_digest); bytes.extend_from_slice(&receipt.commit_digest);
                encode_bytes(&mut bytes, &receipt.proof);
            }
        }
        let request_digest = hash(&bytes)?;
        Ok(RestoreAuthorityRequest { operation_id, request_digest, store_set_digest: self.store_set_digest,
            configuration: Arc::clone(&self.configuration), deadline, operation })
    }

    async fn call(&self, cx: &Cx, request: &RestoreAuthorityRequest, mut uncertain: Option<&mut UncertainMutation>) -> Result<RestoreAuthorityResponse, RestoreError> {
        self.check()?;
        let _lease = CounterLease::acquire(&self.calls, self.configuration.limits.active_calls)?;
        let caller = with_caller(cx, || {
            let current = Cx::current().ok_or(RestoreError::CapabilityUnavailable)?;
            require_caller(&current)?;
            current.checkpoint().map_err(|_| RestoreError::Cancelled)?;
            if current.now() >= request.deadline { return Err(RestoreError::DeadlineExceeded); }
            Ok(current)
        })?;
        // Arm before even constructing a provider future: adapters may perform
        // effects during construction. NotDispatched is the only safe disarm.
        if let Some(guard) = &mut uncertain { guard.armed = true; }
        let future = with_caller(&caller, || self.backend.execute(&caller, request));
        let result = within(self, &caller, request.deadline, future).await?;
        match result {
            Err(failure) => {
                if failure.dispatch == RestoreDispatch::NotDispatched {
                    if let Some(guard) = &mut uncertain { guard.settled = true; }
                    Err(RestoreError::ProviderUnavailable)
                } else { Err(RestoreError::Uncertain) }
            }
            Ok(response) => {
                if response.operation_id != request.operation_id || response.request_digest != request.request_digest {
                    self.quarantine(); return Err(RestoreError::InvalidReceipt);
                }
                if response.dispatch != RestoreDispatch::Dispatched { return Err(RestoreError::Uncertain); }
                self.check()?;
                Ok(response)
            }
        }
    }
}

struct UncertainMutation { shared: Arc<Shared>, armed: bool, settled: bool }
impl UncertainMutation {
    fn new(shared: Arc<Shared>) -> Self { Self { shared, armed: false, settled: false } }
}
impl Drop for UncertainMutation {
    fn drop(&mut self) { if self.armed && !self.settled { self.shared.quarantine(); } }
}

struct CounterLease<'a> { counter: &'a AtomicUsize }
impl<'a> CounterLease<'a> {
    fn acquire(counter: &'a AtomicUsize, maximum: usize) -> Result<Self, RestoreError> {
        counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < maximum).then_some(n + 1))
            .map_err(|_| RestoreError::CapacityExceeded)?;
        Ok(Self { counter })
    }
}
impl Drop for CounterLease<'_> { fn drop(&mut self) { self.counter.fetch_sub(1, Ordering::AcqRel); } }
struct OwnedIntentLease { shared: Arc<Shared> }
impl OwnedIntentLease {
    fn acquire(shared: Arc<Shared>) -> Result<Self, RestoreError> {
        let maximum = shared.configuration.limits.active_intents;
        shared.intents.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < maximum).then_some(n + 1))
            .map_err(|_| RestoreError::CapacityExceeded)?;
        Ok(Self { shared })
    }
}
impl Drop for OwnedIntentLease { fn drop(&mut self) { self.shared.intents.fetch_sub(1, Ordering::AcqRel); } }

fn parse_binding(bytes: &[u8], config: &RestoreEpochConfiguration, store: &RestoreStoreDeclaration) -> Result<RestoreEpochBinding, RestoreError> {
    if bytes.len() > config.limits.binding_bytes || bytes.get(..10) != Some(b"FMCPEPC\0\0\x01".as_slice()) {
        return Err(RestoreError::InvalidBinding);
    }
    let expected_count = if config.certificate_mode == StableCertificateMode::Required { 7_u16 } else { 6 };
    if bytes.get(10..12) != Some(expected_count.to_be_bytes().as_slice()) { return Err(RestoreError::InvalidBinding); }
    let mut offset = 12_usize;
    let mut epoch = 0;
    for tag in 1..=expected_count {
        let header = bytes.get(offset..offset.checked_add(7).ok_or(RestoreError::InvalidBinding)?)
            .ok_or(RestoreError::InvalidBinding)?;
        let expected_type = match tag { 1 => 2, 3 => 3, 6 => 4, _ => 1 };
        if header[0] != expected_type || header[1..3] != tag.to_be_bytes() { return Err(RestoreError::InvalidBinding); }
        let length = u32::from_be_bytes(header[3..7].try_into().map_err(|_| RestoreError::InvalidBinding)?) as usize;
        offset += 7;
        let end = offset.checked_add(length).ok_or(RestoreError::InvalidBinding)?;
        let value = bytes.get(offset..end).ok_or(RestoreError::InvalidBinding)?;
        let valid = match tag {
            1 => value == config.authority_id.as_bytes(),
            2 => value == config.configuration_fingerprint,
            3 => value == config.authority_generation.to_be_bytes(),
            4 => value == config.deployment_uuid,
            5 => value == store.namespace_digest,
            6 => {
                epoch = u128::from_be_bytes(value.try_into().map_err(|_| RestoreError::InvalidBinding)?);
                epoch != 0
            }
            7 => !value.is_empty() && value.len() <= config.limits.certificate_bytes,
            _ => false,
        };
        if !valid { return Err(RestoreError::InvalidBinding); }
        offset = end;
    }
    if offset != bytes.len() { return Err(RestoreError::InvalidBinding); }
    let digest = sha256_bounded(bytes, config.limits.binding_bytes).map_err(|_| RestoreError::InvalidBinding)?;
    Ok(RestoreEpochBinding { digest: *digest.as_bytes(), epoch, namespace: store.namespace_digest })
}

fn duration_between(duration: Duration, maximum_seconds: u64) -> bool {
    !duration.is_zero() && duration <= Duration::from_secs(maximum_seconds)
}
fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDENTIFIER && !value.chars().any(|c| c.is_control() || c.is_whitespace())
}
fn field(out: &mut Vec<u8>, kind: u8, tag: u16, value: &[u8]) {
    out.push(kind); out.extend_from_slice(&tag.to_be_bytes()); encode_bytes(out, value);
}
fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes()); out.extend_from_slice(bytes);
}
fn encode_store(out: &mut Vec<u8>, store: &RestoreStoreDeclaration) {
    encode_bytes(out, store.id.as_bytes()); out.extend_from_slice(&store.namespace_digest);
}
fn hash(bytes: &[u8]) -> Result<[u8; 32], RestoreError> {
    sha256_bounded(bytes, MAX_REQUEST).map(|digest| *digest.as_bytes()).map_err(|_| RestoreError::InvalidConfiguration)
}
fn add_time(time: Time, duration: Duration) -> Result<Time, RestoreError> {
    let nanos = u64::try_from(duration.as_nanos()).map_err(|_| RestoreError::DeadlineExceeded)?;
    time.as_nanos().checked_add(nanos).map(Time::from_nanos).ok_or(RestoreError::DeadlineExceeded)
}
fn with_caller<T>(cx: &Cx, action: impl FnOnce() -> T) -> T {
    let ceiling = ambient_capability_ceiling();
    let _caller = Cx::set_current(Some(cx.clone()));
    let _restriction = Cx::push_restriction(ceiling);
    action()
}
fn require_caller(cx: &Cx) -> Result<(), RestoreError> {
    let effects = cx.capabilities();
    if !effects.time || !effects.entropy || !effects.io || !effects.remote || cx.timer_driver().is_none() {
        return Err(RestoreError::CapabilityUnavailable);
    }
    Ok(())
}

// Keep provider destruction under the same non-widening caller ceiling too.
struct CallerFuture<'a, F> { cx: &'a Cx, ceiling: CapMask, future: Option<Pin<Box<F>>> }
impl<F> Drop for CallerFuture<'_, F> {
    fn drop(&mut self) {
        let ceiling = self.ceiling.intersect(ambient_capability_ceiling());
        let _caller = Cx::set_current(Some(self.cx.clone()));
        let _restriction = Cx::push_restriction(ceiling);
        drop(self.future.take());
    }
}

async fn within<F: Future>(shared: &Shared, cx: &Cx, deadline: Time, future: F) -> Result<F::Output, RestoreError> {
    let mut future = CallerFuture { cx, ceiling: ambient_capability_ceiling(), future: Some(Box::pin(future)) };
    let mut sleep = std::pin::pin!(Sleep::new(deadline));
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancelled = std::pin::pin!(receiver.recv(cx));
    poll_fn(|task| {
        future.ceiling = future.ceiling.intersect(ambient_capability_ceiling());
        let _caller = Cx::set_current(Some(cx.clone()));
        let _restriction = Cx::push_restriction(future.ceiling);
        let active = Cx::current().ok_or(RestoreError::CapabilityUnavailable)?;
        shared.check()?;
        require_caller(&active)?;
        active.checkpoint().map_err(|_| RestoreError::Cancelled)?;
        if active.now() >= deadline { return Poll::Ready(Err(RestoreError::DeadlineExceeded)); }
        if cancelled.as_mut().poll(task).is_ready() { return Poll::Ready(Err(RestoreError::Cancelled)); }
        if sleep.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(if active.is_cancel_requested() { RestoreError::Cancelled } else { RestoreError::DeadlineExceeded }));
        }
        let result = future.future.as_mut().expect("provider future is owned").as_mut().poll(task);
        shared.check()?;
        if active.is_cancel_requested() { return Poll::Ready(Err(RestoreError::Cancelled)); }
        if active.now() >= deadline { return Poll::Ready(Err(RestoreError::DeadlineExceeded)); }
        result.map(Ok)
    }).await
}
