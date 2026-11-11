//! Bounded recovery of the ordinary write protocol.
//!
//! This is an operator consumer of the registered deployment, not an epoch
//! advance or an administrative restore permit. It permanently retires the old
//! handles, scans an immutable authority snapshot, and reconciles the original
//! persisted operation IDs using independent store evidence. Snapshot completion
//! alone never authorizes reopening: a fresh RegisterStoreSet must atomically
//! refuse every unresolved or closed operation, including newer concurrent writes.
//!
//! Provider constructors describe untrusted evidence. External durable
//! linearization, snapshot retention and proof verification remain obligations
//! of the named authority/store adapters and their independent persistence.

use super::{
    Arc, BTreeSet, CallAccess, CounterLease, Cx, DurableRestoreCommitReceipt, Duration, Future,
    InitialAdmission, MAX_COMMIT_PROOF, Ordering, Pin, RegisteredRestoreStore,
    RestoreAuthorityOperation, RestoreAuthorityOutcome, RestoreDispatch, RestoreEpochAuthority,
    RestoreEpochBinding, RestoreEpochConfiguration, RestoreEpochFacade, RestoreError,
    RestoreStoreDeclaration, RestoreWriteFence, Shared, Time, UncertainMutation, add_time,
    duration_between, encode_bytes, encode_store, hash, require_caller, with_caller,
    with_operation_caller, within_access,
};

#[cfg(test)]
mod tests;

/// Independent limits for page size, snapshot lifetime and total recovery work.
/// There is no unbounded drain, background worker or implicit retry.
#[derive(Clone, Copy, Debug)]
pub struct RestoreRecoveryLimits {
    pub page_items: usize,
    pub page_bytes: usize,
    pub cursor_bytes: usize,
    pub cursor_lifetime: Duration,
    pub scan_deadline: Duration,
    pub backlog: usize,
    pub reconciliations_per_minute: usize,
    pub active_snapshots: usize,
    pub retained_snapshot_bytes: usize,
}

impl Default for RestoreRecoveryLimits {
    fn default() -> Self {
        Self {
            page_items: 256,
            page_bytes: 4 * 1024 * 1024,
            cursor_bytes: 4 * 1024,
            cursor_lifetime: Duration::from_secs(300),
            scan_deadline: Duration::from_secs(300),
            backlog: 1024,
            reconciliations_per_minute: 1000,
            active_snapshots: 4,
            retained_snapshot_bytes: 16 * 1024 * 1024,
        }
    }
}

impl RestoreRecoveryLimits {
    fn validate(self) -> Result<(), RestoreError> {
        if !(1..=4096).contains(&self.page_items)
            || !(256..=32 * 1024 * 1024).contains(&self.page_bytes)
            || !(1..=64 * 1024).contains(&self.cursor_bytes)
            || !duration_between(self.cursor_lifetime, 1800)
            || !duration_between(self.scan_deadline, 1800)
            || !(1..=16_384).contains(&self.backlog)
            || !(1..=10_000).contains(&self.reconciliations_per_minute)
            || !(1..=32).contains(&self.active_snapshots)
            || !(256..=128 * 1024 * 1024).contains(&self.retained_snapshot_bytes)
        {
            return Err(RestoreError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Provider-supplied intent metadata. Only a validated snapshot can admit this
/// into the sealed request passed to an independent store recovery adapter.
#[derive(Clone)]
pub struct RestoreUnresolvedWrite {
    pub intent_generation: u64,
    pub operation_id: [u8; 16],
    pub store: RestoreStoreDeclaration,
    pub binding_digest: [u8; 32],
    pub store_fence_generation: u64,
    pub record_digest: [u8; 32],
}

/// An authority snapshot page, ordered by (intent_generation, operation_id).
/// A terminal page has no continuation. Empty nonterminal pages are refused.
/// Providers must apply the requested byte/item limits while decoding the wire.
pub struct RestoreUnresolvedPage {
    pub snapshot_id: [u8; 16],
    pub high_water_generation: u64,
    pub writes: Vec<RestoreUnresolvedWrite>,
    pub next_cursor: Option<Vec<u8>>,
}

/// A tuple in the immutable snapshot ordering; it grants no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RestoreIntentPosition {
    pub generation: u64,
    pub operation_id: [u8; 16],
}

/// Nonconstructible, nonserializable local scan identity. Provider continuation
/// bytes must authenticate these SAME facts, not merely a database row offset.
pub struct RestoreScanBinding {
    configuration: Arc<RestoreEpochConfiguration>,
    store_set_digest: [u8; 32],
    scan_operation_id: [u8; 16],
    snapshot_id: [u8; 16],
    high_water_generation: u64,
    last: Option<RestoreIntentPosition>,
    expires_at: Time,
    limits: RestoreRecoveryLimits,
}

impl RestoreScanBinding {
    pub fn configuration(&self) -> &RestoreEpochConfiguration {
        &self.configuration
    }
    pub const fn store_set_digest(&self) -> [u8; 32] {
        self.store_set_digest
    }
    pub const fn scan_operation_id(&self) -> [u8; 16] {
        self.scan_operation_id
    }
    pub const fn snapshot_id(&self) -> [u8; 16] {
        self.snapshot_id
    }
    pub const fn high_water_generation(&self) -> u64 {
        self.high_water_generation
    }
    pub const fn last_position(&self) -> Option<RestoreIntentPosition> {
        self.last
    }
    pub const fn expires_at(&self) -> Time {
        self.expires_at
    }
    pub const fn limits(&self) -> RestoreRecoveryLimits {
        self.limits
    }
}

/// Opaque, provider-issued continuation bound to the admitted local snapshot.
/// There is deliberately no constructor, Clone or serialization implementation.
pub struct RestoreIntentCursor {
    bytes: Vec<u8>,
    binding: Arc<RestoreScanBinding>,
}

impl RestoreIntentCursor {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn binding(&self) -> &RestoreScanBinding {
        &self.binding
    }
}

/// Sealed correlation for one exact persisted intent. An adapter can inspect
/// every field necessary to query its durable journal without forging a handle.
pub struct RestoreReconcileIntent {
    store: RestoreStoreDeclaration,
    operation_id: [u8; 16],
    binding_digest: [u8; 32],
    fence_generation: u64,
    record_digest: [u8; 32],
    position: Option<RestoreIntentPosition>,
    snapshot: Option<Arc<RestoreScanBinding>>,
}

impl RestoreReconcileIntent {
    pub fn store(&self) -> &RestoreStoreDeclaration {
        &self.store
    }
    pub fn store_id(&self) -> &str {
        &self.store.id
    }
    pub const fn namespace_digest(&self) -> [u8; 32] {
        self.store.namespace_digest
    }
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }
    pub const fn binding_digest(&self) -> [u8; 32] {
        self.binding_digest
    }
    pub const fn store_fence_generation(&self) -> u64 {
        self.fence_generation
    }
    pub const fn record_digest(&self) -> [u8; 32] {
        self.record_digest
    }
    pub const fn position(&self) -> Option<RestoreIntentPosition> {
        self.position
    }
    /// None only for reconciliation of a still-owned live write fence.
    pub fn snapshot(&self) -> Option<&RestoreScanBinding> {
        self.snapshot.as_deref()
    }
}

/// Untrusted evidence of a durable terminal noncommit. A store must atomically
/// fence out the original generation and retain the exact operation's terminal
/// result before constructing this value. Absence, timeout, an expired lease,
/// or a CAS-conflict string cannot authorize this outcome.
pub struct DurableRestoreNonCommitReceipt {
    operation_id: [u8; 16],
    binding_digest: [u8; 32],
    fence_generation: u64,
    record_digest: [u8; 32],
    fenced_generation: u64,
    proof: Vec<u8>,
}

impl DurableRestoreNonCommitReceipt {
    pub fn new(
        operation_id: [u8; 16],
        binding_digest: [u8; 32],
        store_fence_generation: u64,
        record_digest: [u8; 32],
        fenced_generation: u64,
        proof: Vec<u8>,
    ) -> Result<Self, RestoreError> {
        if store_fence_generation == 0
            || fenced_generation <= store_fence_generation
            || proof.is_empty()
            || proof.len() > MAX_COMMIT_PROOF
        {
            return Err(RestoreError::InvalidReceipt);
        }
        Ok(Self {
            operation_id,
            binding_digest,
            fence_generation: store_fence_generation,
            record_digest,
            fenced_generation,
            proof,
        })
    }
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }
    pub const fn binding_digest(&self) -> [u8; 32] {
        self.binding_digest
    }
    pub const fn store_fence_generation(&self) -> u64 {
        self.fence_generation
    }
    pub const fn record_digest(&self) -> [u8; 32] {
        self.record_digest
    }
    pub const fn fenced_generation(&self) -> u64 {
        self.fenced_generation
    }
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
}

/// The closed store outcomes. There is no "not found therefore aborted" variant.
pub enum DurableRestoreResolution {
    Committed(DurableRestoreCommitReceipt),
    FencedNotCommitted(DurableRestoreNonCommitReceipt),
}

impl DurableRestoreResolution {
    /// Canonical correlation digest for an authority response. Computing it does
    /// not validate durable evidence; that is the authority adapter's obligation.
    pub fn digest(&self) -> Result<[u8; 32], RestoreError> {
        let mut encoded = b"FMCPRSL\0\0\x01".to_vec();
        encode_resolution(&mut encoded, self);
        hash(&encoded)
    }

    fn matches(&self, intent: &RestoreReconcileIntent) -> bool {
        match self {
            Self::Committed(receipt) => {
                receipt.operation_id == intent.operation_id
                    && receipt.binding_digest == intent.binding_digest
                    && receipt.fence_generation == intent.fence_generation
                    && receipt.record_digest == intent.record_digest
            }
            Self::FencedNotCommitted(receipt) => {
                receipt.operation_id == intent.operation_id
                    && receipt.binding_digest == intent.binding_digest
                    && receipt.fence_generation == intent.fence_generation
                    && receipt.record_digest == intent.record_digest
                    && receipt.fenced_generation > intent.fence_generation
            }
        }
    }

    fn outcome(&self) -> RestoreWriteResolution {
        match self {
            Self::Committed(receipt) => RestoreWriteResolution::Committed {
                commit_digest: receipt.commit_digest,
            },
            Self::FencedNotCommitted(receipt) => RestoreWriteResolution::FencedNotCommitted {
                fenced_generation: receipt.fenced_generation,
            },
        }
    }
}

/// Confirmed only after a correlated authority reconciliation response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreWriteResolution {
    Committed { commit_digest: [u8; 32] },
    FencedNotCommitted { fenced_generation: u64 },
}

pub struct ReconciledRestoreWrite {
    operation_id: [u8; 16],
    binding_digest: [u8; 32],
    outcome: RestoreWriteResolution,
}

impl ReconciledRestoreWrite {
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }
    pub const fn binding_digest(&self) -> [u8; 32] {
        self.binding_digest
    }
    pub const fn outcome(&self) -> RestoreWriteResolution {
        self.outcome
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RestoreStoreRecoveryFailure {
    pub dispatch: RestoreDispatch,
}

pub type RestoreStoreRecoveryFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<DurableRestoreResolution, RestoreStoreRecoveryFailure>>
            + Send
            + 'a,
    >,
>;

/// A configured independent durable store, not an authority-supplied callback.
///
/// recover queries the exact operation journal. It returns the real committed
/// record proof or transactionally installs a terminal noncommit plus a newer
/// durable CAS fence that prevents any old writer/duplicate from committing.
/// It may never infer noncommit from a missing row. Unknown remains unknown.
/// Calls and destruction run under the caller's effect ceiling and deadline;
/// implementations must not block or detach work without retained admission.
/// declaration is pure and identifies the exact pre-registered persistence domain.
pub trait RestoreStoreRecovery: Send + Sync + 'static {
    fn declaration(&self) -> RestoreStoreDeclaration;
    fn recover<'a>(
        &'a self,
        cx: &'a Cx,
        intent: &'a RestoreReconcileIntent,
        deadline: Time,
    ) -> RestoreStoreRecoveryFuture<'a>;
}

/// An authority-admitted observation for reads of an existing protected record.
/// Its lifetime is measured locally. Provider clocks never extend freshness.
pub struct RestoreBindingObservation {
    store: RegisteredRestoreStore,
    binding: RestoreEpochBinding,
    generation: u64,
    expires_at: Time,
}

impl RestoreBindingObservation {
    pub const fn binding(&self) -> &RestoreEpochBinding {
        &self.binding
    }
    pub fn store_id(&self) -> &str {
        self.store.store_id()
    }
    pub fn namespace_digest(&self) -> [u8; 32] {
        self.store.namespace_digest()
    }
    pub fn store_set_digest(&self) -> [u8; 32] {
        self.store.store_set_digest()
    }
    pub fn configuration(&self) -> &RestoreEpochConfiguration {
        self.store.configuration()
    }
    pub const fn store_fence_generation(&self) -> u64 {
        self.generation
    }
    pub const fn expires_at(&self) -> Time {
        self.expires_at
    }
    pub fn check(&self, cx: &Cx) -> Result<(), RestoreError> {
        check_owned_binding(&self.store.shared, cx, self.expires_at)
    }
}

pub(super) fn check_owned_binding(
    shared: &Shared,
    cx: &Cx,
    expires_at: Time,
) -> Result<(), RestoreError> {
    shared.check()?;
    with_caller(cx, || {
        let active = Cx::current().ok_or(RestoreError::CapabilityUnavailable)?;
        require_caller(&active)?;
        active.checkpoint().map_err(|_| RestoreError::Cancelled)?;
        let deadline = active
            .budget()
            .deadline
            .map_or(expires_at, |parent| parent.min(expires_at));
        if active.now() >= deadline {
            return Err(RestoreError::DeadlineExceeded);
        }
        shared.check()
    })
}

impl RegisteredRestoreStore {
    pub async fn current_binding(
        &self,
        cx: &Cx,
        deadline: Time,
    ) -> Result<RestoreBindingObservation, RestoreError> {
        with_operation_caller(cx, self.current_binding_inner(cx, deadline)).await
    }

    async fn current_binding_inner(
        &self,
        cx: &Cx,
        deadline: Time,
    ) -> Result<RestoreBindingObservation, RestoreError> {
        let (binding, generation, observed_at) = self.current(cx, deadline).await?;
        let observation = RestoreBindingObservation {
            store: self.clone(),
            binding,
            generation,
            expires_at: deadline.min(add_time(
                observed_at,
                self.shared.configuration.limits.observation_freshness,
            )?),
        };
        observation.check(cx)?;
        Ok(observation)
    }

    /// Settle a still-owned fence with real durable evidence. This permits a
    /// proved CAS loser to return a normal conflict without quarantining every
    /// store. Any ambiguous/malformed outcome still drops an unresolved fence.
    pub async fn reconcile_write(
        &self,
        cx: &Cx,
        fence: RestoreWriteFence,
        resolution: DurableRestoreResolution,
        deadline: Time,
    ) -> Result<ReconciledRestoreWrite, RestoreError> {
        with_operation_caller(cx, self.reconcile_write_inner(cx, fence, resolution, deadline)).await
    }

    async fn reconcile_write_inner(
        &self,
        cx: &Cx,
        mut fence: RestoreWriteFence,
        resolution: DurableRestoreResolution,
        deadline: Time,
    ) -> Result<ReconciledRestoreWrite, RestoreError> {
        fence.check(cx)?;
        if !Arc::ptr_eq(&self.shared, &fence.store.shared)
            || self.declaration.as_ref() != fence.store.declaration.as_ref()
        {
            return Err(RestoreError::InvalidReceipt);
        }
        let intent = RestoreReconcileIntent {
            store: (*self.declaration).clone(),
            operation_id: fence.operation_id,
            binding_digest: fence.binding.digest,
            fence_generation: fence.generation,
            record_digest: fence.record_digest,
            position: None,
            snapshot: None,
        };
        let settled = reconcile(
            &self.shared,
            cx,
            intent,
            resolution,
            deadline.min(fence.expires_at),
            CallAccess::Ordinary,
        )
        .await?;
        fence.settled = true;
        Ok(settled)
    }
}

async fn reconcile(
    shared: &Arc<Shared>,
    cx: &Cx,
    intent: RestoreReconcileIntent,
    resolution: DurableRestoreResolution,
    deadline: Time,
    access: CallAccess,
) -> Result<ReconciledRestoreWrite, RestoreError> {
    if !resolution.matches(&intent) {
        return Err(RestoreError::InvalidReceipt);
    }
    let operation_id = intent.operation_id;
    let binding_digest = intent.binding_digest;
    let resolution_digest = resolution.digest()?;
    let outcome = resolution.outcome();
    let request = shared.request_with_access(
        cx,
        RestoreAuthorityOperation::ReconcileWrite {
            intent: Box::new(intent),
            resolution,
        },
        deadline,
        access,
    )?;
    let mut uncertain = UncertainMutation::new(Arc::clone(shared));
    let response = shared
        .call_with_access(cx, &request, Some(&mut uncertain), access)
        .await?;
    match response.outcome {
        RestoreAuthorityOutcome::Reconciled {
            intent_operation_id,
            resolution_digest: echoed,
        } if intent_operation_id == operation_id && echoed == resolution_digest => {}
        _ => return Err(RestoreError::InvalidReceipt),
    }
    uncertain.settled = true;
    Ok(ReconciledRestoreWrite {
        operation_id,
        binding_digest,
        outcome,
    })
}

/// Completed snapshot work. This does not itself authorize writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreRecoverySummary {
    pub snapshot_id: [u8; 16],
    pub high_water_generation: u64,
    pub pages: usize,
    pub committed: usize,
    pub fenced_not_committed: usize,
}

/// The snapshot may be fully reconciled while fresh registration is refused
/// because another writer created a newer intent or the deployment is closed.
pub struct RestoreRecoveryOutcome {
    summary: RestoreRecoverySummary,
    registration: Result<RestoreEpochFacade, RestoreError>,
}

impl RestoreRecoveryOutcome {
    pub const fn summary(&self) -> RestoreRecoverySummary {
        self.summary
    }
    pub fn registration_error(&self) -> Option<RestoreError> {
        self.registration.as_ref().err().copied()
    }
    /// Fresh handles exist only after the authority transaction and matching
    /// Current observations for every member of the original store union.
    pub fn into_facade(self) -> Result<RestoreEpochFacade, RestoreError> {
        self.registration
    }
}

#[derive(Default)]
pub(super) struct RecoveryRate {
    window: Option<Time>,
    count: usize,
}

impl RecoveryRate {
    fn take(&mut self, now: Time, maximum: usize) -> Result<(), RestoreError> {
        if self.window.is_some_and(|start| now < start) {
            return Err(RestoreError::DeadlineExceeded);
        }
        if self
            .window
            .is_none_or(|start| now.as_nanos() - start.as_nanos() >= 60_000_000_000)
        {
            self.window = Some(now);
            self.count = 0;
        }
        if self.count >= maximum {
            return Err(RestoreError::CapacityExceeded);
        }
        self.count += 1;
        Ok(())
    }
}

struct RecoveryLease {
    shared: Arc<Shared>,
}

impl RecoveryLease {
    fn acquire(shared: Arc<Shared>) -> Result<Self, RestoreError> {
        shared.process.verify().map_err(|_| RestoreError::ProcessChanged)?;
        shared
            .recovering
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RestoreError::RecoveryBusy)?;
        let lease = Self { shared };
        // This is permanent retirement of the old facade, never a reset.
        lease.shared.quarantine();
        if lease.shared.calls.load(Ordering::Acquire) != 0
            || lease.shared.reads.load(Ordering::Acquire) != 0
            || lease.shared.intents.load(Ordering::Acquire) != 0
        {
            return Err(RestoreError::RecoveryBusy);
        }
        Ok(lease)
    }
}

impl Drop for RecoveryLease {
    fn drop(&mut self) {
        self.shared.recovering.store(false, Ordering::Release);
    }
}


impl RestoreEpochFacade {
    /// Operator bootstrap after process loss, when no old facade survives and
    /// ordinary registration correctly refuses persisted unresolved intents.
    ///
    /// This constructs only an inaccessible quarantined facade. The authority
    /// must already know the EXACT declared store union and configuration, and
    /// must reject a different union/configuration on every Current/scan/settle
    /// request. No initial registration, fresh deployment UUID, epoch reset,
    /// namespace wipe or caller assertion substitutes for that durable identity.
    /// Live handles escape only after the normal recovery consumer obtains a
    /// real final registration and matching certified bindings for every store.
    pub async fn recover_after_restart(
        cx: &Cx,
        configuration: RestoreEpochConfiguration,
        declarations: Vec<RestoreStoreDeclaration>,
        backend: Arc<dyn RestoreEpochAuthority>,
        stores: Vec<Arc<dyn RestoreStoreRecovery>>,
        limits: RestoreRecoveryLimits,
        deadline: Time,
    ) -> Result<RestoreRecoveryOutcome, RestoreError> {
        with_operation_caller(cx, async move {
            let retired = Self::configured(
                configuration,
                declarations,
                backend,
                InitialAdmission::Recovery,
            )?;
            retired.recover(cx, stores, limits, deadline).await
        }).await
    }

    /// Reconcile a bounded immutable snapshot using the exact predeclared store
    /// union. The old facade remains quarantined even on successful recovery.
    ///
    /// Dropping this future never guesses noncommit or reopens old handles. The
    /// authority retains uncertain intents and expires any abandoned snapshot.
    /// The operator can start a new bounded scan, which queries persisted state
    /// for the original intent IDs instead of replaying an uncertain mutation.
    pub async fn recover(
        &self,
        cx: &Cx,
        stores: Vec<Arc<dyn RestoreStoreRecovery>>,
        limits: RestoreRecoveryLimits,
        deadline: Time,
    ) -> Result<RestoreRecoveryOutcome, RestoreError> {
        with_operation_caller(cx, self.recover_inner(cx, stores, limits, deadline)).await
    }

    async fn recover_inner(
        &self,
        cx: &Cx,
        mut stores: Vec<Arc<dyn RestoreStoreRecovery>>,
        limits: RestoreRecoveryLimits,
        deadline: Time,
    ) -> Result<RestoreRecoveryOutcome, RestoreError> {
        limits.validate()?;
        if stores.len() != self.stores.len() {
            return Err(RestoreError::InvalidConfiguration);
        }
        let mut adapters: Vec<_> = stores
            .drain(..)
            .map(|adapter| (adapter.declaration(), adapter))
            .collect();
        adapters.sort_by(|left, right| left.0.id.cmp(&right.0.id));
        for ((declaration, _), registered) in adapters.iter().zip(&self.stores) {
            if declaration != registered.declaration.as_ref() {
                return Err(RestoreError::InvalidConfiguration);
            }
        }
        let shared = &self.stores[0].shared;
        let deadline = with_caller(cx, || {
            let active = Cx::current().ok_or(RestoreError::CapabilityUnavailable)?;
            require_caller(&active)?;
            active.checkpoint().map_err(|_| RestoreError::Cancelled)?;
            let deadline = deadline.min(add_time(active.now(), limits.scan_deadline)?);
            let deadline = active
                .budget()
                .deadline
                .map_or(deadline, |parent| parent.min(deadline));
            if active.now() >= deadline {
                return Err(RestoreError::DeadlineExceeded);
            }
            Ok(deadline)
        })?;
        let _lease = RecoveryLease::acquire(Arc::clone(shared))?;
        let expires_at = deadline.min(add_time(cx.now(), limits.cursor_lifetime)?);
        let mut stable = Vec::new();
        stable
            .try_reserve_exact(self.stores.len())
            .map_err(|_| RestoreError::CapacityExceeded)?;
        // Pin every namespace before scanning, including previously unused
        // stores. An already-pinned binding may never silently change.
        for store in &self.stores {
            let (binding, _, _) = store
                .current_with_access(cx, deadline, CallAccess::Recovery)
                .await?;
            stable.push((binding.digest, binding.epoch));
        }

        let mut cursor = None;
        let mut snapshot: Option<([u8; 16], u64)> = None;
        let mut scan_operation_id = None;
        let mut last = None;
        let mut seen = BTreeSet::new();
        let mut summary = RestoreRecoverySummary {
            snapshot_id: [0; 16],
            high_water_generation: 0,
            pages: 0,
            committed: 0,
            fenced_not_committed: 0,
        };
        loop {
            CallAccess::Recovery.check(shared)?;
            if cx.now() >= expires_at {
                return Err(RestoreError::ScanRestartRequired);
            }
            if summary.pages > limits.backlog {
                return Err(RestoreError::CapacityExceeded);
            }
            let request = shared.request_with_access(
                cx,
                RestoreAuthorityOperation::ListUnresolvedWrites {
                    limits,
                    expires_at,
                    cursor: cursor.take(),
                },
                deadline.min(expires_at),
                CallAccess::Recovery,
            )?;
            let first_operation_id = *scan_operation_id.get_or_insert(request.operation_id);
            let response = shared
                .call_with_access(cx, &request, None, CallAccess::Recovery)
                .await
                .map_err(|error| {
                    if error == RestoreError::DeadlineExceeded && cx.now() >= expires_at {
                        RestoreError::ScanRestartRequired
                    } else {
                        error
                    }
                })?;
            let page = match response.outcome {
                RestoreAuthorityOutcome::UnresolvedWrites(page) => page,
                RestoreAuthorityOutcome::ScanRestartRequired => {
                    return Err(RestoreError::ScanRestartRequired);
                }
                _ => return Err(RestoreError::InvalidReceipt),
            };
            if page.snapshot_id == [0; 16]
                || snapshot.is_some_and(|expected| {
                    expected != (page.snapshot_id, page.high_water_generation)
                })
                || page.writes.len() > limits.page_items
                || page_size(&page)? > limits.page_bytes
                || page.next_cursor.as_ref().is_some_and(|next| {
                    next.is_empty() || next.len() > limits.cursor_bytes || page.writes.is_empty()
                })
                || seen.len().checked_add(page.writes.len()).is_none_or(|n| n > limits.backlog)
            {
                return Err(RestoreError::InvalidReceipt);
            }
            let mut page_last = last;
            // Validate the whole page before any store mutation is dispatched.
            // Ordering alone does not detect the same ID assigned two generations.
            for intent in &page.writes {
                let position = RestoreIntentPosition {
                    generation: intent.intent_generation,
                    operation_id: intent.operation_id,
                };
                let index = self
                    .stores
                    .binary_search_by(|store| store.declaration.id.cmp(&intent.store.id))
                    .map_err(|_| RestoreError::InvalidReceipt)?;
                if intent.intent_generation == 0
                    || intent.intent_generation > page.high_water_generation
                    || intent.store_fence_generation == 0
                    || intent.store != *self.stores[index].declaration
                    || intent.binding_digest != stable[index].0
                    || page_last.is_some_and(|previous| position <= previous)
                    || !seen.insert(intent.operation_id)
                {
                    return Err(RestoreError::InvalidReceipt);
                }
                page_last = Some(position);
            }
            snapshot = Some((page.snapshot_id, page.high_water_generation));
            summary.snapshot_id = page.snapshot_id;
            summary.high_water_generation = page.high_water_generation;
            summary.pages += 1;
            let binding = Arc::new(RestoreScanBinding {
                configuration: Arc::clone(&shared.configuration),
                store_set_digest: shared.store_set_digest,
                scan_operation_id: first_operation_id,
                snapshot_id: page.snapshot_id,
                high_water_generation: page.high_water_generation,
                last: page_last,
                expires_at,
                limits,
            });
            for raw in page.writes {
                if cx.now() >= expires_at {
                    return Err(RestoreError::ScanRestartRequired);
                }
                shared
                    .recovery_rate
                    .lock()
                    .map_err(|_| RestoreError::Quarantined)?
                    .take(cx.now(), limits.reconciliations_per_minute)?;
                let index = adapters
                    .binary_search_by(|(declaration, _)| declaration.id.cmp(&raw.store.id))
                    .map_err(|_| RestoreError::InvalidReceipt)?;
                let intent = RestoreReconcileIntent {
                    store: raw.store,
                    operation_id: raw.operation_id,
                    binding_digest: raw.binding_digest,
                    fence_generation: raw.store_fence_generation,
                    record_digest: raw.record_digest,
                    position: Some(RestoreIntentPosition {
                        generation: raw.intent_generation,
                        operation_id: raw.operation_id,
                    }),
                    snapshot: Some(Arc::clone(&binding)),
                };
                let resolution = recover_store(
                    shared,
                    cx,
                    adapters[index].1.as_ref(),
                    &intent,
                    deadline.min(expires_at),
                )
                .await?;
                let settled = reconcile(
                    shared,
                    cx,
                    intent,
                    resolution,
                    deadline.min(expires_at),
                    CallAccess::Recovery,
                )
                .await?;
                match settled.outcome {
                    RestoreWriteResolution::Committed { .. } => summary.committed += 1,
                    RestoreWriteResolution::FencedNotCommitted { .. } => {
                        summary.fenced_not_committed += 1;
                    }
                }
            }
            last = page_last;
            match page.next_cursor {
                Some(bytes) => cursor = Some(RestoreIntentCursor { bytes, binding }),
                None => break,
            }
        }
        CallAccess::Recovery.check(shared)?;
        // A complete snapshot can omit writes PREPARED AFTER its high-water.
        // Registration, not local counts or the terminal page, decides whether
        // the exact deployment is currently safe to admit again.
        let registration = self.register_recovered(cx, &stable, deadline).await;
        Ok(RestoreRecoveryOutcome {
            summary,
            registration,
        })
    }

    async fn register_recovered(
        &self,
        cx: &Cx,
        stable: &[([u8; 32], u128)],
        deadline: Time,
    ) -> Result<Self, RestoreError> {
        let old = &self.stores[0].shared;
        CallAccess::Recovery.check(old)?;
        let facade = Self::register(
            cx,
            (*old.configuration).clone(),
            self.stores
                .iter()
                .map(|store| (*store.declaration).clone())
                .collect(),
            Arc::clone(&old.backend),
            deadline,
        )
        .await?;
        let mut closed_until_validated = UncertainMutation::new(Arc::clone(&facade.stores[0].shared));
        closed_until_validated.armed = true;
        CallAccess::Recovery.check(old)?;
        for (store, expected) in facade.stores.iter().zip(stable) {
            *store.stable.lock().map_err(|_| RestoreError::Quarantined)? = Some(*expected);
            store.current(cx, deadline).await?;
            CallAccess::Recovery.check(old)?;
        }
        closed_until_validated.settled = true;
        Ok(facade)
    }
}

async fn recover_store(
    shared: &Shared,
    cx: &Cx,
    store: &dyn RestoreStoreRecovery,
    intent: &RestoreReconcileIntent,
    deadline: Time,
) -> Result<DurableRestoreResolution, RestoreError> {
    CallAccess::Recovery.check(shared)?;
    let _admission = CounterLease::acquire(&shared.calls, shared.configuration.limits.active_calls)?;
    let (caller, deadline) = with_caller(cx, || {
        let current = Cx::current().ok_or(RestoreError::CapabilityUnavailable)?;
        require_caller(&current)?;
        current.checkpoint().map_err(|_| RestoreError::Cancelled)?;
        let deadline = deadline.min(add_time(current.now(), shared.configuration.limits.call_timeout)?);
        let deadline = current
            .budget()
            .deadline
            .map_or(deadline, |parent| parent.min(deadline));
        if current.now() >= deadline {
            return Err(RestoreError::DeadlineExceeded);
        }
        Ok((current, deadline))
    })?;
    CallAccess::Recovery.check(shared)?;
    let future = with_caller(&caller, || store.recover(&caller, intent, deadline));
    let resolution = within_access(shared, &caller, deadline, future, CallAccess::Recovery).await?;
    resolution.map_err(|failure| {
        if failure.dispatch == RestoreDispatch::NotDispatched {
            RestoreError::ProviderUnavailable
        } else {
            RestoreError::Uncertain
        }
    })
}

fn page_size(page: &RestoreUnresolvedPage) -> Result<usize, RestoreError> {
    // Canonical page framing: FMC PRPG/v1, snapshot, high-water, count,
    // fixed-width intent metadata, length-framed store IDs and continuation.
    let mut size = 39_usize;
    for intent in &page.writes {
        size = size
            .checked_add(132)
            .and_then(|n| n.checked_add(intent.store.id.len()))
            .ok_or(RestoreError::InvalidReceipt)?;
    }
    if let Some(cursor) = &page.next_cursor {
        size = size
            .checked_add(4)
            .and_then(|n| n.checked_add(cursor.len()))
            .ok_or(RestoreError::InvalidReceipt)?;
    }
    Ok(size)
}

pub(super) fn encode_scan_request(
    out: &mut Vec<u8>,
    limits: RestoreRecoveryLimits,
    expires_at: Time,
    cursor: Option<&RestoreIntentCursor>,
) {
    encode_limits(out, limits);
    out.extend_from_slice(&expires_at.as_nanos().to_be_bytes());
    match cursor {
        None => out.push(0),
        Some(cursor) => {
            out.push(1);
            encode_scan_binding(out, &cursor.binding);
            encode_bytes(out, &cursor.bytes);
        }
    }
}

fn encode_limits(out: &mut Vec<u8>, limits: RestoreRecoveryLimits) {
    out.extend_from_slice(&(limits.page_items as u64).to_be_bytes());
    out.extend_from_slice(&(limits.page_bytes as u64).to_be_bytes());
    out.extend_from_slice(&(limits.cursor_bytes as u64).to_be_bytes());
    out.extend_from_slice(&limits.cursor_lifetime.as_nanos().to_be_bytes());
    out.extend_from_slice(&limits.scan_deadline.as_nanos().to_be_bytes());
    out.extend_from_slice(&(limits.backlog as u64).to_be_bytes());
    out.extend_from_slice(&(limits.reconciliations_per_minute as u64).to_be_bytes());
    out.extend_from_slice(&(limits.active_snapshots as u64).to_be_bytes());
    out.extend_from_slice(&(limits.retained_snapshot_bytes as u64).to_be_bytes());
}

fn encode_scan_binding(out: &mut Vec<u8>, binding: &RestoreScanBinding) {
    encode_bytes(out, binding.configuration.authority_id.as_bytes());
    encode_bytes(out, binding.configuration.provider_artifact.as_bytes());
    out.extend_from_slice(&binding.configuration.provider_artifact_digest);
    out.extend_from_slice(&binding.configuration.configuration_fingerprint);
    out.extend_from_slice(&binding.configuration.authority_generation.to_be_bytes());
    out.extend_from_slice(&binding.configuration.deployment_uuid);
    out.extend_from_slice(&binding.configuration.store_set_generation.to_be_bytes());
    out.extend_from_slice(&binding.configuration.policy_generation.to_be_bytes());
    out.extend_from_slice(&binding.store_set_digest);
    out.extend_from_slice(&binding.scan_operation_id);
    out.extend_from_slice(&binding.snapshot_id);
    out.extend_from_slice(&binding.high_water_generation.to_be_bytes());
    match binding.last {
        None => out.push(0),
        Some(position) => {
            out.push(1);
            out.extend_from_slice(&position.generation.to_be_bytes());
            out.extend_from_slice(&position.operation_id);
        }
    }
    out.extend_from_slice(&binding.expires_at.as_nanos().to_be_bytes());
    encode_limits(out, binding.limits);
}

pub(super) fn encode_reconciliation(
    out: &mut Vec<u8>,
    intent: &RestoreReconcileIntent,
    resolution: &DurableRestoreResolution,
) {
    encode_store(out, &intent.store);
    out.extend_from_slice(&intent.operation_id);
    out.extend_from_slice(&intent.binding_digest);
    out.extend_from_slice(&intent.fence_generation.to_be_bytes());
    out.extend_from_slice(&intent.record_digest);
    match &intent.snapshot {
        None => out.push(0),
        Some(snapshot) => {
            out.push(1);
            encode_scan_binding(out, snapshot);
        }
    }
    match intent.position {
        None => out.push(0),
        Some(position) => {
            out.push(1);
            out.extend_from_slice(&position.generation.to_be_bytes());
            out.extend_from_slice(&position.operation_id);
        }
    }
    encode_resolution(out, resolution);
}

fn encode_resolution(out: &mut Vec<u8>, resolution: &DurableRestoreResolution) {
    match resolution {
        DurableRestoreResolution::Committed(receipt) => {
            out.push(1);
            out.extend_from_slice(&receipt.operation_id);
            out.extend_from_slice(&receipt.binding_digest);
            out.extend_from_slice(&receipt.fence_generation.to_be_bytes());
            out.extend_from_slice(&receipt.record_digest);
            out.extend_from_slice(&receipt.commit_digest);
            encode_bytes(out, &receipt.proof);
        }
        DurableRestoreResolution::FencedNotCommitted(receipt) => {
            out.push(2);
            out.extend_from_slice(&receipt.operation_id);
            out.extend_from_slice(&receipt.binding_digest);
            out.extend_from_slice(&receipt.fence_generation.to_be_bytes());
            out.extend_from_slice(&receipt.record_digest);
            out.extend_from_slice(&receipt.fenced_generation.to_be_bytes());
            encode_bytes(out, &receipt.proof);
        }
    }
}
