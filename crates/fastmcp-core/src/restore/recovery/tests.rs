//! Independent in-memory authority and store actors exercise the protocol.
//! These are conformance fixtures, not claims of durable provider qualification.

use super::*;
use crate::runtime::block_on;
use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
use std::collections::BTreeMap;
use std::task::{Context, Wake, Waker};

#[derive(Clone, Copy)]
enum FactKind {
    Committed([u8; 32]),
    Fenced(u64),
}

#[derive(Clone)]
struct Fact {
    id: [u8; 16],
    binding: [u8; 32],
    generation: u64,
    record: [u8; 32],
    kind: FactKind,
    proof: Vec<u8>,
}

impl Fact {
    fn resolution(&self) -> DurableRestoreResolution {
        match self.kind {
            FactKind::Committed(commit) => DurableRestoreResolution::Committed(
                DurableRestoreCommitReceipt::new(
                    self.id, self.binding, self.generation, self.record, commit, self.proof.clone(),
                )
                .unwrap(),
            ),
            FactKind::Fenced(generation) => DurableRestoreResolution::FencedNotCommitted(
                DurableRestoreNonCommitReceipt::new(
                    self.id, self.binding, self.generation, self.record, generation, self.proof.clone(),
                )
                .unwrap(),
            ),
        }
    }
}

struct StoreState {
    generation: u64,
    facts: BTreeMap<[u8; 16], Fact>,
    queried: Vec<[u8; 16]>,
}

struct Store {
    declaration: RestoreStoreDeclaration,
    state: Mutex<StoreState>,
    unknown: AtomicBool,
    pending: AtomicBool,
    drop_effects: Arc<Mutex<Vec<[bool; 5]>>>,
    recover_effects: Mutex<Vec<bool>>,
}

impl Store {
    fn new(id: &str, namespace: u8) -> Self {
        Self {
            declaration: RestoreStoreDeclaration { id: id.into(), namespace_digest: [namespace; 32] },
            state: Mutex::new(StoreState { generation: 1, facts: BTreeMap::new(), queried: Vec::new() }),
            unknown: AtomicBool::new(false),
            pending: AtomicBool::new(false),
            drop_effects: Arc::new(Mutex::new(Vec::new())),
            recover_effects: Mutex::new(Vec::new()),
        }
    }

    fn record(
        &self,
        id: [u8; 16],
        binding: [u8; 32],
        generation: u64,
        record: [u8; 32],
        commit: bool,
    ) -> Fact {
        let mut state = self.state.lock().unwrap();
        if let Some(fact) = state.facts.get(&id) {
            return fact.clone();
        }
        if commit {
            assert_eq!(generation, state.generation, "commit requires the durable fence CAS");
        }
        state.generation = state.generation.max(generation + 1);
        let mut proof = b"independent-durable-store-fixture".to_vec();
        proof.extend_from_slice(&self.declaration.namespace_digest);
        proof.extend_from_slice(&id);
        proof.extend_from_slice(&binding);
        proof.extend_from_slice(&generation.to_be_bytes());
        proof.extend_from_slice(&record);
        proof.push(u8::from(commit));
        proof.extend_from_slice(&state.generation.to_be_bytes());
        let kind = if commit {
            FactKind::Committed(hash(&proof).unwrap())
        } else {
            FactKind::Fenced(state.generation)
        };
        let fact = Fact { id, binding, generation, record, kind, proof };
        state.facts.insert(id, fact.clone());
        fact
    }

    fn commit(&self, fence: &RestoreWriteFence) -> DurableRestoreCommitReceipt {
        let fact = self.record(
            fence.operation_id(), fence.binding_digest(), fence.store_fence_generation(),
            fence.record_digest(), true,
        );
        match fact.resolution() {
            DurableRestoreResolution::Committed(receipt) => receipt,
            DurableRestoreResolution::FencedNotCommitted(_) => panic!("operation is terminally fenced"),
        }
    }

    fn fence(&self, fence: &RestoreWriteFence) -> DurableRestoreResolution {
        self.record(
            fence.operation_id(), fence.binding_digest(), fence.store_fence_generation(),
            fence.record_digest(), false,
        )
        .resolution()
    }

    fn verifies(&self, resolution: &DurableRestoreResolution, id: [u8; 16]) -> bool {
        self.state.lock().unwrap().facts.get(&id).is_some_and(|fact| {
            fact.resolution().digest().unwrap() == resolution.digest().unwrap()
        })
    }
}

struct ObserveDrop(Arc<Mutex<Vec<[bool; 5]>>>);

impl Drop for ObserveDrop {
    fn drop(&mut self) {
        let caps = Cx::current().expect("store future drops under its caller").capabilities();
        self.0.lock().unwrap().push([caps.spawn, caps.time, caps.entropy, caps.io, caps.remote]);
    }
}

impl RestoreStoreRecovery for Store {
    fn declaration(&self) -> RestoreStoreDeclaration {
        self.declaration.clone()
    }
    fn recover<'a>(
        &'a self,
        _cx: &'a Cx,
        intent: &'a RestoreReconcileIntent,
        _deadline: Time,
    ) -> RestoreStoreRecoveryFuture<'a> {
        assert!(intent.store() == &self.declaration);
        self.recover_effects.lock().unwrap().push(Cx::current().unwrap().capabilities().spawn);
        self.state.lock().unwrap().queried.push(intent.operation_id());
        if self.unknown.load(Ordering::Acquire) {
            return Box::pin(std::future::ready(Err(RestoreStoreRecoveryFailure {
                dispatch: RestoreDispatch::Unknown,
            })));
        }
        let resolution = self.record(
            intent.operation_id(), intent.binding_digest(), intent.store_fence_generation(),
            intent.record_digest(), false,
        )
        .resolution();
        if self.pending.load(Ordering::Acquire) {
            let observer = ObserveDrop(Arc::clone(&self.drop_effects));
            return Box::pin(async move {
                let _observer = observer;
                let _resolution = resolution;
                std::future::pending().await
            });
        }
        Box::pin(std::future::ready(Ok(resolution)))
    }
}

#[derive(Clone, Copy)]
enum Fault {
    HighWater,
    Reversed,
    DuplicateId,
    ForeignNamespace,
    EmptyContinuation,
    OversizedCursor,
    Invalidated,
    ReconcileDigest,
    ReconcileUnknown,
    ChangedBinding,
    NewerIntent,
    ConcurrentCompletion,
}

struct Snapshot {
    high_water: u64,
    scan_id: [u8; 16],
    expires_at: Time,
    items: Vec<RestoreUnresolvedWrite>,
}

#[derive(Default)]
struct AuthorityState {
    stores: Vec<RestoreStoreDeclaration>,
    intents: BTreeMap<[u8; 16], RestoreUnresolvedWrite>,
    settled: BTreeMap<[u8; 16], [u8; 32]>,
    snapshots: BTreeMap<[u8; 16], Snapshot>,
    generation: u64,
    next_snapshot: u128,
    registrations: usize,
    registration_attempts: usize,
    registered_digest: Option<[u8; 32]>,
    configuration: Option<RestoreEpochConfiguration>,
    lists: usize,
    reconciliations: Vec<([u8; 16], [u8; 16])>,
    epoch: u128,
}

struct Authority {
    stores: Vec<Arc<Store>>,
    state: Mutex<AuthorityState>,
    fault: Mutex<Option<Fault>>,
    yield_current_once: AtomicBool,
    effects: Mutex<Vec<(&'static str, bool)>>,
}

impl Authority {
    fn new(stores: Vec<Arc<Store>>) -> Self {
        Self {
            stores,
            state: Mutex::new(AuthorityState { epoch: 7, ..AuthorityState::default() }),
            fault: Mutex::new(None),
            yield_current_once: AtomicBool::new(false),
            effects: Mutex::new(Vec::new()),
        }
    }

    fn find(&self, id: &str) -> &Store {
        self.stores.iter().find(|store| store.declaration.id == id).unwrap()
    }

    fn inject(&self, fault: Fault) {
        *self.fault.lock().unwrap() = Some(fault);
    }

    fn execute_operation(
        &self,
        request: &RestoreAuthorityRequest,
    ) -> Result<RestoreAuthorityResponse, RestoreAuthorityFailure> {
        let mut state = self.state.lock().unwrap();
        let refused = || RestoreAuthorityFailure { dispatch: RestoreDispatch::Dispatched };
        let fault = *self.fault.lock().unwrap();
        if let Some(configured) = &state.configuration {
            if !same_configuration(configured, request.configuration())
                || state.registered_digest != Some(request.store_set_digest())
            {
                return Err(refused());
            }
        } else if !matches!(request.operation(), RestoreAuthorityOperation::RegisterStoreSet { .. }) {
            return Err(refused());
        }
        let outcome = match request.operation() {
            RestoreAuthorityOperation::RegisterStoreSet { stores } => {
                state.registration_attempts += 1;
                if !state.intents.is_empty()
                    || (!state.stores.is_empty() && state.stores != *stores)
                {
                    return Err(refused());
                }
                if state.registrations != 0 && matches!(fault, Some(Fault::ChangedBinding)) {
                    state.epoch += 1;
                }
                state.stores = stores.clone();
                state.configuration = Some(request.configuration().clone());
                state.registered_digest = Some(request.store_set_digest());
                state.registrations += 1;
                RestoreAuthorityOutcome::Registered { store_set_digest: request.store_set_digest() }
            }
            RestoreAuthorityOperation::Current { store } => {
                if !state.stores.contains(store) { return Err(refused()); }
                let config = request.configuration();
                let certified = CertifiedRestoreEpoch {
                    authority_id: config.authority_id.clone(),
                    configuration_fingerprint: config.configuration_fingerprint,
                    authority_generation: config.authority_generation,
                    deployment_uuid: config.deployment_uuid,
                    namespace_digest: store.namespace_digest,
                    epoch: state.epoch,
                    stable_certificate: None,
                };
                RestoreAuthorityOutcome::Current {
                    certified_binding: certified.canonical_bytes().unwrap(),
                    store_fence_generation: self.find(&store.id).state.lock().unwrap().generation,
                }
            }
            RestoreAuthorityOperation::PrepareWrite {
                store, binding_digest, store_fence_generation, record_digest, ..
            } => {
                if !state.stores.contains(store)
                    || self.find(&store.id).state.lock().unwrap().generation != *store_fence_generation
                { return Err(refused()); }
                state.generation += 1;
                let generation = state.generation;
                state.intents.insert(request.operation_id(), RestoreUnresolvedWrite {
                    intent_generation: generation,
                    operation_id: request.operation_id(),
                    store: store.clone(),
                    binding_digest: *binding_digest,
                    store_fence_generation: *store_fence_generation,
                    record_digest: *record_digest,
                });
                RestoreAuthorityOutcome::Prepared {
                    binding_digest: *binding_digest,
                    store_fence_generation: *store_fence_generation,
                }
            }
            RestoreAuthorityOperation::CompleteWrite { store, intent_operation_id, receipt } => {
                let Some(intent) = state.intents.get(intent_operation_id) else { return Err(refused()); };
                if intent.store != *store
                    || intent.binding_digest != receipt.binding_digest()
                    || intent.store_fence_generation != receipt.store_fence_generation()
                    || intent.record_digest != receipt.record_digest()
                    || *intent_operation_id != receipt.operation_id()
                { return Err(refused()); }
                let stored = self.find(&store.id).state.lock().unwrap().facts.get(intent_operation_id).cloned();
                let Some(stored) = stored else { return Err(refused()); };
                let resolution = stored.resolution();
                let DurableRestoreResolution::Committed(actual) = &resolution else { return Err(refused()); };
                if actual.proof() != receipt.proof() || actual.commit_digest() != receipt.commit_digest() {
                    return Err(refused());
                }
                state.intents.remove(intent_operation_id);
                state.settled.insert(*intent_operation_id, resolution.digest().unwrap());
                RestoreAuthorityOutcome::Completed {
                    intent_operation_id: *intent_operation_id, commit_digest: receipt.commit_digest(),
                }
            }
            RestoreAuthorityOperation::ListUnresolvedWrites { limits, expires_at, cursor } => {
                state.lists += 1;
                if matches!(fault, Some(Fault::Invalidated)) {
                    return Ok(RestoreAuthorityResponse::for_request(
                        request, RestoreAuthorityOutcome::ScanRestartRequired,
                    ));
                }
                let (snapshot_id, offset) = if let Some(cursor) = cursor {
                    let binding = cursor.binding();
                    let id = binding.snapshot_id();
                    let Some(snapshot) = state.snapshots.get(&id) else { return Err(refused()); };
                    if binding.configuration().configuration_fingerprint != request.configuration().configuration_fingerprint
                        || binding.configuration().policy_generation != request.configuration().policy_generation
                        || binding.store_set_digest() != request.store_set_digest()
                        || binding.high_water_generation() != snapshot.high_water
                        || binding.scan_operation_id() != snapshot.scan_id
                        || binding.expires_at() != snapshot.expires_at
                        || *expires_at != snapshot.expires_at
                    { return Err(refused()); }
                    let position = binding.last_position().ok_or_else(refused)?;
                    let offset = snapshot.items.iter().position(|item| {
                        item.intent_generation == position.generation && item.operation_id == position.operation_id
                    }).ok_or_else(refused)? + 1;
                    if cursor.bytes() != cursor_token(id, offset).as_slice() { return Err(refused()); }
                    (id, offset)
                } else {
                    if state.snapshots.len() >= limits.active_snapshots {
                        return Err(RestoreAuthorityFailure { dispatch: RestoreDispatch::NotDispatched });
                    }
                    let mut items: Vec<_> = state.intents.values().cloned().collect();
                    items.sort_by_key(|item| (item.intent_generation, item.operation_id));
                    if items.len() * 256 > limits.retained_snapshot_bytes {
                        return Err(RestoreAuthorityFailure { dispatch: RestoreDispatch::NotDispatched });
                    }
                    state.next_snapshot += 1;
                    let id = state.next_snapshot.to_be_bytes();
                    let high_water = state.generation;
                    state.snapshots.insert(id, Snapshot {
                        high_water, scan_id: request.operation_id(), expires_at: *expires_at,
                        items,
                    });
                    if matches!(fault, Some(Fault::NewerIntent)) {
                        let mut extra = state.intents.values().next().unwrap().clone();
                        state.generation += 1;
                        extra.intent_generation = state.generation;
                        extra.operation_id = [0xfe; 16];
                        state.intents.insert(extra.operation_id, extra);
                    }
                    if matches!(fault, Some(Fault::ConcurrentCompletion)) {
                        let original = state.intents.values().max_by_key(|item| item.intent_generation).unwrap().clone();
                        let store = self.find(&original.store.id);
                        let fact = store.state.lock().unwrap().facts.get(&original.operation_id).cloned().unwrap();
                        state.intents.remove(&original.operation_id);
                        state.settled.insert(original.operation_id, fact.resolution().digest().unwrap());
                    }
                    (id, 0)
                };
                let snapshot = state.snapshots.get(&snapshot_id).unwrap();
                let end = (offset + limits.page_items).min(snapshot.items.len());
                let mut writes = snapshot.items[offset..end].to_vec();
                let mut high_water = snapshot.high_water;
                let mut next = (end < snapshot.items.len()).then(|| cursor_token(snapshot_id, end));
                if offset > 0 && matches!(fault, Some(Fault::HighWater)) { high_water += 1; }
                if matches!(fault, Some(Fault::Reversed)) { writes.reverse(); }
                if matches!(fault, Some(Fault::DuplicateId)) && writes.len() > 1 {
                    writes[1].operation_id = writes[0].operation_id;
                }
                if matches!(fault, Some(Fault::ForeignNamespace)) && !writes.is_empty() {
                    writes[0].store.namespace_digest[0] ^= 1;
                }
                if matches!(fault, Some(Fault::EmptyContinuation)) {
                    writes.clear(); next = Some(vec![1]);
                }
                if matches!(fault, Some(Fault::OversizedCursor)) {
                    next = Some(vec![1; limits.cursor_bytes + 1]);
                }
                if next.is_none() { state.snapshots.remove(&snapshot_id); }
                RestoreAuthorityOutcome::UnresolvedWrites(RestoreUnresolvedPage {
                    snapshot_id, high_water_generation: high_water, writes, next_cursor: next,
                })
            }
            RestoreAuthorityOperation::ReconcileWrite { intent, resolution } => {
                state.reconciliations.push((request.operation_id(), intent.operation_id()));
                if !self.find(intent.store_id()).verifies(resolution, intent.operation_id()) {
                    return Err(refused());
                }
                let digest = resolution.digest().unwrap();
                if let Some(original) = state.intents.get(&intent.operation_id()) {
                    if original.store != *intent.store()
                        || original.binding_digest != intent.binding_digest()
                        || original.store_fence_generation != intent.store_fence_generation()
                        || original.record_digest != intent.record_digest()
                    { return Err(refused()); }
                } else if state.settled.get(&intent.operation_id()) != Some(&digest) {
                    return Err(refused());
                }
                state.intents.remove(&intent.operation_id());
                state.settled.insert(intent.operation_id(), digest);
                if matches!(fault, Some(Fault::ReconcileUnknown)) {
                    return Err(RestoreAuthorityFailure { dispatch: RestoreDispatch::Unknown });
                }
                let mut echoed = digest;
                if matches!(fault, Some(Fault::ReconcileDigest)) { echoed[0] ^= 1; }
                RestoreAuthorityOutcome::Reconciled {
                    intent_operation_id: intent.operation_id(), resolution_digest: echoed,
                }
            }
        };
        Ok(RestoreAuthorityResponse::for_request(request, outcome))
    }
}

impl RestoreEpochAuthority for Authority {
    fn execute<'a>(&'a self, _cx: &'a Cx, request: &'a RestoreAuthorityRequest) -> RestoreAuthorityFuture<'a> {
        let phase = match request.operation() {
            RestoreAuthorityOperation::RegisterStoreSet { .. } => "register",
            RestoreAuthorityOperation::Current { .. } => "current",
            RestoreAuthorityOperation::PrepareWrite { .. } => "prepare",
            RestoreAuthorityOperation::CompleteWrite { .. } => "complete",
            RestoreAuthorityOperation::ListUnresolvedWrites { .. } => "scan",
            RestoreAuthorityOperation::ReconcileWrite { .. } => "reconcile",
        };
        self.effects.lock().unwrap().push((phase, Cx::current().unwrap().capabilities().spawn));
        let result = self.execute_operation(request);
        if matches!(request.operation(), RestoreAuthorityOperation::Current { .. })
            && self.yield_current_once.swap(false, Ordering::AcqRel)
        {
            let mut yielded = false;
            let mut result = Some(result);
            return Box::pin(poll_fn(move |task| {
                if yielded {
                    Poll::Ready(result.take().expect("one response"))
                } else {
                    yielded = true;
                    task.waker().wake_by_ref();
                    Poll::Pending
                }
            }));
        }
        Box::pin(std::future::ready(result))
    }
}

fn same_configuration(left: &RestoreEpochConfiguration, right: &RestoreEpochConfiguration) -> bool {
    left.authority_id == right.authority_id
        && left.provider_artifact == right.provider_artifact
        && left.provider_artifact_digest == right.provider_artifact_digest
        && left.configuration_fingerprint == right.configuration_fingerprint
        && left.authority_generation == right.authority_generation
        && left.deployment_uuid == right.deployment_uuid
        && left.store_set_generation == right.store_set_generation
        && left.policy_generation == right.policy_generation
        && left.certificate_mode == right.certificate_mode
}

fn cursor_token(snapshot: [u8; 16], offset: usize) -> Vec<u8> {
    let mut bytes = snapshot.to_vec();
    bytes.extend_from_slice(&(offset as u64).to_be_bytes());
    bytes
}

fn configuration() -> RestoreEpochConfiguration {
    RestoreEpochConfiguration {
        authority_id: "independent-recovery-authority".into(),
        provider_artifact: "recovery-fixture-is-not-qualified".into(),
        provider_artifact_digest: [1; 32],
        configuration_fingerprint: [2; 32],
        authority_generation: 3,
        deployment_uuid: [4; 16],
        store_set_generation: 5,
        policy_generation: 6,
        certificate_mode: StableCertificateMode::Forbidden,
        limits: RestoreLimits::default(),
    }
}

async fn setup(cx: &Cx) -> (RestoreEpochFacade, Arc<Authority>, Vec<Arc<Store>>) {
    let stores = vec![Arc::new(Store::new("browser", 7)), Arc::new(Store::new("replay", 8))];
    let authority = Arc::new(Authority::new(stores.clone()));
    let facade = RestoreEpochFacade::register(
        cx, configuration(), stores.iter().map(|store| store.declaration.clone()).collect(),
        authority.clone(), Time::MAX,
    ).await.unwrap();
    (facade, authority, stores)
}

fn adapters(stores: &[Arc<Store>]) -> Vec<Arc<dyn RestoreStoreRecovery>> {
    stores.iter().map(|store| store.clone() as Arc<dyn RestoreStoreRecovery>).collect()
}

async fn prepare(cx: &Cx, facade: &RestoreEpochFacade, id: &str, value: u8) -> RestoreWriteFence {
    facade.store(id).unwrap().prepare_write(cx, [value; 32], Time::MAX).await.unwrap()
}

async fn abandon_two(cx: &Cx, facade: &RestoreEpochFacade) -> ([u8; 16], [u8; 16]) {
    let first = prepare(cx, facade, "browser", 11).await;
    let second = prepare(cx, facade, "replay", 12).await;
    let ids = (first.operation_id(), second.operation_id());
    drop(first);
    drop(second);
    ids
}

fn refused<T>(result: Result<T, RestoreError>, expected: RestoreError) {
    assert_eq!(result.err(), Some(expected));
}


#[test]
fn committed_and_fenced_orphans_recover_across_pages_into_fresh_handles() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        let first = prepare(&cx, &facade, "browser", 11).await;
        let second = prepare(&cx, &facade, "replay", 12).await;
        let first_id = first.operation_id();
        let second_id = second.operation_id();
        let binding = first.binding_digest();
        let _receipt = stores[0].commit(&first);
        drop(first);
        drop(second);
        let old = facade.store("browser").unwrap();
        let outcome = facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits {
            page_items: 1, ..RestoreRecoveryLimits::default()
        }, Time::MAX).await.unwrap();
        assert_eq!(outcome.summary().pages, 2);
        assert_eq!(outcome.summary().committed, 1);
        assert_eq!(outcome.summary().fenced_not_committed, 1);
        assert!(outcome.registration_error().is_none());
        let recovered = outcome.into_facade().unwrap();
        assert!(facade.is_quarantined());
        refused(old.prepare_write(&cx, [1; 32], Time::MAX).await, RestoreError::Quarantined);
        assert!(!recovered.is_quarantined());
        let observation = recovered.store("browser").unwrap().current_binding(&cx, Time::MAX).await.unwrap();
        assert_eq!(observation.binding().digest(), binding);
        observation.check(&cx).unwrap();
        let state = authority.state.lock().unwrap();
        assert!(state.intents.is_empty());
        assert!(state.snapshots.is_empty());
        assert_eq!(state.registrations, 2);
        assert_eq!(state.reconciliations.len(), 2);
        assert_eq!(state.reconciliations[0].1, first_id);
        assert_eq!(state.reconciliations[1].1, second_id);
        assert!(state.reconciliations.iter().all(|(transaction, original)| transaction != original));
    });
}

#[test]
fn proved_concurrent_cas_loser_settles_without_quarantining_other_stores() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        let winner = prepare(&cx, &facade, "browser", 11).await;
        let loser = prepare(&cx, &facade, "browser", 12).await;
        let loser_id = loser.operation_id();
        assert_eq!(winner.store_fence_generation(), loser.store_fence_generation());
        let committed = stores[0].commit(&winner);
        facade.store("browser").unwrap().complete_write(&cx, winner, committed, Time::MAX).await.unwrap();
        let terminal = stores[0].fence(&loser);
        let settled = facade.store("browser").unwrap()
            .reconcile_write(&cx, loser, terminal, Time::MAX).await.unwrap();
        assert_eq!(settled.operation_id(), loser_id);
        assert!(matches!(settled.outcome(), RestoreWriteResolution::FencedNotCommitted { .. }));
        assert!(!facade.is_quarantined());
        assert!(authority.state.lock().unwrap().intents.is_empty());
        let next = prepare(&cx, &facade, "replay", 13).await;
        let proof = stores[1].commit(&next);
        facade.store("replay").unwrap().complete_write(&cx, next, proof, Time::MAX).await.unwrap();
        assert!(!facade.is_quarantined());
    });
}

#[test]
fn forged_noncommit_receipt_cannot_release_an_intent() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, _stores) = setup(&cx).await;
        let fence = prepare(&cx, &facade, "browser", 11).await;
        let forged = DurableRestoreNonCommitReceipt::new(
            fence.operation_id(), fence.binding_digest(), fence.store_fence_generation(),
            fence.record_digest(), fence.store_fence_generation() + 1, b"not-durable-proof".to_vec(),
        ).unwrap();
        refused(facade.store("browser").unwrap().reconcile_write(
            &cx, fence, DurableRestoreResolution::FencedNotCommitted(forged), Time::MAX,
        ).await, RestoreError::Uncertain);
        assert!(facade.is_quarantined());
        assert_eq!(authority.state.lock().unwrap().intents.len(), 1);
    });
}

#[test]
fn evidence_for_another_operation_is_rejected_before_authority_dispatch() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, _stores) = setup(&cx).await;
        let fence = prepare(&cx, &facade, "browser", 11).await;
        let wrong = DurableRestoreNonCommitReceipt::new(
            [0xff; 16], fence.binding_digest(), fence.store_fence_generation(),
            fence.record_digest(), fence.store_fence_generation() + 1, vec![1],
        ).unwrap();
        refused(facade.store("browser").unwrap().reconcile_write(
            &cx, fence, DurableRestoreResolution::FencedNotCommitted(wrong), Time::MAX,
        ).await, RestoreError::InvalidReceipt);
        assert!(facade.is_quarantined());
        assert!(authority.state.lock().unwrap().reconciliations.is_empty());
        assert_eq!(authority.state.lock().unwrap().intents.len(), 1);
    });
}

#[test]
fn live_fence_ownership_prevents_recovery_dispatch() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        let fence = prepare(&cx, &facade, "browser", 11).await;
        refused(facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX).await,
            RestoreError::RecoveryBusy);
        assert_eq!(authority.state.lock().unwrap().lists, 0);
        assert!(facade.is_quarantined());
        drop(fence);
        let recovered = facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX)
            .await.unwrap().into_facade().unwrap();
        assert!(!recovered.is_quarantined());
    });
}

#[test]
fn recovery_refuses_missing_duplicate_and_foreign_store_union() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        refused(facade.recover(&cx, vec![stores[0].clone()], RestoreRecoveryLimits::default(), Time::MAX).await,
            RestoreError::InvalidConfiguration);
        refused(facade.recover(&cx, vec![stores[0].clone(), stores[0].clone()],
            RestoreRecoveryLimits::default(), Time::MAX).await, RestoreError::InvalidConfiguration);
        let foreign = Arc::new(Store::new("replay", 99));
        refused(facade.recover(&cx, vec![stores[0].clone(), foreign],
            RestoreRecoveryLimits::default(), Time::MAX).await, RestoreError::InvalidConfiguration);
        assert_eq!(authority.state.lock().unwrap().lists, 0);
        assert!(!facade.is_quarantined());
    });
}

#[test]
fn concurrent_completion_keeps_snapshot_tombstone_and_is_reconciled_idempotently() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        let first = prepare(&cx, &facade, "browser", 11).await;
        let second = prepare(&cx, &facade, "replay", 12).await;
        let second_id = second.operation_id();
        let _proof = stores[1].commit(&second);
        drop(first);
        drop(second);
        authority.inject(Fault::ConcurrentCompletion);
        let outcome = facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits {
            page_items: 1, ..RestoreRecoveryLimits::default()
        }, Time::MAX).await.unwrap();
        assert_eq!(outcome.summary().pages, 2);
        assert_eq!(outcome.summary().committed, 1);
        assert_eq!(outcome.summary().fenced_not_committed, 1);
        assert!(outcome.registration_error().is_none());
        assert_eq!(stores[1].state.lock().unwrap().queried.as_slice(), &[second_id]);
        assert!(authority.state.lock().unwrap().intents.is_empty());
    });
}

#[test]
fn newer_than_snapshot_intent_prevents_fresh_registration() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        drop(prepare(&cx, &facade, "browser", 11).await);
        authority.inject(Fault::NewerIntent);
        let outcome = facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX).await.unwrap();
        assert_eq!(outcome.summary().fenced_not_committed, 1);
        assert_eq!(outcome.registration_error(), Some(RestoreError::Uncertain));
        refused(outcome.into_facade(), RestoreError::Uncertain);
        assert!(facade.is_quarantined());
        assert_eq!(authority.state.lock().unwrap().intents.len(), 1);
        assert_eq!(authority.state.lock().unwrap().registrations, 1);
    });
}

#[test]
fn fresh_registration_cannot_adopt_a_changed_stable_epoch() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        drop(prepare(&cx, &facade, "browser", 11).await);
        authority.inject(Fault::ChangedBinding);
        let outcome = facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX).await.unwrap();
        assert_eq!(outcome.registration_error(), Some(RestoreError::Quarantined));
        refused(outcome.into_facade(), RestoreError::Quarantined);
        assert!(facade.is_quarantined());
        assert!(authority.state.lock().unwrap().intents.is_empty());
    });
}

#[test]
fn changing_snapshot_high_water_cannot_skip_the_remaining_intent() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        abandon_two(&cx, &facade).await;
        authority.inject(Fault::HighWater);
        refused(facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits {
            page_items: 1, ..RestoreRecoveryLimits::default()
        }, Time::MAX).await, RestoreError::InvalidReceipt);
        assert!(facade.is_quarantined());
        assert_eq!(authority.state.lock().unwrap().intents.len(), 1);
        assert_eq!(authority.state.lock().unwrap().registrations, 1);
        assert!(stores[1].state.lock().unwrap().queried.is_empty());
    });
}

#[test]
fn malformed_whole_page_is_refused_before_any_store_recovery() {
    for fault in [Fault::Reversed, Fault::DuplicateId, Fault::ForeignNamespace, Fault::EmptyContinuation, Fault::OversizedCursor] {
        block_on(async {
            let cx = Cx::current().unwrap();
            let (facade, authority, stores) = setup(&cx).await;
            abandon_two(&cx, &facade).await;
            authority.inject(fault);
            refused(facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX).await,
                RestoreError::InvalidReceipt);
            assert!(stores.iter().all(|store| store.state.lock().unwrap().queried.is_empty()));
            assert_eq!(authority.state.lock().unwrap().intents.len(), 2);
            assert_eq!(authority.state.lock().unwrap().registrations, 1);
        });
    }
}

#[test]
fn page_byte_limit_is_independent_of_page_item_limit() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        abandon_two(&cx, &facade).await;
        refused(facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits {
            page_bytes: 256, page_items: 100, ..RestoreRecoveryLimits::default()
        }, Time::MAX).await, RestoreError::InvalidReceipt);
        assert!(stores.iter().all(|store| store.state.lock().unwrap().queried.is_empty()));
        assert_eq!(authority.state.lock().unwrap().intents.len(), 2);
    });
}

#[test]
fn snapshot_invalidation_requires_explicit_restart_without_local_reset() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        drop(prepare(&cx, &facade, "browser", 11).await);
        authority.inject(Fault::Invalidated);
        refused(facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX).await,
            RestoreError::ScanRestartRequired);
        assert_eq!(authority.state.lock().unwrap().intents.len(), 1);
        *authority.fault.lock().unwrap() = None;
        let recovered = facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX)
            .await.unwrap().into_facade().unwrap();
        assert!(facade.is_quarantined());
        assert!(!recovered.is_quarantined());
    });
}

#[test]
fn lost_reconciliation_ack_is_resolved_by_new_scan_of_original_intents() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        let fence = prepare(&cx, &facade, "browser", 11).await;
        let original_id = fence.operation_id();
        drop(fence);
        authority.inject(Fault::ReconcileUnknown);
        refused(facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX).await,
            RestoreError::Uncertain);
        assert!(facade.is_quarantined());
        assert!(authority.state.lock().unwrap().intents.is_empty());
        assert!(authority.state.lock().unwrap().settled.contains_key(&original_id));
        *authority.fault.lock().unwrap() = None;
        let outcome = facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX).await.unwrap();
        assert_eq!(outcome.summary().committed + outcome.summary().fenced_not_committed, 0);
        assert!(outcome.registration_error().is_none());
        assert_eq!(authority.state.lock().unwrap().reconciliations.len(), 1, "no blind repeat mutation");
    });
}

#[test]
fn wrong_reconciliation_digest_keeps_old_handles_closed() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        drop(prepare(&cx, &facade, "browser", 11).await);
        authority.inject(Fault::ReconcileDigest);
        refused(facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX).await,
            RestoreError::InvalidReceipt);
        assert!(facade.is_quarantined());
        assert_eq!(authority.state.lock().unwrap().registrations, 1);
    });
}

#[test]
fn unknown_store_outcome_is_never_inferred_from_an_absent_record() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        drop(prepare(&cx, &facade, "browser", 11).await);
        stores[0].unknown.store(true, Ordering::Release);
        refused(facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX).await,
            RestoreError::Uncertain);
        assert!(stores[0].state.lock().unwrap().facts.is_empty());
        assert_eq!(authority.state.lock().unwrap().intents.len(), 1);
        assert!(authority.state.lock().unwrap().reconciliations.is_empty());
        assert!(facade.is_quarantined());
    });
}

#[test]
fn rate_limit_survives_repeated_recovery_attempts_on_the_same_facade() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        abandon_two(&cx, &facade).await;
        let limits = RestoreRecoveryLimits { reconciliations_per_minute: 1, ..RestoreRecoveryLimits::default() };
        refused(facade.recover(&cx, adapters(&stores), limits, Time::MAX).await, RestoreError::CapacityExceeded);
        assert_eq!(authority.state.lock().unwrap().intents.len(), 1);
        refused(facade.recover(&cx, adapters(&stores), limits, Time::MAX).await, RestoreError::CapacityExceeded);
        assert_eq!(authority.state.lock().unwrap().reconciliations.len(), 1);
        assert!(facade.is_quarantined());
    });
}

#[test]
fn abandoned_snapshot_capacity_is_reserved_by_authority_across_attempts() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        abandon_two(&cx, &facade).await;
        stores[0].unknown.store(true, Ordering::Release);
        let limits = RestoreRecoveryLimits { page_items: 1, active_snapshots: 1, ..RestoreRecoveryLimits::default() };
        refused(facade.recover(&cx, adapters(&stores), limits, Time::MAX).await, RestoreError::Uncertain);
        assert_eq!(authority.state.lock().unwrap().snapshots.len(), 1);
        refused(facade.recover(&cx, adapters(&stores), limits, Time::MAX).await, RestoreError::ProviderUnavailable);
        assert_eq!(authority.state.lock().unwrap().snapshots.len(), 1);
        assert_eq!(authority.state.lock().unwrap().intents.len(), 2);
        assert!(facade.is_quarantined());
    });
}

#[test]
fn invalid_recovery_limits_do_not_retire_a_healthy_facade() {
    for limits in [
        RestoreRecoveryLimits { active_snapshots: 0, ..RestoreRecoveryLimits::default() },
        RestoreRecoveryLimits { active_snapshots: 33, ..RestoreRecoveryLimits::default() },
        RestoreRecoveryLimits { retained_snapshot_bytes: 128 * 1024 * 1024 + 1, ..RestoreRecoveryLimits::default() },
        RestoreRecoveryLimits { page_items: 4097, ..RestoreRecoveryLimits::default() },
        RestoreRecoveryLimits { backlog: 16_385, ..RestoreRecoveryLimits::default() },
    ] {
        block_on(async {
            let cx = Cx::current().unwrap();
            let (facade, authority, stores) = setup(&cx).await;
            refused(facade.recover(&cx, adapters(&stores), limits, Time::MAX).await,
                RestoreError::InvalidConfiguration);
            assert_eq!(authority.state.lock().unwrap().lists, 0);
            assert!(!facade.is_quarantined());
        });
    }
}

struct Noop;
impl Wake for Noop {
    fn wake(self: Arc<Self>) {}
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(&Waker::from(Arc::new(Noop))))
}

#[test]
fn abandoned_store_future_releases_local_lease_without_losing_durable_intent() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        drop(prepare(&cx, &facade, "browser", 11).await);
        stores[0].pending.store(true, Ordering::Release);
        let mut recovery = Box::pin(facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX));
        assert!(poll_once(recovery.as_mut()).is_pending());
        assert!(facade.stores[0].shared.recovering.load(Ordering::Acquire));
        refused(facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX).await,
            RestoreError::RecoveryBusy);
        drop(recovery);
        assert!(!facade.stores[0].shared.recovering.load(Ordering::Acquire));
        assert_eq!(facade.stores[0].shared.calls.load(Ordering::Acquire), 0);
        assert!(facade.is_quarantined());
        assert_eq!(authority.state.lock().unwrap().intents.len(), 1);
        assert_eq!(stores[0].drop_effects.lock().unwrap().len(), 1);
        stores[0].pending.store(false, Ordering::Release);
        let recovered = facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX)
            .await.unwrap().into_facade().unwrap();
        assert!(!recovered.is_quarantined());
    });
}

#[test]
fn binding_observation_cannot_survive_its_facades_quarantine() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, _authority, _stores) = setup(&cx).await;
        let store = facade.store("browser").unwrap();
        let observation = store.current_binding(&cx, Time::MAX).await.unwrap();
        assert_eq!(observation.configuration().deployment_uuid, configuration().deployment_uuid);
        assert_eq!(observation.namespace_digest(), store.namespace_digest());
        assert_eq!(observation.store_set_digest(), store.store_set_digest());
        assert_eq!(observation.store_id(), store.store_id());
        observation.check(&cx).unwrap();
        let fence = prepare(&cx, &facade, "browser", 11).await;
        assert_eq!(fence.binding().digest(), observation.binding().digest());
        fence.check(&cx).unwrap();
        drop(fence);
        refused(observation.check(&cx), RestoreError::Quarantined);
    });
}

#[test]
fn noncommit_receipt_requires_a_new_durable_fence_and_bounded_proof() {
    for (old, new, proof) in [(0, 1, vec![1]), (1, 1, vec![1]), (2, 1, vec![1]), (1, 2, Vec::new()), (1, 2, vec![1; MAX_COMMIT_PROOF + 1])] {
        refused(DurableRestoreNonCommitReceipt::new([1; 16], [2; 32], old, [3; 32], new, proof),
            RestoreError::InvalidReceipt);
    }
}


fn declared(stores: &[Arc<Store>]) -> Vec<RestoreStoreDeclaration> {
    stores.iter().map(|store| store.declaration.clone()).collect()
}

#[test]
fn cold_start_recovers_committed_and_noncommitted_intents_without_initial_registration() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        let committed = prepare(&cx, &facade, "browser", 31).await;
        let uncommitted = prepare(&cx, &facade, "replay", 32).await;
        let committed_id = committed.operation_id();
        let uncommitted_id = uncommitted.operation_id();
        let binding = committed.binding_digest();
        let _receipt = stores[0].commit(&committed);
        drop(committed);
        drop(uncommitted);
        drop(facade);
        refused(RestoreEpochFacade::register(
            &cx, configuration(), declared(&stores), authority.clone(), Time::MAX,
        ).await, RestoreError::Uncertain);
        let before = authority.state.lock().unwrap().registration_attempts;
        let outcome = RestoreEpochFacade::recover_after_restart(
            &cx, configuration(), declared(&stores), authority.clone(), adapters(&stores),
            RestoreRecoveryLimits { page_items: 1, ..RestoreRecoveryLimits::default() }, Time::MAX,
        ).await.unwrap();
        assert_eq!(outcome.summary().committed, 1);
        assert_eq!(outcome.summary().fenced_not_committed, 1);
        assert_eq!(outcome.summary().pages, 2);
        let recovered = outcome.into_facade().unwrap();
        assert!(!recovered.is_quarantined());
        let observed = recovered.store("browser").unwrap().current_binding(&cx, Time::MAX).await.unwrap();
        assert_eq!(observed.binding().digest(), binding);
        let state = authority.state.lock().unwrap();
        assert!(state.intents.is_empty());
        assert_eq!(state.registration_attempts, before + 1, "only the final real admission transaction");
        assert!(state.settled.contains_key(&committed_id));
        assert!(state.settled.contains_key(&uncommitted_id));
    });
}

#[test]
fn cold_start_shape_valid_store_subset_cannot_scan_the_registered_union() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        abandon_two(&cx, &facade).await;
        drop(facade);
        refused(RestoreEpochFacade::recover_after_restart(
            &cx, configuration(), vec![stores[0].declaration.clone()], authority.clone(),
            vec![stores[0].clone()], RestoreRecoveryLimits::default(), Time::MAX,
        ).await, RestoreError::Uncertain);
        let state = authority.state.lock().unwrap();
        assert_eq!(state.lists, 0);
        assert!(state.reconciliations.is_empty());
        assert_eq!(state.intents.len(), 2);
        assert_eq!(state.registrations, 1);
    });
}

#[test]
fn cold_start_changed_configuration_cannot_adopt_existing_authority_state() {
    for changed in 0..3 {
        block_on(async {
            let cx = Cx::current().unwrap();
            let (facade, authority, stores) = setup(&cx).await;
            drop(prepare(&cx, &facade, "browser", 31).await);
            drop(facade);
            let mut config = configuration();
            match changed {
                0 => config.deployment_uuid[0] ^= 1,
                1 => config.configuration_fingerprint[0] ^= 1,
                _ => config.policy_generation += 1,
            }
            refused(RestoreEpochFacade::recover_after_restart(
                &cx, config, declared(&stores), authority.clone(), adapters(&stores),
                RestoreRecoveryLimits::default(), Time::MAX,
            ).await, RestoreError::Uncertain);
            let state = authority.state.lock().unwrap();
            assert_eq!(state.lists, 0);
            assert!(state.reconciliations.is_empty());
            assert_eq!(state.intents.len(), 1);
            assert_eq!(state.registrations, 1);
        });
    }
}

#[test]
fn cold_start_newer_unresolved_intent_still_blocks_final_registration() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        drop(prepare(&cx, &facade, "browser", 31).await);
        drop(facade);
        authority.inject(Fault::NewerIntent);
        let outcome = RestoreEpochFacade::recover_after_restart(
            &cx, configuration(), declared(&stores), authority.clone(), adapters(&stores),
            RestoreRecoveryLimits::default(), Time::MAX,
        ).await.unwrap();
        assert_eq!(outcome.summary().fenced_not_committed, 1);
        assert_eq!(outcome.registration_error(), Some(RestoreError::Uncertain));
        refused(outcome.into_facade(), RestoreError::Uncertain);
        let state = authority.state.lock().unwrap();
        assert_eq!(state.intents.len(), 1);
        assert!(state.intents.contains_key(&[0xfe; 16]));
        assert_eq!(state.registrations, 1);
    });
}

#[test]
fn cold_start_unknown_store_proof_preserves_intent_for_later_operator_attempt() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        let fence = prepare(&cx, &facade, "browser", 31).await;
        let original = fence.operation_id();
        drop(fence);
        drop(facade);
        stores[0].unknown.store(true, Ordering::Release);
        refused(RestoreEpochFacade::recover_after_restart(
            &cx, configuration(), declared(&stores), authority.clone(), adapters(&stores),
            RestoreRecoveryLimits::default(), Time::MAX,
        ).await, RestoreError::Uncertain);
        assert!(authority.state.lock().unwrap().intents.contains_key(&original));
        assert!(stores[0].state.lock().unwrap().facts.is_empty());
        assert_eq!(authority.state.lock().unwrap().registrations, 1);
        stores[0].unknown.store(false, Ordering::Release);
        let recovered = RestoreEpochFacade::recover_after_restart(
            &cx, configuration(), declared(&stores), authority.clone(), adapters(&stores),
            RestoreRecoveryLimits::default(), Time::MAX,
        ).await.unwrap().into_facade().unwrap();
        assert!(!recovered.is_quarantined());
        assert!(authority.state.lock().unwrap().intents.is_empty());
        assert_eq!(stores[0].state.lock().unwrap().queried, vec![original, original]);
    });
}

#[test]
fn cold_start_cannot_create_a_new_authority_registration_or_epoch() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let stores = vec![Arc::new(Store::new("browser", 7)), Arc::new(Store::new("replay", 8))];
        let authority = Arc::new(Authority::new(stores.clone()));
        refused(RestoreEpochFacade::recover_after_restart(
            &cx, configuration(), declared(&stores), authority.clone(), adapters(&stores),
            RestoreRecoveryLimits::default(), Time::MAX,
        ).await, RestoreError::Uncertain);
        let state = authority.state.lock().unwrap();
        assert!(state.stores.is_empty());
        assert_eq!(state.lists, 0);
        assert_eq!(state.registration_attempts, 0);
        assert_eq!(state.registrations, 0);
    });
}

#[test]
fn cold_start_final_current_must_match_the_preserved_scan_binding() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        drop(prepare(&cx, &facade, "browser", 31).await);
        drop(facade);
        authority.inject(Fault::ChangedBinding);
        let outcome = RestoreEpochFacade::recover_after_restart(
            &cx, configuration(), declared(&stores), authority.clone(), adapters(&stores),
            RestoreRecoveryLimits::default(), Time::MAX,
        ).await.unwrap();
        assert_eq!(outcome.registration_error(), Some(RestoreError::Quarantined));
        refused(outcome.into_facade(), RestoreError::Quarantined);
        assert!(authority.state.lock().unwrap().intents.is_empty());
    });
}


#[test]
fn preparation_retains_earlier_narrow_ceiling_across_current_to_prepare_transition() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        authority.effects.lock().unwrap().clear();
        authority.yield_current_once.store(true, Ordering::Release);
        let store = facade.store("browser").unwrap();
        let mut preparation = Box::pin(store.prepare_write(&cx, [41; 32], Time::MAX));
        {
            let _restriction = Cx::push_restriction(CapSet::<false, true, true, true, true>::MASK);
            assert!(poll_once(preparation.as_mut()).is_pending());
        }
        assert!(Cx::current().unwrap().capabilities().spawn);
        let fence = preparation.await.unwrap();
        assert_eq!(authority.effects.lock().unwrap().as_slice(), &[("current", false), ("prepare", false)]);
        let receipt = stores[0].commit(&fence);
        store.complete_write(&cx, fence, receipt, Time::MAX).await.unwrap();
        assert!(!facade.is_quarantined());
    });
}

#[test]
fn recovery_retains_earlier_narrow_ceiling_across_scan_store_reconcile_and_register() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        drop(prepare(&cx, &facade, "browser", 41).await);
        authority.effects.lock().unwrap().clear();
        authority.yield_current_once.store(true, Ordering::Release);
        let mut recovery = Box::pin(facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX));
        {
            let _restriction = Cx::push_restriction(CapSet::<false, true, true, true, true>::MASK);
            assert!(poll_once(recovery.as_mut()).is_pending());
        }
        assert!(Cx::current().unwrap().capabilities().spawn);
        let recovered = recovery.await.unwrap().into_facade().unwrap();
        assert!(!recovered.is_quarantined());
        assert!(authority.effects.lock().unwrap().iter().all(|(_, spawn)| !spawn));
        assert_eq!(stores[0].recover_effects.lock().unwrap().as_slice(), &[false]);
        let effects = authority.effects.lock().unwrap();
        for required in ["current", "scan", "reconcile", "register"] {
            assert!(effects.iter().any(|(phase, _)| *phase == required));
        }
    });
}

#[test]
fn recovery_drop_after_later_provider_transition_keeps_the_original_ceiling() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let (facade, authority, stores) = setup(&cx).await;
        drop(prepare(&cx, &facade, "browser", 41).await);
        authority.yield_current_once.store(true, Ordering::Release);
        stores[0].pending.store(true, Ordering::Release);
        let mut recovery = Box::pin(facade.recover(&cx, adapters(&stores), RestoreRecoveryLimits::default(), Time::MAX));
        {
            let _restriction = Cx::push_restriction(CapSet::<false, true, true, true, true>::MASK);
            assert!(poll_once(recovery.as_mut()).is_pending());
        }
        assert!(Cx::current().unwrap().capabilities().spawn);
        assert!(poll_once(recovery.as_mut()).is_pending(), "later store provider is now pending");
        drop(recovery);
        assert_eq!(stores[0].drop_effects.lock().unwrap().as_slice(), &[[false, true, true, true, true]]);
        assert_eq!(stores[0].recover_effects.lock().unwrap().as_slice(), &[false]);
        assert!(facade.is_quarantined());
        assert_eq!(authority.state.lock().unwrap().intents.len(), 1);
    });
}
