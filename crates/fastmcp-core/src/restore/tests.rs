//! Stateful conformance fixtures for the restore facade. These actors are
//! deliberately in-memory test doubles: they prove protocol coupling and local
//! failure behavior, not external persistence or provider qualification.

use super::*;
use std::collections::BTreeMap;
use std::task::{Context, Waker};

use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};

use crate::runtime::block_on;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Register,
    Current,
    Prepare,
    StoreCommit,
    Complete,
    Scan,
    Reconcile,
}

fn phase(operation: &RestoreAuthorityOperation) -> Phase {
    match operation {
        RestoreAuthorityOperation::RegisterStoreSet { .. } => Phase::Register,
        RestoreAuthorityOperation::Current { .. } => Phase::Current,
        RestoreAuthorityOperation::PrepareWrite { .. } => Phase::Prepare,
        RestoreAuthorityOperation::CompleteWrite { .. } => Phase::Complete,
        RestoreAuthorityOperation::ListUnresolvedWrites { .. } => Phase::Scan,
        RestoreAuthorityOperation::ReconcileWrite { .. } => Phase::Reconcile,
    }
}

#[derive(Clone, Copy)]
enum Fault {
    NotDispatched,
    UnknownAfterDispatch,
    FailedAfterDispatch,
    PendingAfterDispatch,
    CancelAfterDispatch,
    WrongOperation,
    WrongRequestDigest,
    WrongDispatch,
    WrongBinding,
    WrongGeneration,
    WrongCompletion,
    InvalidCertificate,
}

#[derive(Clone)]
struct Intent {
    store: String,
    binding: [u8; 32],
    generation: u64,
    record: [u8; 32],
}

struct StoreCommit {
    digest: [u8; 32],
    proof: Vec<u8>,
}

#[derive(Default)]
struct AuthorityState {
    events: Vec<Phase>,
    requests: Vec<(Phase, [u8; 16], [u8; 32])>,
    stores: Vec<RestoreStoreDeclaration>,
    generations: BTreeMap<String, u64>,
    intents: BTreeMap<[u8; 16], Intent>,
    commits: BTreeMap<[u8; 16], StoreCommit>,
    epoch: u128,
}

struct Authority {
    state: Mutex<AuthorityState>,
    fault: Mutex<Option<(Phase, Fault)>>,
    drops: Arc<Mutex<Vec<[bool; 5]>>>,
}

impl Default for Authority {
    fn default() -> Self {
        Self {
            state: Mutex::new(AuthorityState {
                epoch: 7,
                ..AuthorityState::default()
            }),
            fault: Mutex::new(None),
            drops: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Authority {
    fn inject(&self, phase: Phase, fault: Fault) {
        *self.fault.lock().unwrap() = Some((phase, fault));
    }

    fn calls(&self) -> usize {
        self.state.lock().unwrap().requests.len()
    }

    fn intents(&self) -> usize {
        self.state.lock().unwrap().intents.len()
    }

    fn events(&self) -> Vec<Phase> {
        self.state.lock().unwrap().events.clone()
    }

    fn execute_operation(
        &self,
        request: &RestoreAuthorityRequest,
    ) -> Result<RestoreAuthorityResponse, RestoreAuthorityFailure> {
        let mut state = self.state.lock().unwrap();
        let refused = || RestoreAuthorityFailure {
            dispatch: RestoreDispatch::Dispatched,
        };
        let outcome = match request.operation() {
            RestoreAuthorityOperation::RegisterStoreSet { stores } => {
                if !state.stores.is_empty() || !state.intents.is_empty() {
                    return Err(refused());
                }
                state.stores = stores.clone();
                for store in stores {
                    state.generations.insert(store.id.clone(), 1);
                }
                RestoreAuthorityOutcome::Registered {
                    store_set_digest: request.store_set_digest(),
                }
            }
            RestoreAuthorityOperation::Current { store } => {
                if !state.stores.contains(store) {
                    return Err(refused());
                }
                let certified = certified(request.configuration(), store, state.epoch)
                    .canonical_bytes()
                    .unwrap();
                RestoreAuthorityOutcome::Current {
                    certified_binding: certified,
                    store_fence_generation: *state.generations.get(&store.id).unwrap(),
                }
            }
            RestoreAuthorityOperation::PrepareWrite {
                store,
                binding_digest,
                store_fence_generation,
                record_digest,
                ..
            } => {
                if !state.stores.contains(store) {
                    return Err(refused());
                }
                let expected = certified(request.configuration(), store, state.epoch)
                    .canonical_bytes()
                    .unwrap();
                if *binding_digest != hash(&expected).unwrap()
                    || state.generations.get(&store.id) != Some(store_fence_generation)
                    || state.intents.contains_key(&request.operation_id())
                {
                    return Err(refused());
                }
                state.intents.insert(
                    request.operation_id(),
                    Intent {
                        store: store.id.clone(),
                        binding: *binding_digest,
                        generation: *store_fence_generation,
                        record: *record_digest,
                    },
                );
                RestoreAuthorityOutcome::Prepared {
                    binding_digest: *binding_digest,
                    store_fence_generation: *store_fence_generation,
                }
            }
            RestoreAuthorityOperation::CompleteWrite {
                store,
                intent_operation_id,
                receipt,
            } => {
                let Some(intent) = state.intents.get(intent_operation_id) else {
                    return Err(refused());
                };
                let Some(committed) = state.commits.get(intent_operation_id) else {
                    return Err(refused());
                };
                if intent.store != store.id
                    || receipt.operation_id() != *intent_operation_id
                    || receipt.binding_digest() != intent.binding
                    || receipt.store_fence_generation() != intent.generation
                    || receipt.record_digest() != intent.record
                    || receipt.commit_digest() != committed.digest
                    || receipt.proof() != committed.proof.as_slice()
                {
                    return Err(refused());
                }
                let commit_digest = committed.digest;
                state.intents.remove(intent_operation_id);
                RestoreAuthorityOutcome::Completed {
                    intent_operation_id: *intent_operation_id,
                    commit_digest,
                }
            }
            RestoreAuthorityOperation::ListUnresolvedWrites { .. }
            | RestoreAuthorityOperation::ReconcileWrite { .. } => {
                return Err(RestoreAuthorityFailure { dispatch: RestoreDispatch::NotDispatched });
            }
        };
        Ok(RestoreAuthorityResponse::for_request(request, outcome))
    }

    /// A different actor records the CAS witness before authority completion.
    /// This test ledger is not claimed to survive a crash or a memory clone.
    fn commit_store(&self, fence: &RestoreWriteFence) -> DurableRestoreCommitReceipt {
        let mut state = self.state.lock().unwrap();
        let intent = state.intents.get(&fence.operation_id()).unwrap().clone();
        assert_eq!(intent.store, fence.store_id());
        assert_eq!(intent.binding, fence.binding_digest());
        assert_eq!(intent.record, fence.record_digest());
        assert_eq!(intent.generation, fence.store_fence_generation());
        let generation = state.generations.get_mut(&intent.store).unwrap();
        assert_eq!(
            *generation, intent.generation,
            "the store CAS uses the prepared generation"
        );
        *generation += 1;
        let mut proof = b"restore-store-commit-witness-v1".to_vec();
        proof.extend_from_slice(&fence.operation_id());
        proof.extend_from_slice(&fence.binding_digest());
        proof.extend_from_slice(&fence.store_fence_generation().to_be_bytes());
        proof.extend_from_slice(&fence.record_digest());
        let digest = hash(&proof).unwrap();
        state.commits.insert(
            fence.operation_id(),
            StoreCommit {
                digest,
                proof: proof.clone(),
            },
        );
        state.events.push(Phase::StoreCommit);
        DurableRestoreCommitReceipt::new(
            fence.operation_id(),
            fence.binding_digest(),
            fence.store_fence_generation(),
            fence.record_digest(),
            digest,
            proof,
        )
        .unwrap()
    }
}

struct ObserveDrop(Arc<Mutex<Vec<[bool; 5]>>>);

impl Drop for ObserveDrop {
    fn drop(&mut self) {
        let current = Cx::current().expect("provider destruction retains its caller");
        let caps = current.capabilities();
        self.0
            .lock()
            .unwrap()
            .push([caps.spawn, caps.time, caps.entropy, caps.io, caps.remote]);
    }
}

impl RestoreEpochAuthority for Authority {
    fn execute<'a>(
        &'a self,
        cx: &'a Cx,
        request: &'a RestoreAuthorityRequest,
    ) -> RestoreAuthorityFuture<'a> {
        let stage = phase(request.operation());
        {
            let mut state = self.state.lock().unwrap();
            state.events.push(stage);
            state
                .requests
                .push((stage, request.operation_id(), request.request_digest()));
        }
        let fault = {
            let mut selected = self.fault.lock().unwrap();
            if selected
                .as_ref()
                .is_some_and(|(expected, _)| *expected == stage)
            {
                selected.take().map(|(_, fault)| fault)
            } else {
                None
            }
        };
        if matches!(fault, Some(Fault::NotDispatched)) {
            return Box::pin(std::future::ready(Err(RestoreAuthorityFailure {
                dispatch: RestoreDispatch::NotDispatched,
            })));
        }
        let mut response = match self.execute_operation(request) {
            Ok(response) => response,
            Err(failure) => return Box::pin(std::future::ready(Err(failure))),
        };
        match fault {
            Some(Fault::UnknownAfterDispatch) => {
                return Box::pin(std::future::ready(Err(RestoreAuthorityFailure {
                    dispatch: RestoreDispatch::Unknown,
                })));
            }
            Some(Fault::FailedAfterDispatch) => {
                return Box::pin(std::future::ready(Err(RestoreAuthorityFailure {
                    dispatch: RestoreDispatch::Dispatched,
                })));
            }
            Some(Fault::PendingAfterDispatch) => {
                let observer = ObserveDrop(Arc::clone(&self.drops));
                return Box::pin(async move {
                    let _observer = observer;
                    std::future::pending().await
                });
            }
            Some(Fault::CancelAfterDispatch) => {
                return Box::pin(poll_fn(move |_| {
                    cx.set_cancel_requested(true);
                    Poll::Pending
                }));
            }
            Some(Fault::WrongOperation) => response.operation_id[0] ^= 1,
            Some(Fault::WrongRequestDigest) => response.request_digest[0] ^= 1,
            Some(Fault::WrongDispatch) => response.dispatch = RestoreDispatch::NotDispatched,
            Some(Fault::WrongBinding) => {
                let RestoreAuthorityOutcome::Prepared { binding_digest, .. } =
                    &mut response.outcome
                else {
                    panic!("fault is for preparation");
                };
                binding_digest[0] ^= 1;
            }
            Some(Fault::WrongGeneration) => {
                let RestoreAuthorityOutcome::Prepared {
                    store_fence_generation,
                    ..
                } = &mut response.outcome
                else {
                    panic!("fault is for preparation");
                };
                *store_fence_generation += 1;
            }
            Some(Fault::WrongCompletion) => {
                let RestoreAuthorityOutcome::Completed { commit_digest, .. } =
                    &mut response.outcome
                else {
                    panic!("fault is for completion");
                };
                commit_digest[0] ^= 1;
            }
            Some(Fault::InvalidCertificate) => {
                let RestoreAuthorityOutcome::Current {
                    certified_binding, ..
                } = &mut response.outcome
                else {
                    panic!("fault is for current");
                };
                certified_binding[0] ^= 1;
            }
            None | Some(Fault::NotDispatched) => {}
        }
        Box::pin(std::future::ready(Ok(response)))
    }
}

fn configuration() -> RestoreEpochConfiguration {
    RestoreEpochConfiguration {
        authority_id: "external-authority-A".into(),
        provider_artifact: "qualified-adapter-candidate-v1".into(),
        provider_artifact_digest: [0x11; 32],
        configuration_fingerprint: [0x22; 32],
        authority_generation: 3,
        deployment_uuid: [0x33; 16],
        store_set_generation: 5,
        policy_generation: 9,
        certificate_mode: StableCertificateMode::Forbidden,
        limits: RestoreLimits::default(),
    }
}

fn declaration(id: &str, namespace: u8) -> RestoreStoreDeclaration {
    RestoreStoreDeclaration {
        id: id.into(),
        namespace_digest: [namespace; 32],
    }
}

fn declarations() -> Vec<RestoreStoreDeclaration> {
    vec![declaration("browser", 0x44), declaration("replay", 0x55)]
}

fn certified(
    config: &RestoreEpochConfiguration,
    store: &RestoreStoreDeclaration,
    epoch: u128,
) -> CertifiedRestoreEpoch {
    CertifiedRestoreEpoch {
        authority_id: config.authority_id.clone(),
        configuration_fingerprint: config.configuration_fingerprint,
        authority_generation: config.authority_generation,
        deployment_uuid: config.deployment_uuid,
        namespace_digest: store.namespace_digest,
        epoch,
        stable_certificate: (config.certificate_mode == StableCertificateMode::Required)
            .then(|| b"stable-certificate-fixture-v1".to_vec()),
    }
}

async fn register(
    cx: &Cx,
    config: RestoreEpochConfiguration,
    authority: &Arc<Authority>,
) -> RestoreEpochFacade {
    RestoreEpochFacade::register(cx, config, declarations(), authority.clone(), Time::MAX)
        .await
        .unwrap()
}

async fn finish(
    cx: &Cx,
    store: &RegisteredRestoreStore,
    authority: &Authority,
    fence: RestoreWriteFence,
) -> CompletedRestoreWrite {
    let receipt = authority.commit_store(&fence);
    store
        .complete_write(cx, fence, receipt, Time::MAX)
        .await
        .unwrap()
}

fn refused<T>(result: Result<T, RestoreError>, expected: RestoreError) {
    assert_eq!(result.err(), Some(expected));
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn registered_store_union_drives_current_prepare_store_proof_then_completion() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let facade = register(&cx, configuration(), &authority).await;
        assert!(facade.store("unregistered").is_none());
        let store = facade.store("replay").unwrap();
        let fence = store
            .prepare_write(&cx, [0x66; 32], Time::MAX)
            .await
            .unwrap();
        let id = fence.operation_id();
        let binding = fence.binding_digest();
        assert_eq!(fence.store_id(), "replay");
        assert_eq!(fence.namespace_digest(), [0x55; 32]);
        assert_eq!(fence.store_set_digest(), store.store_set_digest());
        assert_eq!(authority.intents(), 1);
        assert_eq!(
            authority.events(),
            vec![Phase::Register, Phase::Current, Phase::Prepare]
        );

        let completed = finish(&cx, &store, &authority, fence).await;
        assert_eq!(completed.operation_id(), id);
        assert_eq!(completed.binding_digest(), binding);
        assert_eq!(
            completed.commit_digest(),
            authority.state.lock().unwrap().commits[&id].digest
        );
        assert_eq!(authority.intents(), 0);
        assert_eq!(store.shared.intents.load(Ordering::Acquire), 0);
        assert!(!facade.is_quarantined());
        assert_eq!(
            authority.events(),
            vec![
                Phase::Register,
                Phase::Current,
                Phase::Prepare,
                Phase::StoreCommit,
                Phase::Complete,
            ]
        );
    });
}

#[test]
fn stable_binding_is_independent_of_transient_ids_and_store_fence_versions() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let facade = register(&cx, configuration(), &authority).await;
        let store = facade.store("replay").unwrap();
        let first = store.prepare_write(&cx, [1; 32], Time::MAX).await.unwrap();
        let first_id = first.operation_id();
        let binding = first.binding_digest();
        assert_eq!(first.store_fence_generation(), 1);
        finish(&cx, &store, &authority, first).await;

        let second = store.prepare_write(&cx, [2; 32], Time::MAX).await.unwrap();
        assert_ne!(second.operation_id(), first_id);
        assert_eq!(second.binding_digest(), binding);
        assert_eq!(second.store_fence_generation(), 2);
        {
            let state = authority.state.lock().unwrap();
            let currents: Vec<_> = state
                .requests
                .iter()
                .filter(|entry| entry.0 == Phase::Current)
                .collect();
            assert_eq!(currents.len(), 2);
            assert_ne!(currents[0].1, currents[1].1);
            assert_ne!(currents[0].2, currents[1].2);
        }
        finish(&cx, &store, &authority, second).await;
        assert!(!facade.is_quarantined());
    });
}

#[test]
fn canonical_parser_rejects_truncation_trailing_bytes_tags_types_and_lengths() {
    let config = configuration();
    let store = declaration("replay", 0x55);
    let bytes = certified(&config, &store, 7).canonical_bytes().unwrap();
    assert_eq!(&bytes[..12], b"FMCPEPC\0\0\x01\0\x06");
    let binding = parse_binding(&bytes, &config, &store).unwrap();
    assert_eq!(binding.epoch(), 7);
    assert_eq!(binding.namespace_digest(), store.namespace_digest);
    assert_eq!(binding.digest(), hash(&bytes).unwrap());

    for end in 0..bytes.len() {
        refused(
            parse_binding(&bytes[..end], &config, &store),
            RestoreError::InvalidBinding,
        );
    }
    let mut malformed = Vec::new();
    let mut candidate = bytes.clone();
    candidate.push(0);
    malformed.push(candidate);
    for (offset, replacement) in [(0, b'X'), (9, 2), (11, 7), (12, 1), (14, 2)] {
        let mut candidate = bytes.clone();
        candidate[offset] = replacement;
        malformed.push(candidate);
    }
    let mut oversized_length = bytes.clone();
    oversized_length[15..19].copy_from_slice(&u32::MAX.to_be_bytes());
    malformed.push(oversized_length);
    for candidate in malformed {
        refused(
            parse_binding(&candidate, &config, &store),
            RestoreError::InvalidBinding,
        );
    }
}

#[test]
fn canonical_binding_couples_authority_configuration_generation_deployment_and_namespace() {
    let config = configuration();
    let store = declaration("replay", 0x55);
    for field in 0..6 {
        let mut claim = certified(&config, &store, 7);
        match field {
            0 => claim.authority_id = "another-authority".into(),
            1 => claim.configuration_fingerprint[0] ^= 1,
            2 => claim.authority_generation += 1,
            3 => claim.deployment_uuid[0] ^= 1,
            4 => claim.namespace_digest[0] ^= 1,
            5 => claim.epoch = 0,
            _ => unreachable!(),
        }
        if field == 5 {
            refused(claim.canonical_bytes(), RestoreError::InvalidBinding);
        } else {
            let bytes = claim.canonical_bytes().unwrap();
            refused(
                parse_binding(&bytes, &config, &store),
                RestoreError::InvalidBinding,
            );
        }
    }
}

#[test]
fn certificate_mode_and_size_are_enforced_before_a_binding_is_sealed() {
    let store = declaration("replay", 0x55);
    let forbidden = configuration();
    let mut required = configuration();
    required.certificate_mode = StableCertificateMode::Required;
    let plain = certified(&forbidden, &store, 7).canonical_bytes().unwrap();
    let with_certificate = certified(&required, &store, 7).canonical_bytes().unwrap();
    assert!(parse_binding(&plain, &forbidden, &store).is_ok());
    assert!(parse_binding(&with_certificate, &required, &store).is_ok());
    refused(
        parse_binding(&plain, &required, &store),
        RestoreError::InvalidBinding,
    );
    refused(
        parse_binding(&with_certificate, &forbidden, &store),
        RestoreError::InvalidBinding,
    );
    required.limits.certificate_bytes = 1;
    refused(
        parse_binding(&with_certificate, &required, &store),
        RestoreError::InvalidBinding,
    );
    let mut oversized = forbidden.clone();
    oversized.limits.binding_bytes = plain.len() - 1;
    refused(
        parse_binding(&plain, &oversized, &store),
        RestoreError::InvalidBinding,
    );
}

#[test]
fn epoch_changes_quarantine_all_handles_and_do_not_create_another_intent() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let facade = register(&cx, configuration(), &authority).await;
        let store = facade.store("replay").unwrap();
        let first = store.prepare_write(&cx, [1; 32], Time::MAX).await.unwrap();
        finish(&cx, &store, &authority, first).await;
        authority.state.lock().unwrap().epoch += 1;
        refused(
            store.prepare_write(&cx, [2; 32], Time::MAX).await,
            RestoreError::Quarantined,
        );
        assert!(facade.store("browser").unwrap().is_quarantined());
        assert_eq!(authority.intents(), 0);
        assert_eq!(authority.events().last(), Some(&Phase::Current));
    });
}

#[test]
fn malformed_authority_binding_quarantines_before_prepare_dispatch() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let facade = register(&cx, configuration(), &authority).await;
        authority.inject(Phase::Current, Fault::InvalidCertificate);
        refused(
            facade
                .store("replay")
                .unwrap()
                .prepare_write(&cx, [1; 32], Time::MAX)
                .await,
            RestoreError::InvalidBinding,
        );
        assert!(facade.is_quarantined());
        assert_eq!(authority.events(), vec![Phase::Register, Phase::Current]);
        assert_eq!(authority.intents(), 0);
    });
}

#[test]
fn preparation_rejects_response_operation_digest_binding_and_generation_substitution() {
    for fault in [
        Fault::WrongOperation,
        Fault::WrongRequestDigest,
        Fault::WrongBinding,
        Fault::WrongGeneration,
    ] {
        block_on(async {
            let cx = Cx::current().unwrap();
            let authority = Arc::new(Authority::default());
            let facade = register(&cx, configuration(), &authority).await;
            authority.inject(Phase::Prepare, fault);
            refused(
                facade
                    .store("replay")
                    .unwrap()
                    .prepare_write(&cx, [1; 32], Time::MAX)
                    .await,
                RestoreError::InvalidReceipt,
            );
            assert!(facade.is_quarantined());
            assert_eq!(authority.intents(), 1, "external uncertainty is not erased");
        });
    }
}

#[test]
fn forged_store_proof_is_not_a_completion_witness() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let facade = register(&cx, configuration(), &authority).await;
        let store = facade.store("replay").unwrap();
        let fence = store.prepare_write(&cx, [1; 32], Time::MAX).await.unwrap();
        let fabricated = DurableRestoreCommitReceipt::new(
            fence.operation_id(),
            fence.binding_digest(),
            fence.store_fence_generation(),
            fence.record_digest(),
            [8; 32],
            b"not-recorded-by-the-store".to_vec(),
        )
        .unwrap();
        refused(
            store
                .complete_write(&cx, fence, fabricated, Time::MAX)
                .await,
            RestoreError::Uncertain,
        );
        assert!(facade.is_quarantined());
        assert_eq!(authority.intents(), 1);
        assert!(!authority.events().contains(&Phase::StoreCommit));
    });
}

#[test]
fn commit_receipt_field_substitution_is_rejected_before_completion_dispatch() {
    for field in 0..4 {
        block_on(async {
            let cx = Cx::current().unwrap();
            let authority = Arc::new(Authority::default());
            let facade = register(&cx, configuration(), &authority).await;
            let store = facade.store("replay").unwrap();
            let fence = store.prepare_write(&cx, [1; 32], Time::MAX).await.unwrap();
            let mut receipt = authority.commit_store(&fence);
            match field {
                0 => receipt.operation_id[0] ^= 1,
                1 => receipt.binding_digest[0] ^= 1,
                2 => receipt.fence_generation += 1,
                3 => receipt.record_digest[0] ^= 1,
                _ => unreachable!(),
            }
            let calls = authority.calls();
            refused(
                store.complete_write(&cx, fence, receipt, Time::MAX).await,
                RestoreError::InvalidReceipt,
            );
            assert_eq!(authority.calls(), calls);
            assert!(facade.is_quarantined());
            assert_eq!(authority.intents(), 1);
        });
    }
}

#[test]
fn another_registered_store_cannot_complete_the_original_stores_fence() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let facade = register(&cx, configuration(), &authority).await;
        let replay = facade.store("replay").unwrap();
        let browser = facade.store("browser").unwrap();
        let fence = replay.prepare_write(&cx, [1; 32], Time::MAX).await.unwrap();
        let receipt = authority.commit_store(&fence);
        let calls = authority.calls();
        refused(
            browser.complete_write(&cx, fence, receipt, Time::MAX).await,
            RestoreError::InvalidReceipt,
        );
        assert_eq!(authority.calls(), calls);
        assert!(replay.is_quarantined());
        assert!(browser.is_quarantined());
    });
}

#[test]
fn completion_requires_the_exact_authority_acknowledgement() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let facade = register(&cx, configuration(), &authority).await;
        let store = facade.store("replay").unwrap();
        let fence = store.prepare_write(&cx, [1; 32], Time::MAX).await.unwrap();
        let receipt = authority.commit_store(&fence);
        authority.inject(Phase::Complete, Fault::WrongCompletion);
        refused(
            store.complete_write(&cx, fence, receipt, Time::MAX).await,
            RestoreError::InvalidReceipt,
        );
        assert!(
            facade.is_quarantined(),
            "a committed store is not rolled back on an invalid acknowledgement"
        );
        assert!(authority.events().contains(&Phase::StoreCommit));
    });
}

#[test]
fn dropping_an_owned_fence_quarantines_every_clone_without_dispatching_cleanup() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let facade = register(&cx, configuration(), &authority).await;
        let store = facade.store("replay").unwrap();
        let clone = store.clone();
        let fence = store.prepare_write(&cx, [1; 32], Time::MAX).await.unwrap();
        let calls = authority.calls();
        drop(fence);
        assert!(clone.is_quarantined());
        assert!(facade.store("browser").unwrap().is_quarantined());
        refused(
            clone.prepare_write(&cx, [2; 32], Time::MAX).await,
            RestoreError::Quarantined,
        );
        assert_eq!(authority.calls(), calls);
        assert_eq!(authority.intents(), 1);
        assert_eq!(store.shared.intents.load(Ordering::Acquire), 0);
    });
}

#[test]
fn dropped_pending_prepare_keeps_external_intent_and_releases_only_local_admission() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let facade = register(&cx, configuration(), &authority).await;
        let store = facade.store("replay").unwrap();
        authority.inject(Phase::Prepare, Fault::PendingAfterDispatch);
        let mut operation = Box::pin(store.prepare_write(&cx, [1; 32], Time::MAX));
        assert!(poll_once(operation.as_mut()).is_pending());
        assert_eq!(authority.intents(), 1);
        assert_eq!(store.shared.calls.load(Ordering::Acquire), 1);
        drop(operation);
        assert!(facade.is_quarantined());
        assert_eq!(authority.intents(), 1);
        assert_eq!(store.shared.calls.load(Ordering::Acquire), 0);
        assert_eq!(store.shared.intents.load(Ordering::Acquire), 0);
        assert_eq!(authority.drops.lock().unwrap().len(), 1);
    });
}

#[test]
fn provider_drop_retains_the_tightest_ceiling_observed_during_partial_progress() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let facade = register(&cx, configuration(), &authority).await;
        let store = facade.store("replay").unwrap();
        authority.inject(Phase::Prepare, Fault::PendingAfterDispatch);
        let mut operation = Box::pin(store.prepare_write(&cx, [1; 32], Time::MAX));
        assert!(poll_once(operation.as_mut()).is_pending());
        {
            // Spawn is not required for authority I/O, so the operation remains
            // pending while the observer records this narrower ambient frame.
            let _restriction = Cx::push_restriction(CapSet::<false, true, true, true, true>::MASK);
            assert!(poll_once(operation.as_mut()).is_pending());
        }
        assert!(Cx::current().unwrap().capabilities().spawn);
        drop(operation);
        assert_eq!(
            authority.drops.lock().unwrap().as_slice(),
            &[[false, true, true, true, true]]
        );
        assert!(facade.is_quarantined());
    });
}

#[test]
fn uncertain_or_dispatched_failures_and_wrong_dispatch_reports_quarantine() {
    for fault in [
        Fault::UnknownAfterDispatch,
        Fault::FailedAfterDispatch,
        Fault::WrongDispatch,
    ] {
        block_on(async {
            let cx = Cx::current().unwrap();
            let authority = Arc::new(Authority::default());
            let facade = register(&cx, configuration(), &authority).await;
            authority.inject(Phase::Prepare, fault);
            refused(
                facade
                    .store("replay")
                    .unwrap()
                    .prepare_write(&cx, [1; 32], Time::MAX)
                    .await,
                RestoreError::Uncertain,
            );
            assert!(facade.is_quarantined());
            assert_eq!(authority.intents(), 1);
        });
    }
}

#[test]
fn cancellation_after_prepare_dispatch_quarantines_and_keeps_the_intent() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let facade = register(&cx, configuration(), &authority).await;
        let store = facade.store("replay").unwrap();
        authority.inject(Phase::Prepare, Fault::CancelAfterDispatch);
        let result = store.prepare_write(&cx, [1; 32], Time::MAX).await;
        cx.set_cancel_requested(false);
        refused(result, RestoreError::Cancelled);
        assert!(facade.is_quarantined());
        assert_eq!(authority.intents(), 1);
        assert_eq!(store.shared.calls.load(Ordering::Acquire), 0);
    });
}

#[test]
fn provably_not_dispatched_prepare_can_retry_but_not_dispatched_completion_stays_quarantined() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let facade = register(&cx, configuration(), &authority).await;
        let store = facade.store("replay").unwrap();
        authority.inject(Phase::Prepare, Fault::NotDispatched);
        refused(
            store.prepare_write(&cx, [1; 32], Time::MAX).await,
            RestoreError::ProviderUnavailable,
        );
        assert!(!facade.is_quarantined());
        assert_eq!(authority.intents(), 0);
        let fence = store.prepare_write(&cx, [1; 32], Time::MAX).await.unwrap();
        let receipt = authority.commit_store(&fence);
        authority.inject(Phase::Complete, Fault::NotDispatched);
        refused(
            store.complete_write(&cx, fence, receipt, Time::MAX).await,
            RestoreError::ProviderUnavailable,
        );
        assert!(facade.is_quarantined());
        assert_eq!(
            authority.intents(),
            1,
            "an undispatched completion does not undo its preparation"
        );
    });
}

#[test]
fn pending_read_and_call_capacity_are_bounded_and_released_on_drop() {
    for read_limited in [true, false] {
        block_on(async {
            let cx = Cx::current().unwrap();
            let authority = Arc::new(Authority::default());
            let mut config = configuration();
            config.limits.active_reads = if read_limited { 1 } else { 2 };
            config.limits.active_calls = if read_limited { 2 } else { 1 };
            let facade = register(&cx, config, &authority).await;
            let store = facade.store("replay").unwrap();
            authority.inject(Phase::Current, Fault::PendingAfterDispatch);
            let mut first = Box::pin(store.prepare_write(&cx, [1; 32], Time::MAX));
            assert!(poll_once(first.as_mut()).is_pending());
            let calls = authority.calls();
            refused(
                store.prepare_write(&cx, [2; 32], Time::MAX).await,
                RestoreError::CapacityExceeded,
            );
            assert_eq!(authority.calls(), calls);
            drop(first);
            assert!(
                !facade.is_quarantined(),
                "dropping only a read creates no uncertain mutation"
            );
            assert_eq!(store.shared.calls.load(Ordering::Acquire), 0);
            assert_eq!(store.shared.reads.load(Ordering::Acquire), 0);
            assert_eq!(store.shared.intents.load(Ordering::Acquire), 0);
            let fence = store.prepare_write(&cx, [3; 32], Time::MAX).await.unwrap();
            finish(&cx, &store, &authority, fence).await;
        });
    }
}

#[test]
fn outstanding_intent_capacity_is_not_released_until_the_fence_settles() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let mut config = configuration();
        config.limits.active_intents = 1;
        let facade = register(&cx, config, &authority).await;
        let store = facade.store("replay").unwrap();
        let fence = store.prepare_write(&cx, [1; 32], Time::MAX).await.unwrap();
        let calls = authority.calls();
        refused(
            store.prepare_write(&cx, [2; 32], Time::MAX).await,
            RestoreError::CapacityExceeded,
        );
        assert_eq!(authority.calls(), calls);
        assert_eq!(store.shared.intents.load(Ordering::Acquire), 1);
        finish(&cx, &store, &authority, fence).await;
        assert_eq!(store.shared.intents.load(Ordering::Acquire), 0);
        let next = store.prepare_write(&cx, [2; 32], Time::MAX).await.unwrap();
        finish(&cx, &store, &authority, next).await;
    });
}

#[test]
fn denied_retained_and_ambient_effects_never_construct_a_provider_future() {
    let masks = [
        CapSet::<true, false, true, true, true>::MASK,
        CapSet::<true, true, false, true, true>::MASK,
        CapSet::<true, true, true, false, true>::MASK,
        CapSet::<true, true, true, true, false>::MASK,
        CapMask::none(),
    ];
    for mask in masks {
        block_on(async {
            let cx = Cx::current().unwrap();
            let authority = Arc::new(Authority::default());
            let restricted = {
                let _restriction = Cx::push_restriction(mask);
                Cx::current().unwrap()
            };
            refused(
                RestoreEpochFacade::register(
                    &restricted,
                    configuration(),
                    declarations(),
                    authority.clone(),
                    Time::MAX,
                )
                .await,
                RestoreError::CapabilityUnavailable,
            );
            {
                let _restriction = Cx::push_restriction(mask);
                refused(
                    RestoreEpochFacade::register(
                        &cx,
                        configuration(),
                        declarations(),
                        authority.clone(),
                        Time::MAX,
                    )
                    .await,
                    RestoreError::CapabilityUnavailable,
                );
            }
            assert_eq!(authority.calls(), 0);
        });
    }
}

#[test]
fn cancellation_between_request_construction_and_execution_does_not_dispatch() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let facade = register(&cx, configuration(), &authority).await;
        let store = facade.store("replay").unwrap();
        let request = store
            .shared
            .request(
                &cx,
                RestoreAuthorityOperation::Current {
                    store: (*store.declaration).clone(),
                },
                Time::MAX,
            )
            .unwrap();
        let calls = authority.calls();
        cx.set_cancel_requested(true);
        let result = store.shared.call(&cx, &request, None).await;
        cx.set_cancel_requested(false);
        refused(result, RestoreError::Cancelled);
        assert_eq!(authority.calls(), calls);
        assert!(!facade.is_quarantined());
    });
}

#[test]
fn an_elapsed_request_deadline_is_checked_before_provider_construction() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let facade = register(&cx, configuration(), &authority).await;
        let store = facade.store("replay").unwrap();
        let mut request = store
            .shared
            .request(
                &cx,
                RestoreAuthorityOperation::Current {
                    store: (*store.declaration).clone(),
                },
                Time::MAX,
            )
            .unwrap();
        request.deadline = cx.now();
        let calls = authority.calls();
        refused(
            store.shared.call(&cx, &request, None).await,
            RestoreError::DeadlineExceeded,
        );
        assert_eq!(authority.calls(), calls);
        assert!(!facade.is_quarantined());
    });
}

#[test]
fn invalid_store_sets_and_limits_are_rejected_without_provider_dispatch() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let invalid_sets = [
            Vec::new(),
            vec![declaration("same", 1), declaration("same", 2)],
            vec![declaration("one", 1), declaration("two", 1)],
            vec![declaration("contains space", 1)],
        ];
        for stores in invalid_sets {
            refused(
                RestoreEpochFacade::register(
                    &cx,
                    configuration(),
                    stores,
                    authority.clone(),
                    Time::MAX,
                )
                .await,
                RestoreError::InvalidConfiguration,
            );
        }
        for field in 0..6 {
            let mut config = configuration();
            match field {
                0 => config.limits.active_calls = 0,
                1 => config.limits.active_reads = 0,
                2 => config.limits.active_intents = 0,
                3 => config.limits.stores = 1,
                4 => config.limits.call_timeout = Duration::ZERO,
                5 => config.limits.binding_bytes = MAX_BINDING + 1,
                _ => unreachable!(),
            }
            refused(
                RestoreEpochFacade::register(
                    &cx,
                    config,
                    declarations(),
                    authority.clone(),
                    Time::MAX,
                )
                .await,
                RestoreError::InvalidConfiguration,
            );
        }
        assert_eq!(authority.calls(), 0);
    });
}

#[test]
fn store_proof_shape_and_length_have_fixed_finite_bounds() {
    for proof in [Vec::new(), vec![0; MAX_COMMIT_PROOF + 1]] {
        refused(
            DurableRestoreCommitReceipt::new([1; 16], [2; 32], 3, [4; 32], [5; 32], proof),
            RestoreError::InvalidReceipt,
        );
    }
    refused(
        DurableRestoreCommitReceipt::new([1; 16], [2; 32], 0, [4; 32], [5; 32], vec![1]),
        RestoreError::InvalidReceipt,
    );
}

#[test]
fn dropping_pending_completion_quarantines_even_if_the_authority_already_settled() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let facade = register(&cx, configuration(), &authority).await;
        let store = facade.store("replay").unwrap();
        let fence = store.prepare_write(&cx, [1; 32], Time::MAX).await.unwrap();
        let receipt = authority.commit_store(&fence);
        authority.inject(Phase::Complete, Fault::PendingAfterDispatch);
        let mut completion = Box::pin(store.complete_write(&cx, fence, receipt, Time::MAX));
        assert!(poll_once(completion.as_mut()).is_pending());
        // The external authority did settle, but the caller has received no
        // correlated acknowledgement and cannot infer success from dropping.
        assert_eq!(authority.intents(), 0);
        assert_eq!(store.shared.intents.load(Ordering::Acquire), 1);
        let calls = authority.calls();
        drop(completion);
        assert!(facade.is_quarantined());
        assert_eq!(store.shared.intents.load(Ordering::Acquire), 0);
        refused(
            store.prepare_write(&cx, [2; 32], Time::MAX).await,
            RestoreError::Quarantined,
        );
        assert_eq!(authority.calls(), calls);
        assert_eq!(authority.drops.lock().unwrap().len(), 1);
    });
}

#[test]
fn parser_rejects_a_zero_epoch_even_when_the_wire_shape_is_canonical() {
    let config = configuration();
    let store = declaration("replay", 0x55);
    let mut bytes = certified(&config, &store, 7).canonical_bytes().unwrap();
    let epoch_offset = bytes.len() - 16;
    bytes[epoch_offset..].fill(0);
    refused(
        parse_binding(&bytes, &config, &store),
        RestoreError::InvalidBinding,
    );
}

#[test]
fn preparation_dispatch_deadline_cannot_outlive_the_write_intent() {
    struct CapturePrepareDeadline {
        authority: Arc<Authority>,
        observed: Mutex<Vec<(Time, Duration, Time)>>,
    }

    impl RestoreEpochAuthority for CapturePrepareDeadline {
        fn execute<'a>(
            &'a self,
            cx: &'a Cx,
            request: &'a RestoreAuthorityRequest,
        ) -> RestoreAuthorityFuture<'a> {
            if let RestoreAuthorityOperation::PrepareWrite {
                intent_lifetime, ..
            } = request.operation()
            {
                self.observed.lock().unwrap().push((
                    cx.now(),
                    *intent_lifetime,
                    request.deadline(),
                ));
            }
            self.authority.execute(cx, request)
        }
    }

    block_on(async {
        let cx = Cx::current().unwrap();
        let authority = Arc::new(Authority::default());
        let capture = Arc::new(CapturePrepareDeadline {
            authority: Arc::clone(&authority),
            observed: Mutex::new(Vec::new()),
        });
        let mut config = configuration();
        config.limits.intent_lifetime = Duration::from_secs(1);
        config.limits.observation_freshness = Duration::from_secs(30);
        config.limits.call_timeout = Duration::from_secs(60);
        let facade =
            RestoreEpochFacade::register(&cx, config, declarations(), capture.clone(), Time::MAX)
                .await
                .unwrap();
        let store = facade.store("replay").unwrap();
        let fence = store.prepare_write(&cx, [1; 32], Time::MAX).await.unwrap();
        let (dispatch_at, lifetime, deadline) = {
            let observations = capture.observed.lock().unwrap();
            assert_eq!(observations.len(), 1);
            observations[0]
        };
        assert!(deadline <= add_time(dispatch_at, lifetime).unwrap());
        assert!(deadline <= fence.expires_at());
        finish(&cx, &store, &authority, fence).await;
    });
}
