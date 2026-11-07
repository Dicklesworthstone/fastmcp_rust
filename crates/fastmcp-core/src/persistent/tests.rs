//! Behavioral integration fixtures for the persistent blob consumer.
//!
//! The crypto adapter really authenticates XC20P ciphertext and canonical AAD.
//! The store CAS writes a separate proof journal, which the authority consults
//! independently of each submitted receipt. All three actors are in-memory
//! test doubles: these tests do not qualify a persistent provider, establish
//! rollback resistance, or prove crash durability.

use super::*;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::task::{Context, Wake, Waker};

use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadInOut, KeyInit},
};

use crate::restore::{
    CertifiedRestoreEpoch, RestoreAuthorityFailure, RestoreAuthorityFuture,
    RestoreAuthorityOperation, RestoreAuthorityOutcome, RestoreAuthorityRequest,
    RestoreAuthorityResponse, RestoreEpochAuthority, RestoreEpochConfiguration,
    RestoreEpochFacade, RestoreLimits, RestoreStoreDeclaration, StableCertificateMode,
};
use crate::runtime::block_on;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    Register, Current, Prepare, Seal, Cas, Complete, Read, Open, Reconcile,
}
type Events = Arc<Mutex<Vec<Event>>>;

fn record(events: &Events, event: Event) {
    events.lock().unwrap().push(event);
}

#[derive(Default)]
struct Gate {
    released: AtomicBool,
    waker: Mutex<Option<Waker>>,
}
impl Gate {
    async fn wait(&self) {
        poll_fn(|cx| {
            let mut waker = self.waker.lock().unwrap();
            if self.released.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                *waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }).await
    }
    fn release(&self) {
        self.released.store(true, Ordering::Release);
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}

#[derive(Default)]
struct DropLog(Mutex<Vec<[bool; 5]>>);
struct ObserveDrop(Arc<DropLog>);
impl Drop for ObserveDrop {
    fn drop(&mut self) {
        let current = Cx::current().expect("provider destruction retains its caller");
        let caps = current.capabilities();
        self.0.0.lock().unwrap()
            .push([caps.spawn, caps.time, caps.entropy, caps.io, caps.remote]);
    }
}

#[derive(Clone, Copy)]
enum ReceiptFault {
    Operation, Request, Configuration, Generation, Key, Envelope, Dispatch, Artifact,
}
fn corrupt_crypto(receipt: &mut PersistentEnvelopeReceipt, fault: ReceiptFault) {
    match fault {
        ReceiptFault::Operation => receipt.operation_id[0] ^= 1,
        ReceiptFault::Request => receipt.request_digest[0] ^= 1,
        ReceiptFault::Configuration => receipt.configuration_fingerprint[0] ^= 1,
        ReceiptFault::Generation => receipt.ring_generation += 1,
        ReceiptFault::Key => receipt.key_generation += 1,
        ReceiptFault::Envelope => receipt.envelope_digest[0] ^= 1,
        ReceiptFault::Dispatch => receipt.dispatch = RestoreDispatch::Unknown,
        ReceiptFault::Artifact => panic!("artifact fault belongs to the blob receipt"),
    }
}
fn corrupt_blob(receipt: &mut PersistentBlobReceipt, fault: ReceiptFault) {
    match fault {
        ReceiptFault::Operation => receipt.operation_id[0] ^= 1,
        ReceiptFault::Request => receipt.request_digest[0] ^= 1,
        ReceiptFault::Configuration => receipt.configuration_fingerprint[0] ^= 1,
        ReceiptFault::Generation => receipt.backend_generation += 1,
        ReceiptFault::Dispatch => receipt.dispatch = RestoreDispatch::NotDispatched,
        ReceiptFault::Artifact => receipt.artifact_digest[0] ^= 1,
        ReceiptFault::Key | ReceiptFault::Envelope => panic!("fault belongs to crypto receipt"),
    }
}
fn failure(kind: PersistentBackendFailureKind, dispatch: RestoreDispatch) -> PersistentBackendFailure {
    PersistentBackendFailure { dispatch, kind }
}
fn unavailable() -> PersistentBackendFailure {
    failure(PersistentBackendFailureKind::Unavailable, RestoreDispatch::Dispatched)
}
fn authentication_failed() -> PersistentBackendFailure {
    failure(PersistentBackendFailureKind::AuthenticationFailed, RestoreDispatch::Dispatched)
}
fn fingerprint(bytes: &[u8]) -> [u8; 32] {
    sha256_bounded(bytes, MAX_ENVELOPE).unwrap().into_bytes()
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CryptoPhase { Seal, Open }
enum CryptoFault {
    Receipt(ReceiptFault),
    Pause(Arc<Gate>),
    WrongAad,
    WrongPlaintextLength,
    Unknown,
    Cancel,
}

struct Crypto {
    sequence: AtomicU64,
    nonces: Mutex<BTreeSet<(u64, [u8; 24])>>,
    fault: Mutex<Option<(CryptoPhase, CryptoFault)>>,
    seals: AtomicUsize,
    opens: AtomicUsize,
    events: Events,
    drops: Arc<DropLog>,
}
impl Crypto {
    fn new(events: Events) -> Self {
        Self {
            sequence: AtomicU64::new(0),
            nonces: Mutex::new(BTreeSet::new()),
            fault: Mutex::new(None),
            seals: AtomicUsize::new(0),
            opens: AtomicUsize::new(0),
            events,
            drops: Arc::new(DropLog::default()),
        }
    }
    fn inject(&self, phase: CryptoPhase, fault: CryptoFault) {
        *self.fault.lock().unwrap() = Some((phase, fault));
    }
    fn take_fault(&self, phase: CryptoPhase) -> Option<CryptoFault> {
        let mut slot = self.fault.lock().unwrap();
        if slot.as_ref().is_some_and(|(expected, _)| *expected == phase) {
            slot.take().map(|(_, fault)| fault)
        } else {
            None
        }
    }
    // Test-only fixed keys never enter the production facade. The second key
    // allows a real previous-generation read across a configured ring change.
    fn key(generation: u64) -> Result<Zeroizing<[u8; 32]>, PersistentBackendFailure> {
        match generation {
            1 => Ok(Zeroizing::new([0x71; 32])),
            2 => Ok(Zeroizing::new([0x92; 32])),
            _ => Err(authentication_failed()),
        }
    }
}
impl PersistentEnvelopeBackend for Crypto {
    fn seal<'a>(
        &'a self, cx: &'a Cx, request: &'a PersistentEnvelopeRequest<'a>,
        plaintext: BoundedPlaintext,
    ) -> PersistentBackendFuture<'a, PersistentSealResult> {
        Box::pin(async move {
            self.seals.fetch_add(1, Ordering::AcqRel);
            record(&self.events, Event::Seal);
            let _drop = ObserveDrop(Arc::clone(&self.drops));
            let fault = self.take_fault(CryptoPhase::Seal);
            if let Some(CryptoFault::Pause(gate)) = &fault { gate.wait().await; }
            let selected = request.configuration().keys.iter().find(|key| key.sealing)
                .ok_or_else(unavailable)?;
            let sequence = self.sequence.fetch_add(1, Ordering::AcqRel);
            assert_ne!(sequence, u64::MAX, "test fixture nonce counter exhausted");
            let mut nonce = [0x35; 24];
            nonce[16..].copy_from_slice(&sequence.to_be_bytes());
            assert!(self.nonces.lock().unwrap().insert((selected.generation, nonce)));
            let header = PersistentEnvelopeHeader::xc20p(
                selected.key_id.clone(), selected.generation, nonce,
            ).map_err(|_| unavailable())?;
            let mut aad = request.context().canonical_aad(&header).map_err(|_| unavailable())?;
            if matches!(&fault, Some(CryptoFault::WrongAad)) { aad[0] ^= 1; }
            let key = Self::key(selected.generation)?;
            let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| unavailable())?;
            let mut payload = plaintext.into_zeroizing();
            cipher.encrypt_in_place(&XNonce::from(nonce), &aad, &mut *payload)
                .map_err(|_| unavailable())?;
            let envelope = header.encode(&payload).map_err(|_| unavailable())?;
            let mut receipt = PersistentEnvelopeReceipt::for_request(request, &envelope)
                .map_err(|_| unavailable())?;
            if let Some(CryptoFault::Receipt(fault)) = &fault { corrupt_crypto(&mut receipt, *fault); }
            if matches!(&fault, Some(CryptoFault::Unknown)) {
                return Err(failure(PersistentBackendFailureKind::Unavailable, RestoreDispatch::Unknown));
            }
            if matches!(&fault, Some(CryptoFault::Cancel)) { cx.set_cancel_requested(true); }
            Ok(PersistentSealResult { envelope, receipt })
        })
    }

    fn open<'a>(
        &'a self, cx: &'a Cx, request: &'a PersistentEnvelopeRequest<'a>,
        envelope: &'a CanonicalEnvelope,
    ) -> PersistentBackendFuture<'a, PersistentOpenResult> {
        Box::pin(async move {
            self.opens.fetch_add(1, Ordering::AcqRel);
            record(&self.events, Event::Open);
            let _drop = ObserveDrop(Arc::clone(&self.drops));
            let fault = self.take_fault(CryptoPhase::Open);
            if let Some(CryptoFault::Pause(gate)) = &fault { gate.wait().await; }
            let header = envelope.header().map_err(|_| authentication_failed())?;
            let mut aad = request.context().canonical_aad(&header).map_err(|_| authentication_failed())?;
            if matches!(&fault, Some(CryptoFault::WrongAad)) { aad[0] ^= 1; }
            let key = Self::key(header.generation())?;
            let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| unavailable())?;
            let mut payload = Zeroizing::new(envelope.ciphertext_and_tag().to_vec());
            cipher.decrypt_in_place(&XNonce::from(*header.nonce()), &aad, &mut *payload)
                .map_err(|_| authentication_failed())?;
            if matches!(&fault, Some(CryptoFault::WrongPlaintextLength)) { payload.push(0); }
            let plaintext = BoundedPlaintext::new(payload).map_err(|_| unavailable())?;
            let mut receipt = PersistentEnvelopeReceipt::for_request(request, envelope)
                .map_err(|_| unavailable())?;
            if let Some(CryptoFault::Receipt(fault)) = &fault { corrupt_crypto(&mut receipt, *fault); }
            if matches!(&fault, Some(CryptoFault::Unknown)) {
                return Err(failure(PersistentBackendFailureKind::Unavailable, RestoreDispatch::Unknown));
            }
            if matches!(&fault, Some(CryptoFault::Cancel)) { cx.set_cancel_requested(true); }
            Ok(PersistentOpenResult { plaintext, receipt })
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
struct Intent {
    store: String,
    binding: [u8; 32],
    fence: u64,
    logical: [u8; 32],
}
#[derive(Clone)]
enum Witness {
    Committed { intent: Intent, commit: [u8; 32], proof: Vec<u8> },
    Fenced { intent: Intent, new_fence: u64, proof: Vec<u8> },
}
struct Stored {
    revision: PersistentBlobRevision,
    envelope: Zeroizing<Vec<u8>>,
}
struct Journal {
    fence: u64,
    records: BTreeMap<[u8; 16], Stored>,
    witnesses: BTreeMap<[u8; 16], Witness>,
}
impl Default for Journal {
    fn default() -> Self {
        Self { fence: 1, records: BTreeMap::new(), witnesses: BTreeMap::new() }
    }
}
#[derive(Default)]
struct AuthorityState {
    registered: Vec<RestoreStoreDeclaration>,
    intents: BTreeMap<[u8; 16], Intent>,
    completed: usize,
    reconciled: usize,
    rejected_proofs: usize,
}
struct Authority {
    state: Mutex<AuthorityState>,
    journal: Arc<Mutex<Journal>>,
    events: Events,
}
impl Authority {
    fn certified(
        config: &RestoreEpochConfiguration, store: &RestoreStoreDeclaration,
    ) -> CertifiedRestoreEpoch {
        CertifiedRestoreEpoch {
            authority_id: config.authority_id.clone(),
            configuration_fingerprint: config.configuration_fingerprint,
            authority_generation: config.authority_generation,
            deployment_uuid: config.deployment_uuid,
            namespace_digest: store.namespace_digest,
            epoch: 7,
            stable_certificate: None,
        }
    }
    fn unresolved(&self) -> usize { self.state.lock().unwrap().intents.len() }

    fn respond(
        &self, request: &RestoreAuthorityRequest,
    ) -> Result<RestoreAuthorityResponse, RestoreAuthorityFailure> {
        let refused = || RestoreAuthorityFailure { dispatch: RestoreDispatch::Dispatched };
        let mut state = self.state.lock().unwrap();
        let outcome = match request.operation() {
            RestoreAuthorityOperation::RegisterStoreSet { stores } => {
                record(&self.events, Event::Register);
                if !state.registered.is_empty() || !state.intents.is_empty() { return Err(refused()); }
                state.registered = stores.clone();
                RestoreAuthorityOutcome::Registered { store_set_digest: request.store_set_digest() }
            }
            RestoreAuthorityOperation::Current { store } => {
                record(&self.events, Event::Current);
                if !state.registered.contains(store) { return Err(refused()); }
                RestoreAuthorityOutcome::Current {
                    certified_binding: Self::certified(request.configuration(), store).canonical_bytes().unwrap(),
                    store_fence_generation: self.journal.lock().unwrap().fence,
                }
            }
            RestoreAuthorityOperation::PrepareWrite {
                store, binding_digest, store_fence_generation, record_digest, ..
            } => {
                record(&self.events, Event::Prepare);
                let certified = Self::certified(request.configuration(), store).canonical_bytes().unwrap();
                if !state.registered.contains(store)
                    || *binding_digest != fingerprint(&certified)
                    || *store_fence_generation != self.journal.lock().unwrap().fence
                    || state.intents.contains_key(&request.operation_id())
                { return Err(refused()); }
                state.intents.insert(request.operation_id(), Intent {
                    store: store.id.clone(), binding: *binding_digest,
                    fence: *store_fence_generation, logical: *record_digest,
                });
                RestoreAuthorityOutcome::Prepared {
                    binding_digest: *binding_digest, store_fence_generation: *store_fence_generation,
                }
            }
            RestoreAuthorityOperation::CompleteWrite { store, intent_operation_id, receipt } => {
                record(&self.events, Event::Complete);
                let valid = {
                    let journal = self.journal.lock().unwrap();
                    match (state.intents.get(intent_operation_id), journal.witnesses.get(intent_operation_id)) {
                        (Some(intent), Some(Witness::Committed { intent: durable, commit, proof })) => {
                            intent == durable && intent.store == store.id
                                && receipt.operation_id() == *intent_operation_id
                                && receipt.binding_digest() == intent.binding
                                && receipt.store_fence_generation() == intent.fence
                                && receipt.record_digest() == intent.logical
                                && receipt.commit_digest() == *commit && receipt.proof() == proof.as_slice()
                        }
                        _ => false,
                    }
                };
                if !valid { state.rejected_proofs += 1; return Err(refused()); }
                state.intents.remove(intent_operation_id);
                state.completed += 1;
                RestoreAuthorityOutcome::Completed {
                    intent_operation_id: *intent_operation_id, commit_digest: receipt.commit_digest(),
                }
            }
            RestoreAuthorityOperation::ReconcileWrite { intent, resolution } => {
                record(&self.events, Event::Reconcile);
                let valid = {
                    let journal = self.journal.lock().unwrap();
                    match (
                        state.intents.get(&intent.operation_id()),
                        journal.witnesses.get(&intent.operation_id()),
                        resolution,
                    ) {
                        (Some(original), Some(Witness::Fenced { intent: durable, new_fence, proof }),
                            DurableRestoreResolution::FencedNotCommitted(receipt)) => {
                            original == durable && original.store == intent.store_id()
                                && original.binding == intent.binding_digest()
                                && original.fence == intent.store_fence_generation()
                                && original.logical == intent.record_digest()
                                && receipt.operation_id() == intent.operation_id()
                                && receipt.binding_digest() == original.binding
                                && receipt.store_fence_generation() == original.fence
                                && receipt.record_digest() == original.logical
                                && receipt.fenced_generation() == *new_fence
                                && journal.fence >= *new_fence && receipt.proof() == proof.as_slice()
                        }
                        _ => false,
                    }
                };
                if !valid { state.rejected_proofs += 1; return Err(refused()); }
                state.intents.remove(&intent.operation_id());
                state.reconciled += 1;
                RestoreAuthorityOutcome::Reconciled {
                    intent_operation_id: intent.operation_id(), resolution_digest: resolution.digest().unwrap(),
                }
            }
            RestoreAuthorityOperation::ListUnresolvedWrites { .. } => return Err(refused()),
        };
        Ok(RestoreAuthorityResponse::for_request(request, outcome))
    }
}
impl RestoreEpochAuthority for Authority {
    fn execute<'a>(
        &'a self, _cx: &'a Cx, request: &'a RestoreAuthorityRequest,
    ) -> RestoreAuthorityFuture<'a> {
        Box::pin(async move { self.respond(request) })
    }
}

enum ReadFault { Envelope(Zeroizing<Vec<u8>>), Receipt(ReceiptFault) }
enum CommitFault {
    Receipt(ReceiptFault), PauseBefore(Arc<Gate>), PauseAfter(Arc<Gate>),
    UnknownAfterCas, NotDispatched, CancelAfterCas, ForgedCommitProof, ForgedConflictProof,
    UnprovedConflict,
}
struct Blobs {
    journal: Arc<Mutex<Journal>>,
    events: Events,
    read_fault: Mutex<Option<ReadFault>>,
    commit_fault: Mutex<Option<CommitFault>>,
    reads: AtomicUsize,
    commits: AtomicUsize,
    drops: Arc<DropLog>,
}
impl Blobs {
    fn snapshot(&self, revision: &PersistentBlobRevision) -> Zeroizing<Vec<u8>> {
        let journal = self.journal.lock().unwrap();
        let stored = journal.records.get(&revision.record_id()).unwrap();
        assert!(stored.revision == *revision);
        Zeroizing::new(stored.envelope.to_vec())
    }
    fn override_read(&self, bytes: Zeroizing<Vec<u8>>) {
        *self.read_fault.lock().unwrap() = Some(ReadFault::Envelope(bytes));
    }
    fn inject_commit(&self, fault: CommitFault) {
        *self.commit_fault.lock().unwrap() = Some(fault);
    }

    fn cas(
        &self, request: &PersistentBlobCommitRequest<'_>, fault: &Option<CommitFault>,
    ) -> PersistentBlobCommitResult {
        let fence = request.write_fence();
        let intent = Intent {
            store: fence.store_id().to_owned(), binding: fence.binding_digest(),
            fence: fence.store_fence_generation(), logical: fence.record_digest(),
        };
        let mut journal = self.journal.lock().unwrap();
        assert!(!journal.witnesses.contains_key(&fence.operation_id()), "consumer retried an operation");
        let next = request.next_revision();
        assert_eq!(next.namespace_digest(), fence.namespace_digest());
        assert_eq!(next.envelope_digest(), fingerprint(request.envelope().as_bytes()));
        let matches = match (request.expected_revision(), journal.records.get(&next.record_id())) {
            (None, None) => next.generation() == 1,
            (Some(expected), Some(stored)) => stored.revision == expected
                && expected.record_id() == next.record_id()
                && expected.generation().checked_add(1) == Some(next.generation()),
            _ => false,
        };
        let outcome = if matches && fence.store_fence_generation() == journal.fence {
            assert_ne!(request.commit_digest(), fence.record_digest(), "ciphertext proof is not logical intent");
            let mut proof = b"test-cas-commit/".to_vec();
            proof.extend_from_slice(&fence.operation_id());
            proof.extend_from_slice(&request.commit_digest());
            journal.records.insert(next.record_id(), Stored {
                revision: next, envelope: Zeroizing::new(request.envelope().as_bytes().to_vec()),
            });
            journal.witnesses.insert(fence.operation_id(), Witness::Committed {
                intent, commit: request.commit_digest(), proof: proof.clone(),
            });
            if matches!(fault, Some(CommitFault::ForgedCommitProof)) { proof[0] ^= 1; }
            PersistentBlobCommitOutcome::Committed(DurableRestoreCommitReceipt::new(
                fence.operation_id(), fence.binding_digest(), fence.store_fence_generation(),
                fence.record_digest(), request.commit_digest(), proof,
            ).unwrap())
        } else {
            journal.fence = journal.fence.max(fence.store_fence_generation()).checked_add(1).unwrap();
            let new_fence = journal.fence;
            let mut proof = b"test-cas-fenced/".to_vec();
            proof.extend_from_slice(&fence.operation_id());
            proof.extend_from_slice(&new_fence.to_be_bytes());
            journal.witnesses.insert(fence.operation_id(), Witness::Fenced {
                intent, new_fence, proof: proof.clone(),
            });
            if matches!(fault, Some(CommitFault::ForgedConflictProof)) { proof[0] ^= 1; }
            PersistentBlobCommitOutcome::FencedConflict(DurableRestoreNonCommitReceipt::new(
                fence.operation_id(), fence.binding_digest(), fence.store_fence_generation(),
                fence.record_digest(), new_fence, proof,
            ).unwrap())
        };
        PersistentBlobCommitResult { receipt: request.receipt(), outcome }
    }
}
impl PersistentBlobBackend for Blobs {
    fn read<'a>(
        &'a self, _cx: &'a Cx, request: &'a PersistentBlobReadRequest<'a>,
    ) -> PersistentBackendFuture<'a, PersistentBlobReadResult> {
        Box::pin(async move {
            self.reads.fetch_add(1, Ordering::AcqRel);
            record(&self.events, Event::Read);
            let fault = self.read_fault.lock().unwrap().take();
            let mut receipt = request.receipt();
            let bytes = match fault {
                Some(ReadFault::Envelope(bytes)) => bytes,
                other => {
                    if let Some(ReadFault::Receipt(fault)) = other { corrupt_blob(&mut receipt, fault); }
                    let journal = self.journal.lock().unwrap();
                    if journal.fence != request.store_fence_generation() {
                        return Err(failure(PersistentBackendFailureKind::Conflict, RestoreDispatch::Dispatched));
                    }
                    let stored = journal.records.get(&request.expected_revision().record_id())
                        .ok_or_else(unavailable)?;
                    if stored.revision != request.expected_revision() {
                        return Err(failure(PersistentBackendFailureKind::Conflict, RestoreDispatch::Dispatched));
                    }
                    Zeroizing::new(stored.envelope.to_vec())
                }
            };
            Ok(PersistentBlobReadResult {
                envelope: CanonicalEnvelope::from_bytes(bytes).map_err(|_| authentication_failed())?,
                receipt,
            })
        })
    }
    fn commit<'a>(
        &'a self, cx: &'a Cx, request: &'a PersistentBlobCommitRequest<'a>,
    ) -> PersistentBackendFuture<'a, PersistentBlobCommitResult> {
        Box::pin(async move {
            self.commits.fetch_add(1, Ordering::AcqRel);
            record(&self.events, Event::Cas);
            let _drop = ObserveDrop(Arc::clone(&self.drops));
            let fault = self.commit_fault.lock().unwrap().take();
            if matches!(&fault, Some(CommitFault::NotDispatched)) {
                return Err(failure(PersistentBackendFailureKind::Unavailable, RestoreDispatch::NotDispatched));
            }
            if matches!(&fault, Some(CommitFault::UnprovedConflict)) {
                return Err(failure(PersistentBackendFailureKind::Conflict, RestoreDispatch::Dispatched));
            }
            if let Some(CommitFault::PauseBefore(gate)) = &fault { gate.wait().await; }
            let mut result = self.cas(request, &fault);
            if let Some(CommitFault::PauseAfter(gate)) = &fault { gate.wait().await; }
            if let Some(CommitFault::Receipt(fault)) = &fault { corrupt_blob(&mut result.receipt, *fault); }
            if matches!(&fault, Some(CommitFault::UnknownAfterCas)) {
                return Err(failure(PersistentBackendFailureKind::Unavailable, RestoreDispatch::Unknown));
            }
            if matches!(&fault, Some(CommitFault::CancelAfterCas)) { cx.set_cancel_requested(true); }
            Ok(result)
        })
    }
}

fn envelope_configuration() -> PersistentEnvelopeConfiguration {
    PersistentEnvelopeConfiguration {
        artifact: "test-xc20p-adapter-v1".into(),
        artifact_digest: [0x11; 32],
        configuration_fingerprint: [0x12; 32],
        ring_generation: 1,
        keys: vec![PersistentKeyGeneration { key_id: "test-key-1".into(), generation: 1, sealing: true }],
        limits: PersistentEnvelopeLimits {
            plaintext_bytes: 4096, envelope_bytes: 8192, aad_bytes: 4096,
            active_operations: 2, in_flight_bytes: 128 * 1024,
            call_timeout: Duration::from_secs(5),
        },
    }
}
fn blob_configuration() -> PersistentBlobBackendConfiguration {
    PersistentBlobBackendConfiguration {
        artifact: "test-atomic-blob-v1".into(), artifact_digest: [0x21; 32],
        configuration_fingerprint: [0x22; 32], generation: 1,
    }
}
fn restore_configuration() -> RestoreEpochConfiguration {
    RestoreEpochConfiguration {
        authority_id: "test-independent-authority".into(),
        provider_artifact: "test-authority-adapter-v1".into(),
        provider_artifact_digest: [0x31; 32],
        configuration_fingerprint: [0x32; 32],
        authority_generation: 1, deployment_uuid: [0x33; 16],
        store_set_generation: 1, policy_generation: 1,
        certificate_mode: StableCertificateMode::Forbidden,
        limits: RestoreLimits::default(),
    }
}
struct Fixture {
    facade: RestoreEpochFacade,
    store: PersistentBlobStore,
    crypto: Arc<Crypto>,
    blobs: Arc<Blobs>,
    authority: Arc<Authority>,
    events: Events,
}
impl Fixture {
    async fn new(cx: &Cx) -> Self { Self::configured(cx, envelope_configuration()).await }

    async fn configured(cx: &Cx, configuration: PersistentEnvelopeConfiguration) -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        let journal = Arc::new(Mutex::new(Journal::default()));
        let authority = Arc::new(Authority {
            state: Mutex::new(AuthorityState::default()), journal: Arc::clone(&journal),
            events: Arc::clone(&events),
        });
        let facade = RestoreEpochFacade::register(
            cx, restore_configuration(),
            vec![RestoreStoreDeclaration { id: "protected-blob".into(), namespace_digest: [0x41; 32] }],
            authority.clone(), Time::MAX,
        ).await.unwrap();
        let crypto = Arc::new(Crypto::new(Arc::clone(&events)));
        let blobs = Arc::new(Blobs {
            journal, events: Arc::clone(&events),
            read_fault: Mutex::new(None), commit_fault: Mutex::new(None),
            reads: AtomicUsize::new(0), commits: AtomicUsize::new(0),
            drops: Arc::new(DropLog::default()),
        });
        let store = PersistentBlobStore::new(
            facade.store("protected-blob").unwrap(), configuration, blob_configuration(),
            crypto.clone(), blobs.clone(),
        ).unwrap();
        Self { facade, store, crypto, blobs, authority, events }
    }

    fn reopen(&self, configuration: PersistentEnvelopeConfiguration) -> PersistentBlobStore {
        PersistentBlobStore::new(
            self.facade.store("protected-blob").unwrap(), configuration, blob_configuration(),
            self.crypto.clone(), self.blobs.clone(),
        ).unwrap()
    }
}
fn plaintext(bytes: &[u8]) -> BoundedPlaintext {
    BoundedPlaintext::new(Zeroizing::new(bytes.to_vec())).unwrap()
}
fn refused<T>(result: Result<T, PersistentEnvelopeError>, expected: PersistentEnvelopeError) {
    assert_eq!(result.err(), Some(expected));
}
fn revision_for_envelope(
    revision: &PersistentBlobRevision, envelope: &[u8],
) -> PersistentBlobRevision {
    let mut encoded = revision.encode();
    encoded[66..].copy_from_slice(&fingerprint(envelope));
    PersistentBlobRevision::decode(&encoded).unwrap()
}
struct Noop;
impl Wake for Noop { fn wake(self: Arc<Self>) {} }
fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let waker = Waker::from(Arc::new(Noop));
    future.poll(&mut Context::from_waker(&waker))
}

#[test]
fn real_xc20p_create_read_replace_read_completes_both_durable_steps() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let first = f.store.create(&cx, plaintext(b"first protected value"), Time::MAX).await.unwrap();
        assert_eq!(first.generation(), 1);
        assert_eq!(f.authority.unresolved(), 0);
        assert_eq!(f.authority.state.lock().unwrap().completed, 1);
        assert_eq!(*f.events.lock().unwrap(), vec![
            Event::Register, Event::Current, Event::Prepare, Event::Seal, Event::Cas, Event::Complete,
        ]);
        let ciphertext = f.blobs.snapshot(&first);
        assert!(!ciphertext.windows(b"first protected value".len())
            .any(|part| part == b"first protected value"));
        assert_eq!(f.store.read(&cx, &first, Time::MAX).await.unwrap().as_bytes(), b"first protected value");

        let second = f.store.replace(&cx, &first, plaintext(b"rotated protected value"), Time::MAX).await.unwrap();
        assert_eq!(second.record_id(), first.record_id());
        assert_eq!(second.generation(), 2);
        assert_ne!(second.envelope_digest(), first.envelope_digest());
        assert_eq!(f.store.read(&cx, &second, Time::MAX).await.unwrap().as_bytes(), b"rotated protected value");
        assert_eq!(f.authority.state.lock().unwrap().completed, 2);
        assert_eq!(f.authority.unresolved(), 0);
        assert_eq!(f.crypto.nonces.lock().unwrap().len(), 2);
        assert!(!f.store.is_quarantined());
        assert_eq!(f.store.active.load(Ordering::Acquire), 0);
        assert_eq!(f.store.bytes.load(Ordering::Acquire), 0);
    });
}

#[test]
fn old_ciphertext_cannot_satisfy_the_current_exact_revision() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let old = f.store.create(&cx, plaintext(b"old value"), Time::MAX).await.unwrap();
        let old_bytes = f.blobs.snapshot(&old);
        let current = f.store.replace(&cx, &old, plaintext(b"current value"), Time::MAX).await.unwrap();
        f.blobs.override_read(old_bytes);
        refused(f.store.read(&cx, &current, Time::MAX).await, PersistentEnvelopeError::InvalidRevision);
        assert_eq!(f.crypto.opens.load(Ordering::Acquire), 0, "reject before provider decryption");
        assert_eq!(f.store.read(&cx, &current, Time::MAX).await.unwrap().as_bytes(), b"current value");
        assert!(!f.store.is_quarantined());
    });
}

#[test]
fn forged_record_identity_or_generation_cannot_rebind_authenticated_ciphertext() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let original = f.store.create(&cx, plaintext(b"context-bound value"), Time::MAX).await.unwrap();
        for offset in [42, 65] {
            let mut encoded = original.encode();
            encoded[offset] ^= 0x10;
            let forged = PersistentBlobRevision::decode(&encoded).unwrap();
            f.blobs.override_read(f.blobs.snapshot(&original));
            refused(f.store.read(&cx, &forged, Time::MAX).await, PersistentEnvelopeError::InvalidEnvelope);
        }
        assert_eq!(f.crypto.opens.load(Ordering::Acquire), 2, "the real AEAD rejected different AAD");
        assert_eq!(f.store.read(&cx, &original, Time::MAX).await.unwrap().as_bytes(), b"context-bound value");
    });
}

#[test]
fn wrong_namespace_is_rejected_before_authority_store_or_crypto_dispatch() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let original = f.store.create(&cx, plaintext(b"private"), Time::MAX).await.unwrap();
        let mut encoded = original.encode();
        encoded[10] ^= 1;
        let forged = PersistentBlobRevision::decode(&encoded).unwrap();
        let before = f.events.lock().unwrap().len();
        refused(f.store.read(&cx, &forged, Time::MAX).await, PersistentEnvelopeError::InvalidRevision);
        refused(f.store.replace(&cx, &forged, plaintext(b"replacement"), Time::MAX).await,
            PersistentEnvelopeError::InvalidRevision);
        assert_eq!(f.events.lock().unwrap().len(), before);
        assert!(!f.store.is_quarantined());
    });
}

#[test]
fn ciphertext_tamper_is_rejected_even_when_a_forged_locator_matches_its_digest() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let original = f.store.create(&cx, plaintext(b"never release tampered content"), Time::MAX).await.unwrap();
        let mut tampered = f.blobs.snapshot(&original);
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let forged = revision_for_envelope(&original, &tampered);
        f.blobs.override_read(tampered);
        refused(f.store.read(&cx, &forged, Time::MAX).await, PersistentEnvelopeError::InvalidEnvelope);
        assert_eq!(f.crypto.opens.load(Ordering::Acquire), 1);
        assert_eq!(f.store.bytes.load(Ordering::Acquire), 0);
        assert!(!f.store.is_quarantined());
    });
}

#[test]
fn unknown_key_routes_fail_before_crypto_and_known_header_tamper_fails_authentication() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let original = f.store.create(&cx, plaintext(b"header-bound"), Time::MAX).await.unwrap();
        let raw = f.blobs.snapshot(&original);
        let envelope = CanonicalEnvelope::from_bytes(Zeroizing::new(raw.to_vec())).unwrap();
        let header = envelope.header().unwrap();
        for (key, generation) in [("unconfigured-key", 1), ("test-key-1", 99)] {
            let replacement = PersistentEnvelopeHeader::xc20p(key.into(), generation, *header.nonce())
                .unwrap().encode(envelope.ciphertext_and_tag()).unwrap();
            let forged = revision_for_envelope(&original, replacement.as_bytes());
            f.blobs.override_read(Zeroizing::new(replacement.as_bytes().to_vec()));
            refused(f.store.read(&cx, &forged, Time::MAX).await, PersistentEnvelopeError::InvalidEnvelope);
        }
        assert_eq!(f.crypto.opens.load(Ordering::Acquire), 0);
        let mut nonce = *header.nonce();
        nonce[0] ^= 1;
        let replacement = PersistentEnvelopeHeader::xc20p(header.key_id().into(), header.generation(), nonce)
            .unwrap().encode(envelope.ciphertext_and_tag()).unwrap();
        let forged = revision_for_envelope(&original, replacement.as_bytes());
        f.blobs.override_read(Zeroizing::new(replacement.as_bytes().to_vec()));
        refused(f.store.read(&cx, &forged, Time::MAX).await, PersistentEnvelopeError::InvalidEnvelope);
        assert_eq!(f.crypto.opens.load(Ordering::Acquire), 1);
    });
}

#[test]
fn real_provider_authenticates_the_facades_canonical_aad() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let revision = f.store.create(&cx, plaintext(b"exact authenticated context"), Time::MAX).await.unwrap();
        f.crypto.inject(CryptoPhase::Open, CryptoFault::WrongAad);
        refused(f.store.read(&cx, &revision, Time::MAX).await, PersistentEnvelopeError::InvalidEnvelope);
        assert_eq!(f.store.read(&cx, &revision, Time::MAX).await.unwrap().as_bytes(), b"exact authenticated context");
    });
}

#[test]
fn previous_key_overlap_reads_old_values_while_new_writes_use_the_active_generation() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let old = f.store.create(&cx, plaintext(b"old-key value"), Time::MAX).await.unwrap();
        let mut rotated = envelope_configuration();
        rotated.ring_generation = 2;
        rotated.keys[0].sealing = false;
        rotated.keys.push(PersistentKeyGeneration { key_id: "test-key-2".into(), generation: 2, sealing: true });
        let reopened = f.reopen(rotated.clone());
        assert_eq!(reopened.read(&cx, &old, Time::MAX).await.unwrap().as_bytes(), b"old-key value");
        let new = reopened.create(&cx, plaintext(b"new-key value"), Time::MAX).await.unwrap();
        let envelope = CanonicalEnvelope::from_bytes(f.blobs.snapshot(&new)).unwrap();
        assert_eq!(envelope.header().unwrap().generation(), 2);
        assert_eq!(reopened.read(&cx, &new, Time::MAX).await.unwrap().as_bytes(), b"new-key value");
        rotated.keys.remove(0);
        let retired = f.reopen(rotated);
        let before = f.crypto.opens.load(Ordering::Acquire);
        refused(retired.read(&cx, &old, Time::MAX).await, PersistentEnvelopeError::InvalidEnvelope);
        assert_eq!(f.crypto.opens.load(Ordering::Acquire), before);
    });
}

#[test]
fn storage_artifact_configuration_and_generation_are_authenticated_context() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let revision = f.store.create(&cx, plaintext(b"pinned store context"), Time::MAX).await.unwrap();
        for field in 0..3 {
            let mut configuration = blob_configuration();
            match field {
                0 => configuration.artifact_digest[0] ^= 1,
                1 => configuration.configuration_fingerprint[0] ^= 1,
                _ => configuration.generation += 1,
            }
            let changed = PersistentBlobStore::new(
                f.facade.store("protected-blob").unwrap(), envelope_configuration(), configuration,
                f.crypto.clone(), f.blobs.clone(),
            ).unwrap();
            refused(changed.read(&cx, &revision, Time::MAX).await, PersistentEnvelopeError::InvalidEnvelope);
        }
        assert_eq!(f.crypto.opens.load(Ordering::Acquire), 3);
    });
}

#[test]
fn a_different_certified_deployment_cannot_open_the_same_record_bytes() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let revision = f.store.create(&cx, plaintext(b"deployment-bound"), Time::MAX).await.unwrap();
        let other_authority = Arc::new(Authority {
            state: Mutex::new(AuthorityState::default()),
            journal: Arc::clone(&f.blobs.journal), events: Arc::clone(&f.events),
        });
        let mut configuration = restore_configuration();
        configuration.deployment_uuid[0] ^= 1;
        let other_restore = RestoreEpochFacade::register(
            &cx, configuration,
            vec![RestoreStoreDeclaration { id: "protected-blob".into(), namespace_digest: [0x41; 32] }],
            other_authority, Time::MAX,
        ).await.unwrap();
        let other = PersistentBlobStore::new(
            other_restore.store("protected-blob").unwrap(), envelope_configuration(), blob_configuration(),
            f.crypto.clone(), f.blobs.clone(),
        ).unwrap();
        refused(other.read(&cx, &revision, Time::MAX).await, PersistentEnvelopeError::InvalidEnvelope);
    });
}

#[test]
fn concurrent_revision_loser_proves_noncommit_and_leaves_the_store_usable() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let original = f.store.create(&cx, plaintext(b"initial"), Time::MAX).await.unwrap();
        let gate = Arc::new(Gate::default());
        f.blobs.inject_commit(CommitFault::PauseBefore(Arc::clone(&gate)));
        let mut loser = Box::pin(f.store.replace(&cx, &original, plaintext(b"losing value"), Time::MAX));
        assert!(poll_once(loser.as_mut()).is_pending());
        assert_eq!(f.authority.unresolved(), 1);
        let winner = f.store.replace(&cx, &original, plaintext(b"winning value"), Time::MAX).await.unwrap();
        gate.release();
        refused(loser.await, PersistentEnvelopeError::Conflict);
        assert_eq!(f.authority.unresolved(), 0);
        assert_eq!(f.authority.state.lock().unwrap().reconciled, 1);
        assert_eq!(f.blobs.journal.lock().unwrap().fence, 2);
        assert!(!f.store.is_quarantined());
        assert_eq!(f.store.read(&cx, &winner, Time::MAX).await.unwrap().as_bytes(), b"winning value");
        let next = f.store.create(&cx, plaintext(b"after conflict"), Time::MAX).await.unwrap();
        assert_eq!(f.store.read(&cx, &next, Time::MAX).await.unwrap().as_bytes(), b"after conflict");
        assert_eq!(f.crypto.nonces.lock().unwrap().len(), 4, "failed CAS consumed its own fresh nonce");
    });
}

#[test]
fn forged_commit_proof_is_rejected_by_the_independent_authority_journal() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        f.blobs.inject_commit(CommitFault::ForgedCommitProof);
        refused(f.store.create(&cx, plaintext(b"committed but not admitted"), Time::MAX).await,
            PersistentEnvelopeError::Restore(RestoreError::Uncertain));
        assert_eq!(f.authority.state.lock().unwrap().rejected_proofs, 1);
        assert_eq!(f.authority.unresolved(), 1);
        assert_eq!(f.blobs.journal.lock().unwrap().records.len(), 1);
        assert!(f.store.is_quarantined());
        let commits = f.blobs.commits.load(Ordering::Acquire);
        refused(f.store.create(&cx, plaintext(b"cannot retry"), Time::MAX).await, PersistentEnvelopeError::Quarantined);
        assert_eq!(f.blobs.commits.load(Ordering::Acquire), commits);
    });
}

#[test]
fn forged_noncommit_proof_never_turns_a_conflict_into_a_healthy_release() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let old = f.store.create(&cx, plaintext(b"initial"), Time::MAX).await.unwrap();
        let current = f.store.replace(&cx, &old, plaintext(b"winner"), Time::MAX).await.unwrap();
        f.blobs.inject_commit(CommitFault::ForgedConflictProof);
        refused(f.store.replace(&cx, &old, plaintext(b"stale"), Time::MAX).await,
            PersistentEnvelopeError::Restore(RestoreError::Uncertain));
        assert_eq!(f.authority.state.lock().unwrap().rejected_proofs, 1);
        assert_eq!(f.authority.unresolved(), 1);
        assert!(f.store.is_quarantined());
        assert!(f.blobs.journal.lock().unwrap().records[&current.record_id()].revision == current);
    });
}

#[test]
fn unproved_conflict_or_not_dispatched_store_error_keeps_the_live_intent() {
    for (fault, error) in [
        (CommitFault::UnprovedConflict, PersistentEnvelopeError::Uncertain),
        (CommitFault::NotDispatched, PersistentEnvelopeError::ProviderUnavailable),
    ] {
        block_on(async {
            let cx = Cx::current().unwrap();
            let f = Fixture::new(&cx).await;
            f.blobs.inject_commit(fault);
            refused(f.store.create(&cx, plaintext(b"unsettled"), Time::MAX).await, error);
            assert_eq!(f.authority.unresolved(), 1);
            assert!(f.blobs.journal.lock().unwrap().witnesses.is_empty());
            assert!(f.store.is_quarantined());
            assert_eq!(f.blobs.commits.load(Ordering::Acquire), 1);
        });
    }
}

#[test]
fn unknown_after_actual_cas_retains_the_intent_and_never_retries() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        f.blobs.inject_commit(CommitFault::UnknownAfterCas);
        refused(f.store.create(&cx, plaintext(b"unknown acknowledgement"), Time::MAX).await, PersistentEnvelopeError::Uncertain);
        assert_eq!(f.blobs.journal.lock().unwrap().records.len(), 1);
        assert_eq!(f.authority.unresolved(), 1);
        assert_eq!(f.authority.state.lock().unwrap().completed, 0);
        assert!(f.store.is_quarantined());
        refused(f.store.create(&cx, plaintext(b"retry forbidden"), Time::MAX).await, PersistentEnvelopeError::Quarantined);
        assert_eq!(f.crypto.seals.load(Ordering::Acquire), 1);
        assert_eq!(f.blobs.commits.load(Ordering::Acquire), 1);
    });
}

#[test]
fn crypto_receipt_mismatches_quarantine_before_plaintext_or_revision_release() {
    for phase in [CryptoPhase::Seal, CryptoPhase::Open] {
        for fault in [
            ReceiptFault::Operation, ReceiptFault::Request, ReceiptFault::Configuration,
            ReceiptFault::Generation, ReceiptFault::Key, ReceiptFault::Envelope, ReceiptFault::Dispatch,
        ] {
            block_on(async {
                let cx = Cx::current().unwrap();
                let f = Fixture::new(&cx).await;
                if phase == CryptoPhase::Seal {
                    f.crypto.inject(phase, CryptoFault::Receipt(fault));
                    refused(f.store.create(&cx, plaintext(b"private"), Time::MAX).await, PersistentEnvelopeError::InvalidReceipt);
                    assert_eq!(f.blobs.commits.load(Ordering::Acquire), 0);
                    assert_eq!(f.authority.unresolved(), 1);
                } else {
                    let revision = f.store.create(&cx, plaintext(b"private"), Time::MAX).await.unwrap();
                    f.crypto.inject(phase, CryptoFault::Receipt(fault));
                    refused(f.store.read(&cx, &revision, Time::MAX).await, PersistentEnvelopeError::InvalidReceipt);
                }
                assert!(f.store.is_quarantined());
                assert_eq!(f.store.bytes.load(Ordering::Acquire), 0);
            });
        }
    }
}

#[test]
fn independently_pinned_blob_receipts_reject_wrong_route_request_or_dispatch() {
    for committing in [false, true] {
        for fault in [
            ReceiptFault::Operation, ReceiptFault::Request, ReceiptFault::Configuration,
            ReceiptFault::Generation, ReceiptFault::Artifact, ReceiptFault::Dispatch,
        ] {
            block_on(async {
                let cx = Cx::current().unwrap();
                let f = Fixture::new(&cx).await;
                if committing {
                    f.blobs.inject_commit(CommitFault::Receipt(fault));
                    refused(f.store.create(&cx, plaintext(b"private"), Time::MAX).await, PersistentEnvelopeError::InvalidReceipt);
                    assert_eq!(f.authority.state.lock().unwrap().completed, 0);
                    assert_eq!(f.authority.unresolved(), 1);
                } else {
                    let revision = f.store.create(&cx, plaintext(b"private"), Time::MAX).await.unwrap();
                    *f.blobs.read_fault.lock().unwrap() = Some(ReadFault::Receipt(fault));
                    refused(f.store.read(&cx, &revision, Time::MAX).await, PersistentEnvelopeError::InvalidReceipt);
                    assert_eq!(f.crypto.opens.load(Ordering::Acquire), 0);
                }
                assert!(f.store.is_quarantined());
            });
        }
    }
}

#[test]
fn incorrect_plaintext_length_is_not_released_even_after_successful_aead() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let revision = f.store.create(&cx, plaintext(b"exact length"), Time::MAX).await.unwrap();
        f.crypto.inject(CryptoPhase::Open, CryptoFault::WrongPlaintextLength);
        refused(f.store.read(&cx, &revision, Time::MAX).await, PersistentEnvelopeError::InvalidReceipt);
        assert!(f.store.is_quarantined());
        assert_eq!(f.store.bytes.load(Ordering::Acquire), 0);
    });
}

#[test]
fn dropped_pending_seal_retains_intent_and_destroys_owners_under_the_restricted_caller() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        f.crypto.inject(CryptoPhase::Seal, CryptoFault::Pause(Arc::new(Gate::default())));
        let mut future = Box::pin(f.store.create(&cx, plaintext(b"owned pending secret"), Time::MAX));
        assert!(poll_once(future.as_mut()).is_pending());
        assert_eq!(f.authority.unresolved(), 1);
        assert_eq!(f.blobs.commits.load(Ordering::Acquire), 0);
        {
            let _restriction = Cx::push_restriction(CapMask::none());
            drop(future);
        }
        assert_eq!(f.crypto.drops.0.lock().unwrap().last(), Some(&[false; 5]));
        assert!(f.store.is_quarantined());
        assert_eq!(f.store.active.load(Ordering::Acquire), 0);
        assert_eq!(f.store.bytes.load(Ordering::Acquire), 0);
    });
}

#[test]
fn dropped_commit_acknowledgement_does_not_erase_the_actual_commit_or_intent() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        f.blobs.inject_commit(CommitFault::PauseAfter(Arc::new(Gate::default())));
        let mut future = Box::pin(f.store.create(&cx, plaintext(b"committed before drop"), Time::MAX));
        assert!(poll_once(future.as_mut()).is_pending());
        assert_eq!(f.blobs.journal.lock().unwrap().records.len(), 1);
        drop(future);
        assert_eq!(f.authority.unresolved(), 1);
        assert_eq!(f.authority.state.lock().unwrap().completed, 0);
        assert_eq!(f.blobs.drops.0.lock().unwrap().len(), 1);
        assert!(f.store.is_quarantined());
        assert_eq!(f.store.bytes.load(Ordering::Acquire), 0);
    });
}

#[test]
fn cancellation_after_crypto_or_cas_dispatch_releases_no_success() {
    for after_cas in [false, true] {
        block_on(async {
            let cx = Cx::current().unwrap();
            let f = Fixture::new(&cx).await;
            if after_cas {
                f.blobs.inject_commit(CommitFault::CancelAfterCas);
            } else {
                f.crypto.inject(CryptoPhase::Seal, CryptoFault::Cancel);
            }
            let result = f.store.create(&cx, plaintext(b"cancelled secret"), Time::MAX).await;
            cx.set_cancel_requested(false);
            refused(result, PersistentEnvelopeError::Cancelled);
            assert_eq!(f.authority.unresolved(), 1);
            assert_eq!(f.blobs.journal.lock().unwrap().records.len(), usize::from(after_cas));
            assert!(f.store.is_quarantined());
            assert_eq!(f.store.bytes.load(Ordering::Acquire), 0);
        });
    }
}

#[test]
fn cancellation_after_decryption_releases_no_plaintext_and_does_not_invent_a_write() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let revision = f.store.create(&cx, plaintext(b"private output"), Time::MAX).await.unwrap();
        f.crypto.inject(CryptoPhase::Open, CryptoFault::Cancel);
        let result = f.store.read(&cx, &revision, Time::MAX).await;
        cx.set_cancel_requested(false);
        refused(result, PersistentEnvelopeError::Cancelled);
        assert_eq!(f.authority.unresolved(), 0);
        assert_eq!(f.store.bytes.load(Ordering::Acquire), 0);
        assert!(!f.store.is_quarantined());
        assert_eq!(f.store.read(&cx, &revision, Time::MAX).await.unwrap().as_bytes(), b"private output");
    });
}

#[test]
fn pending_read_drop_releases_capacity_without_quarantining_a_nonmutating_operation() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let mut configuration = envelope_configuration();
        configuration.limits.active_operations = 1;
        let f = Fixture::configured(&cx, configuration).await;
        let revision = f.store.create(&cx, plaintext(b"read capacity"), Time::MAX).await.unwrap();
        f.crypto.inject(CryptoPhase::Open, CryptoFault::Pause(Arc::new(Gate::default())));
        let mut first = Box::pin(f.store.read(&cx, &revision, Time::MAX));
        assert!(poll_once(first.as_mut()).is_pending());
        let reads = f.blobs.reads.load(Ordering::Acquire);
        refused(f.store.read(&cx, &revision, Time::MAX).await, PersistentEnvelopeError::CapacityExceeded);
        assert_eq!(f.blobs.reads.load(Ordering::Acquire), reads);
        drop(first);
        assert_eq!(f.store.active.load(Ordering::Acquire), 0);
        assert_eq!(f.store.bytes.load(Ordering::Acquire), 0);
        assert!(!f.store.is_quarantined());
        assert_eq!(f.store.read(&cx, &revision, Time::MAX).await.unwrap().as_bytes(), b"read capacity");
    });
}

#[test]
fn retained_plaintext_capacity_remains_charged_until_its_owner_is_dropped() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let mut configuration = envelope_configuration();
        configuration.limits.in_flight_bytes = configuration.limits.envelope_bytes
            + configuration.limits.plaintext_bytes + configuration.limits.aad_bytes + CONTROL_RESERVE;
        let f = Fixture::configured(&cx, configuration).await;
        let revision = f.store.create(&cx, plaintext(b"held allocation"), Time::MAX).await.unwrap();
        let opened = f.store.read(&cx, &revision, Time::MAX).await.unwrap();
        assert_eq!(f.store.bytes.load(Ordering::Acquire), opened.allocated_bytes());
        assert!(opened.allocated_bytes() >= opened.as_bytes().len());
        refused(f.store.read(&cx, &revision, Time::MAX).await, PersistentEnvelopeError::CapacityExceeded);
        drop(opened);
        assert_eq!(f.store.bytes.load(Ordering::Acquire), 0);
        assert_eq!(f.store.read(&cx, &revision, Time::MAX).await.unwrap().as_bytes(), b"held allocation");
    });
}

#[test]
fn input_capacity_and_expired_deadlines_are_rejected_before_external_effects() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let mut oversized = Zeroizing::new(Vec::with_capacity(8192));
        oversized.push(1);
        refused(f.store.create(&cx, BoundedPlaintext::new(oversized).unwrap(), Time::MAX).await,
            PersistentEnvelopeError::TooLarge);
        refused(f.store.create(&cx, plaintext(b"late"), cx.now()).await, PersistentEnvelopeError::DeadlineExceeded);
        assert_eq!(*f.events.lock().unwrap(), vec![Event::Register]);
        assert_eq!(f.authority.unresolved(), 0);
        assert!(!f.store.is_quarantined());
    });
}

#[test]
fn required_effects_are_checked_against_retained_and_ambient_capability_ceilings() {
    for mask in [
        CapSet::<true, false, true, true, true>::MASK,
        CapSet::<true, true, false, true, true>::MASK,
        CapSet::<true, true, true, false, true>::MASK,
        CapSet::<true, true, true, true, false>::MASK,
    ] {
        block_on(async {
            let cx = Cx::current().unwrap();
            let f = Fixture::new(&cx).await;
            let retained = {
                let _restriction = Cx::push_restriction(mask);
                Cx::current().unwrap()
            };
            refused(f.store.create(&retained, plaintext(b"retained"), Time::MAX).await,
                PersistentEnvelopeError::CapabilityUnavailable);
            {
                let _restriction = Cx::push_restriction(mask);
                refused(f.store.create(&cx, plaintext(b"ambient"), Time::MAX).await,
                    PersistentEnvelopeError::CapabilityUnavailable);
            }
            assert_eq!(*f.events.lock().unwrap(), vec![Event::Register]);
            assert!(!f.store.is_quarantined());
        });
    }
}

#[test]
fn pending_seal_deadline_is_caller_owned_and_keeps_the_unresolved_intent() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let mut configuration = envelope_configuration();
        configuration.limits.call_timeout = Duration::from_millis(100);
        let f = Fixture::configured(&cx, configuration).await;
        f.crypto.inject(CryptoPhase::Seal, CryptoFault::Pause(Arc::new(Gate::default())));
        let mut future = Box::pin(f.store.create(&cx, plaintext(b"finite pending operation"), Time::MAX));
        assert!(poll_once(future.as_mut()).is_pending());
        assert_eq!(f.crypto.seals.load(Ordering::Acquire), 1);
        refused(future.await, PersistentEnvelopeError::DeadlineExceeded);
        assert_eq!(f.authority.unresolved(), 1);
        assert_eq!(f.crypto.drops.0.lock().unwrap().len(), 1);
        assert_eq!(f.blobs.commits.load(Ordering::Acquire), 0);
        assert!(f.store.is_quarantined());
        assert_eq!(f.store.bytes.load(Ordering::Acquire), 0);
    });
}

#[test]
fn unknown_crypto_result_does_not_authorize_a_store_write() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        f.crypto.inject(CryptoPhase::Seal, CryptoFault::Unknown);
        refused(f.store.create(&cx, plaintext(b"unconfirmed sealing"), Time::MAX).await,
            PersistentEnvelopeError::Uncertain);
        assert_eq!(f.blobs.commits.load(Ordering::Acquire), 0);
        assert_eq!(f.authority.unresolved(), 1);
        assert!(f.store.is_quarantined());
    });
}

#[test]
fn a_narrower_poll_ceiling_survives_across_seal_cas_and_authority_completion() {
    block_on(async {
        let cx = Cx::current().unwrap();
        let f = Fixture::new(&cx).await;
        let gate = Arc::new(Gate::default());
        f.crypto.inject(CryptoPhase::Seal, CryptoFault::Pause(Arc::clone(&gate)));
        let mut future = Box::pin(f.store.create(&cx, plaintext(b"one retained caller ceiling"), Time::MAX));
        assert!(poll_once(future.as_mut()).is_pending());
        {
            let _restriction = Cx::push_restriction(CapSet::<false, true, true, true, true>::MASK);
            assert!(poll_once(future.as_mut()).is_pending());
        }
        // The ambient caller is wider again, but the in-flight transaction must
        // retain the narrower ceiling for all subsequent provider boundaries.
        gate.release();
        let revision = future.await.unwrap();
        let expected = [false, true, true, true, true];
        assert_eq!(f.crypto.drops.0.lock().unwrap().last(), Some(&expected));
        assert_eq!(f.blobs.drops.0.lock().unwrap().last(), Some(&expected));
        assert_eq!(f.authority.unresolved(), 0);
        assert_eq!(f.authority.state.lock().unwrap().completed, 1);
        assert!(!f.store.is_quarantined());
        assert_eq!(f.store.read(&cx, &revision, Time::MAX).await.unwrap().as_bytes(),
            b"one retained caller ceiling");
        assert_eq!(Cx::current().unwrap().capabilities().spawn, cx.capabilities().spawn);
    });
}
