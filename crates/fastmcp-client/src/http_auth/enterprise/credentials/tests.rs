//! Credential consumers use the real protected-store and restore facades here.
//!
//! The three external providers are bounded in-memory test doubles. The
//! envelope adapter uses an explicitly synthetic XOR/HMAC construction inside
//! the envelope codec; it is not an XC20P implementation or a deployment
//! qualification. It authenticates the framework's canonical AAD and payload
//! so changing either is observable. The independent restore authority checks
//! an atomic blob journal rather than trusting the caller's completion proof.

use super::*;
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use fastmcp_core::HmacSha256Key;
use fastmcp_core::persistent::{
    CanonicalEnvelope, PersistentBackendFailure, PersistentBackendFailureKind,
    PersistentBackendFuture, PersistentBlobBackend, PersistentBlobBackendConfiguration,
    PersistentBlobCommitOutcome, PersistentBlobCommitRequest, PersistentBlobCommitResult,
    PersistentBlobReadRequest, PersistentBlobReadResult, PersistentEnvelopeBackend,
    PersistentEnvelopeConfiguration, PersistentEnvelopeHeader, PersistentEnvelopeLimits,
    PersistentEnvelopeReceipt, PersistentEnvelopeRequest, PersistentKeyGeneration,
    PersistentOpenResult, PersistentSealResult,
};
use fastmcp_core::restore::{
    CertifiedRestoreEpoch, DurableRestoreCommitReceipt, DurableRestoreNonCommitReceipt,
    DurableRestoreResolution, RestoreAuthorityFailure, RestoreAuthorityFuture,
    RestoreAuthorityOperation, RestoreAuthorityOutcome, RestoreAuthorityRequest,
    RestoreAuthorityResponse, RestoreDispatch, RestoreEpochAuthority, RestoreEpochConfiguration,
    RestoreEpochFacade, RestoreLimits, RestoreStoreDeclaration, StableCertificateMode,
};

use crate::http_auth::enterprise::response::tests::{profile, subject_mappings};

const STORE_ID: &str = "enterprise-credential-fixture";
const MAX_FIXTURE_RECORDS: usize = 64;
const MAX_FIXTURE_OPERATIONS: usize = 128;
const MAX_AUTHENTICATED_BYTES: usize = 32 * 1024;

fn fingerprint(bytes: &[u8]) -> [u8; 32] {
    sha256_bounded(bytes, MAX_AUTHENTICATED_BYTES)
        .unwrap()
        .into_bytes()
}

fn failure(kind: PersistentBackendFailureKind) -> PersistentBackendFailure {
    PersistentBackendFailure {
        dispatch: RestoreDispatch::Dispatched,
        kind,
    }
}

fn unavailable() -> PersistentBackendFailure {
    failure(PersistentBackendFailureKind::Unavailable)
}

fn authentication_failed() -> PersistentBackendFailure {
    failure(PersistentBackendFailureKind::AuthenticationFailed)
}

#[derive(Default)]
pub(in crate::http_auth::enterprise) struct CredentialReadGate {
    released: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl CredentialReadGate {
    async fn wait(&self) {
        poll_fn(|context| {
            let mut waker = self.waker.lock().unwrap();
            if self.released.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                *waker = Some(context.waker().clone());
                Poll::Pending
            }
        })
        .await;
    }

    pub(in crate::http_auth::enterprise) fn release(&self) {
        self.released.store(true, Ordering::Release);
        let waker = self.waker.lock().unwrap().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

struct SyntheticEnvelope {
    nonce_counter: AtomicU64,
    authentication_key: HmacSha256Key,
}

impl SyntheticEnvelope {
    fn tag(&self, aad: &[u8], ciphertext: &[u8]) -> Result<[u8; 16], PersistentBackendFailure> {
        let mut authenticated = aad.to_vec();
        authenticated.extend_from_slice(ciphertext);
        let tag = self
            .authentication_key
            .authenticate_bounded(&authenticated, MAX_AUTHENTICATED_BYTES)
            .map_err(|_| authentication_failed())?;
        Ok(tag.as_bytes()[..16].try_into().unwrap())
    }

    fn transform(payload: &mut [u8], nonce: &[u8; 24]) {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= 0xa5 ^ nonce[index % nonce.len()];
        }
    }
}

impl PersistentEnvelopeBackend for SyntheticEnvelope {
    fn seal<'a>(
        &'a self,
        _cx: &'a Cx,
        request: &'a PersistentEnvelopeRequest<'a>,
        plaintext: BoundedPlaintext,
    ) -> PersistentBackendFuture<'a, PersistentSealResult> {
        Box::pin(async move {
            let key = request
                .configuration()
                .keys
                .iter()
                .find(|key| key.sealing)
                .ok_or_else(unavailable)?;
            let sequence = self.nonce_counter.fetch_add(1, Ordering::AcqRel);
            let mut nonce = [0_u8; 24];
            nonce[..16].copy_from_slice(&request.operation_id());
            nonce[16..].copy_from_slice(&sequence.to_be_bytes());
            let header = PersistentEnvelopeHeader::xc20p(key.key_id.clone(), key.generation, nonce)
                .map_err(|_| unavailable())?;
            let aad = request
                .context()
                .canonical_aad(&header)
                .map_err(|_| unavailable())?;
            let mut payload = plaintext.into_zeroizing();
            Self::transform(&mut payload, &nonce);
            let tag = self.tag(&aad, &payload)?;
            payload.extend_from_slice(&tag);
            let envelope = header.encode(&payload).map_err(|_| unavailable())?;
            let receipt = PersistentEnvelopeReceipt::for_request(request, &envelope)
                .map_err(|_| unavailable())?;
            Ok(PersistentSealResult { envelope, receipt })
        })
    }

    fn open<'a>(
        &'a self,
        _cx: &'a Cx,
        request: &'a PersistentEnvelopeRequest<'a>,
        envelope: &'a CanonicalEnvelope,
    ) -> PersistentBackendFuture<'a, PersistentOpenResult> {
        Box::pin(async move {
            let header = envelope.header().map_err(|_| authentication_failed())?;
            let aad = request
                .context()
                .canonical_aad(&header)
                .map_err(|_| authentication_failed())?;
            let mut payload = BoundedPlaintext::new(envelope.ciphertext_and_tag().to_vec().into())
                .map_err(|_| authentication_failed())?
                .into_zeroizing();
            let length = payload
                .len()
                .checked_sub(16)
                .ok_or_else(authentication_failed)?;
            if payload[length..] != self.tag(&aad, &payload[..length])? {
                return Err(authentication_failed());
            }
            // Deliberately retain ciphertext capacity after removing the tag,
            // as an in-place authenticated decryption normally does.
            payload.truncate(length);
            Self::transform(&mut payload, header.nonce());
            let plaintext = BoundedPlaintext::new(payload).map_err(|_| unavailable())?;
            let receipt = PersistentEnvelopeReceipt::for_request(request, envelope)
                .map_err(|_| unavailable())?;
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

enum Witness {
    Committed {
        intent: Intent,
        commit: [u8; 32],
        proof: Vec<u8>,
    },
    Fenced {
        intent: Intent,
        new_fence: u64,
        proof: Vec<u8>,
    },
}

struct Stored {
    revision: PersistentBlobRevision,
    envelope: CanonicalEnvelope,
}

struct Journal {
    fence: u64,
    records: BTreeMap<[u8; 16], Stored>,
    witnesses: BTreeMap<[u8; 16], Witness>,
}

impl Default for Journal {
    fn default() -> Self {
        Self {
            fence: 1,
            records: BTreeMap::new(),
            witnesses: BTreeMap::new(),
        }
    }
}

#[derive(Default)]
struct AuthorityState {
    registered: Vec<RestoreStoreDeclaration>,
    intents: BTreeMap<[u8; 16], Intent>,
}

struct FixtureAuthority {
    state: Mutex<AuthorityState>,
    journal: Arc<Mutex<Journal>>,
}

impl FixtureAuthority {
    fn certified(
        configuration: &RestoreEpochConfiguration,
        store: &RestoreStoreDeclaration,
    ) -> CertifiedRestoreEpoch {
        CertifiedRestoreEpoch {
            authority_id: configuration.authority_id.clone(),
            configuration_fingerprint: configuration.configuration_fingerprint,
            authority_generation: configuration.authority_generation,
            deployment_uuid: configuration.deployment_uuid,
            namespace_digest: store.namespace_digest,
            epoch: 7,
            stable_certificate: None,
        }
    }

    fn respond(
        &self,
        request: &RestoreAuthorityRequest,
    ) -> Result<RestoreAuthorityResponse, RestoreAuthorityFailure> {
        let refused = || RestoreAuthorityFailure {
            dispatch: RestoreDispatch::Dispatched,
        };
        let mut state = self.state.lock().unwrap();
        let outcome = match request.operation() {
            RestoreAuthorityOperation::RegisterStoreSet { stores } => {
                if !state.registered.is_empty() || stores.len() != 1 || stores[0].id != STORE_ID {
                    return Err(refused());
                }
                state.registered = stores.clone();
                RestoreAuthorityOutcome::Registered {
                    store_set_digest: request.store_set_digest(),
                }
            }
            RestoreAuthorityOperation::Current { store } => {
                if !state.registered.contains(store) {
                    return Err(refused());
                }
                RestoreAuthorityOutcome::Current {
                    certified_binding: Self::certified(request.configuration(), store)
                        .canonical_bytes()
                        .unwrap(),
                    store_fence_generation: self.journal.lock().unwrap().fence,
                }
            }
            RestoreAuthorityOperation::PrepareWrite {
                store,
                binding_digest,
                store_fence_generation,
                record_digest,
                ..
            } => {
                let certified = Self::certified(request.configuration(), store)
                    .canonical_bytes()
                    .unwrap();
                if !state.registered.contains(store)
                    || *binding_digest != fingerprint(&certified)
                    || *store_fence_generation != self.journal.lock().unwrap().fence
                    || state.intents.contains_key(&request.operation_id())
                    || state.intents.len() >= MAX_FIXTURE_OPERATIONS
                {
                    return Err(refused());
                }
                state.intents.insert(
                    request.operation_id(),
                    Intent {
                        store: store.id.clone(),
                        binding: *binding_digest,
                        fence: *store_fence_generation,
                        logical: *record_digest,
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
                let valid = {
                    let journal = self.journal.lock().unwrap();
                    match (
                        state.intents.get(intent_operation_id),
                        journal.witnesses.get(intent_operation_id),
                    ) {
                        (
                            Some(intent),
                            Some(Witness::Committed {
                                intent: durable,
                                commit,
                                proof,
                            }),
                        ) => {
                            intent == durable
                                && intent.store == store.id
                                && receipt.operation_id() == *intent_operation_id
                                && receipt.binding_digest() == intent.binding
                                && receipt.store_fence_generation() == intent.fence
                                && receipt.record_digest() == intent.logical
                                && receipt.commit_digest() == *commit
                                && receipt.proof() == proof.as_slice()
                        }
                        _ => false,
                    }
                };
                if !valid {
                    return Err(refused());
                }
                state.intents.remove(intent_operation_id);
                RestoreAuthorityOutcome::Completed {
                    intent_operation_id: *intent_operation_id,
                    commit_digest: receipt.commit_digest(),
                }
            }
            RestoreAuthorityOperation::ReconcileWrite { intent, resolution } => {
                let valid = {
                    let journal = self.journal.lock().unwrap();
                    match (
                        state.intents.get(&intent.operation_id()),
                        journal.witnesses.get(&intent.operation_id()),
                        resolution,
                    ) {
                        (
                            Some(original),
                            Some(Witness::Fenced {
                                intent: durable,
                                new_fence,
                                proof,
                            }),
                            DurableRestoreResolution::FencedNotCommitted(receipt),
                        ) => {
                            original == durable
                                && original.store == intent.store_id()
                                && original.binding == intent.binding_digest()
                                && original.fence == intent.store_fence_generation()
                                && original.logical == intent.record_digest()
                                && receipt.operation_id() == intent.operation_id()
                                && receipt.binding_digest() == original.binding
                                && receipt.store_fence_generation() == original.fence
                                && receipt.record_digest() == original.logical
                                && receipt.fenced_generation() == *new_fence
                                && journal.fence >= *new_fence
                                && receipt.proof() == proof.as_slice()
                        }
                        _ => false,
                    }
                };
                if !valid {
                    return Err(refused());
                }
                state.intents.remove(&intent.operation_id());
                RestoreAuthorityOutcome::Reconciled {
                    intent_operation_id: intent.operation_id(),
                    resolution_digest: resolution.digest().unwrap(),
                }
            }
            RestoreAuthorityOperation::ListUnresolvedWrites { .. } => return Err(refused()),
        };
        Ok(RestoreAuthorityResponse::for_request(request, outcome))
    }
}

impl RestoreEpochAuthority for FixtureAuthority {
    fn execute<'a>(
        &'a self,
        _cx: &'a Cx,
        request: &'a RestoreAuthorityRequest,
    ) -> RestoreAuthorityFuture<'a> {
        Box::pin(async move { self.respond(request) })
    }
}

struct FixtureBlobs {
    journal: Arc<Mutex<Journal>>,
    reads: AtomicUsize,
    next_read_gate: Mutex<Option<Arc<CredentialReadGate>>>,
    corrupt_read_receipt: AtomicBool,
}

impl PersistentBlobBackend for FixtureBlobs {
    fn read<'a>(
        &'a self,
        _cx: &'a Cx,
        request: &'a PersistentBlobReadRequest<'a>,
    ) -> PersistentBackendFuture<'a, PersistentBlobReadResult> {
        Box::pin(async move {
            self.reads.fetch_add(1, Ordering::AcqRel);
            let gate = self.next_read_gate.lock().unwrap().take();
            if let Some(gate) = gate {
                gate.wait().await;
            }
            let journal = self.journal.lock().unwrap();
            if request.store_id() != STORE_ID || request.store_fence_generation() != journal.fence {
                return Err(failure(PersistentBackendFailureKind::Conflict));
            }
            let stored = journal
                .records
                .get(&request.expected_revision().record_id())
                .ok_or_else(unavailable)?;
            if stored.revision != request.expected_revision() {
                return Err(failure(PersistentBackendFailureKind::Conflict));
            }
            let envelope =
                CanonicalEnvelope::from_bytes(stored.envelope.as_bytes().to_vec().into())
                    .map_err(|_| authentication_failed())?;
            let mut receipt = request.receipt();
            if self.corrupt_read_receipt.swap(false, Ordering::AcqRel) {
                receipt.request_digest[0] ^= 1;
            }
            Ok(PersistentBlobReadResult { envelope, receipt })
        })
    }

    fn commit<'a>(
        &'a self,
        _cx: &'a Cx,
        request: &'a PersistentBlobCommitRequest<'a>,
    ) -> PersistentBackendFuture<'a, PersistentBlobCommitResult> {
        Box::pin(async move {
            let fence = request.write_fence();
            let next = request.next_revision();
            let mut journal = self.journal.lock().unwrap();
            if fence.store_id() != STORE_ID
                || journal.witnesses.contains_key(&fence.operation_id())
                || journal.witnesses.len() >= MAX_FIXTURE_OPERATIONS
                || (!journal.records.contains_key(&next.record_id())
                    && journal.records.len() >= MAX_FIXTURE_RECORDS)
                || next.namespace_digest() != fence.namespace_digest()
                || next.envelope_digest() != fingerprint(request.envelope().as_bytes())
            {
                return Err(unavailable());
            }
            let intent = Intent {
                store: fence.store_id().into(),
                binding: fence.binding_digest(),
                fence: fence.store_fence_generation(),
                logical: fence.record_digest(),
            };
            let matches = match (
                request.expected_revision(),
                journal.records.get(&next.record_id()),
            ) {
                (None, None) => next.generation() == 1,
                (Some(expected), Some(stored)) => {
                    stored.revision == expected
                        && expected.record_id() == next.record_id()
                        && expected.generation().checked_add(1) == Some(next.generation())
                }
                _ => false,
            };
            let outcome = if matches && fence.store_fence_generation() == journal.fence {
                let envelope =
                    CanonicalEnvelope::from_bytes(request.envelope().as_bytes().to_vec().into())
                        .map_err(|_| authentication_failed())?;
                let mut proof = b"credential-fixture-commit/".to_vec();
                proof.extend_from_slice(&fence.operation_id());
                proof.extend_from_slice(&request.commit_digest());
                journal.records.insert(
                    next.record_id(),
                    Stored {
                        revision: next,
                        envelope,
                    },
                );
                journal.witnesses.insert(
                    fence.operation_id(),
                    Witness::Committed {
                        intent,
                        commit: request.commit_digest(),
                        proof: proof.clone(),
                    },
                );
                PersistentBlobCommitOutcome::Committed(
                    DurableRestoreCommitReceipt::new(
                        fence.operation_id(),
                        fence.binding_digest(),
                        fence.store_fence_generation(),
                        fence.record_digest(),
                        request.commit_digest(),
                        proof,
                    )
                    .unwrap(),
                )
            } else {
                let new_fence = journal
                    .fence
                    .max(fence.store_fence_generation())
                    .checked_add(1)
                    .ok_or_else(unavailable)?;
                let mut proof = b"credential-fixture-fenced/".to_vec();
                proof.extend_from_slice(&fence.operation_id());
                proof.extend_from_slice(&new_fence.to_be_bytes());
                journal.fence = new_fence;
                journal.witnesses.insert(
                    fence.operation_id(),
                    Witness::Fenced {
                        intent,
                        new_fence,
                        proof: proof.clone(),
                    },
                );
                PersistentBlobCommitOutcome::FencedConflict(
                    DurableRestoreNonCommitReceipt::new(
                        fence.operation_id(),
                        fence.binding_digest(),
                        fence.store_fence_generation(),
                        fence.record_digest(),
                        new_fence,
                        proof,
                    )
                    .unwrap(),
                )
            };
            Ok(PersistentBlobCommitResult {
                receipt: request.receipt(),
                outcome,
            })
        })
    }
}

pub(in crate::http_auth::enterprise) struct CredentialStoreFixture {
    _facade: RestoreEpochFacade,
    store: Arc<PersistentBlobStore>,
    blobs: Arc<FixtureBlobs>,
}

impl CredentialStoreFixture {
    pub(in crate::http_auth::enterprise) async fn new(cx: &Cx) -> Self {
        ProcessGenerationGuard::install().unwrap();
        let journal = Arc::new(Mutex::new(Journal::default()));
        let authority = Arc::new(FixtureAuthority {
            state: Mutex::new(AuthorityState::default()),
            journal: Arc::clone(&journal),
        });
        let facade = RestoreEpochFacade::register(
            cx,
            RestoreEpochConfiguration {
                authority_id: "credential-fixture-authority".into(),
                provider_artifact: "credential-fixture-authority-v1".into(),
                provider_artifact_digest: [0x31; 32],
                configuration_fingerprint: [0x32; 32],
                authority_generation: 1,
                deployment_uuid: [0x33; 16],
                store_set_generation: 1,
                policy_generation: 1,
                certificate_mode: StableCertificateMode::Forbidden,
                limits: RestoreLimits::default(),
            },
            vec![RestoreStoreDeclaration {
                id: STORE_ID.into(),
                namespace_digest: [0x41; 32],
            }],
            authority,
            Time::MAX,
        )
        .await
        .unwrap();
        let blobs = Arc::new(FixtureBlobs {
            journal,
            reads: AtomicUsize::new(0),
            next_read_gate: Mutex::new(None),
            corrupt_read_receipt: AtomicBool::new(false),
        });
        let store = PersistentBlobStore::new(
            facade.store(STORE_ID).unwrap(),
            PersistentEnvelopeConfiguration {
                artifact: "credential-fixture-synthetic-envelope-v1".into(),
                artifact_digest: [0x11; 32],
                configuration_fingerprint: [0x12; 32],
                ring_generation: 1,
                keys: vec![PersistentKeyGeneration {
                    key_id: "credential-fixture-key-1".into(),
                    generation: 1,
                    sealing: true,
                }],
                limits: PersistentEnvelopeLimits {
                    plaintext_bytes: 16 * 1024,
                    envelope_bytes: 24 * 1024,
                    aad_bytes: 4 * 1024,
                    active_operations: 2,
                    in_flight_bytes: 128 * 1024,
                    call_timeout: Duration::from_secs(5),
                },
            },
            PersistentBlobBackendConfiguration {
                artifact: "credential-fixture-atomic-blob-v1".into(),
                artifact_digest: [0x21; 32],
                configuration_fingerprint: [0x22; 32],
                generation: 1,
            },
            Arc::new(SyntheticEnvelope {
                nonce_counter: AtomicU64::new(1),
                authentication_key: HmacSha256Key::from_bytes([0x51; 32]),
            }),
            blobs.clone(),
        )
        .unwrap();
        Self {
            _facade: facade,
            store: Arc::new(store),
            blobs,
        }
    }

    pub(in crate::http_auth::enterprise) fn store(&self) -> Arc<PersistentBlobStore> {
        Arc::clone(&self.store)
    }

    pub(in crate::http_auth::enterprise) fn read_count(&self) -> usize {
        self.blobs.reads.load(Ordering::Acquire)
    }

    pub(in crate::http_auth::enterprise) fn pause_next_read(&self) -> Arc<CredentialReadGate> {
        let gate = Arc::new(CredentialReadGate::default());
        let mut next = self.blobs.next_read_gate.lock().unwrap();
        assert!(next.is_none(), "previous read gate has not been consumed");
        *next = Some(Arc::clone(&gate));
        gate
    }
}

fn run<T>(future: impl Future<Output = T>) -> T {
    fastmcp_core::runtime::block_on(future)
}

fn deadline(cx: &Cx) -> Time {
    cx.now().saturating_add_nanos(5_000_000_000)
}

fn binding(
    selected: &EnterpriseProfile,
    snapshot: &EnterpriseIdentitySnapshotKey,
    role: EnterpriseCredentialRole,
) -> EnterpriseCredentialBinding {
    EnterpriseCredentialBinding::new(selected.clone(), snapshot.clone(), role).unwrap()
}

fn record(
    binding: &EnterpriseCredentialBinding,
    secret: &str,
    generation: u64,
) -> BoundedPlaintext {
    binding
        .encode_record(EnterpriseClientSecret::try_new(secret).unwrap(), generation)
        .unwrap()
}

async fn provision(
    cx: &Cx,
    fixture: &CredentialStoreFixture,
    binding: EnterpriseCredentialBinding,
    secret: &str,
) -> (EnterpriseClientCredentialProvider, PersistentBlobRevision) {
    let revision = fixture
        .store
        .create(cx, record(&binding, secret, 1), deadline(cx))
        .await
        .unwrap();
    let provider = EnterpriseClientCredentialProvider::new(
        binding,
        fixture.store(),
        revision,
        1,
        Instant::now() + Duration::from_secs(60),
    )
    .unwrap();
    (provider, revision)
}

#[derive(Default)]
struct CountWakes(AtomicUsize);

impl Wake for CountWakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn enterprise_protected_credential_selection_binds_profile_snapshot_and_role_before_read() {
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let selected = profile(&["read"]);
        let mappings = subject_mappings(&selected);
        let snapshot = mappings.snapshot();
        let (provider, _) = provision(
            &cx,
            &fixture,
            binding(&selected, snapshot, EnterpriseCredentialRole::Idp),
            "test-idp-secret",
        )
        .await;
        let pending = provider
            .select(&selected, snapshot, EnterpriseCredentialRole::Idp)
            .unwrap();
        let lease = pending.read(&cx, deadline(&cx)).await.unwrap();
        assert_eq!(lease.as_str().unwrap(), "test-idp-secret");
        assert_eq!(fixture.read_count(), 1);

        let changed = profile(&["write"]);
        let changed_mappings = subject_mappings(&changed);
        for (candidate, candidate_snapshot, role) in [
            (&changed, snapshot, EnterpriseCredentialRole::Idp),
            (
                &selected,
                changed_mappings.snapshot(),
                EnterpriseCredentialRole::Idp,
            ),
            (
                &selected,
                snapshot,
                EnterpriseCredentialRole::ResourceAuthorizationServer,
            ),
        ] {
            assert!(matches!(
                provider.select(candidate, candidate_snapshot, role),
                Err(EnterpriseCredentialError::BindingMismatch)
            ));
            assert_eq!(
                fixture.read_count(),
                1,
                "mismatched authority performed a read"
            );
        }
        assert_eq!(lease.as_str().unwrap(), "test-idp-secret");
    });
}

#[test]
fn enterprise_protected_credential_records_require_exact_binding_generation_and_closed_payload() {
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let selected = profile(&["read"]);
        let mappings = subject_mappings(&selected);
        let snapshot = mappings.snapshot();
        let selected_binding = binding(&selected, snapshot, EnterpriseCredentialRole::Idp);

        let (positive, _) = provision(
            &cx,
            &fixture,
            binding(&selected, snapshot, EnterpriseCredentialRole::Idp),
            "test-bound-secret",
        )
        .await;
        let pending = positive
            .select(&selected, snapshot, EnterpriseCredentialRole::Idp)
            .unwrap();
        assert_eq!(
            pending
                .read(&cx, deadline(&cx))
                .await
                .unwrap()
                .as_str()
                .unwrap(),
            "test-bound-secret"
        );

        for corruption in 0..8 {
            let mut bytes = record(&selected_binding, "test-bound-secret", 1).into_zeroizing();
            match corruption {
                0 => bytes[0] ^= 1,
                1 => bytes[RECORD_PREFIX.len()] ^= 1,
                2 => bytes[RECORD_HEADER - 3] = 2,
                3 => bytes[RECORD_HEADER - 1] += 1,
                4 => bytes[RECORD_HEADER] = 0,
                5 => bytes[RECORD_HEADER] = 0xff,
                6 => bytes.push(b'x'),
                7 => {
                    bytes.truncate(RECORD_HEADER);
                    bytes[RECORD_HEADER - 2..].copy_from_slice(&0_u16.to_be_bytes());
                }
                _ => unreachable!(),
            }
            let revision = fixture
                .store
                .create(&cx, BoundedPlaintext::new(bytes).unwrap(), deadline(&cx))
                .await
                .unwrap();
            let provider = EnterpriseClientCredentialProvider::new(
                binding(&selected, snapshot, EnterpriseCredentialRole::Idp),
                fixture.store(),
                revision,
                1,
                Instant::now() + Duration::from_secs(60),
            )
            .unwrap();
            let pending = provider
                .select(&selected, snapshot, EnterpriseCredentialRole::Idp)
                .unwrap();
            assert!(
                matches!(
                    pending.read(&cx, deadline(&cx)).await,
                    Err(EnterpriseCredentialError::InvalidRecord)
                ),
                "corruption {corruption} yielded a usable credential"
            );
        }

        // This is a correctly encoded and protected record for another role;
        // even an authentic backend response cannot choose the consumer role.
        let other_binding = binding(
            &selected,
            snapshot,
            EnterpriseCredentialRole::ResourceAuthorizationServer,
        );
        let revision = fixture
            .store
            .create(
                &cx,
                record(&other_binding, "test-resource-secret", 1),
                deadline(&cx),
            )
            .await
            .unwrap();
        let mismatched = EnterpriseClientCredentialProvider::new(
            selected_binding,
            fixture.store(),
            revision,
            1,
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap();
        let pending = mismatched
            .select(&selected, snapshot, EnterpriseCredentialRole::Idp)
            .unwrap();
        assert!(matches!(
            pending.read(&cx, deadline(&cx)).await,
            Err(EnterpriseCredentialError::InvalidRecord)
        ));
        assert!(
            !fixture.store.is_quarantined(),
            "record rejection is not a forged store receipt"
        );
    });
}

#[test]
fn enterprise_protected_credential_maximum_secret_survives_in_place_open_allocation() {
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let selected = profile(&["read"]);
        let mappings = subject_mappings(&selected);
        let snapshot = mappings.snapshot();
        let secret = "x".repeat(MAX_SECRET_BYTES);
        let (provider, _) = provision(
            &cx,
            &fixture,
            binding(&selected, snapshot, EnterpriseCredentialRole::Idp),
            &secret,
        )
        .await;
        let pending = provider
            .select(&selected, snapshot, EnterpriseCredentialRole::Idp)
            .unwrap();
        let lease = pending.read(&cx, deadline(&cx)).await.unwrap();
        assert_eq!(lease.as_str().unwrap().len(), MAX_SECRET_BYTES);
        assert_eq!(lease.as_str().unwrap(), secret);
        assert!(lease.record.allocated_bytes() > lease.record.as_bytes().len());

        let selected_binding = binding(&selected, snapshot, EnterpriseCredentialRole::Idp);
        let mut oversized = record(&selected_binding, &secret, 1).into_zeroizing();
        oversized.push(b'x');
        oversized[RECORD_HEADER - 2..RECORD_HEADER]
            .copy_from_slice(&((MAX_SECRET_BYTES + 1) as u16).to_be_bytes());
        let revision = fixture
            .store
            .create(
                &cx,
                BoundedPlaintext::new(oversized).unwrap(),
                deadline(&cx),
            )
            .await
            .unwrap();
        let oversized = EnterpriseClientCredentialProvider::new(
            selected_binding,
            fixture.store(),
            revision,
            1,
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap();
        let pending = oversized
            .select(&selected, snapshot, EnterpriseCredentialRole::Idp)
            .unwrap();
        assert!(matches!(
            pending.read(&cx, deadline(&cx)).await,
            Err(EnterpriseCredentialError::InvalidRecord)
        ));
        assert_eq!(lease.as_str().unwrap().len(), MAX_SECRET_BYTES);
    });
}

#[test]
fn enterprise_protected_credential_rotation_keeps_revision_and_generation_fences_and_wakes_waiters()
{
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let selected = profile(&["read"]);
        let mappings = subject_mappings(&selected);
        let snapshot = mappings.snapshot();
        let (provider, first) = provision(
            &cx,
            &fixture,
            binding(&selected, snapshot, EnterpriseCredentialRole::Idp),
            "test-first-secret",
        )
        .await;
        let old = provider
            .select(&selected, snapshot, EnterpriseCredentialRole::Idp)
            .unwrap();
        let old_lease = old.read(&cx, deadline(&cx)).await.unwrap();
        let selected_binding = binding(&selected, snapshot, EnterpriseCredentialRole::Idp);
        let unrelated = fixture
            .store
            .create(
                &cx,
                record(&selected_binding, "test-unrelated-secret", 2),
                deadline(&cx),
            )
            .await
            .unwrap();
        let valid_until = Instant::now() + Duration::from_secs(60);
        assert_eq!(
            provider.rotate(&first, unrelated, 2, valid_until),
            Err(EnterpriseCredentialError::RevisionMismatch)
        );
        assert_eq!(
            provider.rotate(&unrelated, first, 2, valid_until),
            Err(EnterpriseCredentialError::RevisionMismatch)
        );
        assert_eq!(
            provider.rotate(&first, first, 2, valid_until),
            Err(EnterpriseCredentialError::GenerationRollback)
        );
        assert_eq!(old_lease.as_str().unwrap(), "test-first-secret");

        let second = fixture
            .store
            .replace(
                &cx,
                &first,
                record(&selected_binding, "test-second-secret", 2),
                deadline(&cx),
            )
            .await
            .unwrap();
        assert_eq!(
            provider.rotate(&first, second, 1, valid_until),
            Err(EnterpriseCredentialError::GenerationRollback)
        );
        assert_eq!(old_lease.as_str().unwrap(), "test-first-secret");

        let wake = Arc::new(CountWakes::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut context = Context::from_waker(&waker);
        let mut notified = Box::pin(old.revoked());
        assert!(notified.as_mut().poll(&mut context).is_pending());
        assert_eq!(wake.0.load(Ordering::Acquire), 0);
        provider.rotate(&first, second, 2, valid_until).unwrap();
        assert!(
            wake.0.load(Ordering::Acquire) > 0,
            "rotation did not wake its waiter"
        );
        assert!(notified.as_mut().poll(&mut context).is_ready());
        assert_eq!(old.check(), Err(EnterpriseCredentialError::Revoked));
        assert_eq!(old_lease.as_str(), Err(EnterpriseCredentialError::Revoked));
        let reads = fixture.read_count();
        assert!(matches!(
            old.read(&cx, deadline(&cx)).await,
            Err(EnterpriseCredentialError::Revoked)
        ));
        assert_eq!(fixture.read_count(), reads);

        let current = provider
            .select(&selected, snapshot, EnterpriseCredentialRole::Idp)
            .unwrap();
        assert_eq!(
            current
                .read(&cx, deadline(&cx))
                .await
                .unwrap()
                .as_str()
                .unwrap(),
            "test-second-secret"
        );
        assert_eq!(
            provider.rotate(&first, second, 3, valid_until),
            Err(EnterpriseCredentialError::RevisionMismatch)
        );
        assert!(current.check().is_ok());

        // Exact retained revision is mandatory: a new provider cannot ask the
        // backend to silently substitute the newer record for the old one.
        let stale = EnterpriseClientCredentialProvider::new(
            selected_binding,
            fixture.store(),
            first,
            1,
            valid_until,
        )
        .unwrap();
        let stale = stale
            .select(&selected, snapshot, EnterpriseCredentialRole::Idp)
            .unwrap();
        assert!(matches!(
            stale.read(&cx, deadline(&cx)).await,
            Err(EnterpriseCredentialError::StoreUnavailable)
        ));
    });
}

#[test]
fn enterprise_protected_credential_revoke_wakes_pending_read_and_cannot_cancel_sibling() {
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let selected = profile(&["read"]);
        let mappings = subject_mappings(&selected);
        let snapshot = mappings.snapshot();
        let (provider, revision) = provision(
            &cx,
            &fixture,
            binding(&selected, snapshot, EnterpriseCredentialRole::Idp),
            "test-revoked-secret",
        )
        .await;
        let (sibling, _) = provision(
            &cx,
            &fixture,
            binding(
                &selected,
                snapshot,
                EnterpriseCredentialRole::ResourceAuthorizationServer,
            ),
            "test-live-sibling-secret",
        )
        .await;
        let pending = provider
            .select(&selected, snapshot, EnterpriseCredentialRole::Idp)
            .unwrap();
        let gate = fixture.pause_next_read();
        let wake = Arc::new(CountWakes::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut context = Context::from_waker(&waker);
        let mut read = Box::pin(pending.read(&cx, deadline(&cx)));
        assert!(read.as_mut().poll(&mut context).is_pending());
        assert_eq!(fixture.read_count(), 1);
        let mut revoked = Box::pin(pending.revoked());
        assert!(revoked.as_mut().poll(&mut context).is_pending());
        let previous_wakes = wake.0.load(Ordering::Acquire);
        provider.revoke();
        assert!(
            wake.0.load(Ordering::Acquire) > previous_wakes,
            "revocation did not wake its waiter"
        );
        assert!(revoked.as_mut().poll(&mut context).is_ready());
        gate.release();
        assert!(matches!(
            read.await,
            Err(EnterpriseCredentialError::Revoked)
        ));
        assert!(
            cx.checkpoint().is_ok(),
            "revocation cancelled the shared caller"
        );
        assert!(matches!(
            provider.select(&selected, snapshot, EnterpriseCredentialRole::Idp),
            Err(EnterpriseCredentialError::Revoked)
        ));
        assert_eq!(
            provider.rotate(
                &revision,
                revision,
                2,
                Instant::now() + Duration::from_secs(60)
            ),
            Err(EnterpriseCredentialError::Revoked)
        );
        let sibling = sibling
            .select(
                &selected,
                snapshot,
                EnterpriseCredentialRole::ResourceAuthorizationServer,
            )
            .unwrap();
        assert_eq!(
            sibling
                .read(&cx, deadline(&cx))
                .await
                .unwrap()
                .as_str()
                .unwrap(),
            "test-live-sibling-secret"
        );
    });
}

#[test]
fn enterprise_protected_credential_poisoned_lock_still_revokes_and_wakes_pending_owners() {
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let selected = profile(&["read"]);
        let mappings = subject_mappings(&selected);
        let snapshot = mappings.snapshot();
        let (provider, revision) = provision(
            &cx,
            &fixture,
            binding(&selected, snapshot, EnterpriseCredentialRole::Idp),
            "test-poisoned-generation-secret",
        )
        .await;
        let pending = provider
            .select(&selected, snapshot, EnterpriseCredentialRole::Idp)
            .unwrap();
        let wake = Arc::new(CountWakes::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut context = Context::from_waker(&waker);
        let mut notified = Box::pin(pending.revoked());
        assert!(notified.as_mut().poll(&mut context).is_pending());

        // Simulate the exceptional path in which an application panic poisons
        // the generation mutex. Selection and rotation must still fail closed,
        // but revocation must deliver the wakeup to existing leases.
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = provider.current.lock().unwrap();
            panic!("planted generation-lock poison");
        }));
        assert!(poisoned.is_err());
        assert!(provider.current.is_poisoned());
        let before = wake.0.load(Ordering::Acquire);

        provider.revoke();
        assert!(wake.0.load(Ordering::Acquire) > before);
        assert!(notified.as_mut().poll(&mut context).is_ready());
        assert_eq!(pending.check(), Err(EnterpriseCredentialError::Revoked));
        assert_eq!(provider.active_generation.load(Ordering::Acquire), 0);
        assert!(matches!(
            provider.select(&selected, snapshot, EnterpriseCredentialRole::Idp),
            Err(EnterpriseCredentialError::StoreUnavailable)
        ));
        assert_eq!(
            provider.rotate(
                &revision,
                revision,
                2,
                Instant::now() + Duration::from_secs(60),
            ),
            Err(EnterpriseCredentialError::StoreUnavailable)
        );
        // Repeated revoke stays idempotent and never cancels the caller.
        provider.revoke();
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn enterprise_protected_credential_invalid_store_receipt_quarantines_previously_acquired_leases() {
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let selected = profile(&["read"]);
        let mappings = subject_mappings(&selected);
        let snapshot = mappings.snapshot();
        let (provider, _) = provision(
            &cx,
            &fixture,
            binding(&selected, snapshot, EnterpriseCredentialRole::Idp),
            "test-receipt-secret",
        )
        .await;
        let pending = provider
            .select(&selected, snapshot, EnterpriseCredentialRole::Idp)
            .unwrap();
        let lease = pending.read(&cx, deadline(&cx)).await.unwrap();
        assert_eq!(lease.as_str().unwrap(), "test-receipt-secret");
        fixture
            .blobs
            .corrupt_read_receipt
            .store(true, Ordering::Release);
        assert!(matches!(
            pending.read(&cx, deadline(&cx)).await,
            Err(EnterpriseCredentialError::StoreUnavailable)
        ));
        assert!(fixture.store.is_quarantined());
        assert_eq!(
            lease.as_str(),
            Err(EnterpriseCredentialError::StoreUnavailable)
        );
        let reads = fixture.read_count();
        assert!(matches!(
            provider.select(&selected, snapshot, EnterpriseCredentialRole::Idp),
            Err(EnterpriseCredentialError::StoreUnavailable)
        ));
        assert_eq!(fixture.read_count(), reads);
    });
}

#[test]
fn enterprise_protected_credential_creation_refuses_zero_generation_or_expired_authority() {
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let selected = profile(&["read"]);
        let mappings = subject_mappings(&selected);
        let snapshot = mappings.snapshot();
        let (positive, revision) = provision(
            &cx,
            &fixture,
            binding(&selected, snapshot, EnterpriseCredentialRole::Idp),
            "test-live-secret",
        )
        .await;
        for (generation, valid_until, error) in [
            (
                0,
                Instant::now() + Duration::from_secs(60),
                EnterpriseCredentialError::InvalidConfiguration,
            ),
            (1, Instant::now(), EnterpriseCredentialError::Expired),
        ] {
            let result = EnterpriseClientCredentialProvider::new(
                binding(&selected, snapshot, EnterpriseCredentialRole::Idp),
                fixture.store(),
                revision,
                generation,
                valid_until,
            );
            assert!(matches!(result, Err(actual) if actual == error));
        }
        assert_eq!(fixture.read_count(), 0);
        let pending = positive
            .select(&selected, snapshot, EnterpriseCredentialRole::Idp)
            .unwrap();
        assert_eq!(
            pending
                .read(&cx, deadline(&cx))
                .await
                .unwrap()
                .as_str()
                .unwrap(),
            "test-live-secret"
        );
    });
}
