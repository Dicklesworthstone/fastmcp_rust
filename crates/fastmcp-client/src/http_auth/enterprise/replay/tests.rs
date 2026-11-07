//! Real signed OIDC admission and real facade/provider composition. The MAC,
//! restore-authority and use-store adapters below are explicit in-memory fault
//! fixtures. Their keys and journals exist only under cfg(test); these tests
//! do not qualify persistence, external custody, attestation or deployment EMA.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::task::{Context, Waker};

use asupersync::Budget;
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use fastmcp_core::crypto::{HmacSha256Key, HmacSha256Tag};
use fastmcp_core::replay::{
    PersistentHmacSha256Backend, PersistentMacDispatch, PersistentMacFailure,
    PersistentMacKeyGeneration, PersistentMacProviderIdentity, PersistentMacReceipt,
    PersistentMacReply, PersistentMacRequest, PersistentMacVerification,
    PersistentReplayConfiguration, ReplayDigestLimits, ReplayMacLane,
};
use fastmcp_core::restore::{
    CertifiedRestoreEpoch, RestoreAuthorityFailure, RestoreAuthorityFuture,
    RestoreAuthorityOperation, RestoreAuthorityOutcome, RestoreAuthorityRequest,
    RestoreAuthorityResponse, RestoreDispatch, RestoreEpochAuthority, RestoreEpochConfiguration,
    RestoreEpochFacade, RestoreLimits, RestoreStoreDeclaration, StableCertificateMode,
};
use fastmcp_core::{CanonicalHttpUrl, CanonicalResourceId, CanonicalResourceIdPolicy};
use fastmcp_protocol::jose::enterprise::{OidcVerificationKeys, TenantExpectation};
use serde_json::{Value, json};

use super::super::policy::{
    EnterpriseClientAuthentication, EnterpriseProfileConfiguration,
    EnterpriseRegistrationConfiguration, ID_JAG_GRANT_PROFILE, ID_JAG_TOKEN_TYPE,
    IdJagCryptoConfiguration, JWT_BEARER_GRANT, RequestedEnterpriseScopeSet, TOKEN_EXCHANGE_GRANT,
};
use super::super::response::{
    EnterpriseResponseOutcome, EnterpriseResponsePolicy, EnterpriseTokenResponse,
};

const STORE_ID: &str = "enterprise-identity-assertions";
const PROOF: &[u8] = b"fixture-durable-operation-journal";

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(2_000_000_000)
}
fn deadline(cx: &Cx) -> Time {
    Time::from_nanos(cx.now().as_nanos() + 5_000_000_000)
}
fn flow(byte: u8) -> IdentityAssertionFlowEvidence {
    IdentityAssertionFlowEvidence::new([byte; 32], [byte + 1; 32]).unwrap()
}
fn ready<F: Future>(future: F) -> F::Output {
    match Box::pin(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("fixture unexpectedly suspended"),
    }
}
fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn run(test: impl FnOnce(&Cx, Arc<VirtualClock>)) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .with_timer_driver(timer)
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let ambient = Cx::set_current(Some(cx.clone()));
    test(&cx, clock);
    drop(ambient);
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

fn profile(policy: u64, registration: u64, keys: u64) -> EnterpriseProfile {
    let resource = CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap();
    let config = EnterpriseProfileConfiguration {
        idp: EnterpriseRegistrationConfiguration {
            issuer: "https://idp.example".into(),
            token_endpoint: "https://idp.example/token".into(),
            client_id: "native-idp".into(),
            authentication: EnterpriseClientAuthentication::ClientSecretBasic,
            generation: registration,
            scope_allowance: vec!["openid".into(), "read".into()],
        },
        resource_as: EnterpriseRegistrationConfiguration {
            issuer: "https://as.example".into(),
            token_endpoint: "https://as.example/token".into(),
            client_id: "native-resource".into(),
            authentication: EnterpriseClientAuthentication::ClientSecretPost,
            generation: 12,
            scope_allowance: vec!["read".into()],
        },
        idp_authorization_endpoint: "https://idp.example/authorize".into(),
        oidc_jwks_uri: "https://idp.example/oidc-keys".into(),
        oidc_key_generation: keys,
        id_jag_crypto: IdJagCryptoConfiguration {
            issuer: "https://idp.example".into(),
            jwks_uri: "https://idp.example/id-jag-keys".into(),
            resource_as_issuer: "https://as.example".into(),
            algorithm: "RS256".into(),
            key_generation: 22,
            policy_generation: 23,
        },
        resource: CanonicalResourceId::parse_for_endpoint(
            resource.as_str(),
            &resource,
            CanonicalResourceIdPolicy::default(),
        )
        .unwrap(),
        requested_scopes: RequestedEnterpriseScopeSet::from_literals(["read".to_owned()]).unwrap(),
        deployment_scope_allowance: vec!["read".into()],
        policy_generation: policy,
        idp_metadata_generation: 31,
        resource_as_metadata_generation: 32,
        aggregate_registration_generation: 33,
    };
    let docs = [
        json!({
            "issuer":"https://idp.example", "token_endpoint":"https://idp.example/token",
            "authorization_endpoint":"https://idp.example/authorize",
            "jwks_uri":"https://idp.example/oidc-keys",
            "grant_types_supported":["authorization_code",TOKEN_EXCHANGE_GRANT],
            "response_types_supported":["code"], "code_challenge_methods_supported":["S256"],
            "token_endpoint_auth_methods_supported":["client_secret_basic"],
            "identity_chaining_requested_token_types_supported":[ID_JAG_TOKEN_TYPE],
            "id_token_signing_alg_values_supported":["RS256"],
            "scopes_supported":["openid","read"]
        }),
        json!({
            "issuer":"https://as.example", "token_endpoint":"https://as.example/token",
            "authorization_grant_profiles_supported":[ID_JAG_GRANT_PROFILE],
            "grant_types_supported":[JWT_BEARER_GRANT],
            "token_endpoint_auth_methods_supported":["client_secret_post"]
        }),
        json!({
            "authorization_grant_profiles_supported":[ID_JAG_GRANT_PROFILE],
            "grant_types":[TOKEN_EXCHANGE_GRANT,JWT_BEARER_GRANT]
        }),
        json!({
            "issuer":"https://idp.example", "token_endpoint":"https://idp.example/token",
            "client_id":"native-idp", "grant_types":["authorization_code",TOKEN_EXCHANGE_GRANT],
            "token_endpoint_auth_method":"client_secret_basic"
        }),
        json!({
            "issuer":"https://as.example", "token_endpoint":"https://as.example/token",
            "client_id":"native-resource", "grant_types":[JWT_BEARER_GRANT],
            "token_endpoint_auth_method":"client_secret_post"
        }),
    ]
    .map(|document| serde_json::to_vec(&document).unwrap());
    EnterpriseProfile::from_documents(config, &docs[0], &docs[1], &docs[2], &docs[3], &docs[4])
        .unwrap()
}

fn assertion(profile: &EnterpriseProfile) -> EnterpriseIdentityAssertion {
    let fixture: Value = serde_json::from_str(include_str!("../response/assertions.json")).unwrap();
    let keys = OidcVerificationKeys::from_trusted_jwks(
        "https://idp.example",
        21,
        &serde_json::to_vec(&fixture["jwks"]).unwrap(),
    )
    .unwrap();
    let headers = vec![
        ("Content-Type".to_owned(), "application/json".to_owned()),
        ("Cache-Control".to_owned(), "no-store".to_owned()),
    ];
    let body = serde_json::to_vec(&json!({
        "access_token":"temporary-access", "token_type":"Bearer",
        "id_token":fixture["oidc"], "scope":"openid"
    }))
    .unwrap();
    match profile
        .admit_oidc_code_response(
            EnterpriseTokenResponse {
                status: 200,
                headers: &headers,
                body: &body,
            },
            &keys,
            "oidc-flow-nonce",
            TenantExpectation::SingleTenant,
            Some(Duration::from_secs(60)),
            EnterpriseResponsePolicy::default(),
            now(),
        )
        .unwrap()
    {
        EnterpriseResponseOutcome::Success { value, .. } => value,
        _ => panic!("signed fixture must produce an identity assertion"),
    }
}

type Alias = (String, u64, [u8; 32]);
type Intent = ([u8; 32], u64, [u8; 32]);
type Commit = ([u8; 32], u64, [u8; 32], [u8; 32]);
#[derive(Default)]
struct State {
    events: Vec<&'static str>,
    aliases: BTreeSet<Alias>,
    requests: Vec<(Vec<Alias>, [u8; 32], u64, u64, SystemTime)>,
    intents: BTreeMap<[u8; 16], Intent>,
    commits: BTreeMap<[u8; 16], Commit>,
    rings: BTreeMap<[u8; 32], [u8; 32]>,
    request_deadlines: Vec<Time>,
    pending_polls: usize,
    drop_effects: Vec<(bool, bool)>,
}
type Journal = Arc<Mutex<State>>;

struct Mac {
    journal: Journal,
    fail: AtomicBool,
}
impl PersistentHmacSha256Backend for Mac {
    fn mac<'a>(
        &'a self,
        _: &'a Cx,
        request: PersistentMacRequest,
        _: Time,
    ) -> Pin<Box<dyn Future<Output = Result<PersistentMacReply, PersistentMacFailure>> + Send + 'a>>
    {
        Box::pin(async move {
            self.journal.lock().unwrap().events.push("mac");
            if self.fail.load(Ordering::SeqCst) {
                return Err(PersistentMacFailure::new(
                    PersistentMacReceipt::reported_for(&request, PersistentMacDispatch::Unknown),
                ));
            }
            let tag = HmacSha256Key::from_bytes([request.generation() as u8; 32])
                .authenticate_bounded(request.input(), request.input().len())
                .unwrap()
                .into_bytes();
            Ok(PersistentMacReply::new(
                PersistentMacReceipt::reported_for(&request, PersistentMacDispatch::Dispatched),
                tag,
            ))
        })
    }
    fn verify<'a>(
        &'a self,
        _: &'a Cx,
        request: PersistentMacRequest,
        tag: [u8; 32],
        _: Time,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<PersistentMacVerification, PersistentMacFailure>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let verified = HmacSha256Key::from_bytes([request.generation() as u8; 32])
                .verify_bounded(
                    request.input(),
                    request.input().len(),
                    &HmacSha256Tag::from_bytes(tag),
                )
                .is_ok();
            Ok(PersistentMacVerification::new(
                PersistentMacReceipt::reported_for(&request, PersistentMacDispatch::Dispatched),
                verified,
            ))
        })
    }
}
fn engine(
    journal: &Journal,
    mac: Arc<Mac>,
    active: u64,
) -> (Arc<PersistentReplayDigest>, Sha256Digest) {
    let provider = PersistentMacProviderIdentity::new(
        "test-only-mac",
        Sha256Digest::from_bytes([1; 32]),
        Sha256Digest::from_bytes([2; 32]),
    )
    .unwrap();
    let key = |generation| {
        PersistentMacKeyGeneration::new(&format!("generation-{generation}"), generation).unwrap()
    };
    let config = PersistentReplayConfiguration::new(
        provider,
        active,
        key(active),
        (1..active).map(key).collect(),
    )
    .unwrap();
    let digest = Arc::new(
        PersistentReplayDigest::new(
            config,
            mac,
            Arc::new(ReplayMacLane::new(ReplayDigestLimits::default()).unwrap()),
        )
        .unwrap(),
    );
    let acknowledgement = sha256_bounded(digest.ring_digest().as_bytes(), 32).unwrap();
    journal.lock().unwrap().rings.insert(
        digest.ring_digest().into_bytes(),
        acknowledgement.into_bytes(),
    );
    (digest, acknowledgement)
}

struct Authority {
    journal: Journal,
    reject_completion: AtomicBool,
}
impl RestoreEpochAuthority for Authority {
    fn execute<'a>(
        &'a self,
        _: &'a Cx,
        request: &'a RestoreAuthorityRequest,
    ) -> RestoreAuthorityFuture<'a> {
        Box::pin(async move {
            let mut journal = self.journal.lock().unwrap();
            let outcome = match request.operation() {
                RestoreAuthorityOperation::RegisterStoreSet { .. } => {
                    journal.events.push("register");
                    if !journal.intents.is_empty() {
                        return Err(RestoreAuthorityFailure {
                            dispatch: RestoreDispatch::NotDispatched,
                        });
                    }
                    RestoreAuthorityOutcome::Registered {
                        store_set_digest: request.store_set_digest(),
                    }
                }
                RestoreAuthorityOperation::Current { store } => {
                    journal.events.push("current");
                    let configuration = request.configuration();
                    let bytes = CertifiedRestoreEpoch {
                        authority_id: configuration.authority_id.clone(),
                        configuration_fingerprint: configuration.configuration_fingerprint,
                        authority_generation: configuration.authority_generation,
                        deployment_uuid: configuration.deployment_uuid,
                        namespace_digest: store.namespace_digest,
                        epoch: 7,
                        stable_certificate: None,
                    }
                    .canonical_bytes()
                    .unwrap();
                    RestoreAuthorityOutcome::Current {
                        certified_binding: bytes,
                        store_fence_generation: 5,
                    }
                }
                RestoreAuthorityOperation::PrepareWrite {
                    binding_digest,
                    store_fence_generation,
                    record_digest,
                    ..
                } => {
                    journal.events.push("prepare");
                    journal.intents.insert(
                        request.operation_id(),
                        (*binding_digest, *store_fence_generation, *record_digest),
                    );
                    RestoreAuthorityOutcome::Prepared {
                        binding_digest: *binding_digest,
                        store_fence_generation: *store_fence_generation,
                    }
                }
                RestoreAuthorityOperation::CompleteWrite {
                    intent_operation_id,
                    receipt,
                    ..
                } => {
                    journal.events.push("complete");
                    let expected = (
                        receipt.binding_digest(),
                        receipt.store_fence_generation(),
                        receipt.record_digest(),
                        receipt.commit_digest(),
                    );
                    if self.reject_completion.load(Ordering::SeqCst)
                        || receipt.proof() != PROOF
                        || journal.commits.get(intent_operation_id) != Some(&expected)
                        || journal.intents.get(intent_operation_id)
                            != Some(&(expected.0, expected.1, expected.2))
                    {
                        return Err(RestoreAuthorityFailure {
                            dispatch: RestoreDispatch::Unknown,
                        });
                    }
                    journal.intents.remove(intent_operation_id);
                    RestoreAuthorityOutcome::Completed {
                        intent_operation_id: *intent_operation_id,
                        commit_digest: receipt.commit_digest(),
                    }
                }
            };
            Ok(RestoreAuthorityResponse::for_request(request, outcome))
        })
    }
}

fn store_identity(artifact: u8, configuration: u8) -> IdentityAssertionStoreIdentity {
    IdentityAssertionStoreIdentity::new(
        "test-only-identity-use-store-v1",
        Sha256Digest::from_bytes([artifact; 32]),
        Sha256Digest::from_bytes([configuration; 32]),
    )
    .unwrap()
}
struct Store {
    journal: Journal,
    mode: AtomicUsize,
    identity: IdentityAssertionStoreIdentity,
    alternate_identity: IdentityAssertionStoreIdentity,
    substitute_identity: AtomicBool,
}
struct PendingStore {
    journal: Journal,
}
impl Future for PendingStore {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        self.journal.lock().unwrap().pending_polls += 1;
        Poll::Pending
    }
}
impl Drop for PendingStore {
    fn drop(&mut self) {
        let capabilities = Cx::current()
            .expect("provider drop has caller")
            .capabilities();
        self.journal
            .lock()
            .unwrap()
            .drop_effects
            .push((capabilities.spawn, capabilities.remote));
    }
}
impl IdentityAssertionUseStore for Store {
    fn store_id(&self) -> &str {
        STORE_ID
    }
    fn identity(&self) -> &IdentityAssertionStoreIdentity {
        if self.substitute_identity.load(Ordering::SeqCst) {
            &self.alternate_identity
        } else {
            &self.identity
        }
    }
    fn reserve_all<'a>(
        &'a self,
        _: &'a Cx,
        request: IdentityAssertionReservationRequest<'a>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<IdentityAssertionStoreResult, IdentityAssertionStoreError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let decision;
            let commit;
            {
                let mut journal = self.journal.lock().unwrap();
                journal.events.push("store");
                if request.store_identity() != self.identity() {
                    return Err(IdentityAssertionStoreError::Rejected);
                }
                if journal
                    .rings
                    .get(&request.aliases().ring_digest().into_bytes())
                    != Some(&request.ring_acknowledgement_digest().into_bytes())
                {
                    return Err(IdentityAssertionStoreError::Rejected);
                }
                let aliases: Vec<_> = request
                    .aliases()
                    .aliases()
                    .iter()
                    .map(|alias| (alias.key_id().to_owned(), alias.generation(), *alias.tag()))
                    .collect();
                decision = if aliases.iter().any(|alias| journal.aliases.contains(alias)) {
                    IdentityAssertionReservationDecision::AlreadyReserved
                } else {
                    journal.aliases.extend(aliases.iter().cloned());
                    IdentityAssertionReservationDecision::Reserved
                };
                journal.requests.push((
                    aliases,
                    *request.evidence().flow().flow_id(),
                    request.evidence().policy_generation(),
                    request.evidence().idp_registration_generation(),
                    request.evidence().retain_until(),
                ));
                journal.request_deadlines.push(request.deadline());
                commit = request.commit_digest(decision);
                journal.commits.insert(
                    request.fence().operation_id(),
                    (
                        request.fence().binding_digest(),
                        request.fence().store_fence_generation(),
                        request.fence().record_digest(),
                        commit,
                    ),
                );
            }
            match self.mode.load(Ordering::SeqCst) {
                1 => return Ok(IdentityAssertionStoreResult::Unknown),
                3 => {
                    PendingStore {
                        journal: self.journal.clone(),
                    }
                    .await
                }
                4 => return Err(IdentityAssertionStoreError::Unavailable),
                _ => {}
            }
            let commit = if self.mode.load(Ordering::SeqCst) == 2 {
                [0x77; 32]
            } else {
                commit
            };
            let receipt = DurableRestoreCommitReceipt::new(
                request.fence().operation_id(),
                request.fence().binding_digest(),
                request.fence().store_fence_generation(),
                request.fence().record_digest(),
                commit,
                PROOF.to_vec(),
            )
            .unwrap();
            Ok(IdentityAssertionStoreResult::Committed { decision, receipt })
        })
    }
}

struct Harness {
    replay: IdentityAssertionReplay,
    restore: RegisteredRestoreStore,
    journal: Journal,
    mac: Arc<Mac>,
    store: Arc<Store>,
    authority: Arc<Authority>,
}
impl Harness {
    fn new(cx: &Cx) -> Self {
        Self::with_intent_lifetime(cx, RestoreLimits::default().intent_lifetime)
    }
    fn with_intent_lifetime(cx: &Cx, intent_lifetime: Duration) -> Self {
        let journal = Arc::new(Mutex::new(State::default()));
        let mac = Arc::new(Mac {
            journal: journal.clone(),
            fail: AtomicBool::new(false),
        });
        let (digest, acknowledgement) = engine(&journal, mac.clone(), 2);
        let authority = Arc::new(Authority {
            journal: journal.clone(),
            reject_completion: AtomicBool::new(false),
        });
        let facade = ready(RestoreEpochFacade::register(
            cx,
            RestoreEpochConfiguration {
                authority_id: "test-only-epoch-authority".into(),
                provider_artifact: "test-only-authority-v1".into(),
                provider_artifact_digest: [3; 32],
                configuration_fingerprint: [4; 32],
                authority_generation: 1,
                deployment_uuid: [5; 16],
                store_set_generation: 1,
                policy_generation: 1,
                certificate_mode: StableCertificateMode::Forbidden,
                limits: RestoreLimits {
                    intent_lifetime,
                    ..RestoreLimits::default()
                },
            },
            vec![RestoreStoreDeclaration {
                id: STORE_ID.into(),
                namespace_digest: [6; 32],
            }],
            authority.clone(),
            deadline(cx),
        ))
        .unwrap();
        let restore = facade.store(STORE_ID).unwrap();
        let store = Arc::new(Store {
            journal: journal.clone(),
            mode: AtomicUsize::new(0),
            identity: store_identity(7, 8),
            alternate_identity: store_identity(7, 80),
            substitute_identity: AtomicBool::new(false),
        });
        let replay = IdentityAssertionReplay::new(
            digest,
            restore.clone(),
            store.clone(),
            acknowledgement,
            store.identity.clone(),
        )
        .unwrap();
        Self {
            replay,
            restore,
            journal,
            mac,
            store,
            authority,
        }
    }
}

#[test]
fn verified_assertion_reserves_every_alias_then_completes_the_independent_intent() {
    run(|cx, _| {
        let harness = Harness::new(cx);
        let profile = profile(30, 11, 21);
        let reserved = ready(harness.replay.reserve(
            cx,
            &profile,
            assertion(&profile),
            flow(10),
            now(),
            deadline(cx),
        ))
        .unwrap();
        assert_eq!(reserved.identity().subject().as_str(), "client-facing");
        assert_eq!(
            harness.replay.process,
            ProcessGenerationGuard::installed().unwrap().token(),
        );
        assert!(harness.replay.process.verify().is_ok());
        assert!(reserved.store_identity() == &harness.store.identity);
        assert_eq!(
            reserved.evidence().retain_until(),
            now() + Duration::from_secs(540)
        );
        assert_eq!(
            reserved.evidence().assertion_expires_at(),
            now() + Duration::from_secs(240)
        );
        let journal = harness.journal.lock().unwrap();
        assert_eq!(
            journal.events,
            [
                "register", "mac", "mac", "current", "prepare", "store", "complete"
            ]
        );
        assert_eq!(journal.aliases.len(), 2);
        assert!(journal.intents.is_empty());
        assert_eq!(journal.requests[0].0.len(), 2);
        assert_eq!(journal.requests[0].1, [10; 32]);
        assert!(!harness.restore.is_quarantined());
        assert_ne!(reserved.restore_binding_digest(), [0; 32]);
    });
}

#[test]
fn flow_session_registration_and_policy_changes_never_partition_replay_keys() {
    run(|cx, _| {
        let harness = Harness::new(cx);
        let first = profile(30, 11, 21);
        drop(
            ready(harness.replay.reserve(
                cx,
                &first,
                assertion(&first),
                flow(10),
                now(),
                deadline(cx),
            ))
            .unwrap(),
        );
        let second = profile(91, 92, 21);
        assert!(matches!(
            ready(harness.replay.reserve(
                cx,
                &second,
                assertion(&second),
                flow(20),
                now(),
                deadline(cx),
            )),
            Err(IdentityAssertionReplayError::AlreadyReserved)
        ));
        let journal = harness.journal.lock().unwrap();
        assert_eq!(journal.requests.len(), 2);
        assert_eq!(journal.requests[0].0, journal.requests[1].0);
        assert_ne!(journal.requests[0].1, journal.requests[1].1);
        assert_ne!(journal.requests[0].2, journal.requests[1].2);
        assert_ne!(journal.requests[0].3, journal.requests[1].3);
        assert_eq!(journal.requests[0].4, journal.requests[1].4);
        assert!(journal.intents.is_empty());
        assert!(!harness.restore.is_quarantined());
    });
}

#[test]
fn rotation_checks_previous_aliases_and_cannot_reopen_a_consumed_assertion() {
    run(|cx, _| {
        let harness = Harness::new(cx);
        let profile = profile(30, 11, 21);
        drop(
            ready(harness.replay.reserve(
                cx,
                &profile,
                assertion(&profile),
                flow(10),
                now(),
                deadline(cx),
            ))
            .unwrap(),
        );
        let (engine, acknowledgement) = engine(&harness.journal, harness.mac.clone(), 3);
        let rotated = IdentityAssertionReplay::new(
            engine,
            harness.restore.clone(),
            harness.store.clone(),
            acknowledgement,
            harness.store.identity.clone(),
        )
        .unwrap();
        assert!(matches!(
            ready(rotated.reserve(
                cx,
                &profile,
                assertion(&profile),
                flow(30),
                now(),
                deadline(cx),
            )),
            Err(IdentityAssertionReplayError::AlreadyReserved)
        ));
        let journal = harness.journal.lock().unwrap();
        assert_eq!(journal.requests[1].0.len(), 3);
        assert_eq!(
            &journal.requests[1].0[..2],
            journal.requests[0].0.as_slice()
        );
        assert_eq!(journal.aliases.len(), 2);
        assert!(journal.intents.is_empty());
    });
}

#[test]
fn unknown_failed_or_misbound_store_output_never_releases_or_retries() {
    run(|cx, _| {
        for mode in [1, 2, 4] {
            let harness = Harness::new(cx);
            let profile = profile(30, 11, 21);
            harness.store.mode.store(mode, Ordering::SeqCst);
            let result = ready(harness.replay.reserve(
                cx,
                &profile,
                assertion(&profile),
                flow(10),
                now(),
                deadline(cx),
            ));
            let expected = match mode {
                1 => IdentityAssertionReplayError::UnknownStoreOutcome,
                2 => IdentityAssertionReplayError::InvalidReceipt,
                _ => IdentityAssertionReplayError::StoreUnavailable,
            };
            assert!(matches!(result, Err(error) if error == expected));
            assert!(harness.restore.is_quarantined());
            let before = harness.journal.lock().unwrap().events.len();
            assert!(matches!(
                ready(harness.replay.reserve(
                    cx,
                    &profile,
                    assertion(&profile),
                    flow(40),
                    now(),
                    deadline(cx),
                )),
                Err(IdentityAssertionReplayError::RestoreUnavailable)
            ));
            let journal = harness.journal.lock().unwrap();
            assert_eq!(journal.events.len(), before);
            assert_eq!(journal.aliases.len(), 2);
            assert_eq!(journal.intents.len(), 1);
            assert!(!journal.events.contains(&"complete"));
        }
    });
}

#[test]
fn authority_rejection_does_not_expose_the_reserved_assertion() {
    run(|cx, _| {
        let harness = Harness::new(cx);
        let profile = profile(30, 11, 21);
        harness
            .authority
            .reject_completion
            .store(true, Ordering::SeqCst);
        assert!(matches!(
            ready(harness.replay.reserve(
                cx,
                &profile,
                assertion(&profile),
                flow(10),
                now(),
                deadline(cx),
            )),
            Err(IdentityAssertionReplayError::RestoreUnavailable)
        ));
        let journal = harness.journal.lock().unwrap();
        assert_eq!(journal.events.last(), Some(&"complete"));
        assert_eq!(journal.aliases.len(), 2);
        assert_eq!(journal.intents.len(), 1);
        assert!(harness.restore.is_quarantined());
    });
}

#[test]
fn invalid_profile_expiration_and_deadline_fail_before_mac_or_store_access() {
    run(|cx, _| {
        let harness = Harness::new(cx);
        let valid = profile(30, 11, 21);
        let wrong_keys = profile(30, 11, 99);
        assert!(matches!(
            ready(harness.replay.reserve(
                cx,
                &wrong_keys,
                assertion(&valid),
                flow(10),
                now(),
                deadline(cx),
            )),
            Err(IdentityAssertionReplayError::InvalidAssertion)
        ));
        assert!(matches!(
            ready(harness.replay.reserve(
                cx,
                &valid,
                assertion(&valid),
                flow(10),
                now() + Duration::from_secs(240),
                deadline(cx),
            )),
            Err(IdentityAssertionReplayError::InvalidLifetime)
        ));
        assert!(matches!(
            ready(harness.replay.reserve(
                cx,
                &valid,
                assertion(&valid),
                flow(10),
                now(),
                Time::ZERO,
            )),
            Err(IdentityAssertionReplayError::TimedOut)
        ));
        assert_eq!(harness.journal.lock().unwrap().events, ["register"]);
        assert!(!harness.restore.is_quarantined());
    });
}

#[test]
fn failed_mac_derivation_never_creates_an_authority_intent_or_partial_reservation() {
    run(|cx, _| {
        let harness = Harness::new(cx);
        let profile = profile(30, 11, 21);
        harness.mac.fail.store(true, Ordering::SeqCst);
        assert!(matches!(
            ready(harness.replay.reserve(
                cx,
                &profile,
                assertion(&profile),
                flow(10),
                now(),
                deadline(cx),
            )),
            Err(IdentityAssertionReplayError::DigestUnavailable)
        ));
        let journal = harness.journal.lock().unwrap();
        assert_eq!(journal.events, ["register", "mac"]);
        assert!(journal.aliases.is_empty());
        assert!(journal.intents.is_empty());
        assert!(!harness.restore.is_quarantined());
    });
}

#[test]
fn caller_cancellation_retains_the_written_aliases_and_unresolved_intent() {
    run(|cx, _| {
        let harness = Harness::new(cx);
        let profile = profile(30, 11, 21);
        harness.store.mode.store(3, Ordering::SeqCst);
        let mut future = Box::pin(harness.replay.reserve(
            cx,
            &profile,
            assertion(&profile),
            flow(10),
            now(),
            deadline(cx),
        ));
        assert!(poll(future.as_mut()).is_pending());
        cx.set_cancel_requested(true);
        assert!(matches!(
            poll(future.as_mut()),
            Poll::Ready(Err(IdentityAssertionReplayError::Cancelled))
        ));
        drop(future);
        cx.set_cancel_requested(false);
        let journal = harness.journal.lock().unwrap();
        assert_eq!(journal.pending_polls, 1);
        assert_eq!(journal.aliases.len(), 2);
        assert_eq!(journal.intents.len(), 1);
        assert!(harness.restore.is_quarantined());
        assert_eq!(harness.replay.pending.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn deadline_discards_pending_store_work_without_retry_or_release() {
    run(|cx, clock| {
        let harness = Harness::new(cx);
        let profile = profile(30, 11, 21);
        harness.store.mode.store(3, Ordering::SeqCst);
        let mut future = Box::pin(harness.replay.reserve(
            cx,
            &profile,
            assertion(&profile),
            flow(10),
            now(),
            deadline(cx),
        ));
        assert!(poll(future.as_mut()).is_pending());
        clock.advance(5_000_000_001);
        assert!(matches!(
            poll(future.as_mut()),
            Poll::Ready(Err(IdentityAssertionReplayError::TimedOut))
        ));
        drop(future);
        assert!(harness.restore.is_quarantined());
        assert_eq!(harness.journal.lock().unwrap().pending_polls, 1);
    });
}

#[test]
fn pending_store_drop_keeps_the_tightest_previously_observed_effect_ceiling() {
    run(|cx, _| {
        let harness = Harness::new(cx);
        let profile = profile(30, 11, 21);
        harness.store.mode.store(3, Ordering::SeqCst);
        let mut future = Box::pin(harness.replay.reserve(
            cx,
            &profile,
            assertion(&profile),
            flow(10),
            now(),
            deadline(cx),
        ));
        assert!(poll(future.as_mut()).is_pending());
        {
            let _restricted = Cx::push_restriction(CapSet::<false, true, true, true, true>::MASK);
            assert!(poll(future.as_mut()).is_pending());
        }
        drop(future);
        let journal = harness.journal.lock().unwrap();
        assert_eq!(journal.drop_effects, [(false, true)]);
        assert!(harness.restore.is_quarantined());
        assert_eq!(harness.replay.pending.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn resumed_denied_effects_reject_before_polling_the_store_again() {
    run(|cx, _| {
        let harness = Harness::new(cx);
        let profile = profile(30, 11, 21);
        harness.store.mode.store(3, Ordering::SeqCst);
        let mut future = Box::pin(harness.replay.reserve(
            cx,
            &profile,
            assertion(&profile),
            flow(10),
            now(),
            deadline(cx),
        ));
        assert!(poll(future.as_mut()).is_pending());
        {
            let _restricted = Cx::push_restriction(CapSet::<true, true, true, true, false>::MASK);
            assert!(matches!(
                poll(future.as_mut()),
                Poll::Ready(Err(IdentityAssertionReplayError::RuntimeUnavailable))
            ));
        }
        drop(future);
        let journal = harness.journal.lock().unwrap();
        assert_eq!(journal.pending_polls, 1);
        assert_eq!(journal.drop_effects, [(true, false)]);
        assert!(harness.restore.is_quarantined());
    });
}

#[test]
fn reservation_capacity_rejects_before_access_and_releases_on_drop() {
    run(|cx, _| {
        let harness = Harness::new(cx);
        let profile = profile(30, 11, 21);
        let permits: Vec<_> = (0..MAX_PENDING_ASSERTION_RESERVATIONS)
            .map(|_| ReservationPermit::new(&harness.replay.pending).unwrap())
            .collect();
        assert!(matches!(
            ready(harness.replay.reserve(
                cx,
                &profile,
                assertion(&profile),
                flow(10),
                now(),
                deadline(cx),
            )),
            Err(IdentityAssertionReplayError::Saturated)
        ));
        assert_eq!(harness.journal.lock().unwrap().events, ["register"]);
        drop(permits);
        drop(
            ready(harness.replay.reserve(
                cx,
                &profile,
                assertion(&profile),
                flow(10),
                now(),
                deadline(cx),
            ))
            .unwrap(),
        );
        assert_eq!(harness.replay.pending.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn signed_assertion_lifetime_shortens_the_full_provider_deadline() {
    run(|cx, clock| {
        let harness = Harness::new(cx);
        let profile = profile(30, 11, 21);
        harness.store.mode.store(3, Ordering::SeqCst);
        let mut future = Box::pin(harness.replay.reserve(
            cx,
            &profile,
            assertion(&profile),
            flow(10),
            now() + Duration::from_secs(239),
            deadline(cx),
        ));
        assert!(poll(future.as_mut()).is_pending());
        clock.advance(1_000_000_001);
        assert!(matches!(
            poll(future.as_mut()),
            Poll::Ready(Err(IdentityAssertionReplayError::TimedOut))
        ));
        drop(future);
        let journal = harness.journal.lock().unwrap();
        assert_eq!(journal.requests[0].4, now() + Duration::from_secs(540));
        assert_eq!(journal.pending_polls, 1);
        assert!(harness.restore.is_quarantined());
    });
}

#[test]
fn store_work_cannot_outlive_the_authoritys_shorter_write_intent() {
    run(|cx, clock| {
        let harness = Harness::with_intent_lifetime(cx, Duration::from_secs(1));
        let profile = profile(30, 11, 21);
        harness.store.mode.store(3, Ordering::SeqCst);
        let outer_deadline = deadline(cx);
        let mut future = Box::pin(harness.replay.reserve(
            cx,
            &profile,
            assertion(&profile),
            flow(10),
            now(),
            outer_deadline,
        ));
        assert!(poll(future.as_mut()).is_pending());
        assert_eq!(
            harness.journal.lock().unwrap().request_deadlines,
            [Time::from_nanos(1_000_000_000)],
        );
        clock.advance(2_000_000_000);
        assert!(
            cx.now() < outer_deadline,
            "the caller's longer budget remains live"
        );
        assert!(matches!(
            poll(future.as_mut()),
            Poll::Ready(Err(IdentityAssertionReplayError::TimedOut))
        ));
        drop(future);
        let journal = harness.journal.lock().unwrap();
        assert_eq!(journal.pending_polls, 1);
        assert_eq!(journal.aliases.len(), 2);
        assert_eq!(journal.intents.len(), 1);
        assert!(!journal.events.contains(&"complete"));
        assert!(harness.restore.is_quarantined());
    });
}

#[test]
fn same_store_id_cannot_substitute_its_named_artifact_or_configuration() {
    run(|cx, _| {
        let harness = Harness::new(cx);
        let profile = profile(30, 11, 21);
        for expected in [store_identity(70, 8), store_identity(7, 80)] {
            let (engine, acknowledgement) = engine(&harness.journal, harness.mac.clone(), 2);
            assert!(matches!(
                IdentityAssertionReplay::new(
                    engine,
                    harness.restore.clone(),
                    harness.store.clone(),
                    acknowledgement,
                    expected,
                ),
                Err(IdentityAssertionReplayError::InvalidConfiguration)
            ));
        }
        harness
            .store
            .substitute_identity
            .store(true, Ordering::SeqCst);
        assert_eq!(harness.store.store_id(), STORE_ID);
        assert!(matches!(
            ready(harness.replay.reserve(
                cx,
                &profile,
                assertion(&profile),
                flow(10),
                now(),
                deadline(cx),
            )),
            Err(IdentityAssertionReplayError::InvalidConfiguration)
        ));
        assert_eq!(harness.journal.lock().unwrap().events, ["register"]);
        assert!(!harness.restore.is_quarantined());
        harness
            .store
            .substitute_identity
            .store(false, Ordering::SeqCst);
        let reserved = ready(harness.replay.reserve(
            cx,
            &profile,
            assertion(&profile),
            flow(10),
            now(),
            deadline(cx),
        ))
        .unwrap();
        assert!(reserved.store_identity() == &harness.store.identity);
        assert_eq!(
            reserved.store_identity().digest(),
            store_identity(7, 8).digest(),
        );
    });
}
