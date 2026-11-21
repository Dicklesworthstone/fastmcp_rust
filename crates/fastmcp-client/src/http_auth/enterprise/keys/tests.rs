//! The private response fixture exercises the public acquisition orchestration
//! and real signed consumers. It does not replace or qualify DNS, TCP or TLS.
//! Separate resolver tests use the actual guarded adapter to check caller
//! authority. No fixture seam is present in non-test builds.

use super::*;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Mutex, atomic::AtomicUsize};
use std::task::{Context, Waker};
use std::time::SystemTime;

use asupersync::Budget;
use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use fastmcp_core::{CanonicalResourceId, CanonicalResourceIdPolicy};
use fastmcp_transport::{GuardedHttpRedirect, GuardedHttpResolver};
use serde_json::{Value, json};

use super::super::policy::{
    EnterpriseClientAuthentication, EnterpriseProfileConfiguration,
    EnterpriseRegistrationConfiguration, ID_JAG_GRANT_PROFILE, ID_JAG_TOKEN_TYPE,
    IdJagCryptoConfiguration, JWT_BEARER_GRANT, RequestedEnterpriseScopeSet, TOKEN_EXCHANGE_GRANT,
};
use super::super::response::{
    EnterpriseResponseError, EnterpriseResponseOutcome, EnterpriseResponsePolicy,
    EnterpriseTokenResponse,
};
use super::super::verification::{ResourceTenantExpectation, TenantExpectation};

const OIDC: &str = "https://oidc-keys.example/jwks";
const ID_JAG: &str = "https://id-jag-keys.example/jwks";

fn fixtures() -> Value {
    serde_json::from_str(include_str!("../response/assertions.json")).unwrap()
}
fn profile() -> EnterpriseProfile {
    profile_for("https://idp.example", OIDC, ID_JAG, 21, 22)
}
fn profile_for(
    issuer: &str,
    oidc: &str,
    jag: &str,
    oidc_generation: u64,
    jag_generation: u64,
) -> EnterpriseProfile {
    let resource = CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap();
    let token_endpoint = format!("{issuer}/token");
    let authorization_endpoint = format!("{issuer}/authorize");
    let configuration = EnterpriseProfileConfiguration {
        idp: EnterpriseRegistrationConfiguration {
            issuer: issuer.into(),
            token_endpoint: token_endpoint.clone(),
            client_id: "native-idp".into(),
            authentication: EnterpriseClientAuthentication::ClientSecretBasic,
            generation: 11,
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
        idp_authorization_endpoint: authorization_endpoint.clone(),
        oidc_jwks_uri: oidc.into(),
        oidc_key_generation: oidc_generation,
        id_jag_crypto: IdJagCryptoConfiguration {
            issuer: issuer.into(),
            jwks_uri: jag.into(),
            resource_as_issuer: "https://as.example".into(),
            algorithm: "RS256".into(),
            key_generation: jag_generation,
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
        policy_generation: 30,
        idp_metadata_generation: 31,
        resource_as_metadata_generation: 32,
        aggregate_registration_generation: 33,
    };
    let documents = [
        json!({
            "issuer":issuer, "token_endpoint":token_endpoint,
            "authorization_endpoint":authorization_endpoint, "jwks_uri":oidc,
            "grant_types_supported":["authorization_code",TOKEN_EXCHANGE_GRANT],
            "response_types_supported":["code"], "code_challenge_methods_supported":["S256"],
            "token_endpoint_auth_methods_supported":["client_secret_basic"],
            "identity_chaining_requested_token_types_supported":[ID_JAG_TOKEN_TYPE],
            "id_token_signing_alg_values_supported":["RS256"], "scopes_supported":["openid","read"]
        }),
        json!({
            "issuer":"https://as.example", "token_endpoint":"https://as.example/token",
            "authorization_grant_profiles_supported":[ID_JAG_GRANT_PROFILE],
            "grant_types_supported":[JWT_BEARER_GRANT],
            "token_endpoint_auth_methods_supported":["client_secret_post"]
        }),
        json!({"authorization_grant_profiles_supported":[ID_JAG_GRANT_PROFILE],
            "grant_types":[TOKEN_EXCHANGE_GRANT,JWT_BEARER_GRANT]}),
        json!({"issuer":issuer, "token_endpoint":token_endpoint, "client_id":"native-idp",
            "grant_types":["authorization_code",TOKEN_EXCHANGE_GRANT],
            "token_endpoint_auth_method":"client_secret_basic"}),
        json!({"issuer":"https://as.example", "token_endpoint":"https://as.example/token",
            "client_id":"native-resource", "grant_types":[JWT_BEARER_GRANT],
            "token_endpoint_auth_method":"client_secret_post"}),
    ]
    .map(|value| serde_json::to_vec(&value).unwrap());
    EnterpriseProfile::from_documents(
        configuration,
        &documents[0],
        &documents[1],
        &documents[2],
        &documents[3],
        &documents[4],
    )
    .unwrap()
}
fn policy() -> GuardedHttpFetchPolicy {
    GuardedHttpFetchPolicy::new(
        MAX_JWKS_BYTES,
        Duration::from_secs(5),
        Duration::from_secs(2),
        "reviewed-roots-7",
    )
    .unwrap()
}
fn response(uri: &str) -> GuardedHttpFetchResponse {
    let url = GuardedHttpsUrl::parse(uri).unwrap();
    let mut body = serde_json::to_vec(&fixtures()["jwks"]).unwrap();
    // The operator deliberately authorizes the public RFC fixture key for both
    // purposes. Different exact documents still require independent GETs.
    if uri == ID_JAG {
        body.push(b'\n');
    }
    GuardedHttpFetchResponse {
        status: 200,
        body,
        redirect: None,
        headers: vec![(
            "Content-Type".into(),
            if uri == OIDC {
                "application/json; charset=\"UTF-8\"".into()
            } else {
                "application/jwk-set+json".into()
            },
        )],
        provenance: GuardedHttpPeerProvenance {
            host: url.host().into(),
            selected_address: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)),
                url.port(),
            ),
            leaf_certificate_sha256: [42; 32],
            alpn: Some(b"http/1.1".to_vec()),
            tls_protocol: Some("TLSv1_3".into()),
            root_policy_revision: "reviewed-roots-7".into(),
        },
    }
}

pub(super) trait Exchange: Send + Sync {
    fn get<'a>(
        &'a self,
        cx: &'a Cx,
        url: &'a GuardedHttpsUrl,
        lifetime: Arc<dyn Send + Sync>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<GuardedHttpFetchResponse, GuardedHttpFetchError>>
                + Send
                + 'a,
        >,
    >;
}
struct Step {
    ready_at: Time,
    result: Result<GuardedHttpFetchResponse, GuardedHttpFetchError>,
}
struct Script {
    answers: Mutex<VecDeque<Step>>,
    urls: Mutex<Vec<String>>,
    polls: Mutex<Vec<usize>>,
    retain: AtomicBool,
    retained: Mutex<Vec<Arc<dyn Send + Sync>>>,
}
impl Script {
    fn new(answers: Vec<GuardedHttpFetchResponse>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(
                answers
                    .into_iter()
                    .map(|response| Step {
                        ready_at: Time::ZERO,
                        result: Ok(response),
                    })
                    .collect(),
            ),
            urls: Mutex::new(Vec::new()),
            polls: Mutex::new(Vec::new()),
            retain: AtomicBool::new(false),
            retained: Mutex::new(Vec::new()),
        })
    }
}
impl Exchange for Script {
    fn get<'a>(
        &'a self,
        cx: &'a Cx,
        url: &'a GuardedHttpsUrl,
        lifetime: Arc<dyn Send + Sync>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<GuardedHttpFetchResponse, GuardedHttpFetchError>>
                + Send
                + 'a,
        >,
    > {
        let step = self
            .answers
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected additional fetch");
        self.urls
            .lock()
            .unwrap()
            .push(format!("https://{}{}", url.host(), url.target()));
        let index = {
            let mut polls = self.polls.lock().unwrap();
            polls.push(0);
            polls.len() - 1
        };
        if self.retain.load(Ordering::SeqCst) {
            self.retained.lock().unwrap().push(lifetime.clone());
        }
        Box::pin(async move {
            let _lifetime = lifetime;
            let mut result = Some(step.result);
            poll_fn(|_| {
                self.polls.lock().unwrap()[index] += 1;
                if cx.now() < step.ready_at {
                    Poll::Pending
                } else {
                    Poll::Ready(result.take().expect("response already returned"))
                }
            })
            .await
        })
    }
}
fn source(script: &Arc<Script>) -> EnterpriseKeySource {
    let mut source =
        EnterpriseKeySource::new(profile(), GuardedHttpFetcher::new(policy()).unwrap(), 7).unwrap();
    Arc::get_mut(&mut source.inner).unwrap().test_exchange = Some(script.clone());
    source
}
fn run(test: impl FnOnce(&Cx, Arc<VirtualClock>)) {
    run_with_budget(Budget::INFINITE, test);
}
fn run_with_budget(budget: Budget, test: impl FnOnce(&Cx, Arc<VirtualClock>)) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .with_timer_driver(timer)
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(budget);
    let ambient = Cx::set_current(Some(cx.clone()));
    test(&cx, clock);
    drop(ambient);
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}
fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn ready<F: Future>(future: F) -> F::Output {
    match poll(Box::pin(future).as_mut()) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("fixture unexpectedly suspended"),
    }
}
fn success<T>(outcome: EnterpriseResponseOutcome<T>) -> T {
    match outcome {
        EnterpriseResponseOutcome::Success { value, .. } => value,
        _ => panic!("expected actual signed success"),
    }
}

#[test]
fn guarded_key_pair_preserves_purpose_and_drives_signed_response_chain() {
    run(|cx, _| {
        let script = Script::new(vec![response(OIDC), response(ID_JAG)]);
        let source = source(&script);
        let keys = ready(source.fetch(cx)).unwrap();
        assert_eq!(*script.urls.lock().unwrap(), [OIDC, ID_JAG]);
        assert_eq!(keys.oidc().issuer(), "https://idp.example");
        assert_eq!(keys.id_jag().issuer(), "https://idp.example");
        assert_eq!(keys.oidc().generation(), 21);
        assert_eq!(keys.id_jag().generation(), 22);
        assert_eq!(keys.oidc_observation().endpoint(), OIDC);
        assert_eq!(keys.id_jag_observation().endpoint(), ID_JAG);
        assert_eq!(keys.oidc_observation().key_generation(), 21);
        assert_eq!(keys.id_jag_observation().key_generation(), 22);
        assert_eq!(
            keys.oidc_observation().document_digest(),
            keys.oidc().document_digest()
        );
        assert_eq!(
            keys.id_jag_observation().document_digest(),
            keys.id_jag().document_digest()
        );
        assert_ne!(
            keys.oidc().document_digest(),
            keys.id_jag().document_digest()
        );
        assert_eq!(
            keys.id_jag_observation().provenance().host,
            "id-jag-keys.example"
        );
        assert_eq!(keys.fetch_policy(), &policy());
        assert_eq!(keys.fetch_policy_generation(), 7);
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        let fields = vec![("content-type".into(), "application/json".into())];
        let oidc_body = serde_json::to_vec(&json!({
            "access_token":"temporary-access", "token_type":"Bearer",
            "id_token":fixtures()["oidc"], "scope":"openid"
        }))
        .unwrap();
        let identity = success(
            keys.profile()
                .admit_oidc_code_response(
                    EnterpriseTokenResponse {
                        status: 200,
                        headers: &fields,
                        body: &oidc_body,
                    },
                    keys.oidc(),
                    "oidc-flow-nonce",
                    TenantExpectation::SingleTenant,
                    None,
                    EnterpriseResponsePolicy::default(),
                    at,
                )
                .unwrap(),
        );
        assert_eq!(identity.identity().subject().as_str(), "client-facing");
        let jag_body = serde_json::to_vec(&json!({
            "access_token":fixtures()["id_jag"], "token_type":"N_A",
            "issued_token_type":ID_JAG_TOKEN_TYPE, "scope":"read", "expires_in":60
        }))
        .unwrap();
        let jag = success(
            keys.profile()
                .admit_id_jag_response(
                    EnterpriseTokenResponse {
                        status: 200,
                        headers: &fields,
                        body: &jag_body,
                    },
                    keys.id_jag(),
                    TenantExpectation::SingleTenant,
                    ResourceTenantExpectation::SingleTenant,
                    EnterpriseResponsePolicy::default(),
                    at,
                )
                .unwrap(),
        );
        assert_eq!(jag.granted_scopes(), ["read"]);
        let access_body = serde_json::to_vec(&json!({
            "access_token":"resource-access", "token_type":"Bearer", "scope":"read",
            "resource":"https://mcp.example/mcp", "expires_in":30
        }))
        .unwrap();
        let access = success(
            jag.admit_access_token_response(
                EnterpriseTokenResponse {
                    status: 200,
                    headers: &fields,
                    body: &access_body,
                },
                at,
            )
            .unwrap(),
        );
        assert_eq!(access.granted_scopes(), ["read"]);
        assert_eq!(access.expires_at(), at + Duration::from_secs(30));
        for changed in [
            profile_for("https://idp.example", OIDC, ID_JAG, 22, 21),
            profile_for("https://another-idp.example", OIDC, ID_JAG, 21, 22),
        ] {
            assert!(matches!(
                changed.admit_oidc_code_response(
                    EnterpriseTokenResponse {
                        status: 200,
                        headers: &fields,
                        body: &oidc_body
                    },
                    keys.oidc(),
                    "oidc-flow-nonce",
                    TenantExpectation::SingleTenant,
                    None,
                    EnterpriseResponsePolicy::default(),
                    at,
                ),
                Err(EnterpriseResponseError::PolicyBindingMismatch)
            ));
            assert!(matches!(
                changed.admit_id_jag_response(
                    EnterpriseTokenResponse {
                        status: 200,
                        headers: &fields,
                        body: &jag_body
                    },
                    keys.id_jag(),
                    TenantExpectation::SingleTenant,
                    ResourceTenantExpectation::SingleTenant,
                    EnterpriseResponsePolicy::default(),
                    at,
                ),
                Err(EnterpriseResponseError::PolicyBindingMismatch)
            ));
        }
        assert!(!source.inner.busy.load(Ordering::Acquire));
        let debug = format!("{source:?} {keys:?} {:?}", keys.oidc_observation());
        for private in ["idp.example", "oidc-keys.example", "enterprise-rfc7515"] {
            assert!(!debug.contains(private));
        }
    });
}

#[test]
fn guarded_key_pair_refuses_swapped_invalid_or_partial_responses() {
    for mutation in 0..12 {
        run(|cx, _| {
            let mut first = response(OIDC);
            let mut second = response(ID_JAG);
            let (expected, calls) = match mutation {
                0 => {
                    std::mem::swap(&mut first, &mut second);
                    (EnterpriseKeyFetchError::EvidenceMismatch, 1)
                }
                1 => {
                    second.body.clear();
                    (EnterpriseKeyFetchError::InvalidResponse, 2)
                }
                2 => {
                    let mut wrong_use = fixtures()["jwks"].clone();
                    wrong_use["keys"][0]["key_ops"] = json!(["sign"]);
                    second.body = serde_json::to_vec(&wrong_use).unwrap();
                    (EnterpriseKeyFetchError::InvalidKeys, 2)
                }
                3 => {
                    first.redirect = Some(GuardedHttpRedirect {
                        status: 302,
                        location: Some(ID_JAG.into()),
                    });
                    (EnterpriseKeyFetchError::InvalidResponse, 1)
                }
                4 => {
                    first.headers.clear();
                    (EnterpriseKeyFetchError::InvalidResponse, 1)
                }
                5 => {
                    first
                        .headers
                        .push(("content-type".into(), "application/json".into()));
                    (EnterpriseKeyFetchError::InvalidResponse, 1)
                }
                6 => {
                    first.headers[0].1 = "application/jwk-set+json; charset=iso-8859-1".into();
                    (EnterpriseKeyFetchError::InvalidResponse, 1)
                }
                7 => {
                    first
                        .headers
                        .push(("Content-Encoding".into(), "gzip".into()));
                    (EnterpriseKeyFetchError::InvalidResponse, 1)
                }
                8 => {
                    first.body.resize(MAX_JWKS_BYTES + 1, b' ');
                    (EnterpriseKeyFetchError::InvalidResponse, 1)
                }
                9 => {
                    first.provenance.root_policy_revision = "other-roots".into();
                    (EnterpriseKeyFetchError::EvidenceMismatch, 1)
                }
                10 => {
                    first.provenance.selected_address.set_port(444);
                    (EnterpriseKeyFetchError::EvidenceMismatch, 1)
                }
                _ => {
                    first.body = br#"{"keys":[],"keys":[]}"#.to_vec();
                    (EnterpriseKeyFetchError::InvalidKeys, 1)
                }
            };
            let script = Script::new(vec![first, second]);
            let source = source(&script);
            assert_eq!(ready(source.fetch(cx)).unwrap_err(), expected);
            assert_eq!(script.urls.lock().unwrap().len(), calls);
            assert!(!source.inner.busy.load(Ordering::Acquire));
        });
    }
}

struct ObservedResolver {
    calls: Arc<AtomicUsize>,
    held: Arc<AtomicUsize>,
    ambient: Arc<AtomicUsize>,
}
fn capability_bits(cx: &Cx) -> usize {
    let cap = cx.capabilities();
    usize::from(cap.spawn)
        | (usize::from(cap.time) << 1)
        | (usize::from(cap.entropy) << 2)
        | (usize::from(cap.io) << 3)
        | (usize::from(cap.remote) << 4)
}
impl GuardedHttpResolver for ObservedResolver {
    fn resolve_all(
        &self,
        cx: Cx,
        _host: String,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, GuardedHttpFetchError>> + Send + 'static>>
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.held.store(capability_bits(&cx), Ordering::SeqCst);
        self.ambient
            .store(capability_bits(&Cx::current().unwrap()), Ordering::SeqCst);
        Box::pin(async { Err(GuardedHttpFetchError::ResolutionEmpty) })
    }
}
fn native_fetcher(policy: GuardedHttpFetchPolicy, calls: &Arc<AtomicUsize>) -> GuardedHttpFetcher {
    GuardedHttpFetcher::with_resolver(
        policy,
        Arc::new(ObservedResolver {
            calls: Arc::clone(calls),
            held: Arc::new(AtomicUsize::new(0)),
            ambient: Arc::new(AtomicUsize::new(0)),
        }),
    )
    .unwrap()
}

#[test]
fn guarded_key_source_rejects_policy_before_resolution() {
    let calls = Arc::new(AtomicUsize::new(0));
    assert_eq!(
        EnterpriseKeySource::new(profile(), native_fetcher(policy(), &calls), 0).unwrap_err(),
        EnterpriseKeyFetchError::InvalidFetchPolicy
    );
    let oversized = GuardedHttpFetchPolicy::new(
        MAX_JWKS_BYTES + 1,
        Duration::from_secs(5),
        Duration::from_secs(2),
        "reviewed-roots-7",
    )
    .unwrap();
    assert_eq!(
        EnterpriseKeySource::new(profile(), native_fetcher(oversized, &calls), 7).unwrap_err(),
        EnterpriseKeyFetchError::InvalidFetchPolicy
    );
    for (oidc, jag) in [
        ("https://127.0.0.1/jwks", ID_JAG),
        (OIDC, "https://127.0.0.1/jwks"),
    ] {
        assert_eq!(
            EnterpriseKeySource::new(
                profile_for("https://idp.example", oidc, jag, 21, 22),
                native_fetcher(policy(), &calls),
                7,
            )
            .unwrap_err(),
            EnterpriseKeyFetchError::InvalidEndpoint
        );
    }
    let source = EnterpriseKeySource::new(profile(), native_fetcher(policy(), &calls), 7).unwrap();
    let cx = Cx::for_testing();
    assert_eq!(
        ready(source.fetch(&cx)).unwrap_err(),
        EnterpriseKeyFetchError::RuntimeUnavailable
    );
    cx.set_cancel_requested(true);
    assert_eq!(
        ready(source.fetch(&cx)).unwrap_err(),
        EnterpriseKeyFetchError::Cancelled
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn guarded_key_source_preserves_caller_authority_and_cancellation() {
    for (denied, mask) in [
        (4, CapSet::<true, true, false, true, true>::MASK),
        (16, CapSet::<true, true, true, true, false>::MASK),
        (20, CapSet::<true, true, false, true, false>::MASK),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let held = Arc::new(AtomicUsize::new(0));
        let ambient = Arc::new(AtomicUsize::new(0));
        let fetcher = GuardedHttpFetcher::with_resolver(
            policy(),
            Arc::new(ObservedResolver {
                calls: Arc::clone(&calls),
                held: Arc::clone(&held),
                ambient: Arc::clone(&ambient),
            }),
        )
        .unwrap();
        let source = EnterpriseKeySource::new(profile(), fetcher, 7).unwrap();
        let outcome = fastmcp_core::block_on(async {
            let caller = Cx::current().unwrap();
            let mut future = std::pin::pin!(source.fetch(&caller));
            poll_fn(|task| {
                let _restriction = Cx::push_restriction(mask);
                future.as_mut().poll(task)
            })
            .await
        });
        assert_eq!(outcome.unwrap_err(), EnterpriseKeyFetchError::FetchFailed);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(held.load(Ordering::SeqCst), 31 & !denied);
        assert_eq!(ambient.load(Ordering::SeqCst), 31 & !denied);
    }
    for mask in [
        CapSet::<false, true, true, true, true>::MASK,
        CapSet::<true, false, true, true, true>::MASK,
        CapSet::<true, true, false, true, true>::MASK,
        CapSet::<true, true, true, false, true>::MASK,
        CapSet::<true, true, true, true, false>::MASK,
    ] {
        run_with_budget(
            Budget::new().with_deadline(Time::from_nanos(10_000_000_000)),
            |cx, _| {
                let script = Script::new(vec![response(OIDC)]);
                script.answers.lock().unwrap()[0].ready_at = Time::from_nanos(u64::MAX);
                let source = source(&script);
                let mut future = Box::pin(source.fetch(cx));
                assert!(poll(future.as_mut()).is_pending());
                {
                    let _restriction = Cx::push_restriction(mask);
                    assert!(matches!(
                        poll(future.as_mut()),
                        Poll::Ready(Err(EnterpriseKeyFetchError::RuntimeUnavailable))
                    ));
                }
                assert_eq!(*script.polls.lock().unwrap(), [1]);
                drop(future);
                assert!(!source.inner.busy.load(Ordering::Acquire));
            },
        );
    }
    run(|cx, _| {
        let script = Script::new(vec![response(OIDC)]);
        script.answers.lock().unwrap()[0].ready_at = Time::from_nanos(u64::MAX);
        let source = source(&script);
        let mut future = Box::pin(source.fetch(cx));
        assert!(poll(future.as_mut()).is_pending());
        cx.set_cancel_requested(true);
        assert!(matches!(
            poll(future.as_mut()),
            Poll::Ready(Err(EnterpriseKeyFetchError::Cancelled))
        ));
        drop(future);
        cx.set_cancel_requested(false);
        assert_eq!(*script.polls.lock().unwrap(), [1]);
        assert!(!source.inner.busy.load(Ordering::Acquire));
    });
}

#[test]
fn guarded_key_source_excludes_concurrent_refreshes_until_custody_settles() {
    run(|cx, _| {
        let script = Script::new(vec![response(OIDC), response(OIDC), response(ID_JAG)]);
        script.answers.lock().unwrap()[0].ready_at = Time::from_nanos(u64::MAX);
        script.retain.store(true, Ordering::SeqCst);
        let source = source(&script);
        let clone = source.clone();
        let mut future = Box::pin(source.fetch(cx));
        assert!(poll(future.as_mut()).is_pending());
        assert_eq!(
            ready(clone.fetch(cx)).unwrap_err(),
            EnterpriseKeyFetchError::FetchInProgress
        );
        drop(future);
        // The fixture retains the exact production phase-lifetime argument.
        // Abandoning the joiner alone must not release that reservation.
        assert_eq!(
            ready(clone.fetch(cx)).unwrap_err(),
            EnterpriseKeyFetchError::FetchInProgress
        );
        assert_eq!(script.urls.lock().unwrap().len(), 1);
        script.retain.store(false, Ordering::SeqCst);
        script.retained.lock().unwrap().clear();
        assert!(ready(clone.fetch(cx)).is_ok());
        assert_eq!(*script.urls.lock().unwrap(), [OIDC, OIDC, ID_JAG]);
        assert!(!source.inner.busy.load(Ordering::Acquire));
    });
}

#[test]
fn guarded_key_pair_uses_one_deadline_across_both_fetches() {
    run(|cx, clock| {
        let script = Script::new(vec![response(OIDC), response(ID_JAG)]);
        {
            let mut steps = script.answers.lock().unwrap();
            steps[0].ready_at = Time::from_nanos(4_000_000_000);
            steps[1].ready_at = Time::from_nanos(6_000_000_000);
        }
        let source = source(&script);
        let mut future = Box::pin(source.fetch(cx));
        assert!(poll(future.as_mut()).is_pending());
        clock.advance(4_000_000_000);
        assert!(poll(future.as_mut()).is_pending());
        assert_eq!(*script.urls.lock().unwrap(), [OIDC, ID_JAG]);
        assert_eq!(*script.polls.lock().unwrap(), [2, 1]);
        clock.advance(1_000_000_001);
        assert!(matches!(
            poll(future.as_mut()),
            Poll::Ready(Err(EnterpriseKeyFetchError::TimedOut))
        ));
        assert_eq!(*script.polls.lock().unwrap(), [2, 1]);
        drop(future);
        assert!(!source.inner.busy.load(Ordering::Acquire));
    });
    run_with_budget(
        Budget::new().with_deadline(Time::from_nanos(2_000_000_000)),
        |cx, clock| {
            let script = Script::new(vec![response(OIDC), response(ID_JAG)]);
            {
                let mut steps = script.answers.lock().unwrap();
                steps[0].ready_at = Time::from_nanos(1_000_000_000);
                steps[1].ready_at = Time::from_nanos(3_000_000_000);
            }
            let source = source(&script);
            let mut future = Box::pin(source.fetch(cx));
            assert!(poll(future.as_mut()).is_pending());
            clock.advance(1_000_000_000);
            assert!(poll(future.as_mut()).is_pending());
            clock.advance(1_000_000_001);
            assert!(matches!(
                poll(future.as_mut()),
                Poll::Ready(Err(
                    EnterpriseKeyFetchError::TimedOut | EnterpriseKeyFetchError::Cancelled
                ))
            ));
            assert_eq!(*script.polls.lock().unwrap(), [2, 1]);
            drop(future);
            assert!(!source.inner.busy.load(Ordering::Acquire));
        },
    );
}
