use super::*;
use crate::auth::{AuthProvider, TokenAuthProvider};
use crate::providers::jwt_resource::tests::{claims, header, jwks, policy, sign};
use asupersync::Cx;
use fastmcp_transport::http::{GuardedHttpFetchPolicy, GuardedHttpPeerProvenance};
use serde_json::json;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Waker};
use std::time::{SystemTime, UNIX_EPOCH};

// This seam supplies an already admitted response. It exercises provider
// policy and ownership, not DNS, TCP or TLS; those remain transport tests.
pub(super) trait Exchange: Send + Sync {
    fn get<'a>(
        &'a self,
        ctx: &'a McpContext,
        url: &'a GuardedHttpsUrl,
    ) -> Pin<Box<dyn Future<Output = McpResult<GuardedHttpFetchResponse>> + Send + 'a>>;
}

struct Script {
    answers: Mutex<VecDeque<McpResult<GuardedHttpFetchResponse>>>,
    calls: AtomicUsize,
    urls: Mutex<Vec<String>>,
}

impl Script {
    fn new(answers: Vec<McpResult<GuardedHttpFetchResponse>>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.into()),
            calls: AtomicUsize::new(0),
            urls: Mutex::new(Vec::new()),
        })
    }
}

impl Exchange for Script {
    fn get<'a>(
        &'a self,
        _: &'a McpContext,
        url: &'a GuardedHttpsUrl,
    ) -> Pin<Box<dyn Future<Output = McpResult<GuardedHttpFetchResponse>> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.urls
                .lock()
                .unwrap()
                .push(format!("{}{}", url.host(), url.target()));
            self.answers
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected extra key fetch")
        })
    }
}

fn response(body: Vec<u8>) -> GuardedHttpFetchResponse {
    GuardedHttpFetchResponse {
        status: 200,
        headers: vec![(
            "Content-Type".to_owned(),
            "application/jwk-set+json".to_owned(),
        )],
        body,
        redirect: None,
        provenance: GuardedHttpPeerProvenance {
            host: "issuer.example".to_owned(),
            selected_address: "93.184.216.34:443".parse().unwrap(),
            leaf_certificate_sha256: [9; 32],
            alpn: Some(b"http/1.1".to_vec()),
            tls_protocol: Some("script-only".to_owned()),
            root_policy_revision: "guarded-jwks-tests".to_owned(),
        },
    }
}

fn ctx() -> McpContext {
    McpContext::new(Cx::for_testing(), 1)
}

fn source(pool: JwksFetchAdmissionPool, provider: &str, endpoint: &str) -> GuardedJwksSource {
    let fetch = GuardedHttpFetchPolicy::new(
        MAX_REFRESH_JWKS_BYTES,
        Duration::from_secs(2),
        Duration::from_secs(1),
        "guarded-jwks-tests",
    )
    .unwrap();
    GuardedJwksSource::new(
        endpoint,
        provider,
        "deployment",
        GuardedHttpFetcher::new(fetch).unwrap(),
        pool,
    )
    .unwrap()
}

fn fixture(
    answers: Vec<McpResult<GuardedHttpFetchResponse>>,
) -> (GuardedJwtResourceVerifier, Arc<Script>, Arc<AtomicU64>) {
    let script = Script::new(answers);
    let mut source = source(
        JwksFetchAdmissionPool::default(),
        "provider",
        "https://issuer.example/keys",
    );
    source.test_exchange = Some(script.clone());
    let elapsed = Arc::new(AtomicU64::new(0));
    let clock = elapsed.clone();
    let origin = Instant::now();
    let refresh = JwksRefreshPolicy::new(
        Duration::from_secs(10),
        Duration::from_secs(20),
        Duration::from_secs(2),
        Duration::from_secs(3),
    )
    .unwrap();
    let managed = ManagedJwtResourceVerifier::with_clock(
        policy(),
        refresh,
        Arc::new(move || origin + Duration::from_secs(clock.load(Ordering::SeqCst))),
    );
    (
        GuardedJwtResourceVerifier { managed, source },
        script,
        elapsed,
    )
}

fn token(kid: &str) -> AccessToken {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut header = header();
    header["kid"] = json!(kid);
    sign(&header, &claims(now))
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("scripted immediate operation unexpectedly pending"),
    }
}

#[test]
fn guarded_jwks_cold_authentication_refreshes_once_and_keeps_fresh_fast_path_local() {
    let (verifier, script, _) = fixture(vec![Ok(response(jwks("one")))]);
    let signed = token("one");
    assert_eq!(
        verifier
            .verify_access_token(&ctx(), &signed)
            .unwrap_err()
            .code,
        crate::auth::AUTH_PROVIDER_UNAVAILABLE_CODE
    );
    let provider = TokenAuthProvider::new(verifier.clone());
    let authorization = format!("Bearer {}", signed.token);
    let facts = ready(provider.authenticate_async(
        &ctx(),
        AuthRequest {
            method: "tools/list",
            params: None,
            transport_authorization: Some(&authorization),
            request_id: 1,
        },
    ))
    .unwrap();
    assert_eq!(facts.subject.as_deref(), Some("alice"));
    assert!(facts.verification_valid_until().unwrap() > Instant::now());
    for _ in 0..4 {
        assert_eq!(
            ready(verifier.verify_access_token_async(&ctx(), &signed))
                .unwrap()
                .session_owner(),
            facts.session_owner()
        );
    }
    assert_eq!(script.calls.load(Ordering::SeqCst), 1);
    assert_eq!(*script.urls.lock().unwrap(), ["issuer.example/keys"]);
}

#[test]
fn guarded_jwks_rotates_at_due_time_without_unknown_kid_fetch_amplification() {
    let (verifier, script, elapsed) =
        fixture(vec![Ok(response(jwks("one"))), Ok(response(jwks("two")))]);
    let first = token("one");
    let second = token("two");
    let owner = ready(verifier.verify_access_token_async(&ctx(), &first))
        .unwrap()
        .session_owner();
    for _ in 0..4 {
        assert_eq!(
            ready(verifier.verify_access_token_async(&ctx(), &second))
                .unwrap_err()
                .code,
            McpErrorCode::ResourceForbidden
        );
    }
    assert_eq!(script.calls.load(Ordering::SeqCst), 1);
    elapsed.store(10, Ordering::SeqCst);
    assert_eq!(
        ready(verifier.verify_access_token_async(&ctx(), &second))
            .unwrap()
            .session_owner(),
        owner
    );
    assert!(ready(verifier.verify_access_token_async(&ctx(), &first)).is_err());
    assert_eq!(script.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn guarded_jwks_outage_preserves_only_unexpired_keys_and_applies_backoff() {
    let (verifier, script, elapsed) = fixture(vec![
        Ok(response(jwks("one"))),
        Err(McpError::internal_error("secret upstream error")),
        Err(unavailable()),
    ]);
    let signed = token("one");
    ready(verifier.verify_access_token_async(&ctx(), &signed)).unwrap();
    elapsed.store(10, Ordering::SeqCst);
    ready(verifier.verify_access_token_async(&ctx(), &signed)).unwrap();
    ready(verifier.verify_access_token_async(&ctx(), &signed)).unwrap();
    assert_eq!(script.calls.load(Ordering::SeqCst), 2);
    elapsed.store(20, Ordering::SeqCst);
    let error = ready(verifier.verify_access_token_async(&ctx(), &signed)).unwrap_err();
    assert_eq!(error.code, crate::auth::AUTH_PROVIDER_UNAVAILABLE_CODE);
    assert!(!format!("{error:?}").contains("secret upstream"));
    assert_eq!(script.calls.load(Ordering::SeqCst), 3);
}

#[test]
fn guarded_jwks_source_and_deployment_capacity_are_held_until_last_child_owner_drops() {
    let pool = JwksFetchAdmissionPool::new(2).unwrap();
    let first = source(pool.clone(), "same-provider", "https://issuer.example/keys");
    let alias = source(pool.clone(), "same-provider", "https://other.example/keys");
    let second = source(
        pool.clone(),
        "other-provider",
        "https://issuer.example/keys",
    );
    let third = source(
        pool.clone(),
        "third-provider",
        "https://issuer.example/keys",
    );
    let permit = Arc::new(pool.acquire(first.source).unwrap());
    let phase_owner = permit.clone();
    assert!(pool.acquire(alias.source).is_err());
    let sibling = pool.acquire(second.source).unwrap();
    assert!(pool.acquire(third.source).is_err());
    drop(permit);
    assert!(pool.acquire(first.source).is_err());
    drop(phase_owner);
    assert!(pool.acquire(first.source).is_ok());
    drop(sibling);
    assert!(pool.active.lock().unwrap().is_empty());
}

#[test]
fn guarded_jwks_endpoint_and_root_configuration_isolate_owner_but_key_refresh_does_not() {
    let (verifier, _, _) = fixture(vec![Ok(response(jwks("one")))]);
    let signed = token("one");
    let first = ready(verifier.verify_access_token_async(&ctx(), &signed))
        .unwrap()
        .session_owner();
    verifier.install_jwks(&jwks("one")).unwrap();
    assert_eq!(
        verifier
            .verify_access_token(&ctx(), &signed)
            .unwrap()
            .session_owner(),
        first
    );
    let alternate = GuardedJwtResourceVerifier::new(
        policy(),
        JwksRefreshPolicy::default(),
        source(
            JwksFetchAdmissionPool::default(),
            "provider",
            "https://issuer.example/other-keys",
        ),
    );
    alternate.install_jwks(&jwks("one")).unwrap();
    assert_ne!(
        alternate
            .verify_access_token(&ctx(), &signed)
            .unwrap()
            .session_owner(),
        first
    );
    let fetch = GuardedHttpFetchPolicy::new(
        MAX_REFRESH_JWKS_BYTES,
        Duration::from_secs(2),
        Duration::from_secs(1),
        "different-root-revision",
    )
    .unwrap();
    let source = GuardedJwksSource::new(
        "https://issuer.example/keys",
        "provider",
        "deployment",
        GuardedHttpFetcher::new(fetch).unwrap(),
        JwksFetchAdmissionPool::default(),
    )
    .unwrap();
    let alternate = GuardedJwtResourceVerifier::new(policy(), JwksRefreshPolicy::default(), source);
    alternate.install_jwks(&jwks("one")).unwrap();
    assert_ne!(
        alternate
            .verify_access_token(&ctx(), &signed)
            .unwrap()
            .session_owner(),
        first
    );
}

#[test]
fn guarded_jwks_rejects_bad_http_documents_without_publishing_trust() {
    for kind in 0..6 {
        let mut bad = response(jwks("one"));
        match kind {
            0 => bad.status = 302,
            1 => bad.headers[0].1 = "text/html".to_owned(),
            2 => bad
                .headers
                .push(("content-type".to_owned(), "application/json".to_owned())),
            3 => bad.body = vec![b' '; MAX_REFRESH_JWKS_BYTES + 1],
            4 => bad.body = b"{\"keys\":[],\"keys\":[]}".to_vec(),
            _ => bad.body = b"{\"keys\":[]}".to_vec(),
        }
        let (verifier, script, _) = fixture(vec![Ok(bad)]);
        assert_eq!(
            ready(verifier.verify_access_token_async(&ctx(), &token("one")))
                .unwrap_err()
                .code,
            crate::auth::AUTH_PROVIDER_UNAVAILABLE_CODE
        );
        assert!(verifier.managed.fresh_generation().is_err());
        assert_eq!(script.calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn guarded_jwks_revocation_cannot_be_undone_by_a_remote_refresh() {
    let (verifier, script, elapsed) = fixture(vec![Ok(response(jwks("one")))]);
    let signed = token("one");
    ready(verifier.verify_access_token_async(&ctx(), &signed)).unwrap();
    verifier.revoke_all().unwrap();
    elapsed.store(100, Ordering::SeqCst);
    assert_eq!(
        ready(verifier.verify_access_token_async(&ctx(), &signed))
            .unwrap_err()
            .code,
        crate::auth::AUTH_PROVIDER_UNAVAILABLE_CODE
    );
    assert_eq!(script.calls.load(Ordering::SeqCst), 1);
    verifier.install_jwks(&jwks("one")).unwrap();
    assert!(verifier.verify_access_token(&ctx(), &signed).is_ok());
}

struct RekeyDuringFetch {
    managed: ManagedJwtResourceVerifier,
    revoke: bool,
}

impl Exchange for RekeyDuringFetch {
    fn get<'a>(
        &'a self,
        _: &'a McpContext,
        _: &'a GuardedHttpsUrl,
    ) -> Pin<Box<dyn Future<Output = McpResult<GuardedHttpFetchResponse>> + Send + 'a>> {
        Box::pin(async move {
            if self.revoke {
                self.managed.revoke_all().unwrap();
            } else {
                self.managed.install_jwks(&jwks("two")).unwrap();
            }
            Ok(response(jwks("one")))
        })
    }
}

#[test]
fn guarded_jwks_fetch_cannot_overwrite_concurrent_rotation_or_revocation() {
    for revoke in [false, true] {
        let (mut verifier, _, _) = fixture(vec![]);
        verifier.source.test_exchange = Some(Arc::new(RekeyDuringFetch {
            managed: verifier.managed.clone(),
            revoke,
        }));
        let error = ready(verifier.verify_access_token_async(&ctx(), &token("one"))).unwrap_err();
        assert_eq!(
            error.code,
            if revoke {
                crate::auth::AUTH_PROVIDER_UNAVAILABLE_CODE
            } else {
                McpErrorCode::ResourceForbidden
            }
        );
        assert_eq!(
            verifier.verify_access_token(&ctx(), &token("two")).is_ok(),
            !revoke
        );
        assert!(verifier.source.admission.active.lock().unwrap().is_empty());
    }
}

struct PendingExchange(Arc<AtomicUsize>);

impl Exchange for PendingExchange {
    fn get<'a>(
        &'a self,
        _: &'a McpContext,
        _: &'a GuardedHttpsUrl,
    ) -> Pin<Box<dyn Future<Output = McpResult<GuardedHttpFetchResponse>> + Send + 'a>> {
        struct Dropped(Arc<AtomicUsize>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        Box::pin(async move {
            let _dropped = Dropped(self.0.clone());
            std::future::pending().await
        })
    }
}

#[test]
fn guarded_jwks_pending_fetch_without_caller_timer_drops_and_releases_capacity() {
    let (mut verifier, _, _) = fixture(vec![]);
    let dropped = Arc::new(AtomicUsize::new(0));
    verifier.source.test_exchange = Some(Arc::new(PendingExchange(dropped.clone())));
    assert_eq!(
        ready(verifier.verify_access_token_async(&ctx(), &token("one")))
            .unwrap_err()
            .code,
        crate::auth::AUTH_PROVIDER_UNAVAILABLE_CODE
    );
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert!(verifier.source.admission.active.lock().unwrap().is_empty());
    assert!(
        verifier
            .managed
            .shared
            .state
            .read()
            .unwrap()
            .flight
            .is_none()
    );
}

struct CountingResolver(Arc<AtomicUsize>);

impl fastmcp_transport::http::GuardedHttpResolver for CountingResolver {
    fn resolve_all(
        &self,
        _: Cx,
        _: String,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Vec<std::net::IpAddr>,
                        fastmcp_transport::http::GuardedHttpFetchError,
                    >,
                > + Send
                + 'static,
        >,
    > {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(vec!["93.184.216.34".parse().unwrap()]) })
    }
}

#[test]
fn guarded_jwks_production_exchange_requires_timer_before_starting_dns() {
    let calls = Arc::new(AtomicUsize::new(0));
    let fetch = GuardedHttpFetcher::with_resolver(
        GuardedHttpFetchPolicy::new(
            MAX_REFRESH_JWKS_BYTES,
            Duration::from_secs(2),
            Duration::from_secs(1),
            "timer-test",
        )
        .unwrap(),
        Arc::new(CountingResolver(calls.clone())),
    )
    .unwrap();
    let source = GuardedJwksSource::new(
        "https://issuer.example/keys",
        "provider",
        "deployment",
        fetch,
        JwksFetchAdmissionPool::default(),
    )
    .unwrap();
    let verifier = GuardedJwtResourceVerifier::new(policy(), JwksRefreshPolicy::default(), source);
    assert_eq!(
        ready(verifier.verify_access_token_async(&ctx(), &token("one")))
            .unwrap_err()
            .code,
        crate::auth::AUTH_PROVIDER_UNAVAILABLE_CODE
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(verifier.source.admission.active.lock().unwrap().is_empty());
}

#[test]
fn guarded_jwks_cancelled_caller_and_denied_effects_never_start_exchange() {
    use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
    let (verifier, script, _) = fixture(vec![]);
    let signed = token("one");
    let context = ctx();
    context.request_cancellation().cancel();
    assert!(ready(verifier.verify_access_token_async(&context, &signed)).is_err());
    let context = ctx();
    let _current = Cx::set_current(Some(context.cx().clone()));
    let _restriction = Cx::push_restriction(CapSet::<false, true, true, true, true>::MASK);
    assert!(ready(verifier.verify_access_token_async(&context, &signed)).is_err());
    assert_eq!(script.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn guarded_jwks_configuration_is_bounded_and_debug_redacts_destination() {
    assert!(JwksFetchAdmissionPool::new(0).is_err());
    assert!(JwksFetchAdmissionPool::new(65).is_err());
    let fetch = || {
        GuardedHttpFetcher::new(
            GuardedHttpFetchPolicy::new(
                MAX_REFRESH_JWKS_BYTES,
                Duration::from_secs(2),
                Duration::from_secs(1),
                "roots",
            )
            .unwrap(),
        )
        .unwrap()
    };
    for endpoint in [
        "http://issuer.example/keys",
        "https://user:secret@issuer.example/keys",
        "https://issuer.example/keys#fragment",
    ] {
        assert!(
            GuardedJwksSource::new(
                endpoint,
                "provider",
                "deployment",
                fetch(),
                JwksFetchAdmissionPool::default()
            )
            .is_err()
        );
    }
    let source = GuardedJwksSource::new(
        "https://issuer.example/keys",
        "provider-private",
        "deployment-private",
        fetch(),
        JwksFetchAdmissionPool::default(),
    )
    .unwrap();
    let debug = format!("{source:?}");
    assert!(!debug.contains("issuer.example"));
    assert!(!debug.contains("provider-private"));
    assert!(!debug.contains("deployment-private"));
}

#[cfg(feature = "enterprise-auth")]
mod enterprise {
    use super::*;
    use crate::auth::enterprise::{
        EnterpriseResourceConfiguration, EnterpriseResourceError, EnterpriseResourcePolicy,
    };
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use fastmcp_core::{CanonicalHttpUrl, CanonicalResourceId, CanonicalResourceIdPolicy};
    use serde_json::Value;
    use std::sync::atomic::AtomicBool;
    use std::task::Wake;

    fn configuration(generation: u64) -> EnterpriseResourceConfiguration {
        let endpoint = CanonicalHttpUrl::parse("https://tools.example/mcp").unwrap();
        EnterpriseResourceConfiguration {
            idp_issuer: "https://idp.example".to_owned(),
            idp_token_endpoint: "https://idp.example/token".to_owned(),
            resource_as_issuer: "https://issuer.example".to_owned(),
            resource_as_token_endpoint: "https://issuer.example/token".to_owned(),
            resource: CanonicalResourceId::parse_for_endpoint(
                endpoint.as_str(),
                &endpoint,
                CanonicalResourceIdPolicy::default(),
            )
            .unwrap(),
            policy_generation: generation,
            idp_metadata_generation: generation,
            resource_as_metadata_generation: generation,
        }
    }

    fn documents() -> [Vec<u8>; 2] {
        [
            serde_json::to_vec(&json!({
                "issuer":"https://idp.example",
                "token_endpoint":"https://idp.example/token",
                "grant_types_supported":["urn:ietf:params:oauth:grant-type:token-exchange"],
                "identity_chaining_requested_token_types_supported":["urn:ietf:params:oauth:token-type:id-jag"]
            }))
            .unwrap(),
            serde_json::to_vec(&json!({
                "issuer":"https://issuer.example",
                "token_endpoint":"https://issuer.example/token",
                "authorization_grant_profiles_supported":["urn:ietf:params:oauth:grant-profile:id-jag"],
                "grant_types_supported":["urn:ietf:params:oauth:grant-type:jwt-bearer"]
            }))
            .unwrap(),
        ]
    }

    fn owner() -> EnterpriseResourcePolicy {
        let documents = documents();
        let deadline = Instant::now() + Duration::from_secs(120);
        EnterpriseResourcePolicy::new(
            configuration(1),
            &documents[0],
            &documents[1],
            deadline,
            deadline,
        )
        .unwrap()
    }

    fn params() -> Value {
        json!({"_meta":{
            "io.modelcontextprotocol/protocolVersion":fastmcp_protocol::FINAL_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities":{"extensions":{
                "io.modelcontextprotocol/enterprise-managed-authorization":{}
            }}
        }})
    }

    fn request<'a>(params: &'a Value, authorization: &'a str) -> AuthRequest<'a> {
        AuthRequest {
            method: "tools/list",
            params: Some(params),
            transport_authorization: Some(authorization),
            request_id: 1,
        }
    }

    #[test]
    fn enterprise_guarded_provider_refreshes_rotates_and_preserves_owner_identity() {
        let (verifier, script, elapsed) =
            fixture(vec![Ok(response(jwks("one"))), Ok(response(jwks("two")))]);
        let owner = owner();
        let provider = owner.guarded_provider(verifier.clone()).unwrap();
        let context = ctx();
        let params = params();
        let first = format!("Bearer {}", token("one").token);
        let second = format!("Bearer {}", token("two").token);
        assert_eq!(
            provider
                .authenticate(&context, request(&params, &first))
                .unwrap_err()
                .code,
            crate::auth::AUTH_PROVIDER_UNAVAILABLE_CODE
        );
        assert_eq!(script.calls.load(Ordering::SeqCst), 0);

        let first_facts =
            ready(provider.authenticate_async(&context, request(&params, &first))).unwrap();
        assert_eq!(first_facts.subject.as_deref(), Some("alice"));
        assert!(first_facts.verification_is_current());
        assert_eq!(
            provider
                .authenticate(&context, request(&params, &first))
                .unwrap()
                .session_owner(),
            first_facts.session_owner()
        );
        assert!(ready(provider.authenticate_async(&context, request(&params, &second))).is_err());
        assert_eq!(script.calls.load(Ordering::SeqCst), 1);

        elapsed.store(10, Ordering::SeqCst);
        let second_facts =
            ready(provider.authenticate_async(&context, request(&params, &second))).unwrap();
        assert!(!first_facts.verification_is_current());
        assert!(second_facts.verification_is_current());
        assert_eq!(second_facts.session_owner(), first_facts.session_owner());
        assert!(ready(provider.authenticate_async(&context, request(&params, &first))).is_err());
        assert_eq!(script.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            *script.urls.lock().unwrap(),
            ["issuer.example/keys", "issuer.example/keys"]
        );
        owner.revoke();
        assert!(!second_facts.verification_is_current());
        assert!(ready(provider.authenticate_async(&context, request(&params, &second))).is_err());
        assert_eq!(script.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn enterprise_managed_provider_preserves_rotation_and_hard_key_expiry() {
        let (verifier, script, elapsed) = fixture(vec![]);
        let managed = verifier.managed.clone();
        let owner = owner();
        let provider = owner.managed_provider(managed.clone()).unwrap();
        let context = ctx();
        let params = params();
        let first = format!("Bearer {}", token("one").token);
        let second = format!("Bearer {}", token("two").token);
        assert!(ready(provider.authenticate_async(&context, request(&params, &first))).is_err());
        managed.install_jwks(&jwks("one")).unwrap();
        let first_facts = provider
            .authenticate(&context, request(&params, &first))
            .unwrap();
        assert_eq!(
            ready(provider.authenticate_async(&context, request(&params, &first)))
                .unwrap()
                .session_owner(),
            first_facts.session_owner()
        );
        managed.install_jwks(&jwks("two")).unwrap();
        assert!(!first_facts.verification_is_current());
        let second_facts =
            ready(provider.authenticate_async(&context, request(&params, &second))).unwrap();
        assert_eq!(second_facts.session_owner(), first_facts.session_owner());
        assert!(
            provider
                .authenticate(&context, request(&params, &first))
                .is_err()
        );

        elapsed.store(20, Ordering::SeqCst);
        assert!(
            provider
                .authenticate(&context, request(&params, &second))
                .is_err()
        );
        assert!(ready(provider.authenticate_async(&context, request(&params, &second))).is_err());
        managed.revoke_all().unwrap();
        assert!(!second_facts.verification_is_current());
        assert_eq!(script.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn enterprise_guarded_provider_rejects_wrong_binding_and_declaration_before_fetch() {
        let (verifier, script, _) = fixture(vec![Ok(response(jwks("one")))]);
        let owner = owner();
        for (issuer, resource) in [
            ("https://other-issuer.example", "https://tools.example/mcp"),
            ("https://issuer.example", "https://other-tools.example/mcp"),
        ] {
            let policy =
                JwtResourcePolicy::new(issuer, resource, Duration::from_secs(3600), Duration::ZERO)
                    .unwrap();
            assert_eq!(
                owner
                    .managed_provider(ManagedJwtResourceVerifier::new(
                        policy.clone(),
                        JwksRefreshPolicy::default(),
                    ))
                    .unwrap_err(),
                EnterpriseResourceError::VerifierMismatch
            );
            assert_eq!(
                owner
                    .guarded_provider(GuardedJwtResourceVerifier::new(
                        policy,
                        JwksRefreshPolicy::default(),
                        verifier.source.clone(),
                    ))
                    .unwrap_err(),
                EnterpriseResourceError::VerifierMismatch
            );
        }
        let provider = owner.guarded_provider(verifier).unwrap();
        let context = ctx();
        let authorization = format!("Bearer {}", token("one").token);
        let valid = params();
        for case in 0..6 {
            let mut invalid = valid.clone();
            match case {
                1 => invalid = json!({}),
                2 => {
                    invalid["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"] =
                        json!({});
                }
                3 => {
                    invalid["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]
                        ["io.modelcontextprotocol/enterprise-managed-authorization"] =
                        json!({"enabled":true});
                }
                4 => {
                    invalid["_meta"]["io.modelcontextprotocol/protocolVersion"] =
                        json!("2025-11-25");
                }
                _ => {}
            }
            let mut request = request(&invalid, &authorization);
            if case == 0 {
                request.params = None;
            } else if case == 5 {
                request.transport_authorization = None;
            }
            assert!(ready(provider.authenticate_async(&context, request)).is_err());
            assert_eq!(script.calls.load(Ordering::SeqCst), 0);
        }
        assert!(
            ready(provider.authenticate_async(&context, request(&valid, &authorization))).is_ok()
        );
        assert_eq!(script.calls.load(Ordering::SeqCst), 1);
    }

    struct DelayedExchange {
        released: AtomicBool,
        calls: AtomicUsize,
        waker: Mutex<Option<Waker>>,
    }

    #[derive(Default)]
    struct AuthenticationWake(AtomicUsize);

    impl Wake for AuthenticationWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl DelayedExchange {
        fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            if let Some(waker) = self.waker.lock().unwrap().take() {
                waker.wake();
            }
        }
    }

    impl Exchange for DelayedExchange {
        fn get<'a>(
            &'a self,
            _: &'a McpContext,
            _: &'a GuardedHttpsUrl,
        ) -> Pin<Box<dyn Future<Output = McpResult<GuardedHttpFetchResponse>> + Send + 'a>>
        {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                poll_fn(|task| {
                    let mut waker = self.waker.lock().unwrap();
                    if self.released.load(Ordering::SeqCst) {
                        Poll::Ready(Ok(response(jwks("one"))))
                    } else {
                        *waker = Some(task.waker().clone());
                        Poll::Pending
                    }
                })
                .await
            })
        }
    }

    #[test]
    fn enterprise_guarded_provider_policy_invalidation_interrupts_suspended_refresh() {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock);
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let caller = runtime.request_cx_with_budget(Budget::INFINITE);
        runtime.block_on(async {
            let _ambient = Cx::set_current(None);
            let context = McpContext::new(caller.clone(), 1);
            let sibling = McpContext::new(caller.clone(), 2);
            for change in ["replace", "revoke", "drop"] {
                let (mut verifier, _, elapsed) = fixture(vec![]);
                let delayed = Arc::new(DelayedExchange {
                    released: AtomicBool::new(false),
                    calls: AtomicUsize::new(0),
                    waker: Mutex::new(None),
                });
                verifier.source.test_exchange = Some(delayed.clone());
                let mut owner = Some(owner());
                let provider = owner
                    .as_ref()
                    .unwrap()
                    .guarded_provider(verifier.clone())
                    .unwrap();
                let params = params();
                let authorization = format!("Bearer {}", token("one").token);
                let mut authentication =
                    provider.authenticate_async(&context, request(&params, &authorization));
                let wakes = Arc::new(AuthenticationWake::default());
                let waker = Waker::from(wakes.clone());
                let mut task = Context::from_waker(&waker);
                assert!(authentication.as_mut().poll(&mut task).is_pending());
                assert_eq!(delayed.calls.load(Ordering::SeqCst), 1);
                assert_eq!(verifier.source.admission.active.lock().unwrap().len(), 1);
                // Key-fetch deadline and enterprise metadata expiry.
                assert_eq!(timer.pending_count(), 2);
                let wake_count = wakes.0.load(Ordering::SeqCst);

                match change {
                    "replace" => {
                        let documents = documents();
                        let deadline = Instant::now() + Duration::from_secs(120);
                        owner
                            .as_mut()
                            .unwrap()
                            .replace(
                                configuration(2),
                                &documents[0],
                                &documents[1],
                                deadline,
                                deadline,
                            )
                            .unwrap();
                    }
                    "revoke" => owner.as_ref().unwrap().revoke(),
                    _ => drop(owner.take()),
                }
                assert!(
                    wakes.0.load(Ordering::SeqCst) > wake_count,
                    "{change} must wake authentication without waiting for the key endpoint"
                );
                assert!(!delayed.released.load(Ordering::SeqCst));
                match authentication.as_mut().poll(&mut task) {
                    Poll::Ready(Err(error)) => {
                        assert_eq!(error.code, McpErrorCode::ResourceForbidden)
                    }
                    _ => {
                        panic!("{change} did not interrupt the suspended authentication")
                    }
                }
                assert!(verifier.source.admission.active.lock().unwrap().is_empty());
                assert_eq!(timer.pending_count(), 0);
                {
                    let state = verifier.managed.shared.state.read().unwrap();
                    assert!(state.flight.is_none());
                    assert!(state.active.is_none());
                }
                drop(authentication);
                assert!(verifier.source.admission.active.lock().unwrap().is_empty());
                assert_eq!(timer.pending_count(), 0);
                assert!(context.checkpoint().is_ok());
                assert!(sibling.checkpoint().is_ok());
                assert!(caller.checkpoint().is_ok());
                assert_eq!(
                    verifier
                        .verify_access_token(&context, &token("one"))
                        .unwrap_err()
                        .code,
                    crate::auth::AUTH_PROVIDER_UNAVAILABLE_CODE,
                    "an interrupted response must not install keys"
                );
                // The response becoming ready after cancellation has no owner
                // left that could publish it. A replacement can make its own
                // fresh attempt after the unchanged fetch backoff expires.
                delayed.release();
                elapsed.store(3, Ordering::SeqCst);
                let next =
                    ready(provider.authenticate_async(&context, request(&params, &authorization)));
                assert_eq!(next.is_ok(), change == "replace");
                assert_eq!(
                    delayed.calls.load(Ordering::SeqCst),
                    if change == "replace" { 2 } else { 1 }
                );
                assert!(verifier.source.admission.active.lock().unwrap().is_empty());
                assert_eq!(timer.pending_count(), 0);
            }
        });
        assert_eq!(timer.pending_count(), 0);
        drop(caller);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn enterprise_guarded_provider_rejected_policy_update_preserves_suspended_refresh() {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock);
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let caller = runtime.request_cx_with_budget(Budget::INFINITE);
        runtime.block_on(async {
            let _ambient = Cx::set_current(None);
            let context = McpContext::new(caller.clone(), 1);
            let (mut verifier, _, _) = fixture(vec![]);
            let delayed = Arc::new(DelayedExchange {
                released: AtomicBool::new(false),
                calls: AtomicUsize::new(0),
                waker: Mutex::new(None),
            });
            verifier.source.test_exchange = Some(delayed.clone());
            let mut owner = owner();
            let provider = owner.guarded_provider(verifier.clone()).unwrap();
            let params = params();
            let authorization = format!("Bearer {}", token("one").token);
            let mut authentication =
                provider.authenticate_async(&context, request(&params, &authorization));
            let wakes = Arc::new(AuthenticationWake::default());
            let waker = Waker::from(wakes.clone());
            let mut task = Context::from_waker(&waker);
            assert!(authentication.as_mut().poll(&mut task).is_pending());
            let wake_count = wakes.0.load(Ordering::SeqCst);
            let documents = documents();
            let deadline = Instant::now() + Duration::from_secs(120);
            assert_eq!(
                owner.replace(
                    configuration(1),
                    &documents[0],
                    &documents[1],
                    deadline,
                    deadline,
                ),
                Err(EnterpriseResourceError::GenerationRollback)
            );
            assert_eq!(wakes.0.load(Ordering::SeqCst), wake_count);
            assert!(authentication.as_mut().poll(&mut task).is_pending());
            assert_eq!(delayed.calls.load(Ordering::SeqCst), 1);
            assert_eq!(verifier.source.admission.active.lock().unwrap().len(), 1);
            // Key-fetch deadline and enterprise metadata expiry.
            assert_eq!(timer.pending_count(), 2);

            delayed.release();
            let facts = match authentication.as_mut().poll(&mut task) {
                Poll::Ready(Ok(facts)) => facts,
                _ => panic!("rejected policy update must preserve valid pending authentication"),
            };
            assert_eq!(facts.subject.as_deref(), Some("alice"));
            assert!(facts.verification_is_current());
            drop(authentication);
            assert!(verifier.source.admission.active.lock().unwrap().is_empty());
            assert_eq!(timer.pending_count(), 0);
            assert!(context.checkpoint().is_ok());
            assert!(caller.checkpoint().is_ok());
            let again =
                ready(provider.authenticate_async(&context, request(&params, &authorization)))
                    .unwrap();
            assert_eq!(again.session_owner(), facts.session_owner());
            assert_eq!(delayed.calls.load(Ordering::SeqCst), 1);
        });
        assert_eq!(timer.pending_count(), 0);
        drop(caller);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn enterprise_guarded_provider_metadata_expiry_interrupts_suspended_refresh() {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let caller = runtime.request_cx_with_budget(Budget::INFINITE);
        runtime.block_on(async {
            // A foreign clock is already past every caller deadline. Only the
            // explicit caller's driver may register or wake these timers.
            let foreign_clock = Arc::new(VirtualClock::new());
            foreign_clock.advance(1_000_000_000_000);
            let foreign_timer = TimerDriverHandle::with_virtual_clock(foreign_clock);
            let foreign_runtime = RuntimeBuilder::current_thread()
                .blocking_threads(0, 0)
                .with_timer_driver(foreign_timer.clone())
                .build()
                .unwrap();
            let foreign_caller = foreign_runtime.request_cx_with_budget(Budget::INFINITE);
            let ambient = Cx::set_current(Some(foreign_caller.clone()));
            let context = McpContext::new(caller.clone(), 1);
            let sibling = McpContext::new(caller.clone(), 2);
            let documents = documents();
            let params = params();
            // Signing precedes short-lived policy construction; expensive key
            // setup must not consume the metadata lifetime under test.
            let authorization = format!("Bearer {}", token("one").token);
            for idp_expires_first in [true, false] {
                for fresh in [false, true] {
                    for reply_ready in [false, true] {
                        let (mut verifier, _, elapsed) = fixture(vec![]);
                        let delayed = Arc::new(DelayedExchange {
                            released: AtomicBool::new(false),
                            calls: AtomicUsize::new(0),
                            waker: Mutex::new(None),
                        });
                        verifier.source.test_exchange = Some(delayed.clone());
                        let long = Instant::now() + Duration::from_secs(120);
                        let short = if fresh {
                            long
                        } else {
                            Instant::now() + Duration::from_secs(1)
                        };
                        let (idp_deadline, resource_deadline) = if idp_expires_first {
                            (short, long)
                        } else {
                            (long, short)
                        };
                        let policy_owner = EnterpriseResourcePolicy::new(
                            configuration(1),
                            &documents[0],
                            &documents[1],
                            idp_deadline,
                            resource_deadline,
                        )
                        .unwrap();
                        let provider = policy_owner.guarded_provider(verifier.clone()).unwrap();
                        let selected = if fresh { &sibling } else { &context };
                        let mut authentication =
                            provider.authenticate_async(selected, request(&params, &authorization));
                        let wakes = Arc::new(AuthenticationWake::default());
                        let waker = Waker::from(wakes.clone());
                        let mut task = Context::from_waker(&waker);
                        assert!(authentication.as_mut().poll(&mut task).is_pending());
                        assert_eq!(delayed.calls.load(Ordering::SeqCst), 1);
                        assert_eq!(verifier.source.admission.active.lock().unwrap().len(), 1);
                        assert_eq!(timer.pending_count(), 2);
                        assert_eq!(foreign_timer.pending_count(), 0);
                        assert_eq!(Cx::current().unwrap().now(), foreign_caller.now());

                        // Polling again must not restart the original expiry.
                        clock.advance(600_000_000);
                        assert_eq!(timer.process_timers(), 0);
                        assert!(authentication.as_mut().poll(&mut task).is_pending());
                        let wake_count = wakes.0.load(Ordering::SeqCst);
                        clock.advance(500_000_000);
                        assert_eq!(timer.process_timers(), usize::from(!fresh));
                        assert_eq!(wakes.0.load(Ordering::SeqCst) > wake_count, !fresh);
                        assert!(!delayed.released.load(Ordering::SeqCst));
                        if reply_ready {
                            // A response ready on the same turn cannot publish
                            // keys after this request's metadata has expired.
                            delayed.release();
                        }
                        let outcome = authentication.as_mut().poll(&mut task);
                        if fresh {
                            let outcome = if reply_ready {
                                outcome
                            } else {
                                assert!(outcome.is_pending());
                                delayed.release();
                                authentication.as_mut().poll(&mut task)
                            };
                            let Poll::Ready(Ok(facts)) = outcome else {
                                panic!("fresh policy must retain successful authentication");
                            };
                            assert_eq!(facts.subject.as_deref(), Some("alice"));
                            assert!(facts.verification_is_current());
                        } else {
                            let Poll::Ready(Err(error)) = outcome else {
                                panic!("metadata expiry must interrupt the pending key fetch");
                            };
                            assert_eq!(error.code, McpErrorCode::ResourceForbidden);
                            let state = verifier.managed.shared.state.read().unwrap();
                            assert!(state.flight.is_none());
                            assert!(state.active.is_none());
                        }
                        // Capacity and timers are released as authentication
                        // returns, even before its completed future is dropped.
                        assert!(verifier.source.admission.active.lock().unwrap().is_empty());
                        assert_eq!(timer.pending_count(), 0);
                        assert_eq!(foreign_timer.pending_count(), 0);
                        drop(authentication);
                        assert!(context.checkpoint().is_ok());
                        assert!(sibling.checkpoint().is_ok());
                        assert!(caller.checkpoint().is_ok());
                        assert!(foreign_caller.checkpoint().is_ok());
                        assert_eq!(Cx::current().unwrap().now(), foreign_caller.now());

                        if !fresh {
                            // The same caller and fetch capacity remain usable
                            // by a current policy after the unchanged backoff.
                            delayed.release();
                            elapsed.store(3, Ordering::SeqCst);
                            let fresh_owner = owner();
                            let fresh_provider =
                                fresh_owner.guarded_provider(verifier.clone()).unwrap();
                            let facts = ready(fresh_provider.authenticate_async(
                                &sibling,
                                request(&params, &authorization),
                            ))
                            .unwrap();
                            assert_eq!(facts.subject.as_deref(), Some("alice"));
                            assert!(facts.verification_is_current());
                            assert_eq!(delayed.calls.load(Ordering::SeqCst), 2);
                            assert!(verifier.source.admission.active.lock().unwrap().is_empty());
                            assert_eq!(timer.pending_count(), 0);
                            assert_eq!(foreign_timer.pending_count(), 0);
                        }
                    }
                }
            }
            drop(ambient);
            drop(foreign_caller);
            assert!(foreign_runtime.shutdown_timeout(Duration::from_secs(1)));
        });
        assert_eq!(timer.pending_count(), 0);
        drop(caller);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }
}
