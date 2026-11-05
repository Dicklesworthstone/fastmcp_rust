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
