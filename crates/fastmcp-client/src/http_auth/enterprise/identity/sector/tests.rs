//! Unit tests of the shipped response-admission and consumer-binding boundaries.
//! Synthetic response fixtures below are not public-network or TLS proofs. The
//! public fetch tests cover preflight refusal and resolver-child authority using
//! the real adapter, without making DNS, socket or TLS claims.

use super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::task::{Context, Waker};
use std::time::Duration;

use asupersync::Budget;
use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
use asupersync::types::Time;
use fastmcp_transport::{GuardedHttpRedirect, GuardedHttpResolver};

const SECTOR: &str = "https://sector.example/redirects.json";
const FIRST: &str = "https://client.example/callback";
const SECOND: &str = "https://alternate.example/callback";

fn registration() -> EnterpriseOidcRelyingPartyConfiguration {
    EnterpriseOidcRelyingPartyConfiguration {
        issuer: "https://idp.example".into(), tenant: None,
        client_id: "native-idp".into(), registration_generation: 11,
        subject_type: EnterpriseOidcSubjectType::Pairwise,
        redirect_uris: vec![FIRST.into(), SECOND.into()],
    }
}

fn policy() -> GuardedHttpFetchPolicy {
    GuardedHttpFetchPolicy::new(
        MAX_OIDC_SECTOR_DOCUMENT_BYTES, Duration::from_secs(5),
        Duration::from_secs(2), "reviewed-roots-7",
    ).unwrap()
}

fn request_for(registration: &EnterpriseOidcRelyingPartyConfiguration) -> PreparedSectorReview {
    PreparedSectorReview::new(
        OidcSectorRegistrationRole::Client, registration, SECTOR, &policy(), 7,
    ).unwrap()
}

fn response(
    body: &[u8],
    url: &GuardedHttpsUrl,
    policy: &GuardedHttpFetchPolicy,
) -> GuardedHttpFetchResponse {
    GuardedHttpFetchResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json; charset=utf-8".into())],
        body: body.to_vec(), redirect: None,
        provenance: GuardedHttpPeerProvenance {
            host: url.host().into(),
            selected_address: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)), url.port(),
            ),
            leaf_certificate_sha256: [42; 32], alpn: Some(b"http/1.1".to_vec()),
            tls_protocol: Some("TLSv1_3".into()),
            root_policy_revision: policy.root_policy_revision().into(),
        },
    }
}

/// Reuses the private production response-admission boundary in consumer tests.
/// This fabricates only transport response input; it makes no network-proof claim.
pub(crate) fn reviewed_fixture(
    role: OidcSectorRegistrationRole,
    registration: &EnterpriseOidcRelyingPartyConfiguration,
    sector_uri: &str,
    additional: &[&str],
) -> OidcSectorDocumentReview {
    let request = PreparedSectorReview::new(role, registration, sector_uri, &policy(), 7).unwrap();
    let mut entries = registration.redirect_uris.clone();
    entries.extend(additional.iter().map(|entry| (*entry).to_owned()));
    let bytes = serde_json::to_vec(&entries).unwrap();
    let wire = response(&bytes, &request.url, &request.policy);
    request.admit_response(wire).unwrap()
}

#[test]
fn sector_review_accepts_multi_host_registration_without_granting_additional_redirects() {
    let registration = registration();
    assert!(OidcSubjectNamespace::from_preregistered_redirects(
        &registration.issuer, registration.subject_type, registration.registration_generation,
        &registration.redirect_uris,
    ).is_err());
    let review = reviewed_fixture(
        OidcSectorRegistrationRole::Client, &registration, SECTOR,
        &["custom:another-client-callback", "https://extra.example/callback"],
    );
    let namespace = OidcSubjectNamespace::from_reviewed_sector(
        &registration, OidcSectorRegistrationRole::Client, &review,
    ).unwrap();
    assert_eq!(namespace.sector_host(), Some("sector.example"));
    assert_eq!(namespace.registration_generation(), Some(11));
    assert_eq!(namespace.sector_review_digest(), Some(review.binding_digest()));
    assert_eq!(review.sector_identifier_uri(), SECTOR);
    assert_eq!(review.fetch_policy_generation(), 7);
    assert_eq!(review.fetch_policy(), &policy());
    assert_eq!(review.provenance().leaf_certificate_sha256, [42; 32]);
    let mut reordered = registration.clone();
    reordered.redirect_uris.reverse();
    assert_eq!(OidcSubjectNamespace::from_reviewed_sector(
        &reordered, OidcSectorRegistrationRole::Client, &review,
    ).unwrap(), namespace);
    let mut expanded = registration.clone();
    expanded.redirect_uris.push("https://extra.example/callback".into());
    assert_eq!(OidcSubjectNamespace::from_reviewed_sector(
        &expanded, OidcSectorRegistrationRole::Client, &review,
    ).err(), Some(EnterpriseIdentityError::RegistrationMismatch));
    let debug = format!("{review:?} {namespace:?}");
    for private in ["idp.example", "sector.example", "native-idp", FIRST] {
        assert!(!debug.contains(private));
    }
}

#[test]
fn sector_review_rejects_wrong_shapes_duplicates_and_missing_registered_redirects() {
    let registration = registration();
    let valid = serde_json::to_vec(&registration.redirect_uris).unwrap();
    let request = request_for(&registration);
    let wire = response(&valid, &request.url, &request.policy);
    assert!(request.admit_response(wire).is_ok());
    for body in [
        b"{}".as_slice(), b"null", b"[]", b"[null]", b"[42]", b"[[\"https://client.example/callback\"]]",
        br#"["https://client.example/callback"]"#,
        br#"["https://client.example/callback","https://alternate.example/callback","https://client.example/callback"]"#,
        br#"["https://client.example/callback","https://alternate.example/callback","https://client.example/\u0063allback"]"#,
        br#"["https://client.example/callback","https://alternate.example/callback","relative/callback"]"#,
        br#"["https://client.example/callback","https://alternate.example/callback","https://extra.example/callback#fragment"]"#,
        br#"["https://client.example/callback","https://alternate.example/callback"] {}"#,
    ] {
        let request = request_for(&registration);
        let wire = response(body, &request.url, &request.policy);
        assert!(request.admit_response(wire).is_err(), "accepted malformed sector document");
    }
    let mut entries = registration.redirect_uris.clone();
    entries.extend((2..MAX_OIDC_SECTOR_DOCUMENT_REDIRECTS).map(|index| {
        format!("https://extra.example/callback-{index}")
    }));
    let request = request_for(&registration);
    let wire = response(&serde_json::to_vec(&entries).unwrap(), &request.url, &request.policy);
    assert!(request.admit_response(wire).is_ok());
    entries.push("https://extra.example/one-too-many".into());
    let request = request_for(&registration);
    let wire = response(&serde_json::to_vec(&entries).unwrap(), &request.url, &request.policy);
    assert_eq!(request.admit_response(wire).err(), Some(OidcSectorReviewError::InvalidDocument));
}

#[test]
fn sector_review_is_bound_to_exact_relying_party_role_and_generation() {
    let registration = registration();
    let review = reviewed_fixture(OidcSectorRegistrationRole::Client, &registration, SECTOR, &[]);
    let before = review.binding_digest();
    for mutation in 0..7 {
        let mut changed = registration.clone();
        match mutation {
            0 => changed.issuer = "https://other-idp.example".into(),
            1 => changed.tenant = Some("other-tenant".into()),
            2 => changed.client_id = "other-rp".into(),
            3 => changed.registration_generation += 1,
            4 => changed.subject_type = EnterpriseOidcSubjectType::Public,
            5 => { changed.redirect_uris.pop(); }
            6 => changed.redirect_uris.push(FIRST.into()),
            _ => unreachable!(),
        }
        assert_eq!(OidcSubjectNamespace::from_reviewed_sector(
            &changed, OidcSectorRegistrationRole::Client, &review,
        ).err(), Some(EnterpriseIdentityError::RegistrationMismatch));
        assert_eq!(review.binding_digest(), before);
    }
    assert_eq!(OidcSubjectNamespace::from_reviewed_sector(
        &registration, OidcSectorRegistrationRole::ResourceAuthorizationServer, &review,
    ).err(), Some(EnterpriseIdentityError::RegistrationMismatch));
    assert!(OidcSubjectNamespace::from_reviewed_sector(
        &registration, OidcSectorRegistrationRole::Client, &review,
    ).is_ok());
}

#[test]
fn sector_review_refuses_redirects_representation_confusion_and_foreign_provenance() {
    let registration = registration();
    let body = serde_json::to_vec(&registration.redirect_uris).unwrap();
    for mutation in 0..13 {
        let request = request_for(&registration);
        let mut wire = response(&body, &request.url, &request.policy);
        match mutation {
            0 => wire.status = 302,
            1 => wire.redirect = Some(GuardedHttpRedirect {
                status: 302, location: Some("https://other.example/redirects.json".into()),
            }),
            2 => wire.headers.clear(),
            3 => wire.headers[0].1 = "text/plain".into(),
            4 => wire.headers[0].1 = "application/json; charset=latin1".into(),
            5 => wire.headers.push(("Content-Type".into(), "application/json".into())),
            6 => wire.headers.push(("content-encoding".into(), "gzip".into())),
            7 => wire.provenance.host = "other.example".into(),
            8 => wire.provenance.selected_address.set_port(8443),
            9 => wire.provenance.root_policy_revision = "foreign-roots".into(),
            10 => wire.provenance.alpn = Some(b"h2".to_vec()),
            11 => wire.body = vec![b' '; MAX_OIDC_SECTOR_DOCUMENT_BYTES + 1],
            12 => wire.provenance.tls_protocol = Some("TLSv1_3\nforeign".into()),
            _ => unreachable!(),
        }
        assert!(request.admit_response(wire).is_err(), "accepted response mutation {mutation}");
    }
}

#[test]
fn sector_review_digest_binds_document_url_policy_and_tls_observation() {
    let registration = registration();
    let base = reviewed_fixture(OidcSectorRegistrationRole::Client, &registration, SECTOR, &[]);
    let extra = reviewed_fixture(
        OidcSectorRegistrationRole::Client, &registration, SECTOR,
        &["https://extra.example/callback"],
    );
    assert_ne!(base.document_digest(), extra.document_digest());
    assert_ne!(base.binding_digest(), extra.binding_digest());
    let moved = reviewed_fixture(
        OidcSectorRegistrationRole::Client, &registration,
        "https://sector.example/revised.json", &[],
    );
    assert_eq!(base.sector_host(), moved.sector_host());
    assert_eq!(base.document_digest(), moved.document_digest());
    assert_ne!(base.binding_digest(), moved.binding_digest());
    let body = serde_json::to_vec(&registration.redirect_uris).unwrap();
    for mutation in 0..6 {
        let mut request = request_for(&registration);
        if mutation == 0 { request.policy_generation += 1; }
        if mutation == 1 {
            request.policy = GuardedHttpFetchPolicy::new(
                MAX_OIDC_SECTOR_DOCUMENT_BYTES, Duration::from_secs(4),
                Duration::from_secs(2), "reviewed-roots-7",
            ).unwrap();
        }
        if mutation == 2 {
            request.policy = GuardedHttpFetchPolicy::new(
                MAX_OIDC_SECTOR_DOCUMENT_BYTES, Duration::from_secs(5),
                Duration::from_secs(2), "reviewed-roots-8",
            ).unwrap();
        }
        let mut wire = response(&body, &request.url, &request.policy);
        if mutation == 3 { wire.provenance.leaf_certificate_sha256[0] ^= 1; }
        if mutation == 4 {
            wire.provenance.selected_address.set_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 215, 15)));
        }
        if mutation == 5 { wire.body.push(b' '); }
        let changed = request.admit_response(wire).unwrap();
        if mutation != 5 { assert_eq!(base.document_digest(), changed.document_digest()); }
        assert_ne!(base.binding_digest(), changed.binding_digest());
    }
}

struct CountingResolver(Arc<AtomicUsize>);
impl GuardedHttpResolver for CountingResolver {
    fn resolve_all(
        &self,
        _cx: Cx,
        _host: String,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, GuardedHttpFetchError>> + Send + 'static>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(GuardedHttpFetchError::ResolutionEmpty) })
    }
}

fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
    let mut future = std::pin::pin!(future);
    future.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn public_sector_fetch_refuses_invalid_inputs_and_effect_ceiling_before_resolution() {
    let calls = Arc::new(AtomicUsize::new(0));
    let fetcher = GuardedHttpFetcher::with_resolver(
        policy(), Arc::new(CountingResolver(Arc::clone(&calls))),
    ).unwrap();
    let cx = Cx::for_testing();
    let registration = registration();
    for (uri, generation, error) in [
        (SECTOR, 0, OidcSectorReviewError::InvalidFetchPolicy),
        ("http://sector.example/redirects.json", 7, OidcSectorReviewError::InvalidSectorUri),
        ("https://user@sector.example/redirects.json", 7, OidcSectorReviewError::InvalidSectorUri),
        ("https://sector.example/redirects.json#fragment", 7, OidcSectorReviewError::InvalidSectorUri),
        ("https://127.0.0.1/redirects.json", 7, OidcSectorReviewError::InvalidSectorUri),
    ] {
        assert!(matches!(poll_once(OidcSectorDocumentReview::fetch(
            &cx, &fetcher, OidcSectorRegistrationRole::Client, &registration, uri, generation,
        )), Poll::Ready(Err(actual)) if actual == error));
    }
    let mut public = registration.clone();
    public.subject_type = EnterpriseOidcSubjectType::Public;
    assert!(matches!(poll_once(OidcSectorDocumentReview::fetch(
        &cx, &fetcher, OidcSectorRegistrationRole::Client, &public, SECTOR, 7,
    )), Poll::Ready(Err(OidcSectorReviewError::InvalidRegistration))));
    let oversized = GuardedHttpFetcher::with_resolver(
        GuardedHttpFetchPolicy::new(
            MAX_OIDC_SECTOR_DOCUMENT_BYTES + 1, Duration::from_secs(5),
            Duration::from_secs(2), "reviewed-roots-7",
        ).unwrap(), Arc::new(CountingResolver(Arc::clone(&calls))),
    ).unwrap();
    assert!(matches!(poll_once(OidcSectorDocumentReview::fetch(
        &cx, &oversized, OidcSectorRegistrationRole::Client, &registration, SECTOR, 7,
    )), Poll::Ready(Err(OidcSectorReviewError::InvalidFetchPolicy))));
    {
        let _caller = Cx::set_current(Some(cx.clone()));
        let _no_io = Cx::push_restriction(CapSet::<true, true, true, false, true>::MASK);
        assert!(matches!(poll_once(OidcSectorDocumentReview::fetch(
            &cx, &fetcher, OidcSectorRegistrationRole::Client, &registration, SECTOR, 7,
        )), Poll::Ready(Err(OidcSectorReviewError::RuntimeUnavailable))));
    }
    cx.set_cancel_requested(true);
    assert!(matches!(poll_once(OidcSectorDocumentReview::fetch(
        &cx, &fetcher, OidcSectorRegistrationRole::Client, &registration, SECTOR, 7,
    )), Poll::Ready(Err(OidcSectorReviewError::Cancelled))));
    let expired = Cx::for_testing_with_budget(Budget::new().with_deadline(Time::ZERO));
    assert!(matches!(poll_once(OidcSectorDocumentReview::fetch(
        &expired, &fetcher, OidcSectorRegistrationRole::Client, &registration, SECTOR, 7,
    )), Poll::Ready(Err(OidcSectorReviewError::TimedOut | OidcSectorReviewError::Cancelled))));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}


fn capability_bits(cx: &Cx) -> usize {
    let capabilities = cx.capabilities();
    usize::from(capabilities.spawn)
        | (usize::from(capabilities.time) << 1)
        | (usize::from(capabilities.entropy) << 2)
        | (usize::from(capabilities.io) << 3)
        | (usize::from(capabilities.remote) << 4)
}

struct CapabilityResolver {
    calls: Arc<AtomicUsize>,
    held: Arc<AtomicUsize>,
    ambient: Arc<AtomicUsize>,
    pending: bool,
}

impl GuardedHttpResolver for CapabilityResolver {
    fn resolve_all(
        &self,
        cx: Cx,
        _host: String,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, GuardedHttpFetchError>> + Send + 'static>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.held.store(capability_bits(&cx), Ordering::SeqCst);
        self.ambient.store(
            capability_bits(&Cx::current().expect("resolver child has its caller context")),
            Ordering::SeqCst,
        );
        if self.pending {
            Box::pin(std::future::pending())
        } else {
            Box::pin(async { Err(GuardedHttpFetchError::ResolutionEmpty) })
        }
    }
}

#[test]
fn public_sector_fetch_passes_the_admitted_effect_ceiling_to_resolver_children() {
    // The custom resolver performs no DNS and returns no addresses. These
    // observations prove child authority propagation, not a live HTTPS fetch.
    for denied in [4, 16, 20] {
        let calls = Arc::new(AtomicUsize::new(0));
        let held = Arc::new(AtomicUsize::new(usize::MAX));
        let ambient = Arc::new(AtomicUsize::new(usize::MAX));
        let fetcher = GuardedHttpFetcher::with_resolver(policy(), Arc::new(CapabilityResolver {
            calls: Arc::clone(&calls), held: Arc::clone(&held),
            ambient: Arc::clone(&ambient), pending: false,
        })).unwrap();
        let registration = registration();
        let mask = match denied {
            4 => CapSet::<true, true, false, true, true>::MASK,
            16 => CapSet::<true, true, true, true, false>::MASK,
            20 => CapSet::<true, true, false, true, false>::MASK,
            _ => unreachable!(),
        };
        let outcome = fastmcp_core::block_on(async {
            let caller = Cx::current().expect("test runtime installs its caller");
            assert_eq!(capability_bits(&caller), 31);
            let mut review = std::pin::pin!(OidcSectorDocumentReview::fetch(
                &caller, &fetcher, OidcSectorRegistrationRole::Client, &registration, SECTOR, 7,
            ));
            poll_fn(|task_cx| {
                let _restriction = Cx::push_restriction(mask);
                review.as_mut().poll(task_cx)
            }).await
        });
        assert_eq!(outcome.err(), Some(OidcSectorReviewError::FetchFailed));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(held.load(Ordering::SeqCst), 31 & !denied);
        assert_eq!(ambient.load(Ordering::SeqCst), 31 & !denied);
    }
}

#[test]
fn public_sector_fetch_stops_before_repolling_under_a_narrower_effect_ceiling() {
    for mask in [
        CapSet::<true, true, false, true, true>::MASK,
        CapSet::<true, true, true, true, false>::MASK,
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = GuardedHttpFetcher::with_resolver(policy(), Arc::new(CapabilityResolver {
            calls: Arc::clone(&calls),
            held: Arc::new(AtomicUsize::new(usize::MAX)),
            ambient: Arc::new(AtomicUsize::new(usize::MAX)),
            pending: true,
        })).unwrap();
        let registration = registration();
        fastmcp_core::block_on(async {
            let caller = Cx::current().expect("test runtime installs its caller");
            let mut review = std::pin::pin!(OidcSectorDocumentReview::fetch(
                &caller, &fetcher, OidcSectorRegistrationRole::Client, &registration, SECTOR, 7,
            ));
            poll_fn(|task_cx| {
                assert!(review.as_mut().poll(task_cx).is_pending());
                let before = calls.load(Ordering::SeqCst);
                let result = {
                    let _restriction = Cx::push_restriction(mask);
                    review.as_mut().poll(task_cx)
                };
                assert!(matches!(result, Poll::Ready(Err(OidcSectorReviewError::RuntimeUnavailable))));
                assert_eq!(calls.load(Ordering::SeqCst), before);
                Poll::Ready(())
            }).await;
        });
    }
}
