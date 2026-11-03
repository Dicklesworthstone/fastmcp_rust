//! Local admission tests. No signer operation or remote registration is proved
//! by these tests; the separate TLS target exercises real RS256 signatures.

use super::*;
use fastmcp_protocol::jose::{
    AttestedRs256PublicKey, ExternalRs256SignDisposition, ExternalRs256SignerBackend,
    ExternalRs256SigningRequest, RedactedSignerProvenance,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};

struct NeverSign(AtomicUsize);
impl ExternalRs256SignerBackend for NeverSign {
    fn sign<'a>(
        &'a self,
        _: &'a Cx,
        _: ExternalRs256SigningRequest,
    ) -> Pin<Box<dyn Future<Output = ExternalRs256SignDisposition> + Send + 'a>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::pending())
    }
}
fn binding() -> Rs256SigningBinding {
    Rs256SigningBinding::new(1, 2, 3, 4).unwrap()
}
fn signer(byte: u8, binding: Rs256SigningBinding) -> (Arc<ExternalRs256Signer>, Arc<NeverSign>) {
    let backend = Arc::new(NeverSign(AtomicUsize::new(0)));
    // Shape-only public modulus for admission tests; never used for signing.
    let public = AttestedRs256PublicKey::admit(
        "registered-key",
        vec![byte; 256],
        binding,
        RedactedSignerProvenance::new("admission-only-fixture").unwrap(),
    )
    .unwrap();
    (
        Arc::new(ExternalRs256Signer::new(backend.clone(), public)),
        backend,
    )
}
fn document(signer: &ExternalRs256Signer) -> Value {
    json!({
        "issuer":"https://issuer.example", "token_endpoint":"https://issuer.example/token",
        "resource":"https://resource.example/mcp", "client_id":"registered-service",
        "grant_types":["client_credentials"], "token_endpoint_auth_method":"private_key_jwt",
        "token_endpoint_auth_signing_alg":"RS256",
        "jwks":serde_json::from_slice::<Value>(signer.canonical_public_jwks().unwrap().as_bytes()).unwrap(),
    })
}
fn registration(
    value: &Value,
    audience: ClientAssertionAudience,
) -> Result<PrivateKeyJwtRegistration, ClientCredentialsError> {
    PrivateKeyJwtRegistration::from_trusted_json(
        &serde_json::to_vec(value).unwrap(),
        9,
        Instant::now() + Duration::from_secs(300),
        binding(),
        audience,
    )
}
fn plan(
    value: &Value,
    signer: Arc<ExternalRs256Signer>,
) -> Result<ClientCredentialsPlan, ClientCredentialsError> {
    ClientCredentialsPlan::private_key_jwt(
        TrustedOAuthIssuer::new("https://issuer.example").unwrap(),
        registration(value, ClientAssertionAudience::Issuer)?,
        signer,
        vec!["read".to_owned()],
    )
}
fn metadata() -> Value {
    json!({"issuer":"https://issuer.example", "token_endpoint":"https://issuer.example/token",
        "grant_types_supported":["client_credentials"],
        "token_endpoint_auth_methods_supported":["private_key_jwt", "client_secret_basic"],
        "token_endpoint_auth_signing_alg_values_supported":["RS256"], "scopes_supported":["read"]})
}
fn admit(
    plan: &ClientCredentialsPlan,
    document: &Value,
) -> Result<CanonicalHttpUrl, ClientCredentialsError> {
    super::super::admit_machine_issuer(
        &plan.discovery,
        &plan.discovery.issuers[0],
        &serde_json::to_vec(document).unwrap(),
        &plan.authentication,
    )
}

#[test]
fn registration_and_metadata_admission_never_invoke_the_signer() {
    let (signer, backend) = signer(0xa1, binding());
    let plan = plan(&document(&signer), signer.clone()).unwrap();
    assert_eq!(plan.authentication.method(), "private_key_jwt");
    assert_eq!(
        admit(&plan, &metadata()).unwrap().as_str(),
        "https://issuer.example/token"
    );
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
    assert!(!format!("{plan:?}").contains("registered-service"));
}

#[test]
fn registration_declarations_cannot_be_defaulted_or_replaced_by_server_fields() {
    let (signer, _) = signer(0xa1, binding());
    let good = document(&signer);
    for (field, value) in [
        ("grant_types", json!(["authorization_code"])),
        (
            "grant_types",
            json!(["client_credentials", "client_credentials"]),
        ),
        ("token_endpoint_auth_method", json!("client_secret_basic")),
        ("token_endpoint_auth_signing_alg", json!("HS256")),
        ("client_id", json!("")),
        ("client_id", json!("https://portable.example/client")),
        ("token_endpoint", json!("http://issuer.example/token")),
        ("token_endpoint", json!("https://user@issuer.example/token")),
        (
            "token_endpoint",
            json!("https://issuer.example/token?override=yes"),
        ),
        ("resource", json!("http://resource.example/mcp")),
    ] {
        let mut changed = good.clone();
        changed[field] = value;
        assert!(registration(&changed, ClientAssertionAudience::Issuer).is_err());
    }
    for field in [
        "grant_types",
        "token_endpoint_auth_method",
        "token_endpoint_auth_signing_alg",
    ] {
        let mut changed = good.clone();
        changed.as_object_mut().unwrap().remove(field);
        changed[format!("{field}_supported")] = good[field].clone();
        assert!(registration(&changed, ClientAssertionAudience::Issuer).is_err());
    }
    let bytes = serde_json::to_string(&good)
        .unwrap()
        .replacen('{', "{\"client_id\":\"other\",", 1);
    assert!(
        PrivateKeyJwtRegistration::from_trusted_json(
            bytes.as_bytes(),
            9,
            Instant::now() + Duration::from_secs(300),
            binding(),
            ClientAssertionAudience::Issuer
        )
        .is_err()
    );
    assert!(registration(&good, ClientAssertionAudience::Issuer).is_ok());
}

#[test]
fn same_kid_cannot_substitute_different_rsa_material_or_signing_generations() {
    let (first, backend) = signer(0xa1, binding());
    let registered = document(&first);
    assert!(plan(&registered, first.clone()).is_ok());
    let (different_key, _) = signer(0xb1, binding());
    assert_eq!(first.key_id(), different_key.key_id());
    assert!(matches!(
        plan(&registered, different_key),
        Err(ClientCredentialsError::InvalidRegistration)
    ));
    let (different_binding, _) = signer(0xa1, Rs256SigningBinding::new(1, 2, 3, 5).unwrap());
    assert!(matches!(
        plan(&registered, different_binding),
        Err(ClientCredentialsError::InvalidRegistration)
    ));
    assert!(plan(&registered, first).is_ok());
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
}

#[test]
fn audience_is_selected_once_and_preserves_exact_imported_spelling() {
    let (signer, _) = signer(0xa1, binding());
    let mut doc = document(&signer);
    doc["issuer"] = json!("https://ISSUER.example:443");
    doc["token_endpoint"] = json!("https://ISSUER.example:443/token");
    let issuer = registration(&doc, ClientAssertionAudience::Issuer).unwrap();
    let token = registration(&doc, ClientAssertionAudience::TokenEndpoint).unwrap();
    assert_eq!(issuer.audience(), "https://ISSUER.example:443");
    assert_eq!(token.audience(), "https://ISSUER.example:443/token");
    assert_ne!(issuer.audience(), token.audience());
    assert!(
        ClientCredentialsPlan::private_key_jwt(
            TrustedOAuthIssuer::new("https://issuer.example").unwrap(),
            issuer,
            signer,
            vec![]
        )
        .is_err(),
        "canonical equivalence cannot replace exact issuer identity"
    );
}

#[test]
fn authorization_server_must_admit_rs256_and_the_exact_registered_endpoint() {
    let (signer, backend) = signer(0xa1, binding());
    let plan = plan(&document(&signer), signer.clone()).unwrap();
    let good = metadata();
    for (key, value) in [
        (
            "token_endpoint_auth_signing_alg_values_supported",
            json!(["ES256"]),
        ),
        (
            "token_endpoint_auth_signing_alg_values_supported",
            json!(["RS256", "RS256"]),
        ),
        (
            "token_endpoint_auth_signing_alg_values_supported",
            Value::Null,
        ),
        (
            "token_endpoint_auth_methods_supported",
            json!(["client_secret_basic"]),
        ),
        ("token_endpoint", json!("https://issuer.example/other")),
        ("token_endpoint", json!("https://ISSUER.example:443/token")),
    ] {
        let mut changed = good.clone();
        changed[key] = value;
        assert!(admit(&plan, &changed).is_err());
        assert!(admit(&plan, &good).is_ok());
    }
    let mut absent = good.clone();
    absent
        .as_object_mut()
        .unwrap()
        .remove("token_endpoint_auth_signing_alg_values_supported");
    assert!(admit(&plan, &absent).is_err());
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
}

#[test]
fn private_or_ambiguous_registration_keys_and_unbounded_validity_are_refused() {
    let (signer, _) = signer(0xa1, binding());
    let good = document(&signer);
    let mut private = good.clone();
    private["jwks"]["keys"][0]["d"] = json!("private-canary");
    assert!(registration(&private, ClientAssertionAudience::Issuer).is_err());
    let mut many = good.clone();
    let mut other = many["jwks"]["keys"][0].clone();
    other["kid"] = json!("second");
    many["jwks"]["keys"].as_array_mut().unwrap().push(other);
    assert!(registration(&many, ClientAssertionAudience::Issuer).is_err());
    let bytes = serde_json::to_vec(&good).unwrap();
    for (generation, until) in [
        (0, Instant::now() + Duration::from_secs(60)),
        (1, Instant::now()),
        (1, Instant::now() + Duration::from_secs(86_402)),
    ] {
        assert!(
            PrivateKeyJwtRegistration::from_trusted_json(
                &bytes,
                generation,
                until,
                binding(),
                ClientAssertionAudience::Issuer
            )
            .is_err()
        );
    }
    let imported = registration(&good, ClientAssertionAudience::Issuer).unwrap();
    assert_eq!(imported.generation(), 9);
    assert!(imported.valid_until() > Instant::now());
    assert!(!format!("{imported:?}").contains("registered-service"));
}

#[test]
fn selecting_basic_does_not_silently_switch_methods_when_both_are_advertised() {
    let basic = ClientCredentialsPlan::new(
        CanonicalHttpUrl::parse("https://resource.example/mcp").unwrap(),
        TrustedOAuthIssuer::new("https://issuer.example").unwrap(),
        "basic-client",
        "basic-secret",
        vec!["read".to_owned()],
    )
    .unwrap();
    assert_eq!(basic.authentication.method(), "client_secret_basic");
    assert!(admit(&basic, &metadata()).is_ok());
    let mut jwt_only = metadata();
    jwt_only["token_endpoint_auth_methods_supported"] = json!(["private_key_jwt"]);
    assert!(matches!(
        admit(&basic, &jwt_only),
        Err(ClientCredentialsError::UnsupportedAuthentication)
    ));
    assert_eq!(basic.authentication.method(), "client_secret_basic");
}


#[test]
fn revocation_registration_keeps_audience_and_exact_endpoint_separate_from_token_auth() {
    let (signer, backend) = signer(0xa1, binding());
    let document = document(&signer);
    for audience in [
        RevocationAssertionAudience::Issuer,
        RevocationAssertionAudience::RevocationEndpoint,
    ] {
        let registered = registration(&document, ClientAssertionAudience::TokenEndpoint)
            .unwrap()
            .with_trusted_revocation("https://ISSUER.example:443/revoke", audience)
            .unwrap();
        assert_eq!(registered.audience(), "https://issuer.example/token");
        assert_eq!(registered.revocation.as_ref().unwrap().audience, audience);
        assert_eq!(registered.revocation.as_ref().unwrap().endpoint, "https://ISSUER.example:443/revoke");
        let selected = PrivateKeyJwtAuthentication::new(registered, signer.clone()).unwrap();
        assert!(selected.admits_revocation("https://ISSUER.example:443/revoke").unwrap());
        assert!(matches!(
            selected.admits_revocation("https://issuer.example/revoke"),
            Err(ClientCredentialsError::InvalidRegistration)
        ));
    }
    for endpoint in [
        "http://issuer.example/revoke",
        "https://issuer.example/revoke?token=x",
        "https://issuer.example/revoke#fragment",
        "https://user@issuer.example/revoke",
    ] {
        assert!(registration(&document, ClientAssertionAudience::Issuer).unwrap()
            .with_trusted_revocation(endpoint, RevocationAssertionAudience::Issuer).is_err());
    }
    let registered = registration(&document, ClientAssertionAudience::Issuer).unwrap()
        .with_trusted_revocation("https://issuer.example/revoke", RevocationAssertionAudience::Issuer)
        .unwrap();
    assert!(registered.with_trusted_revocation(
        "https://issuer.example/revoke", RevocationAssertionAudience::RevocationEndpoint,
    ).is_err());
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
}

#[test]
fn revocation_jwt_metadata_requires_its_own_method_algorithm_and_registration() {
    use super::super::lifetime::{RevocationTarget, admit_revocation};
    let (signer, backend) = signer(0xa1, binding());
    let registered = registration(&document(&signer), ClientAssertionAudience::TokenEndpoint)
        .unwrap()
        .with_trusted_revocation(
            "https://issuer.example/revoke", RevocationAssertionAudience::RevocationEndpoint,
        ).unwrap();
    let plan = ClientCredentialsPlan::private_key_jwt(
        TrustedOAuthIssuer::new("https://issuer.example").unwrap(),
        registered, signer.clone(), vec!["read".to_owned()],
    ).unwrap();
    let good = serde_json::json!({
        "revocation_endpoint":"https://issuer.example/revoke",
        "revocation_endpoint_auth_methods_supported":["private_key_jwt"],
        "revocation_endpoint_auth_signing_alg_values_supported":["RS256"]
    });
    let admit = |value: &Value| admit_revocation(
        &plan.discovery.issuers[0], &serde_json::to_vec(value).unwrap(), &plan.authentication,
    );
    assert!(matches!(admit(&good), Ok(RevocationTarget::Endpoint(_))));
    let mut default_basic = good.clone();
    default_basic.as_object_mut().unwrap().remove("revocation_endpoint_auth_methods_supported");
    assert!(matches!(admit(&default_basic), Ok(RevocationTarget::AuthenticationUnavailable)));
    let mut unsupported = good.clone();
    unsupported["revocation_endpoint_auth_signing_alg_values_supported"] = json!(["ES256"]);
    assert!(matches!(admit(&unsupported), Ok(RevocationTarget::AuthenticationUnavailable)));
    let mut absent = good.clone();
    absent.as_object_mut().unwrap().remove("revocation_endpoint_auth_signing_alg_values_supported");
    assert!(admit(&absent).is_err());
    let missing_registration = self::plan(&document(&signer), signer).unwrap();
    assert!(matches!(
        admit_revocation(
            &missing_registration.discovery.issuers[0],
            &serde_json::to_vec(&good).unwrap(),
            &missing_registration.authentication,
        ),
        Ok(RevocationTarget::RegistrationUnavailable)
    ));
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
}

#[test]
fn expired_private_key_registration_refuses_logout_before_closure_or_custody_transfer() {
    use super::super::{
        ClientCredentialsClient, ClientCredentialsRemoteRevocation, ClientInner, ServiceToken,
        TokenState,
    };
    use crate::http_auth::BoundBearerCredential;
    use asupersync::sync::Mutex;
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use fastmcp_core::McpRequestCancellation;
    use std::task::{Context, Poll, Waker};

    for expired in [false, true] {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock);
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0).with_timer_driver(timer).build().unwrap();
        let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let (signer, backend) = signer(0xa1, binding());
        let mut plan = plan(&document(&signer), signer).unwrap();
        if expired {
            let MachineAuthentication::PrivateKeyJwt(selected) = &mut plan.authentication else {
                panic!("private-key registration required");
            };
            Arc::get_mut(selected).unwrap().registration.valid_until = Instant::now();
        }
        let closed = McpRequestCancellation::new();
        let expires_at = Instant::now() + Duration::from_secs(60);
        let bearer = BoundBearerCredential::bind_with_expiry(
            plan.discovery.resource.clone(), "cached-access", expires_at,
        ).unwrap().for_owner(&closed).unwrap();
        let client = ClientCredentialsClient {
            inner: Arc::new(ClientInner {
                resource: plan.discovery.resource,
                token_endpoint: CanonicalHttpUrl::parse("https://issuer.example/token").unwrap(),
                client_id: "registered-service".to_owned(),
                scopes: vec!["read".to_owned()],
                authentication: plan.authentication,
                issuer_roots: vec![],
                resource_tls: None,
                timeout: Duration::from_secs(10),
                maximum_lifetime: Duration::from_secs(60),
                leeway: Duration::ZERO,
                closed,
                pending: AtomicUsize::new(0),
                state: Arc::new(Mutex::new(TokenState {
                    current: Some(ServiceToken {
                        bearer: bearer.clone(),
                        scopes: vec!["read".to_owned()],
                        expires_at,
                        renew_after: expires_at,
                    }),
                    generation: 1,
                    ..TokenState::default()
                })),
            }),
        };
        let mut logout = Box::pin(client.logout(&cx));
        let mut task = Context::from_waker(Waker::noop());
        match (expired, logout.as_mut().poll(&mut task)) {
            (true, Poll::Ready(Err(ClientCredentialsError::InvalidRegistration))) => {
                assert!(!client.inner.closed.is_cancel_requested());
                assert!(!bearer.is_revoked());
                assert!(client.inner.state.try_lock_owned().unwrap().current.is_some());
            }
            (false, Poll::Ready(Ok(report))) => {
                assert_eq!(report.remote(), ClientCredentialsRemoteRevocation::EndpointUnavailable);
                assert!(client.inner.closed.is_cancel_requested());
                assert!(bearer.is_revoked());
                assert!(client.inner.state.try_lock_owned().unwrap().current.is_none());
            }
            _ => panic!("registration preflight must precede every logout effect"),
        }
        drop(logout);
        assert_eq!(backend.0.load(Ordering::SeqCst), 0);
        client.close();
        drop(client);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }
}
