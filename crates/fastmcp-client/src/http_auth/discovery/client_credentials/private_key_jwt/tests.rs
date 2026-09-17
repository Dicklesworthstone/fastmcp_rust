//! Local admission tests. No signer operation or remote registration is proved
//! by these tests; the separate TLS target exercises real RS256 signatures.

use super::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use fastmcp_protocol::jose::{
    AttestedRs256PublicKey, ExternalRs256SignDisposition, ExternalRs256SignerBackend,
    ExternalRs256SigningRequest, RedactedSignerProvenance,
};

struct NeverSign(AtomicUsize);
impl ExternalRs256SignerBackend for NeverSign {
    fn sign<'a>(
        &'a self, _: &'a Cx, _: ExternalRs256SigningRequest,
    ) -> Pin<Box<dyn Future<Output = ExternalRs256SignDisposition> + Send + 'a>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::pending())
    }
}
fn binding() -> Rs256SigningBinding { Rs256SigningBinding::new(1, 2, 3, 4).unwrap() }
fn signer(byte: u8, binding: Rs256SigningBinding) -> (Arc<ExternalRs256Signer>, Arc<NeverSign>) {
    let backend = Arc::new(NeverSign(AtomicUsize::new(0)));
    // Shape-only public modulus for admission tests; never used for signing.
    let public = AttestedRs256PublicKey::admit("registered-key", vec![byte; 256], binding,
        RedactedSignerProvenance::new("admission-only-fixture").unwrap()).unwrap();
    (Arc::new(ExternalRs256Signer::new(backend.clone(), public)), backend)
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
fn registration(value: &Value, audience: ClientAssertionAudience) -> Result<PrivateKeyJwtRegistration, ClientCredentialsError> {
    PrivateKeyJwtRegistration::from_trusted_json(&serde_json::to_vec(value).unwrap(), 9,
        Instant::now() + Duration::from_secs(300), binding(), audience)
}
fn plan(value: &Value, signer: Arc<ExternalRs256Signer>) -> Result<ClientCredentialsPlan, ClientCredentialsError> {
    ClientCredentialsPlan::private_key_jwt(TrustedOAuthIssuer::new("https://issuer.example").unwrap(),
        registration(value, ClientAssertionAudience::Issuer)?, signer, vec!["read".to_owned()])
}
fn metadata() -> Value {
    json!({"issuer":"https://issuer.example", "token_endpoint":"https://issuer.example/token",
        "grant_types_supported":["client_credentials"],
        "token_endpoint_auth_methods_supported":["private_key_jwt", "client_secret_basic"],
        "token_endpoint_auth_signing_alg_values_supported":["RS256"], "scopes_supported":["read"]})
}
fn admit(plan: &ClientCredentialsPlan, document: &Value) -> Result<CanonicalHttpUrl, ClientCredentialsError> {
    super::super::admit_machine_issuer(&plan.discovery, &plan.discovery.issuers[0],
        &serde_json::to_vec(document).unwrap(), &plan.authentication)
}

#[test]
fn registration_and_metadata_admission_never_invoke_the_signer() {
    let (signer, backend) = signer(0xa1, binding());
    let plan = plan(&document(&signer), signer.clone()).unwrap();
    assert_eq!(plan.authentication.method(), "private_key_jwt");
    assert_eq!(admit(&plan, &metadata()).unwrap().as_str(), "https://issuer.example/token");
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
    assert!(!format!("{plan:?}").contains("registered-service"));
}

#[test]
fn registration_declarations_cannot_be_defaulted_or_replaced_by_server_fields() {
    let (signer, _) = signer(0xa1, binding());
    let good = document(&signer);
    for (field, value) in [
        ("grant_types", json!(["authorization_code"])),
        ("grant_types", json!(["client_credentials", "client_credentials"])),
        ("token_endpoint_auth_method", json!("client_secret_basic")),
        ("token_endpoint_auth_signing_alg", json!("HS256")),
        ("client_id", json!("")), ("client_id", json!("https://portable.example/client")),
        ("token_endpoint", json!("http://issuer.example/token")),
        ("token_endpoint", json!("https://user@issuer.example/token")),
        ("token_endpoint", json!("https://issuer.example/token?override=yes")),
        ("resource", json!("http://resource.example/mcp")),
    ] {
        let mut changed = good.clone(); changed[field] = value;
        assert!(registration(&changed, ClientAssertionAudience::Issuer).is_err());
    }
    for field in ["grant_types", "token_endpoint_auth_method", "token_endpoint_auth_signing_alg"] {
        let mut changed = good.clone();
        changed.as_object_mut().unwrap().remove(field);
        changed[format!("{field}_supported")] = good[field].clone();
        assert!(registration(&changed, ClientAssertionAudience::Issuer).is_err());
    }
    let bytes = serde_json::to_string(&good).unwrap().replacen("{", "{\"client_id\":\"other\",", 1);
    assert!(PrivateKeyJwtRegistration::from_trusted_json(bytes.as_bytes(), 9,
        Instant::now() + Duration::from_secs(300), binding(), ClientAssertionAudience::Issuer).is_err());
    assert!(registration(&good, ClientAssertionAudience::Issuer).is_ok());
}

#[test]
fn same_kid_cannot_substitute_different_rsa_material_or_signing_generations() {
    let (first, backend) = signer(0xa1, binding());
    let registered = document(&first);
    assert!(plan(&registered, first.clone()).is_ok());
    let (different_key, _) = signer(0xb1, binding());
    assert_eq!(first.key_id(), different_key.key_id());
    assert!(matches!(plan(&registered, different_key), Err(ClientCredentialsError::InvalidRegistration)));
    let (different_binding, _) = signer(0xa1, Rs256SigningBinding::new(1, 2, 3, 5).unwrap());
    assert!(matches!(plan(&registered, different_binding), Err(ClientCredentialsError::InvalidRegistration)));
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
    assert!(ClientCredentialsPlan::private_key_jwt(TrustedOAuthIssuer::new("https://issuer.example").unwrap(),
        issuer, signer, vec![]).is_err(), "canonical equivalence cannot replace exact issuer identity");
}

#[test]
fn authorization_server_must_admit_rs256_and_the_exact_registered_endpoint() {
    let (signer, backend) = signer(0xa1, binding());
    let plan = plan(&document(&signer), signer.clone()).unwrap();
    let good = metadata();
    for (key, value) in [
        ("token_endpoint_auth_signing_alg_values_supported", json!(["ES256"])),
        ("token_endpoint_auth_signing_alg_values_supported", json!(["RS256", "RS256"])),
        ("token_endpoint_auth_signing_alg_values_supported", Value::Null),
        ("token_endpoint_auth_methods_supported", json!(["client_secret_basic"])),
        ("token_endpoint", json!("https://issuer.example/other")),
        ("token_endpoint", json!("https://ISSUER.example:443/token")),
    ] {
        let mut changed = good.clone(); changed[key] = value;
        assert!(admit(&plan, &changed).is_err());
        assert!(admit(&plan, &good).is_ok());
    }
    let mut absent = good.clone();
    absent.as_object_mut().unwrap().remove("token_endpoint_auth_signing_alg_values_supported");
    assert!(admit(&plan, &absent).is_err());
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
}

#[test]
fn private_or_ambiguous_registration_keys_and_unbounded_validity_are_refused() {
    let (signer, _) = signer(0xa1, binding());
    let good = document(&signer);
    let mut private = good.clone(); private["jwks"]["keys"][0]["d"] = json!("private-canary");
    assert!(registration(&private, ClientAssertionAudience::Issuer).is_err());
    let mut many = good.clone();
    let mut other = many["jwks"]["keys"][0].clone(); other["kid"] = json!("second");
    many["jwks"]["keys"].as_array_mut().unwrap().push(other);
    assert!(registration(&many, ClientAssertionAudience::Issuer).is_err());
    let bytes = serde_json::to_vec(&good).unwrap();
    for (generation, until) in [(0, Instant::now() + Duration::from_secs(60)),
        (1, Instant::now()), (1, Instant::now() + Duration::from_secs(86_402))]
    {
        assert!(PrivateKeyJwtRegistration::from_trusted_json(&bytes, generation, until,
            binding(), ClientAssertionAudience::Issuer).is_err());
    }
    let imported = registration(&good, ClientAssertionAudience::Issuer).unwrap();
    assert_eq!(imported.generation(), 9);
    assert!(imported.valid_until() > Instant::now());
    assert!(!format!("{imported:?}").contains("registered-service"));
}

#[test]
fn selecting_basic_does_not_silently_switch_methods_when_both_are_advertised() {
    let basic = ClientCredentialsPlan::new(CanonicalHttpUrl::parse("https://resource.example/mcp").unwrap(),
        TrustedOAuthIssuer::new("https://issuer.example").unwrap(), "basic-client", "basic-secret",
        vec!["read".to_owned()]).unwrap();
    assert_eq!(basic.authentication.method(), "client_secret_basic");
    assert!(admit(&basic, &metadata()).is_ok());
    let mut jwt_only = metadata(); jwt_only["token_endpoint_auth_methods_supported"] = json!(["private_key_jwt"]);
    assert!(matches!(admit(&basic, &jwt_only), Err(ClientCredentialsError::UnsupportedAuthentication)));
    assert_eq!(basic.authentication.method(), "client_secret_basic");
}
