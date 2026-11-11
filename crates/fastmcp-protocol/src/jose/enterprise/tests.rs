//! Real-signature enterprise verification regression fixtures.
//!
//! Every compact value below was signed with the public example RSA key from
//! RFC 7515 Appendix A.2. Fixture preparation first reproduced that appendix's
//! known-answer signature. Only its public JWK and signed assertions are kept;
//! these tests require no signer, private key, network, clock or random source.

use std::sync::OnceLock;

use serde_json::json;

use super::*;

const ISSUER: &str = "https://idp.example";
const GENERATION: u64 = 7;
const ISSUED: u64 = 2_000_000_000;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn now() -> SystemTime {
    at(ISSUED + 120)
}

fn oidc_keys() -> OidcVerificationKeys {
    OidcVerificationKeys::from_trusted_jwks(ISSUER, GENERATION, PUBLIC_JWKS.as_bytes())
        .expect("admitted OIDC fixture key")
}

fn id_jag_keys() -> IdJagVerificationKeys {
    IdJagVerificationKeys::from_trusted_jwks(ISSUER, GENERATION, PUBLIC_JWKS.as_bytes())
        .expect("separately admitted ID-JAG fixture key")
}

fn oidc_expected() -> OidcIdTokenExpectations<'static> {
    OidcIdTokenExpectations {
        client_id: "native-idp",
        nonce: "oidc-flow-nonce",
        access_token: Some("temporary-access"),
        tenant: TenantExpectation::SingleTenant,
        max_authentication_age: None,
        time: JwtTimePolicy::oidc_default(),
    }
}

fn id_jag_expected() -> IdJagExpectations<'static> {
    IdJagExpectations {
        audience: "https://as.example",
        client_id: "native-resource",
        resource: "https://mcp.example/mcp",
        require_resource: true,
        idp_tenant: TenantExpectation::SingleTenant,
        resource_tenant: ResourceTenantExpectation::SingleTenant,
        time: JwtTimePolicy::id_jag_default(),
    }
}

fn signed(name: &str) -> &'static str {
    static FIXTURES: OnceLock<Value> = OnceLock::new();
    FIXTURES
        .get_or_init(|| serde_json::from_str(SIGNED_FIXTURES).expect("fixture JSON"))[name]
        .as_str()
        .expect("named signed fixture")
}

fn oidc_failure(name: &str, error: EnterpriseVerificationError) {
    assert_eq!(
        verify_oidc_id_token(signed(name), &oidc_keys(), &oidc_expected(), now()).unwrap_err(),
        error,
        "{name}",
    );
}

fn id_jag_failure(name: &str, error: EnterpriseVerificationError) {
    assert_eq!(
        verify_id_jag(signed(name), &id_jag_keys(), &id_jag_expected(), now()).unwrap_err(),
        error,
        "{name}",
    );
}

#[test]
fn signed_oidc_and_id_jag_return_only_their_bound_identity_facts() {
    let oidc_keys = oidc_keys();
    let jag_keys = id_jag_keys();
    let oidc =
        verify_oidc_id_token(signed("oidc_base"), &oidc_keys, &oidc_expected(), now()).unwrap();
    let jag =
        verify_id_jag(signed("id_jag_base"), &jag_keys, &id_jag_expected(), now()).unwrap();

    assert_eq!(oidc.issuer(), ISSUER);
    assert_eq!(oidc.client_id(), "native-idp");
    assert_eq!(oidc.subject().as_str(), "client-facing");
    assert!(oidc.tenant().is_none());
    assert_eq!(oidc.issued_at(), at(ISSUED));
    assert_eq!(oidc.expires_at(), at(ISSUED + 240));
    assert_eq!(oidc.authentication_time(), Some(at(ISSUED)));
    assert_eq!(oidc.key_id(), "enterprise-rfc7515");
    assert_eq!(oidc.generation(), GENERATION);
    assert_eq!(
        oidc.compact_digest(),
        sha256_bounded(signed("oidc_base").as_bytes(), MAX_COMPACT_JWS_BYTES).unwrap(),
    );
    assert_eq!(jag.issuer(), ISSUER);
    assert_eq!(jag.audience(), "https://as.example");
    assert_eq!(jag.client_id(), "native-resource");
    assert_eq!(jag.subject().as_str(), "resource-facing");
    assert!(jag.idp_tenant().is_none());
    assert!(jag.resource_tenant().is_none());
    assert!(jag.audience_subject().is_none());
    assert_eq!(jag.resource(), Some("https://mcp.example/mcp"));
    assert_eq!(jag.scope(), Some("read"));
    assert_eq!(jag.jti(), "id-jag-flow-1");
    assert_eq!(jag.issued_at(), at(ISSUED));
    assert_eq!(jag.expires_at(), at(ISSUED + 240));
    assert_eq!(jag.key_id(), "enterprise-rfc7515");
    assert_eq!(jag.generation(), GENERATION);
    assert_eq!(
        jag.compact_digest(),
        sha256_bounded(signed("id_jag_base").as_bytes(), MAX_COMPACT_JWS_BYTES).unwrap(),
    );
    assert_ne!(oidc.compact_digest(), jag.compact_digest());
    assert_eq!(oidc_keys.document_digest(), jag_keys.document_digest());

    let diagnostic = format!("{oidc:?} {jag:?} {:?} {:?}", oidc.subject(), jag.subject());
    for secret in [
        signed("oidc_base"),
        signed("id_jag_base"),
        "client-facing",
        "resource-facing",
        "temporary-access",
        "oidc-flow-nonce",
        "id-jag-flow-1",
    ] {
        assert!(!diagnostic.contains(secret));
    }
}

#[test]
fn signed_singleton_audiences_and_media_type_case_variants_are_accepted() {
    let oidc = verify_oidc_id_token(
        signed("oidc_singleton"),
        &oidc_keys(),
        &oidc_expected(),
        now(),
    )
    .unwrap();
    let jag = verify_id_jag(
        signed("id_jag_singleton"),
        &id_jag_keys(),
        &id_jag_expected(),
        now(),
    )
    .unwrap();
    assert_eq!(oidc.client_id(), "native-idp");
    assert_eq!(jag.resource(), Some("https://mcp.example/mcp"));
    oidc_failure("oidc_multi_audience", EnterpriseVerificationError::BindingMismatch);
    oidc_failure("oidc_null_azp", EnterpriseVerificationError::InvalidClaims);
    id_jag_failure("id_jag_multi_audience", EnterpriseVerificationError::BindingMismatch);
    id_jag_failure("id_jag_multi_resource", EnterpriseVerificationError::BindingMismatch);
}

#[test]
fn valid_signatures_cannot_change_the_trusted_flow_or_resource_bindings() {
    let keys = oidc_keys();
    let mut expected = oidc_expected();
    expected.client_id = "other-client";
    assert_eq!(
        verify_oidc_id_token(signed("oidc_base"), &keys, &expected, now()).unwrap_err(),
        EnterpriseVerificationError::BindingMismatch,
    );
    let mut expected = oidc_expected();
    expected.nonce = "other-flow-nonce";
    assert_eq!(
        verify_oidc_id_token(signed("oidc_base"), &keys, &expected, now()).unwrap_err(),
        EnterpriseVerificationError::InvalidNonce,
    );
    oidc_failure("oidc_foreign_issuer", EnterpriseVerificationError::BindingMismatch);

    let keys = id_jag_keys();
    for changed in ["audience", "client", "resource"] {
        let mut expected = id_jag_expected();
        match changed {
            "audience" => expected.audience = "https://other.example",
            "client" => expected.client_id = "other-client",
            "resource" => expected.resource = "https://mcp.example/other",
            _ => unreachable!(),
        }
        assert_eq!(
            verify_id_jag(signed("id_jag_base"), &keys, &expected, now()).unwrap_err(),
            EnterpriseVerificationError::BindingMismatch,
            "{changed}",
        );
    }
}

#[test]
fn signed_at_hash_requires_the_exact_access_token_and_canonical_128_bits() {
    let keys = oidc_keys();
    for token in [None, Some("different-access-token")] {
        let mut expected = oidc_expected();
        expected.access_token = token;
        assert_eq!(
            verify_oidc_id_token(signed("oidc_base"), &keys, &expected, now()).unwrap_err(),
            EnterpriseVerificationError::InvalidAccessTokenHash,
        );
    }
    oidc_failure("oidc_hash_padding", EnterpriseVerificationError::InvalidAccessTokenHash);
    oidc_failure("oidc_hash_trailing_bits", EnterpriseVerificationError::InvalidAccessTokenHash);

    let mut expected = oidc_expected();
    expected.access_token = None;
    assert!(verify_oidc_id_token(signed("oidc_without_hash"), &keys, &expected, now()).is_ok());
    expected.access_token = Some("credential with spaces");
    assert_eq!(
        verify_oidc_id_token(signed("oidc_without_hash"), &keys, &expected, now()).unwrap_err(),
        EnterpriseVerificationError::InvalidConfiguration,
    );
}

#[test]
fn signed_tenants_use_separate_exact_namespaces_without_normalization() {
    let mut expected = oidc_expected();
    expected.tenant = TenantExpectation::Exact("e\u{301}");
    let verified =
        verify_oidc_id_token(signed("oidc_tenant"), &oidc_keys(), &expected, now()).unwrap();
    assert_eq!(verified.tenant().unwrap().as_str(), "e\u{301}");
    assert!(!format!("{:?}", verified.tenant()).contains("e\u{301}"));
    expected.tenant = TenantExpectation::Exact("\u{e9}");
    assert_eq!(
        verify_oidc_id_token(signed("oidc_tenant"), &oidc_keys(), &expected, now()).unwrap_err(),
        EnterpriseVerificationError::BindingMismatch,
    );
    oidc_failure("oidc_tenant", EnterpriseVerificationError::BindingMismatch);
    oidc_failure("oidc_null_tenant", EnterpriseVerificationError::BindingMismatch);

    let mut expected = id_jag_expected();
    expected.idp_tenant = TenantExpectation::Exact("idp-tenant");
    expected.resource_tenant = ResourceTenantExpectation::Exact("resource-tenant");
    let verified =
        verify_id_jag(signed("id_jag_tenants"), &id_jag_keys(), &expected, now()).unwrap();
    assert_eq!(verified.idp_tenant().unwrap().as_str(), "idp-tenant");
    assert_eq!(verified.resource_tenant().unwrap().as_str(), "resource-tenant");
    assert_eq!(verified.audience_subject().unwrap().as_str(), "opaque/account");
    assert_eq!(
        verify_id_jag(
            signed("id_jag_tenant_missing_subject"),
            &id_jag_keys(),
            &expected,
            now(),
        )
        .unwrap_err(),
        EnterpriseVerificationError::InvalidClaims,
    );
    expected.resource_tenant = ResourceTenantExpectation::Exact("idp-tenant");
    assert_eq!(
        verify_id_jag(signed("id_jag_tenants"), &id_jag_keys(), &expected, now()).unwrap_err(),
        EnterpriseVerificationError::BindingMismatch,
    );
    id_jag_failure("id_jag_tenants", EnterpriseVerificationError::BindingMismatch);
}

#[test]
fn signed_optional_resource_and_scope_remain_explicit_caller_policy() {
    id_jag_failure("id_jag_missing_resource", EnterpriseVerificationError::BindingMismatch);
    let mut expected = id_jag_expected();
    expected.require_resource = false;
    let without_resource = verify_id_jag(
        signed("id_jag_missing_resource"),
        &id_jag_keys(),
        &expected,
        now(),
    )
    .unwrap();
    assert!(without_resource.resource().is_none());
    assert_eq!(without_resource.scope(), Some("read"));
    let without_scope = verify_id_jag(
        signed("id_jag_missing_scope"),
        &id_jag_keys(),
        &id_jag_expected(),
        now(),
    )
    .unwrap();
    assert!(without_scope.scope().is_none());
    id_jag_failure("id_jag_duplicate_scope", EnterpriseVerificationError::InvalidClaims);
    id_jag_failure("id_jag_empty_jti", EnterpriseVerificationError::InvalidClaims);
}

#[test]
fn signed_claims_and_headers_cannot_cross_the_closed_enterprise_profiles() {
    for name in ["oidc_forbidden_cnf", "oidc_forbidden_disclosure", "oidc_subject_nonascii"] {
        oidc_failure(name, EnterpriseVerificationError::InvalidClaims);
    }
    for name in [
        "oidc_duplicate_claim",
        "oidc_nested_type",
        "oidc_remote_key",
        "oidc_unknown_key",
    ] {
        oidc_failure(name, EnterpriseVerificationError::InvalidToken);
    }
    for name in ["id_jag_forbidden_cnf", "id_jag_forbidden_actor"] {
        id_jag_failure(name, EnterpriseVerificationError::InvalidClaims);
    }
    for name in ["id_jag_missing_type", "id_jag_oidc_type"] {
        id_jag_failure(name, EnterpriseVerificationError::InvalidToken);
    }
    assert_eq!(
        verify_oidc_id_token(signed("id_jag_base"), &oidc_keys(), &oidc_expected(), now())
            .unwrap_err(),
        EnterpriseVerificationError::InvalidToken,
    );
    assert_eq!(
        verify_id_jag(signed("oidc_base"), &id_jag_keys(), &id_jag_expected(), now()).unwrap_err(),
        EnterpriseVerificationError::InvalidToken,
    );
    let mut corrupted = signed("oidc_base").to_owned();
    let signature = corrupted.rfind('.').unwrap() + 1;
    let changed = if &corrupted[signature..=signature] == "A" { "B" } else { "A" };
    corrupted.replace_range(signature..=signature, changed);
    assert_eq!(
        verify_oidc_id_token(&corrupted, &oidc_keys(), &oidc_expected(), now()).unwrap_err(),
        EnterpriseVerificationError::InvalidToken,
    );
}

#[test]
fn signed_numeric_dates_retain_nanoseconds_and_equivalent_exponents() {
    let fraction = verify_oidc_id_token(
        signed("oidc_fraction_time"),
        &oidc_keys(),
        &oidc_expected(),
        now(),
    )
    .unwrap();
    assert_eq!(fraction.issued_at(), at(ISSUED) + Duration::from_nanos(1));
    assert_eq!(fraction.expires_at(), at(ISSUED + 240) + Duration::from_nanos(1));
    let exponent = verify_oidc_id_token(
        signed("oidc_exponent_time"),
        &oidc_keys(),
        &oidc_expected(),
        now(),
    )
    .unwrap();
    assert_eq!(exponent.issued_at(), at(ISSUED));
    assert_eq!(exponent.expires_at(), at(ISSUED + 240));
    oidc_failure("oidc_bad_precision", EnterpriseVerificationError::InvalidTime);
    oidc_failure("oidc_negative_zero", EnterpriseVerificationError::InvalidTime);
}

#[test]
fn signed_times_enforce_exact_expiration_future_and_authentication_boundaries() {
    let keys = oidc_keys();
    let expected = oidc_expected();
    assert!(verify_oidc_id_token(
        signed("oidc_base"),
        &keys,
        &expected,
        at(ISSUED - 60),
    )
    .is_ok());
    assert_eq!(
        verify_oidc_id_token(signed("oidc_base"), &keys, &expected, at(ISSUED - 61))
            .unwrap_err(),
        EnterpriseVerificationError::NotYetValid,
    );
    assert!(verify_oidc_id_token(
        signed("oidc_base"),
        &keys,
        &expected,
        at(ISSUED + 300) - Duration::from_nanos(1),
    )
    .is_ok());
    assert_eq!(
        verify_oidc_id_token(signed("oidc_base"), &keys, &expected, at(ISSUED + 300))
            .unwrap_err(),
        EnterpriseVerificationError::Expired,
    );
    assert!(verify_oidc_id_token(
        signed("oidc_not_before"),
        &keys,
        &expected,
        at(ISSUED + 60),
    )
    .is_ok());
    assert_eq!(
        verify_oidc_id_token(signed("oidc_not_before"), &keys, &expected, at(ISSUED + 59))
            .unwrap_err(),
        EnterpriseVerificationError::NotYetValid,
    );
    let mut expected = oidc_expected();
    expected.time = JwtTimePolicy::new(Duration::from_secs(239), Duration::from_secs(60)).unwrap();
    assert_eq!(
        verify_oidc_id_token(signed("oidc_base"), &keys, &expected, now()).unwrap_err(),
        EnterpriseVerificationError::InvalidTime,
    );
    let mut expected = oidc_expected();
    expected.max_authentication_age = Some(Duration::from_secs(60));
    assert!(verify_oidc_id_token(signed("oidc_base"), &keys, &expected, now()).is_ok());
    assert_eq!(
        verify_oidc_id_token(
            signed("oidc_base"),
            &keys,
            &expected,
            now() + Duration::from_nanos(1),
        )
        .unwrap_err(),
        EnterpriseVerificationError::Expired,
    );
    assert_eq!(
        verify_oidc_id_token(signed("oidc_without_auth_time"), &keys, &expected, now())
            .unwrap_err(),
        EnterpriseVerificationError::InvalidClaims,
    );
    oidc_failure("oidc_future_auth_time", EnterpriseVerificationError::InvalidTime);

    let mut expected = id_jag_expected();
    expected.time = JwtTimePolicy::oidc_default();
    assert_eq!(
        verify_id_jag(signed("id_jag_base"), &id_jag_keys(), &expected, now()).unwrap_err(),
        EnterpriseVerificationError::InvalidConfiguration,
    );
    assert_eq!(
        verify_id_jag(
            signed("id_jag_base"),
            &id_jag_keys(),
            &id_jag_expected(),
            at(ISSUED + 300),
        )
        .unwrap_err(),
        EnterpriseVerificationError::Expired,
    );
}

#[test]
fn numeric_dates_have_closed_precision_range_and_sign() {
    for (lexeme, expected) in [
        ("0", Duration::ZERO),
        ("0e-9999", Duration::ZERO),
        ("1", Duration::from_secs(1)),
        ("1.0000000000", Duration::from_secs(1)),
        ("10e-1", Duration::from_secs(1)),
        ("1e-9", Duration::from_nanos(1)),
        ("10e-10", Duration::from_nanos(1)),
        ("2000000000.000000001", Duration::new(ISSUED, 1)),
        ("253402300799.999999999", Duration::new(253_402_300_799, 999_999_999)),
    ] {
        let value = serde_json::from_str(lexeme).unwrap();
        assert_eq!(numeric_date(&value), Ok(expected), "{lexeme}");
    }
    for lexeme in [
        "-0",
        "-0.0",
        "-1",
        "1e-10",
        "1.0000000001",
        "253402300800",
        "1e9999",
        "0e10000",
        "100000000000000000000000000000000",
        r#""2000000000""#,
        "null",
    ] {
        let value = serde_json::from_str(lexeme).unwrap();
        assert_eq!(
            numeric_date(&value),
            Err(EnterpriseVerificationError::InvalidTime),
            "{lexeme}",
        );
    }
}

#[test]
fn scope_grammar_limits_are_exact_and_duplicates_do_not_grant_more_scope() {
    fn parse(scope: Value) -> Result<Option<String>, EnterpriseVerificationError> {
        let claims = json!({"scope": scope});
        scope_claim(claims.as_object().unwrap())
    }
    let maximum_count = (0..MAX_ENTERPRISE_SCOPE_COUNT)
        .map(|index| format!("scope-{index}"))
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(parse(json!(maximum_count)), Ok(Some(maximum_count.clone())));
    assert!(parse(json!(format!("{maximum_count} another"))).is_err());
    let maximum_token = "x".repeat(MAX_ENTERPRISE_SCOPE_BYTES);
    assert_eq!(parse(json!(maximum_token)), Ok(Some(maximum_token.clone())));
    assert!(parse(json!("x".repeat(MAX_ENTERPRISE_SCOPE_BYTES + 1))).is_err());

    let mut maximum_set = (0..16)
        .map(|index| format!("{index:02}{}", "a".repeat(253)))
        .collect::<Vec<_>>();
    maximum_set[0].push('a');
    let maximum_set = maximum_set.join(" ");
    assert_eq!(maximum_set.len(), MAX_ENTERPRISE_SCOPE_SET_BYTES);
    assert!(parse(json!(maximum_set)).is_ok());
    assert!(parse(json!(format!("{maximum_set}a"))).is_err());
    for scope in [
        "",
        "read read",
        " read",
        "read ",
        "read  write",
        "read\twrite",
        "read\u{a0}write",
        "read\"write",
        "read\\write",
    ] {
        assert_eq!(parse(json!(scope)), Err(EnterpriseVerificationError::InvalidClaims));
    }
    for scope in [Value::Null, json!(["read"]), json!(3)] {
        assert_eq!(parse(scope), Err(EnterpriseVerificationError::InvalidClaims));
    }
}

#[test]
fn trusted_imports_reject_repaired_urls_invalid_generations_and_wrong_key_use() {
    for issuer in [
        "http://idp.example",
        "https://idp.example?query",
        "https://idp.example#fragment",
        "https://user@idp.example",
        r"https:\\idp.example",
        "https:///idp.example",
        " https://idp.example",
    ] {
        assert_eq!(
            OidcVerificationKeys::from_trusted_jwks(issuer, GENERATION, PUBLIC_JWKS.as_bytes())
                .err(),
            Some(EnterpriseVerificationError::InvalidConfiguration),
            "{issuer}",
        );
        assert_eq!(
            IdJagVerificationKeys::from_trusted_jwks(issuer, GENERATION, PUBLIC_JWKS.as_bytes())
                .err(),
            Some(EnterpriseVerificationError::InvalidConfiguration),
            "{issuer}",
        );
    }
    assert_eq!(
        OidcVerificationKeys::from_trusted_jwks(ISSUER, 0, PUBLIC_JWKS.as_bytes()).err(),
        Some(EnterpriseVerificationError::InvalidConfiguration),
    );
    let mut wrong_use: Value = serde_json::from_str(PUBLIC_JWKS).unwrap();
    wrong_use["keys"][0]["key_ops"] = json!(["sign"]);
    let bytes = serde_json::to_vec(&wrong_use).unwrap();
    assert_eq!(
        IdJagVerificationKeys::from_trusted_jwks(ISSUER, GENERATION, &bytes).err(),
        Some(EnterpriseVerificationError::InvalidKeys),
    );
    let oidc = oidc_keys();
    let jag = id_jag_keys();
    assert_eq!(oidc.issuer(), ISSUER);
    assert_eq!(jag.issuer(), ISSUER);
    assert_eq!(oidc.generation(), GENERATION);
    assert_eq!(jag.generation(), GENERATION);

    for (lifetime, skew) in [
        (Duration::ZERO, Duration::ZERO),
        (MAX_ENTERPRISE_TOKEN_LIFETIME + Duration::from_secs(1), Duration::ZERO),
        (Duration::from_secs(1), MAX_ENTERPRISE_CLOCK_SKEW + Duration::from_secs(1)),
    ] {
        assert_eq!(
            JwtTimePolicy::new(lifetime, skew),
            Err(EnterpriseVerificationError::InvalidConfiguration),
        );
    }
    assert_eq!(JwtTimePolicy::default(), JwtTimePolicy::oidc_default());
    assert_eq!(JwtTimePolicy::id_jag_default().max_lifetime(), Duration::from_secs(300));
    assert_eq!(JwtTimePolicy::oidc_default().clock_skew(), Duration::from_secs(60));
}

#[test]
fn verification_errors_never_echo_compact_or_identity_input() {
    for error in [
        EnterpriseVerificationError::InvalidConfiguration,
        EnterpriseVerificationError::InvalidKeys,
        EnterpriseVerificationError::InvalidToken,
        EnterpriseVerificationError::InvalidClaims,
        EnterpriseVerificationError::BindingMismatch,
        EnterpriseVerificationError::InvalidTime,
        EnterpriseVerificationError::Expired,
        EnterpriseVerificationError::NotYetValid,
        EnterpriseVerificationError::InvalidNonce,
        EnterpriseVerificationError::InvalidAccessTokenHash,
    ] {
        let message = format!("{error} {error:?}");
        for sensitive in [
            ISSUER,
            "client-facing",
            "resource-facing",
            "oidc-flow-nonce",
            "temporary-access",
            signed("oidc_base"),
            signed("id_jag_base"),
        ] {
            assert!(!message.contains(sensitive));
        }
    }
}

const PUBLIC_JWKS: &str = r#"{"keys":[{"kty":"RSA","kid":"enterprise-rfc7515","alg":"RS256","use":"sig","n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ","e":"AQAB"}]}"#;

const SIGNED_FIXTURES: &str = r#"
{
  "oidc_base": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1BIn0.aiXjCgHfEAfh_5efvRZ8G5cdfJiKRmUemPNk6xZzEb1twmX_8uRiiQFpE67CXrOfDZrlR5QFHG4Mx8w4bdiZwogSAJbfJ_BrZ9yUeH5J7ZZmjKEtuRFoOKUUg6uiPUEGzkoZFVVDjAjBA_sCSTKO-oNEZczV2iQTIfGA_DaBlpFxZMQ1dLM2jExuTmrlBUqg0rKvVvcrDFUN3B9gHAgi8DlJPWATiiPSmKRiEqw_iQ7qG8a6dNVPVQNlpEG1Bhn-R2UUX6hOaXiKZ8MvyXE8A567Fm0pqyDF1SLKMRp9a5nyprxdpy7sb96FhhBccZ6O78JcLjyOBrMPZbFjgBMtew",
  "id_jag_base": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsInR5cCI6Im9hdXRoLWlkLWphZytqd3QifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoicmVzb3VyY2UtZmFjaW5nIiwiYXVkIjoiaHR0cHM6Ly9hcy5leGFtcGxlIiwiY2xpZW50X2lkIjoibmF0aXZlLXJlc291cmNlIiwianRpIjoiaWQtamFnLWZsb3ctMSIsImlhdCI6MjAwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMjQwLCJyZXNvdXJjZSI6Imh0dHBzOi8vbWNwLmV4YW1wbGUvbWNwIiwic2NvcGUiOiJyZWFkIn0.RB4rbITee-1mWu0P5urfsvlRWZqjEjr5EsRlHZd6OrZGb0oBE23dqq2wV4gg-vFqybo94yGVM6QZAyXcaLuFPlGHAY8ctSab0hPlz6wt1rdLuxNlSF34T7CztMV841Aint_uKOG3ELZD4XkAW7z6ojjdjvVhddbn5Uk7IS4AkXF8ucDMnhHOOpIYYyy6s8vMDjHMeBczL0pNuVxDrG8CrCXzkhluXeXFJBaKPMq3NBY2Jj0PVg2eNqJjua7aIr9h9z0jC_vOA7PVpWv5k3_dP38Y8-CJi0zo3CxVSSURpFMO4dnlqToKKw_lP95cPHH52ndn43sj2-dGmx-3Lucycg",
  "oidc_singleton": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsInR5cCI6IkFQUExJQ0FUSU9OL0pXVCJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6WyJuYXRpdmUtaWRwIl0sImlhdCI6MjAwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMjQwLCJhdXRoX3RpbWUiOjIwMDAwMDAwMDAsIm5vbmNlIjoib2lkYy1mbG93LW5vbmNlIiwiYXRfaGFzaCI6InFJQkNfWnRUWVh1MkVsdjk5RDlDLUEiLCJhenAiOiJuYXRpdmUtaWRwIn0.kEHhnlqZiglrUr8eDwVIFhxUhO5DtzuyWISVrIB6bcLmdNSscAE53FBjM1DrDNWKQLvY2hn55Kr6gaMLn0RDjrO1uIJwmbqVDn3RHGugJCAwsdwgRDl4nYElHMxo_E5V6-cEa2nRkU7UG34UUTGSiTD_OLtW-fu5ldRrO_Flaoe29XPPKJWGf7acTKno4UPgQQrZ6PqdURYvBpFMLuj1okZQwUtrcafN2hG1y6ascpCZ18NuRJn6x23rKo9cAPdvMzXYWi5Rqi7mmKqRuCoC2l_2Goic14erg99n94OyOJJuQy1OfPpojxYIfAs6I_kxVDPFFIW0cOikzvl2m0dD-A",
  "oidc_multi_audience": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6WyJuYXRpdmUtaWRwIiwib3RoZXItY2xpZW50Il0sImlhdCI6MjAwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMjQwLCJhdXRoX3RpbWUiOjIwMDAwMDAwMDAsIm5vbmNlIjoib2lkYy1mbG93LW5vbmNlIiwiYXRfaGFzaCI6InFJQkNfWnRUWVh1MkVsdjk5RDlDLUEifQ.S9e0bUWTN-btKoOCKqwBv2gWkxM9KLp2EqF3MzxGc3KenarDcRke4qu7SWsnKxXcz8mAe742WOtw-Fe7WVGwEUX_zXmCew7j_CBV8Kru4rryzhdBABjzIkxFTnrxDtu2RupkoiZKddofLtXRJLoozZWVLgecRE17o7-WAmH7gBsvFxMWO3Pjl-HPtx35PfgD7mRdIjzSqBpQNy_3javbiadNvha9DCeuiWcAxK-je8PLv6ss14jN7KARRIpseOYJ-ANR4X0zLrByYP47NPtvCTCCqqc2SXQ3m8RNR2_xsSIyqjXhU6WxbcALORYEOfhlEp4OGWbexk_jGhimHnf7Vw",
  "oidc_null_azp": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1BIiwiYXpwIjpudWxsfQ.aDh-xGQHqF4iQ-b0_CgOsv0vt9PNAhjrJ-QNrPWRAbM5kTL-RvJQfY-8D3l9LdluS5OLfl54he4bKPJcrDi2zN72mQnoxb4dYZ9Z8NZMz9HWGPcK3WPannwPgAbdzSw8z-iDxHud320YTtdSSJ5LXoKjEjZk_Cofbk_Ysi0wYedBG9bAHgGk7SVjiBdZljoM8iM3v2TRi3-KA74_AmhMcO1zvcpxqmfpA6gpYJMU7dfFygyH29IN4PBg92--ldQDZUtfEnsEI5ZIzXg6uDJRfdVVSnpIbeANzHifjSJytbEEK6zs_a60ajxK59MNCM5QzeR1o9Y6DHH8HRRjIpMG4w",
  "oidc_tenant": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1BIiwidGVuYW50IjoiZcyBIn0.d4h93jRBgHYbAIAwZgc15WLEJ84H1Pl2jbfnKRsbx1-fR8PzdZaxqvVuX2dnpS5bxMJdlOW_x6HMLmp0gSu8NCLqCJ40d5Dp-GPMiCtp09DVPgNCCVi36P4-wIUhfINsLb4TyVHUE2WHhE9V5umiJ-vQEXUkm0U4nIki8thBsb1wyviUxMWl-9vDgl8ZhTZSSmSwJXD0EX21bnwbc011FsbFNaXhbLq9MLkVsylbSYYMciueOXpyY35OjtfA5YvLDtng4uh93xAr37L93JUZnZPUz3S2G6l5RwvFNFIeeBGE9hAYbkRxaclLrD_VZFTaXVhGxzYBt5yPemef65QyGw",
  "oidc_null_tenant": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1BIiwidGVuYW50IjpudWxsfQ.mQJU8pKAaEIh-4h-KpbCiOCTdQr2OL9V1e77_ZUfkqhN9Wi_v8rUN_0vfCvfN8MFSitrSyycHHLPtLB0Ida1nbOhvj-sN842kwV7L1EEGUfbATmZFbXCEika1gPPsVAwbdIAf6ZKfuDQ5Qb1NNzibsuIAiXeCDD6io8tSaM7YDPme-W4d7P1ddFd54w7KY_0MdR8BLL-XVCd9NaQpdKdFykx3pZgRb5yyZY3BAuD1ToT0c1BxfLmYBPhSPdgkQmN2_687d0QZQKOOmh0dBwlsQ2tMTepU7WFBF7tSZYAuEJsnGapSvykFaHnlxDtuvpdw7ZTSp4CmwtD8Y2HLBMUBQ",
  "oidc_forbidden_cnf": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1BIiwiY25mIjp7ImprdCI6InVudXNlZCJ9fQ.XMXFRcLFKHEhH_tlWXRWAiXRjRa2Qy2WcLkkfqxXZaMjfn-EX_tWqKS2-_yc1tdOMbD9GmgK2OrptYl6pQdrMcL_weW9CGNf0xDTQMi-iFgRXAM-zgmAQG8ks04kpOxAbETfEN1_E3AHKeSuHjXFHmzAoslWtuzRA806mY_sAfRQzsf2BTKzt1y7_1KhacX4-qvX_MKBcWUnLcEABTWbz7JeBULTggHJQqm4PLb1X_nbB-ce6IYsvwhx6T5IkHcDt9VBCLpB_5ULi4UnKSuV5kYX4qE0EdW2QDqe1v8GrsqW2sk67R5oyEJu4qGwPwTflSlz9LUZTmKVoSSLISDhrw",
  "oidc_forbidden_disclosure": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1BIiwiYXVkX3N1YiI6ImFjY291bnQtYWxpYXMifQ.CGky58sN0nYmS-EFm8PJ0TLrc69twWqDO7bDLNpFFyuSL1uboMeCI5BJkpeWRDqNE5XSJA3I1c8p_H9N5mw_DHKfUhTHTYMZGaqH_Tn8kj38QN9BGwzRDfPY-C8-4ukLl3n-_fS4vJXHuzo8PvX6wDbhLOTMMSS_bbWmKDMJisvRkalJZapZynpRAZqwPD3SH--NT6hyoJYqpC52fDxb3odcDY0qnywK4AvnQ3QlrtVAWwVTwDIGAWqkT276gS2umXKGkcdXUizmwso9hi6irdtxbngxoHrEnj8Ln7iacQV5B1PqUVqogLxKncE8qSI2hKpskYyj2f6bK_OSu7ooCw",
  "oidc_hash_padding": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1BPSJ9.jgwQgm5FcxD_shiBDAZwGvr-XR6UJyygDUcRqy-nVw426xVfUqroRBacsx8NEo-Sh96YYXZnDd8YJ7w-0mJejPiBmKLNtb2DvbIEjnSQWoo2urGqRVymvnzfUxrgePMDqI1mvr0r6DWEQR3EqFsZgY6LrfR3sE2MoedS23WdJs6VQNVtvY2tiCJfqxreXdYrnxxhQ16SpxuiG-EekHuMi5Kwntfk9WEuAAhjLkWD4twBRNtWuN_-bKqBW4-rvcAN0QgqmEIKnPGv0Wl1pXA6qjaOL2hWmnjXN9fRBQM2DmzoQw6Z-FhFSiwreEV4hrswsGRSa1GWViDkjoW4WB_7MQ",
  "oidc_hash_trailing_bits": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1CIn0.Nr2cLjxgJlLyL8zqRj4nWcabAHRX4Blv6m_WpUiXspVg6tknYGscYLMbXafI940wkBWhXIxjXBNSfKihKD_GWKrKD_Os_7UgSuQJv-BW26rXmrncB2X7KJdfOD179iwwS8i-Pc-IP51xF2soK7bt3Av-BlaRJB8jg2ypHNAw0nbjhsA7-3gAwP3DxHr2aJSRxMP18zgWBha_GmYD-quZzLTnwxvjLioUV_9n08krvcry6qvzktciQqiX8YjmnoRToVxh11Q3VXC0d6jwk0_0kIwrphRkS9d7ouQfxGeVNpnJbPx-XjG8HqdJJen7VOsTM3MQEyetiTScZjxYvn_QIQ",
  "oidc_without_hash": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSJ9.h0e1ae9PF8rP17HNeoYaRNPLbAJAW3i4mR26PgopLyxbO_IDUuzGMo1FqdnzHSxBp8KifLuFjWeH-TxUqwYY7lIpzJONhM1H-uOZ0lXMJQ2sz0Ay-AAaF5l3pF7-bcwEnp2fYQjt4DfQLeLs3XrSC3fNZMZyJ5r4AvKQ6tkJPVTgBbU8VwyccgdqniHC44bi7Tdwh2Y1VVRJWcV0o6Iu_THqBasQLFxbEqwkKrFZUvWsekkOqoNamFKvAhl-cu1rZoqaGfO1-sY4A4UhGkcmVDqYXMPKfN0Dbe4OxnAlEX-eAUCNIlFPNgJEsGhVSQPMd8iIsSqZ1d7hd11_NkOMLg",
  "oidc_without_auth_time": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwibm9uY2UiOiJvaWRjLWZsb3ctbm9uY2UiLCJhdF9oYXNoIjoicUlCQ19adFRZWHUyRWx2OTlEOUMtQSJ9.cXGqK-PwuFL73q6VIlEfr0Wqh-lXOt_ql05Ujch75PiD6_z3MyYiyGaUB6kvwKjlpxMFXiE3BQGRYFaIXpbzFcPVaxJ90aSCLlfPaZ-q6aIT3BdTEEWQZidiPs2RZxIKlHLS2dRrKtoLF0jL0WZz0KhVXBIJKyun9Y83YDHXA3scH3YyFoBg8u5U7eXcJgNDBk6YJEEtMbSUznhaAbkZIrUzpbRAcRa_WaIbz_XMBwqMjYbWi235qvuLtAnjG1JXQtdb8EY4yNSr4YZaqyTYswP0khzMZBLThivf2oH3E8AI6UGyPG3Cqamj4Cats1OpRlY2sLrCgWKIvtoyYSK8JA",
  "oidc_future_auth_time": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAxLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1BIn0.c0jPBKK4m_RxnlbozairRLqRGLXrgA6zMb29zdPrI-4cK9QQxkxKX6HA2X_XPGcfg4g8cJg81HVOEc5Q4yQ_LZ_q8jxrDsjeR5uWUARPONU9DPCI6p3pfEyhV_LvW0yRADyeMno6JkdsN47UUtdyKhGKTrLQw_P-6ug-_jtqI1DPsmT2hC3rB3YokKZOIJbi5p-_WvEB6uJZu_ffpFAcIXGcVMOiijJ8zCZa6TuJz8on5pCjoz3MpxcKLdUvC23BRUicvq1XTl50qNi1WjgDFJSyio_5wxrmbA6vvYYsf1ciRRrQMcM_tbuBZUCJT4yFQBxjHjpZvJ9XxWMWOrEzog",
  "oidc_fraction_time": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAuMDAwMDAwMDAxLCJleHAiOjIwMDAwMDAyNDAuMDAwMDAwMDAxLCJhdXRoX3RpbWUiOjIwMDAwMDAwMDAsIm5vbmNlIjoib2lkYy1mbG93LW5vbmNlIiwiYXRfaGFzaCI6InFJQkNfWnRUWVh1MkVsdjk5RDlDLUEifQ.aN7MDasnuwq5BBcTcim4pQ0vcCnjyvkZY01qZYWnXOPrCsVWOMlEZEVwPOFrAX8DLasYFTjIpmU-fL6oliPVU2zugYOY95kK5BbHkZeyJ1rSJS6CN4iBBbbdojGWWpUwolbn89ScXRMD7oZutZEt9TUZWnTpr03FwjMN9uQQ_c0pDc5E3tVdsxYxvvkJ78xs6p0utNHw2Df3zeWLL_GlD61JSA10tZxFRarT799wwJhLmnC8njYBbjswS38b3rvHPJeEQSReTb9qmr-UStBs8w894eVNCz82APoBDwzts9QEW95xxIC1VTN-nOzxhUXhHljH7FMSg2omGp8QjxEu4Q",
  "oidc_exponent_time": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjJlOSwiZXhwIjoyMDAwMDAwMjRlMSwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1BIn0.c_vh2D19JqQbzTXu6aw-2SfEOXrt31MsLIRwHezyOgKEm0brm9xanQOOWj0cfFvD42DtsWIIR94_I_Nswg_umrZPSZuL3FoPKw6oB7Vg_CqXsY3WlKvDMDpjGGsmbLtPnZ_g7N7uvF518J7blngMFgaTB5sUfJgGr-Ia1YCe0pbA7XBKdlpSCf7QrppXWqZe1m_7UHxvxdYXQj2tvliCk9G54TAGHMgYvvNULO4ShcfhBKwmP3TF8M6CdoAw-gLpEbKR9KUwllMXeJcOrICiRGfpC3SUFxArRwIkyOw7cBSN2320wUWV_mN8sZhsK4m87PoCL0T9S7-j0RTpIoh20w",
  "oidc_bad_precision": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAuMDAwMDAwMDAwMSwiZXhwIjoyMDAwMDAwMjQwLCJhdXRoX3RpbWUiOjIwMDAwMDAwMDAsIm5vbmNlIjoib2lkYy1mbG93LW5vbmNlIiwiYXRfaGFzaCI6InFJQkNfWnRUWVh1MkVsdjk5RDlDLUEifQ.JuHQDHYPUvWl4Wz7sTaNvL5Dv5NB71Gcn1X62LDSOkHgOe9XqfZ-GRq0kpXa40f7_4sQrgTwPMoKG5d_SrZXeXGLmpVu9H6pV0Y6Lwq6SFGX2ADFaxfIxqQCg0SYd4juZIFCVA5T8mR0winJ9ACMX9TNfTL-Umxujcs0BiE3KkFeIE2FsRCDIP6pmQqBzouD7jntWRt1_pZQm7K0gnWINHAui3Qh-QIylCkFrpciKTd3dwn89oIrbEy7u0ECYGIwNttwobDR3cJ5y6mdYB8EzRD4-_O6phqViOsF30WiJx2SZEfUEoLiTN9dvS2I53WFFbMotODeT5KZCNA5Af128w",
  "oidc_negative_zero": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOi0wLCJleHAiOjIwMDAwMDAyNDAsImF1dGhfdGltZSI6MjAwMDAwMDAwMCwibm9uY2UiOiJvaWRjLWZsb3ctbm9uY2UiLCJhdF9oYXNoIjoicUlCQ19adFRZWHUyRWx2OTlEOUMtQSJ9.eYlnjCD9VRj7Notu_U5QkuHcI8NIZI2vIK0A6SGsivCiAK2FAAehl7ZFiilgmYF4XRUBFbCB86_Sz_ILdiKX4bVxTgdPVpVEFA9L3VC9XtySNvk1kmw4NGgQKcuNC4z-m0XMT6yUOHCXSGiJMv_tsSDJaV1FtDQcKS_588fTpqtzOEPTuUWj0pWBCUGzj-p6Xn58xGt_uFILgqHdkFMWBfWJMsoz4EntTVRvdVsj4deuFw7tMDSu9U86VOXzUVZl02IcFnM5PZSUS1E4XSmfK-gdIsivaE_gYO80HaI2T35__t_DMu9JiIYx177l9qRogyVMxDQk59wkIqQQ2x8D_g",
  "oidc_subject_nonascii": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoic3ViamVjdC3DqSIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1BIn0.K_9wCs0ZDGCTtvtmgCPjOyZHIpDlYlRi1tYsNLZiw1d7-JqW8g8MJLSTBFHrbdTUctLzDPGXSITTMbsPcqT5IX9HAUpwepSfI_UdpQBaRVJZXIATJlO8ERT9FNNvj5nJHNaMrTsTOXV9CdurizJJSKY7tygBmNknLRtFJRBjHXAQm0C0K4jCWC2oUK_XeEPDuSMsAByYkkN2Cf6rWKG659hc_f2by8xUBliw4-nfcqrRWqYOKdoSqQCDc8uxH6pqyMUEAmkP-W-1a8nbVAxjFxrScjapHSRfhANyTQTDwqLfb0gyHKJWWfPXm5tZDOFGOIZPRUHw60xk1o4Pkps5tA",
  "oidc_duplicate_claim": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsIm5vbmNlIjoib2lkYy1mbG93LW5vbmNlIiwiYXRfaGFzaCI6InFJQkNfWnRUWVh1MkVsdjk5RDlDLUEifQ.lUT4puRufoJWE2TuXtwu5jVew3Oq5-AZFama02QYaBiokKCDTCCzd1zCNywoK-dtJ1KY8KhFZCcuXyCQoL4Sfy8Iio4OZU85MmZsnZ0EbcCSKjBUinX1ZNRQY5vG3sPomPoIB16RpvbTOGd6nFotzSTmEwzG4yxtKaElmkbVPEg0cqfM_8n6VxISgR09y0Wd9YRk-SKBTiX_Cxe_KIDfYUM38FQHgLPKv1ofs7sgM1JSr24AYaij72SC81wWsdEfNqseDLDyhx-vbgwidj3el01W9yYwfBsavoIpq5LpaQKQdhK0GkxOBqUNwjfqwDByR3Q16Dx-OtwlP27inmRGdQ",
  "oidc_nested_type": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1BIn0.nLpye2WVeUKzOZ-C9Nwzwo4YbplgANT_BrXyRKy7B-WVlr82D0zt3J-eUwOBYT_-20J74u8olGJl43AsQY2dBLMH_nJ970MMVPqos-ap6z_1JVTOimX_bzrtK7IACp_Auc00oi_r4uVOoJH3yZohE9-Ot9NnqqeoVHNLrhGlo5t3m0V75ZXdJi7SeovYPVpm3ABZUC9FpnwgNHPiX10AnFu6KcScE3UY1sVyhq7d02NykfQhcRDZGAHE2t6fHtqfYlv5KUI1C6I9gDggQF__Csm5OiBpRlwbyx-eDGSZM_oqkCeNz_NKi8bUEYPCSB6j0HxVQrBtkMQ8RR5Vb-SUyw",
  "oidc_remote_key": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsImprdSI6Imh0dHBzOi8vdW50cnVzdGVkLmV4YW1wbGUvandrcyJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1BIn0.EbGqzw33h4EE85WUi5S7-AkEt5m7JcnACJGd8FGUZKIfbY8dkLH2qVzfVQPjrwEMybX5YWcNSrC_Uh0Qzo8X8ja0wefxvoue-EJU_mYMM7Vn0o5FcmlXiD7Kv5_Pe7wJ49ysoDz7V1-Xpv0MGK6362fZMkTqXmMG2YRu8bUlGVXK75ylKsg_xuKPWuvRkZ6G3c4yjBJq--8HUajqm489_0D5yelzNZC6QrVWp4FTRlHt9sJL83KEcofp9PfU_ZwP8L2JhPQV4nGdVir6mIKpQ22uRrtFhf5fCgO-D7VG0c-sV6tAqFUW8WHO-3pPCxWh9V7mO4jCO4oQILDMIkgBUg",
  "oidc_unknown_key": "eyJhbGciOiJSUzI1NiIsImtpZCI6InVudHJ1c3RlZCJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1BIn0.GbgfVJyMOulBBvVVMGhoxMD2uHFRqJNYsJrlWHFBXGVUF-4dVVxNLwMTO5Eh4We0QkTLdPRn6Azd6aU_4C1jl2mqAYGooKTTmf0MX1IXpnUclLv02Qib8Ewo7sAaLS82iO1Wf-slDSuPxLQi1hvZdBNy9AEC0tEX3wydRf5ROpH4wtywZRySbrKXbYPzTFbdYp9ZJnJUfL11IE1Rip2OEapj0_mj2razMWkARMYCCOJY83ZJ-tsasvrkJgfPiiMiyiPDc0rTxvhnurB1befI5KccfMKJaMvq6cF0va0FJSASCuiaBUhlW5fBynvgfBIml_yfrVO4-1jIvkJlxDBoGQ",
  "oidc_foreign_issuer": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2ZvcmVpZ24uZXhhbXBsZSIsInN1YiI6ImNsaWVudC1mYWNpbmciLCJhdWQiOiJuYXRpdmUtaWRwIiwiaWF0IjoyMDAwMDAwMDAwLCJleHAiOjIwMDAwMDAyNDAsImF1dGhfdGltZSI6MjAwMDAwMDAwMCwibm9uY2UiOiJvaWRjLWZsb3ctbm9uY2UiLCJhdF9oYXNoIjoicUlCQ19adFRZWHUyRWx2OTlEOUMtQSJ9.TjulZtWJDXv4jxdaouA_UT-txtMhvG-Edb-DS79fX4OTKLqKMKYXJMiD521osbSv-3MHGCDi6AnP3ESmjnW62xezThExACv0yme2r3BxPtvh4ASXT_9YmB-SY01xrBDGYNOfcbg8LvqrOW3WWnKSxJ2ElcCWXBGmxZE7oqDpjSgEJLrIulQmN3xju0w4Ba8VPqTebT6l1KoaxvELKgMFEaYvta-yncqDGiNTs8SgdMccJHyJjLhbWuPO88_sryD-r5fqwunli4SwewnGuCSyyi3f4PNz7pt3aUGJ_TVD4bLUI1mWSzs_o0nnPo1j1q-ty070DSW2Ef1vXKVa_TREIA",
  "oidc_not_before": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LWZhY2luZyIsImF1ZCI6Im5hdGl2ZS1pZHAiLCJpYXQiOjIwMDAwMDAwMDAsImV4cCI6MjAwMDAwMDI0MCwiYXV0aF90aW1lIjoyMDAwMDAwMDAwLCJub25jZSI6Im9pZGMtZmxvdy1ub25jZSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1BIiwibmJmIjoyMDAwMDAwMTIwfQ.SCp2QbLXqzzpqjz7gJivCCKIymzNn6NAbQK3Ykb0GV-rcX5eyPdIJAKf16XD72igaP--6Ew04CMLsYVDPoHNS_Y7F4yGBFGs1r7mCjqcj13MjHO7cSOYexCUF74wyFBCxSX5MljGVCbGBJhwvBkXsN79mNJXz4peTKTcHmiaqglTC7kq7CNdVQFpfWXuvzA_V-wzIgr7Y0E9fTzyuJm2JyK8pO3adkBBz8ppoAakwdCRZ4vLDlfhuLBSUt1eRYyo7dHxLCFW9XWMGATrN5bau4MsTqABGRhXibx_tsvr5IE9Uj4Ntj2eK1FSiflhrWowiNO3PsOCIHtpYqft51_dPg",
  "id_jag_singleton": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsInR5cCI6IkFwcGxpY2F0aW9uL09BVVRILUlELUpBRytKV1QifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoicmVzb3VyY2UtZmFjaW5nIiwiYXVkIjpbImh0dHBzOi8vYXMuZXhhbXBsZSJdLCJjbGllbnRfaWQiOiJuYXRpdmUtcmVzb3VyY2UiLCJqdGkiOiJpZC1qYWctZmxvdy0xIiwiaWF0IjoyMDAwMDAwMDAwLCJleHAiOjIwMDAwMDAyNDAsInJlc291cmNlIjpbImh0dHBzOi8vbWNwLmV4YW1wbGUvbWNwIl0sInNjb3BlIjoicmVhZCJ9.cJPWUlxazx3WRiyWJcIEu45g_tELCCTOOkXEVkkIIpB8orgiTA_TI-923PwH7LTA-PXJemU8Sie1zIw8IcmO6OiauOVcKztlm1g0yNKd7cCEs02zCl6EnVpZLBsc8sz8Gs9oMNYEMCJ4V4KJdBxreCn__7U9-Z2aI3pp_SHcmcSfldUB9nbJfNXbDi4NHLVoZaB-a6KuH1HGZIK6RpnjRgN0o3eNnNMv0aIVJyASCwr77QMtHhPCnCSDn2QnmTRi6c6QZ1gWaWPt1RWpXVVXiDdZ_z-c4bU7yOShEI_hoCNDogagaIUWI6_07mpWCdVX7jTkRK7sd8DH0rN4cAvToQ",
  "id_jag_multi_resource": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsInR5cCI6Im9hdXRoLWlkLWphZytqd3QifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoicmVzb3VyY2UtZmFjaW5nIiwiYXVkIjoiaHR0cHM6Ly9hcy5leGFtcGxlIiwiY2xpZW50X2lkIjoibmF0aXZlLXJlc291cmNlIiwianRpIjoiaWQtamFnLWZsb3ctMSIsImlhdCI6MjAwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMjQwLCJyZXNvdXJjZSI6WyJodHRwczovL21jcC5leGFtcGxlL21jcCIsImh0dHBzOi8vbWNwLmV4YW1wbGUvb3RoZXIiXSwic2NvcGUiOiJyZWFkIn0.ZQarXy-yI0rJtI4ncwJNZjwISjOb9ChBLk71izUeqVY65Lk6Fig_WF4-6b573MmqtFjbHWXMzQXvyEXxhPP_w0rvbnlbfJ5OaYVJKPFUK32QrD_q6RqZARHcqmlus3X4HeOycGtKLl6fQghDaBTIA8EO9swsR8YnRjAnxULFB_r0zcxM8XQg40De6wQt1GIrUATpIRuRKphtp5_6ZIR4mkUjIb9LgNJP2OARqP7oGvcg1y_6ux10UzhA-QCZg6dygkAXDj3j5yl1BzXYT9mkvuM0SzzygjhHsT6Bo2kz3FvyaS0hiTUK2RwUlNM1_81xx2Tha4V1LIPOJyOpuBvKJQ",
  "id_jag_multi_audience": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsInR5cCI6Im9hdXRoLWlkLWphZytqd3QifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoicmVzb3VyY2UtZmFjaW5nIiwiYXVkIjpbImh0dHBzOi8vYXMuZXhhbXBsZSIsImh0dHBzOi8vb3RoZXIuZXhhbXBsZSJdLCJjbGllbnRfaWQiOiJuYXRpdmUtcmVzb3VyY2UiLCJqdGkiOiJpZC1qYWctZmxvdy0xIiwiaWF0IjoyMDAwMDAwMDAwLCJleHAiOjIwMDAwMDAyNDAsInJlc291cmNlIjoiaHR0cHM6Ly9tY3AuZXhhbXBsZS9tY3AiLCJzY29wZSI6InJlYWQifQ.FpR0Mfm7MNzAt4LZd9gj_C0DSh0S7EXcKr9tNHoIpUAVVwkmnOcXIyeyf0t1bCjZHCwpp7K3L35RIdAfLSc2zfFyj5bh2qDG1IKc3ObAcXYsCWRsP0xT9nsacP-W41-eCAgOVHCTW28EReZPceCArZQo27aw53BHoIbmOpiOdeTbiCEHMZ8R4CgWbIWqm1Uhvpw-7B2SG3v-r943LLoHslUin9jBgfkRnu29MP0wlLAnq9jDRrtMQE0V1UWR2lkwVHSts8OB0CGUmSmZe5GVi3CilFFQQrrfwdFLlJgk82xZ2iiipnJApOgMEDLQ6UGDvsGkj6aMRQUdHcXXq8Wysg",
  "id_jag_missing_resource": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsInR5cCI6Im9hdXRoLWlkLWphZytqd3QifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoicmVzb3VyY2UtZmFjaW5nIiwiYXVkIjoiaHR0cHM6Ly9hcy5leGFtcGxlIiwiY2xpZW50X2lkIjoibmF0aXZlLXJlc291cmNlIiwianRpIjoiaWQtamFnLWZsb3ctMSIsImlhdCI6MjAwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMjQwLCJzY29wZSI6InJlYWQifQ.HyKhLBwE4iJ0w4BogGeMFyWZMIk1j5kR1f2tyghg2OLvOFDzAvmPtLTQDYhVEucBuktuuvZMx_L5wzFM7dkXItPJyDsKIaQpNMoKVBwXdKYKPP18ohkVYte_PZe0LZk-q16pI9csKp_Rvs47h2WES3pUc4ywpqLsOgnzPWTwlCpp0KJ0BRYmNlYCmxG9uSLibDnhxgn2HxQC5pCrJPhhjNnVLuGQFo6rlSaQ6dfB3EJZCJfNDpJ2ByoQll4P96jQU3f-KjuFtIGXI3hMzVkukGkaS_RiExsF_W3Rn9zjYGWkgG0XKiS0oP4xVyUGdcicF3Yjpby5t2IlEnlu1Br8ww",
  "id_jag_missing_scope": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsInR5cCI6Im9hdXRoLWlkLWphZytqd3QifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoicmVzb3VyY2UtZmFjaW5nIiwiYXVkIjoiaHR0cHM6Ly9hcy5leGFtcGxlIiwiY2xpZW50X2lkIjoibmF0aXZlLXJlc291cmNlIiwianRpIjoiaWQtamFnLWZsb3ctMSIsImlhdCI6MjAwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMjQwLCJyZXNvdXJjZSI6Imh0dHBzOi8vbWNwLmV4YW1wbGUvbWNwIn0.EQXDExx3cTNuPp3DozxZvdRIgx9khETs0e1d3O1zXjypkIDVqCUu1DZ-Td7Dbr60Prdzqhw8oX5Femslpiag3s6UHIaLgbbi0ZbALdbIa_CKhFIm6qxWT1M8Uwx1ek5D5LPAiiJRi8fsExUzphl3-wKMa3U5STW4Glh3WJOl9xGg_-m26cZF9myU2H0X8gC9KtlDJh6tU-uzyn4XaVCjt6dcw6DYe03hvTdk3h3ocJKSxmvkasdtRJCQuBmf0cJpA6IuuMUiPjeXgdDx3LQxIpL4MEzi5xcCUUM8rz8B1oNOx7FhF43U285PEoFaEqj6BXxwNCv_8JKkFmlXipIhQg",
  "id_jag_duplicate_scope": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsInR5cCI6Im9hdXRoLWlkLWphZytqd3QifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoicmVzb3VyY2UtZmFjaW5nIiwiYXVkIjoiaHR0cHM6Ly9hcy5leGFtcGxlIiwiY2xpZW50X2lkIjoibmF0aXZlLXJlc291cmNlIiwianRpIjoiaWQtamFnLWZsb3ctMSIsImlhdCI6MjAwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMjQwLCJyZXNvdXJjZSI6Imh0dHBzOi8vbWNwLmV4YW1wbGUvbWNwIiwic2NvcGUiOiJyZWFkIHJlYWQifQ.Oqc7ooR_5EAF_CKJUWxX3cz6vQI1SxWHFoQ8dn_AQVuM-jEoeeY5NQO_mztkQwIf8VJFgtpXwHuPpP3w7C4sbPcj_F80mthzyByw1NHT0BDPFcFSlYerlCOhHXin1PLlKNE5wid-NaylnGqA7oSn5RmIjnC2LTRr_DtDD2KZ2zNth_Qmmp29N6TcZkUFxS8_uk-lnxFWROjEB2VqeY8bQFAM5kYcjU0baosp1LwR6lN7wIw7boBlEZpEfn8J0wHyFThsVgtryI6erFrEJ9kOJ4GiZNWudVdBqa__lWpOy6GWvdVwGO1bHp9jLvJWnGuqYygJg4XYpCUqS4e3l14UEw",
  "id_jag_tenants": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsInR5cCI6Im9hdXRoLWlkLWphZytqd3QifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoicmVzb3VyY2UtZmFjaW5nIiwiYXVkIjoiaHR0cHM6Ly9hcy5leGFtcGxlIiwiY2xpZW50X2lkIjoibmF0aXZlLXJlc291cmNlIiwianRpIjoiaWQtamFnLWZsb3ctMSIsImlhdCI6MjAwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMjQwLCJyZXNvdXJjZSI6Imh0dHBzOi8vbWNwLmV4YW1wbGUvbWNwIiwic2NvcGUiOiJyZWFkIiwidGVuYW50IjoiaWRwLXRlbmFudCIsImF1ZF90ZW5hbnQiOiJyZXNvdXJjZS10ZW5hbnQiLCJhdWRfc3ViIjoib3BhcXVlL2FjY291bnQifQ.KlmLEfjjXSySC-8cvOdXcZ-MNutykKqAzKz8fcvowbUkRxF5e-KwHZxHfkrdqWot9IkUWHH6m_NvzjewJ6IalVzjP318QkWy9VsYNigWUFNigK8-VOken37I5-xRt7NvPE2zhHphBHY9iAT-xMMJvMhRCa33-VcucE3Se6tAKpE4zw71oKlc3R2zjlP7CppScypRHyv4zzrIeD2NlVz4WPqlqWYusp-oNIOOijdZuqXyDZPuUyf02uxeCDWPqY06Jx3kap0ql2Rrk8YBs-0BApSiYVvf39puvdZ3gizkvXJ43Rr_qGiwZVRW-XohsfRjwedFe9xE1rMErGiJt9nl0g",
  "id_jag_tenant_missing_subject": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsInR5cCI6Im9hdXRoLWlkLWphZytqd3QifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoicmVzb3VyY2UtZmFjaW5nIiwiYXVkIjoiaHR0cHM6Ly9hcy5leGFtcGxlIiwiY2xpZW50X2lkIjoibmF0aXZlLXJlc291cmNlIiwianRpIjoiaWQtamFnLWZsb3ctMSIsImlhdCI6MjAwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMjQwLCJyZXNvdXJjZSI6Imh0dHBzOi8vbWNwLmV4YW1wbGUvbWNwIiwic2NvcGUiOiJyZWFkIiwidGVuYW50IjoiaWRwLXRlbmFudCIsImF1ZF90ZW5hbnQiOiJyZXNvdXJjZS10ZW5hbnQifQ.eAf5t9oxLYps1KaXdpmz515T_YWMZVp0bfF24x2bVYB2utYhqPY5EqNFKV0VtBZj1t9KCguGGjj_nwqOZQqjHo81faCuPjHzUcAtM8Ci6XMLXiDFcRO2hu7OaUpFKFrXh_gXzahBOAUitMeHv_JUIKeWyZTSZ9QrWs6cVL4UcnCWIDBDZKdULrrBtgz-moZHLJvhtRwzFw07Pk9suhU2S0HLe0nLymj95tFUWO__Ag1kOrquNoaabNmAZIlkg4CWsHuaYC-JcJMsvs_rxL-NFN6Xa-WLKuE_Spjdaqj58-cdmdAOVc-iM7FGpqCSStbpQKeW8ialivYQIXr0PqtKNA",
  "id_jag_missing_type": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoicmVzb3VyY2UtZmFjaW5nIiwiYXVkIjoiaHR0cHM6Ly9hcy5leGFtcGxlIiwiY2xpZW50X2lkIjoibmF0aXZlLXJlc291cmNlIiwianRpIjoiaWQtamFnLWZsb3ctMSIsImlhdCI6MjAwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMjQwLCJyZXNvdXJjZSI6Imh0dHBzOi8vbWNwLmV4YW1wbGUvbWNwIiwic2NvcGUiOiJyZWFkIn0.CzUTe9gZEd-RbpbkZDwJRV9z_JL3Q0Sy2WHPvcLSW0plm4tvYtivAhGPa4Xxg5SfNI_QUbT30wAP7BKnTh4Q8zmumXZ52RNWSdOZ5Zi2JNZcLXCHKRkEF8Sukwo_xzxW3ZPVC5VbGghMJGRQaxFYt3DHmmt19dQOXN-B40G3FqffGpLKtvYfalSxh0EuYB0IJ6KpJz2PnrCCuhR1fUwV9HqqTTDSUi-IXBIe6CqIao8N1BdAzWqpyrhS9CnXKDk6BFPKIinycxi6OhRki5yaM7yP7fSNnT0DWoDuYmWAOukrQuQWnraCBjia7e_WIBx-iBIBVP70eXRABWA2eIN9VA",
  "id_jag_oidc_type": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoicmVzb3VyY2UtZmFjaW5nIiwiYXVkIjoiaHR0cHM6Ly9hcy5leGFtcGxlIiwiY2xpZW50X2lkIjoibmF0aXZlLXJlc291cmNlIiwianRpIjoiaWQtamFnLWZsb3ctMSIsImlhdCI6MjAwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMjQwLCJyZXNvdXJjZSI6Imh0dHBzOi8vbWNwLmV4YW1wbGUvbWNwIiwic2NvcGUiOiJyZWFkIn0.eXVautZPQiW97kpcqDcLEGC29g4gKQ6v8G-pDR5Boh2-egxxm27XN2zLCKDtysuYzYqbT5tmRf3HnL-e3DTjkoFJweyeEhbF0ytYLeqGecAMBFkln1hgwgMnhbudW6EWwDTHIeMZyfAQ1Bk7N2-eXfApt7_No2n_0y4ubVed-boTgplkrUrCn7CaVyPE0XMW7CrkW_2146fVrfLDjT9sJgl2MTHZ4x3Vgb1mB3lrFOP7tY1yBNSD_iwVsyhbk3enriwDR2b78JcH5q-_eEprIKYdbaoH2DZ8l7QlesDjwRj6GW-uxkunnvFrriBD74nUNtV4lBpAemp6FZhGzfKJEQ",
  "id_jag_forbidden_cnf": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsInR5cCI6Im9hdXRoLWlkLWphZytqd3QifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoicmVzb3VyY2UtZmFjaW5nIiwiYXVkIjoiaHR0cHM6Ly9hcy5leGFtcGxlIiwiY2xpZW50X2lkIjoibmF0aXZlLXJlc291cmNlIiwianRpIjoiaWQtamFnLWZsb3ctMSIsImlhdCI6MjAwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMjQwLCJyZXNvdXJjZSI6Imh0dHBzOi8vbWNwLmV4YW1wbGUvbWNwIiwic2NvcGUiOiJyZWFkIiwiY25mIjp7ImprdCI6InVudXNlZCJ9fQ.gUyLNnlh5hyJfNYjfpz07ETW4mnCcNA3CWkNf5uKcB-r9iQOY-U4tgEpyJ671jWdONMI12mcTSyaKyJg_OB9BvLerXZ-uPz-oZ4BejfYbA5F71kDgZSczbhjqLCcVMl-dUGbVlC3qaNJSRUuvWqZW-Ado1M3c0mcts0d7RK3i5265R8cUZWutA1nryyiQJLpSQ35HaWc49B_Ag105egNXreatpTGiAf7-yNEFNhCioJqTc1XWqMpLsTGbI5BJPckXvd0Wtp3rfpnE3kXu-JP50LL6AKUnmi7P4T7lhdaLwZbPD-lsBF8hf18Y-ywU3GY-0mRZxw55v3jMoEJ5VDAWQ",
  "id_jag_forbidden_actor": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsInR5cCI6Im9hdXRoLWlkLWphZytqd3QifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoicmVzb3VyY2UtZmFjaW5nIiwiYXVkIjoiaHR0cHM6Ly9hcy5leGFtcGxlIiwiY2xpZW50X2lkIjoibmF0aXZlLXJlc291cmNlIiwianRpIjoiaWQtamFnLWZsb3ctMSIsImlhdCI6MjAwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMjQwLCJyZXNvdXJjZSI6Imh0dHBzOi8vbWNwLmV4YW1wbGUvbWNwIiwic2NvcGUiOiJyZWFkIiwiYWN0Ijp7InN1YiI6ImFjdG9yIn19.EYVW92XeRcXeKAQYU53mDkFIQkVMyrPJbgWor4H_knUvDNY-a408AFyto0kITpg5JaiQWMhurJzTxS9MKLSWuWp6-SrtlS7K38P299a6nndA4tFZZ6YFougFAUKuON81n66bdrS-4bRm5OwuOHhXa2C7Gbqld3Fif_qGo9RoxcVgBxjgD2hjEbiS12dfa2VBZmTb6V44C7aIaPkqBpNgFOG9SADsLQyOs4ArCweoo2oRbafBcJ71nYPQpJviV-Li71Fq60N3IEdXIyt-KdsYYeBuHdZuG79lpswf082Yp6NfDNQ0naSLEhzSNVCVb798jD8DakXFs72dF7kzkrwcow",
  "id_jag_empty_jti": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsInR5cCI6Im9hdXRoLWlkLWphZytqd3QifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoicmVzb3VyY2UtZmFjaW5nIiwiYXVkIjoiaHR0cHM6Ly9hcy5leGFtcGxlIiwiY2xpZW50X2lkIjoibmF0aXZlLXJlc291cmNlIiwianRpIjoiIiwiaWF0IjoyMDAwMDAwMDAwLCJleHAiOjIwMDAwMDAyNDAsInJlc291cmNlIjoiaHR0cHM6Ly9tY3AuZXhhbXBsZS9tY3AiLCJzY29wZSI6InJlYWQifQ.Es7o_cSWSgbOJZFsoglIDQMCygErKKXIP4AJRtTpO4dYeWTqWApqKs6rCSnMjfsL3XtIo4tHnp4oeJbulcopTW_-qrEDmchDSiAmmHWJ2HSncpXLh7NtXXF4zpmsco54G8-xPP2L2b_fj_Fq3JTO-lK4Epkz-Z8wrfoJQMyDY9PgugxlYbxLbNyoQSHE1jmPnLwUYeUhlarzZxQDLDsPzTXxLs6r0bhV6Z6VMjxOTl3HK9o089FMkqKnqAdwy2kLbFHQe4vLg2g4rcLTD2AJsLt8oMVpsJNxts6EskMZuuDqDbEsDFJHIu8tXIFSJPxLajNyRzeN5TPmTbmuWE3IPQ"
}
"#;
