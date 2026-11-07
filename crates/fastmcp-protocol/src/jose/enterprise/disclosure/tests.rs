//! Real-signature coverage for reviewed optional ID-JAG disclosures.
//!
//! Fixtures use only the public example RSA key from RFC 7515 Appendix A.2.
//! Preparation reproduced that appendix's published signature before signing
//! these cases. No private key or fixture signer is part of the repository.

use std::sync::OnceLock;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;

use super::*;
use super::super::{
    IdJagExpectations, IdJagVerificationKeys, JwtTimePolicy, ResourceTenantExpectation,
    TenantExpectation, verify_id_jag, verify_id_jag_with_disclosure,
};

const ISSUED: u64 = 2_000_000_000;
const ALL_CLAIMS: [IdJagDisclosureClaim; 4] = [
    IdJagDisclosureClaim::Email,
    IdJagDisclosureClaim::AuthenticationTime,
    IdJagDisclosureClaim::AuthenticationContext,
    IdJagDisclosureClaim::AuthenticationMethods,
];
const FIXTURE_NAMES: [&str; 14] = [
    "base", "email", "all_disclosures", "email_null", "email_too_long",
    "email_wrong_type", "amr_not_array", "amr_duplicate", "auth_time_future",
    "unknown_claim", "cnf", "act", "duplicate_email", "foreign_resource",
];

fn fixtures() -> &'static Value {
    static FIXTURES: OnceLock<Value> = OnceLock::new();
    FIXTURES.get_or_init(|| serde_json::from_str(include_str!("fixtures.json")).unwrap())
}

fn signed(name: &str) -> &'static str {
    fixtures()[name].as_str().expect("named signed disclosure fixture")
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn now() -> SystemTime {
    at(ISSUED + 10)
}

fn keys() -> IdJagVerificationKeys {
    let jwks = serde_json::to_vec(&fixtures()["jwks"]).unwrap();
    IdJagVerificationKeys::from_trusted_jwks("https://idp.example", 22, &jwks).unwrap()
}

fn expected() -> IdJagExpectations<'static> {
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

fn configuration(claims: &[IdJagDisclosureClaim]) -> IdJagDisclosureConfiguration {
    IdJagDisclosureConfiguration {
        policy_id: "reviewed-id-jag-disclosures".to_owned(),
        generation: 7,
        idp_issuer: "https://idp.example".to_owned(),
        resource_as_issuer: "https://as.example".to_owned(),
        reviewed_at: at(ISSUED - 5),
        review_expires_at: at(ISSUED + 120),
        rules: claims.iter().map(|claim| IdJagDisclosureRule {
            claim: *claim,
            purpose: format!("Validate and discard reviewed {}", claim.name()),
        }).collect(),
    }
}

fn policy(claims: &[IdJagDisclosureClaim]) -> IdJagDisclosurePolicy {
    IdJagDisclosurePolicy::from_trusted_configuration(configuration(claims)).unwrap()
}

#[test]
fn every_disclosure_fixture_has_a_real_rs256_signature_including_invalid_json() {
    let jwk = &fixtures()["jwks"]["keys"][0];
    let modulus = URL_SAFE_NO_PAD.decode(jwk["n"].as_str().unwrap()).unwrap();
    let exponent = URL_SAFE_NO_PAD.decode(jwk["e"].as_str().unwrap()).unwrap();
    let key = ring::signature::RsaPublicKeyComponents {
        n: modulus.as_slice(),
        e: exponent.as_slice(),
    };
    assert_eq!(fixtures().as_object().unwrap().len(), FIXTURE_NAMES.len() + 1);
    for name in FIXTURE_NAMES {
        let (input, signature) = signed(name).rsplit_once('.').unwrap();
        let signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
        key.verify(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            input.as_bytes(),
            &signature,
        ).unwrap_or_else(|_| panic!("fixture signature failed: {name}"));
    }
}

#[test]
fn signed_optional_disclosures_require_explicit_permission_and_retain_only_names() {
    let keys = keys();
    let expected = expected();
    let strict = verify_id_jag(signed("base"), &keys, &expected, now()).unwrap();
    assert!(strict.disclosure().is_none());
    for name in ["email", "all_disclosures"] {
        assert_eq!(
            verify_id_jag(signed(name), &keys, &expected, now()).unwrap_err(),
            EnterpriseVerificationError::InvalidClaims,
        );
    }

    let policy = policy(&ALL_CLAIMS);
    let admitted = verify_id_jag_with_disclosure(
        signed("all_disclosures"), &keys, &expected, &policy, now(),
    ).unwrap();
    assert_eq!(admitted.subject().as_str(), "resource-facing");
    assert_eq!(admitted.resource(), Some("https://mcp.example/mcp"));
    assert_eq!(admitted.scope(), Some("read"));
    let facts = admitted.disclosure().expect("reviewed disclosure facts");
    assert_eq!(facts.policy_id(), "reviewed-id-jag-disclosures");
    assert_eq!(facts.generation(), 7);
    assert_eq!(facts.configuration_digest(), policy.configuration_digest());
    assert_eq!(facts.review_expires_at(), at(ISSUED + 120));
    assert_eq!(facts.admitted_claims(), ALL_CLAIMS.as_slice());

    let diagnostic = format!("{policy:?} {admitted:?} {facts:?}");
    for private_value in [
        "hidden-contact@example.test", "urn:example:assurance:reviewed", "pwd", "hwk",
        "resource-facing", signed("all_disclosures"),
    ] {
        assert!(!diagnostic.contains(private_value));
    }
}

#[test]
fn partial_and_empty_allowlists_do_not_inherit_other_disclosure_permissions() {
    let keys = keys();
    let expected = expected();
    let email_only = policy(&[IdJagDisclosureClaim::Email]);
    let admitted = verify_id_jag_with_disclosure(
        signed("email"), &keys, &expected, &email_only, now(),
    ).unwrap();
    assert_eq!(
        admitted.disclosure().unwrap().admitted_claims(),
        &[IdJagDisclosureClaim::Email],
    );
    assert_eq!(
        verify_id_jag_with_disclosure(
            signed("all_disclosures"), &keys, &expected, &email_only, now(),
        ).unwrap_err(),
        EnterpriseVerificationError::InvalidClaims,
    );
    let empty = policy(&[]);
    let admitted = verify_id_jag_with_disclosure(
        signed("base"), &keys, &expected, &empty, now(),
    ).unwrap();
    assert!(admitted.disclosure().unwrap().admitted_claims().is_empty());
    assert_eq!(
        verify_id_jag_with_disclosure(
            signed("email"), &keys, &expected, &empty, now(),
        ).unwrap_err(),
        EnterpriseVerificationError::InvalidClaims,
    );
}

#[test]
fn signed_disclosure_values_refuse_wrong_types_bounds_and_authentication_order() {
    let keys = keys();
    let expected = expected();
    let policy = policy(&ALL_CLAIMS);
    for name in [
        "email_null", "email_too_long", "email_wrong_type",
        "amr_not_array", "amr_duplicate", "auth_time_future",
    ] {
        assert_eq!(
            verify_id_jag_with_disclosure(
                signed(name), &keys, &expected, &policy, now(),
            ).unwrap_err(),
            EnterpriseVerificationError::InvalidClaims,
            "{name}",
        );
    }
    assert!(verify_id_jag_with_disclosure(
        signed("all_disclosures"), &keys, &expected, &policy, now(),
    ).is_ok());
}

#[test]
fn disclosure_permission_cannot_enable_actors_sender_constraints_or_duplicate_members() {
    let keys = keys();
    let expected = expected();
    let policy = policy(&ALL_CLAIMS);
    for name in ["unknown_claim", "cnf", "act"] {
        assert_eq!(
            verify_id_jag_with_disclosure(
                signed(name), &keys, &expected, &policy, now(),
            ).unwrap_err(),
            EnterpriseVerificationError::InvalidClaims,
            "{name}",
        );
    }
    assert_eq!(
        verify_id_jag_with_disclosure(
            signed("duplicate_email"), &keys, &expected, &policy, now(),
        ).unwrap_err(),
        EnterpriseVerificationError::InvalidToken,
    );
    for name in [
        "authorization_details", "act", "sub_id", "name", "given_name",
        "family_name", "preferred_username", "cnf", "jku", "jwk", "x5u",
        "iss", "sub", "aud", "client_id", "resource", "scope",
    ] {
        assert!(IdJagDisclosureClaim::from_name(name).is_none(), "{name}");
    }
}

#[test]
fn optional_claims_do_not_bypass_signature_target_or_signed_expiry_checks() {
    let keys = keys();
    let mut expected = expected();
    let mut config = configuration(&ALL_CLAIMS);
    config.review_expires_at = at(ISSUED + 3600);
    let policy = IdJagDisclosurePolicy::from_trusted_configuration(config).unwrap();
    assert_eq!(
        verify_id_jag_with_disclosure(
            signed("foreign_resource"), &keys, &expected, &policy, now(),
        ).unwrap_err(),
        EnterpriseVerificationError::BindingMismatch,
    );
    expected.client_id = "different-resource-client";
    assert_eq!(
        verify_id_jag_with_disclosure(
            signed("email"), &keys, &expected, &policy, now(),
        ).unwrap_err(),
        EnterpriseVerificationError::BindingMismatch,
    );
    expected.client_id = "native-resource";
    assert_eq!(
        verify_id_jag_with_disclosure(
            signed("email"), &keys, &expected, &policy, at(ISSUED + 300),
        ).unwrap_err(),
        EnterpriseVerificationError::Expired,
    );
    let (input, signature) = signed("email").rsplit_once('.').unwrap();
    let first = if signature.starts_with('A') { 'B' } else { 'A' };
    let altered = format!("{input}.{first}{}", &signature[1..]);
    assert_eq!(
        verify_id_jag_with_disclosure(
            &altered, &keys, &expected, &policy, now(),
        ).unwrap_err(),
        EnterpriseVerificationError::InvalidToken,
    );
}

#[test]
fn exact_trust_relationship_and_review_window_have_no_implicit_alias_or_skew() {
    let keys = keys();
    let expected = expected();
    let selected = policy(&[IdJagDisclosureClaim::Email]);
    for time in [at(ISSUED - 5), at(ISSUED + 119)] {
        assert!(verify_id_jag_with_disclosure(
            signed("email"), &keys, &expected, &selected, time,
        ).is_ok());
    }
    for time in [at(ISSUED - 6), at(ISSUED + 120)] {
        assert_eq!(
            verify_id_jag_with_disclosure(
                signed("email"), &keys, &expected, &selected, time,
            ).unwrap_err(),
            EnterpriseVerificationError::InvalidConfiguration,
        );
    }
    for change_idp in [false, true] {
        let mut config = configuration(&[IdJagDisclosureClaim::Email]);
        if change_idp {
            config.idp_issuer = "https://idp.example/".to_owned();
        } else {
            config.resource_as_issuer = "https://as.example/".to_owned();
        }
        let other = IdJagDisclosurePolicy::from_trusted_configuration(config).unwrap();
        assert_eq!(
            verify_id_jag_with_disclosure(
                signed("email"), &keys, &expected, &other, now(),
            ).unwrap_err(),
            EnterpriseVerificationError::BindingMismatch,
        );
    }
}

#[test]
fn disclosure_configuration_requires_bounded_reviewed_identity_and_unique_purposes() {
    for mutation in 0..13 {
        let mut config = configuration(&[IdJagDisclosureClaim::Email]);
        match mutation {
            0 => config.generation = 0,
            1 => config.policy_id.clear(),
            2 => config.policy_id = "unreviewed ".to_owned(),
            3 => config.policy_id = "x".repeat(MAX_POLICY_ID_BYTES + 1),
            4 => config.idp_issuer = "http://idp.example".to_owned(),
            5 => config.resource_as_issuer = "https://user@as.example".to_owned(),
            6 => config.reviewed_at = UNIX_EPOCH - Duration::from_secs(1),
            7 => config.review_expires_at = config.reviewed_at,
            8 => config.review_expires_at =
                config.reviewed_at + MAX_DISCLOSURE_REVIEW_LIFETIME + Duration::from_nanos(1),
            9 => config.rules.push(IdJagDisclosureRule {
                claim: IdJagDisclosureClaim::Email,
                purpose: "Another purpose cannot duplicate an existing claim".to_owned(),
            }),
            10 => config.rules[0].purpose.clear(),
            11 => config.rules[0].purpose = "x".repeat(MAX_PURPOSE_BYTES + 1),
            12 => config.rules[0].purpose = "hidden\ncontrol".to_owned(),
            _ => unreachable!(),
        }
        assert_eq!(
            IdJagDisclosurePolicy::from_trusted_configuration(config).unwrap_err(),
            EnterpriseVerificationError::InvalidConfiguration,
            "mutation {mutation}",
        );
    }
    assert!(IdJagDisclosurePolicy::from_trusted_configuration(configuration(&ALL_CLAIMS)).is_ok());
}

#[test]
fn disclosure_digest_is_order_independent_and_changes_with_each_authority_dimension() {
    let original = policy(&ALL_CLAIMS);
    let mut reordered = configuration(&ALL_CLAIMS);
    reordered.rules.reverse();
    let reordered = IdJagDisclosurePolicy::from_trusted_configuration(reordered).unwrap();
    assert_eq!(original.configuration_digest(), reordered.configuration_digest());

    for mutation in 0..8 {
        let mut config = configuration(&ALL_CLAIMS);
        match mutation {
            0 => config.policy_id.push_str("-different"),
            1 => config.generation += 1,
            2 => config.idp_issuer.push('/'),
            3 => config.resource_as_issuer.push('/'),
            4 => config.reviewed_at += Duration::from_secs(1),
            5 => config.review_expires_at += Duration::from_secs(1),
            6 => config.rules[0].purpose.push_str(" for a different reviewed purpose"),
            7 => { config.rules.pop(); }
            _ => unreachable!(),
        }
        let changed = IdJagDisclosurePolicy::from_trusted_configuration(config).unwrap();
        assert_ne!(original.configuration_digest(), changed.configuration_digest(), "{mutation}");
    }
}

#[test]
fn optional_disclosure_schemas_enforce_exact_size_and_type_boundaries() {
    let policy = policy(&ALL_CLAIMS);
    let methods: Vec<String> = (0..MAX_AUTHENTICATION_METHODS)
        .map(|index| format!("{index:02}{}", "m".repeat(MAX_AUTHENTICATION_METHOD_BYTES - 2)))
        .collect();
    for (name, value) in [
        ("email", json!("x".repeat(MAX_EMAIL_BYTES))),
        ("acr", json!("x".repeat(MAX_AUTHENTICATION_CONTEXT_BYTES))),
        ("amr", json!(methods)),
        ("auth_time", serde_json::from_str("2000000000.000000000").unwrap()),
    ] {
        let mut claims = Map::new();
        claims.insert("iat".to_owned(), json!(ISSUED));
        claims.insert(name.to_owned(), value);
        assert_eq!(policy.admit_claims(&claims).unwrap().admitted_claims().len(), 1);
    }

    for (name, value) in [
        ("email", json!("")),
        ("email", json!("x".repeat(MAX_EMAIL_BYTES + 1))),
        ("email", Value::Null),
        ("acr", json!(true)),
        ("acr", json!("x".repeat(MAX_AUTHENTICATION_CONTEXT_BYTES + 1))),
        ("amr", json!([])),
        ("amr", json!("pwd")),
        ("amr", json!([null])),
        ("amr", json!(["pwd", "pwd"])),
        ("amr", json!(["x".repeat(MAX_AUTHENTICATION_METHOD_BYTES + 1)])),
        ("amr", json!((0..=MAX_AUTHENTICATION_METHODS)
            .map(|index| format!("method-{index}")).collect::<Vec<_>>())),
        ("auth_time", json!("2000000000")),
        ("auth_time", json!(ISSUED + 1)),
        ("auth_time", serde_json::from_str("-0").unwrap()),
        ("auth_time", serde_json::from_str("1999999999.0000000001").unwrap()),
    ] {
        let mut claims = Map::new();
        claims.insert("iat".to_owned(), json!(ISSUED));
        claims.insert(name.to_owned(), value);
        assert_eq!(
            policy.admit_claims(&claims).unwrap_err(),
            EnterpriseVerificationError::InvalidClaims,
            "{name}",
        );
    }
}
