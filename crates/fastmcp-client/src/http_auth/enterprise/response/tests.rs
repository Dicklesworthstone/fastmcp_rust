//! Real signed fixtures use the public RFC7515 Appendix A.2 test RSA key.
//! Only public key material and compact signatures are retained here.

use super::*;
use crate::http_auth::enterprise::policy::{
    EnterpriseProfileConfiguration, EnterpriseRegistrationConfiguration,
    IdJagCryptoConfiguration, RequestedEnterpriseScopeSet,
    ID_JAG_GRANT_PROFILE, ID_JAG_TOKEN_TYPE, JWT_BEARER_GRANT, TOKEN_EXCHANGE_GRANT,
};
use fastmcp_core::{CanonicalHttpUrl, CanonicalResourceId, CanonicalResourceIdPolicy};
use serde_json::{Value, json};

fn fixtures() -> Value {
    serde_json::from_str(include_str!("assertions.json")).unwrap()
}
fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000)
}
fn headers() -> Vec<(String, String)> {
    vec![
        ("Content-Type".to_owned(), "application/json".to_owned()),
        ("Cache-Control".to_owned(), "no-store".to_owned()),
        ("Pragma".to_owned(), "no-cache".to_owned()),
    ]
}
fn profile(requested: &[&str]) -> EnterpriseProfile {
    let url = CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap();
    let cfg = EnterpriseProfileConfiguration {
        idp: EnterpriseRegistrationConfiguration {
            issuer: "https://idp.example".into(),
            token_endpoint: "https://idp.example/token".into(),
            client_id: "native-idp".into(),
            authentication: EnterpriseClientAuthentication::ClientSecretBasic,
            generation: 11,
            scope_allowance: vec!["openid".into(), "read".into(), "write".into()],
        },
        resource_as: EnterpriseRegistrationConfiguration {
            issuer: "https://as.example".into(),
            token_endpoint: "https://as.example/token".into(),
            client_id: "native-resource".into(),
            authentication: EnterpriseClientAuthentication::ClientSecretPost,
            generation: 12,
            scope_allowance: vec!["read".into(), "write".into()],
        },
        idp_authorization_endpoint: "https://idp.example/authorize".into(),
        oidc_jwks_uri: "https://idp.example/oidc-keys".into(),
        oidc_key_generation: 21,
        id_jag_crypto: IdJagCryptoConfiguration {
            issuer: "https://idp.example".into(),
            jwks_uri: "https://idp.example/id-jag-keys".into(),
            resource_as_issuer: "https://as.example".into(),
            algorithm: "RS256".into(),
            key_generation: 22,
            policy_generation: 23,
        },
        resource: CanonicalResourceId::parse_for_endpoint(
            url.as_str(), &url, CanonicalResourceIdPolicy::default(),
        ).unwrap(),
        requested_scopes: RequestedEnterpriseScopeSet::from_literals(
            requested.iter().map(|s| (*s).to_owned()),
        ).unwrap(),
        deployment_scope_allowance: vec!["read".into(), "write".into()],
        policy_generation: 30,
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
            "scopes_supported":["openid","read","write"]
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
    ].map(|value| serde_json::to_vec(&value).unwrap());
    EnterpriseProfile::from_documents(cfg, &docs[0], &docs[1], &docs[2], &docs[3], &docs[4]).unwrap()
}
fn keys() -> (OidcVerificationKeys, IdJagVerificationKeys) {
    let jwks = serde_json::to_vec(&fixtures()["jwks"]).unwrap();
    (
        OidcVerificationKeys::from_trusted_jwks("https://idp.example", 21, &jwks).unwrap(),
        IdJagVerificationKeys::from_trusted_jwks("https://idp.example", 22, &jwks).unwrap(),
    )
}
fn success<T>(outcome: EnterpriseResponseOutcome<T>) -> T {
    match outcome {
        EnterpriseResponseOutcome::Success { value, .. } => value,
        _ => panic!("expected the actual success branch"),
    }
}
fn jag_body() -> Value {
    json!({
        "access_token":fixtures()["id_jag"], "token_type":"N_A",
        "issued_token_type":ID_JAG_TOKEN_TYPE, "scope":"read", "expires_in":60
    })
}
fn access_body() -> Value {
    json!({
        "access_token":"final-opaque-token", "token_type":"Bearer",
        "resource":"https://mcp.example/mcp", "scope":"read", "expires_in":600
    })
}
fn jag(
    profile: &EnterpriseProfile, keys: &IdJagVerificationKeys, body: &Value, time: SystemTime,
) -> Result<EnterpriseResponseOutcome<EnterpriseIdJagResponse>, EnterpriseResponseError> {
    let headers = headers();
    let body = serde_json::to_vec(body).unwrap();
    profile.admit_id_jag_response(
        EnterpriseTokenResponse { status: 200, headers: &headers, body: &body },
        keys, TenantExpectation::SingleTenant, ResourceTenantExpectation::SingleTenant,
        EnterpriseResponsePolicy::default(), time,
    )
}
fn finish(
    admitted: EnterpriseIdJagResponse, body: &Value, time: SystemTime,
) -> Result<EnterpriseResponseOutcome<EnterpriseAccessTokenResponse>, EnterpriseResponseError> {
    let headers = headers();
    let body = serde_json::to_vec(body).unwrap();
    admitted.admit_access_token_response(
        EnterpriseTokenResponse { status: 200, headers: &headers, body: &body }, time,
    )
}

#[test]
fn enterprise_response_chain_preserves_all_three_scope_sets_and_exact_resource() {
    let profile = profile(&["write", "read"]);
    let (_, keys) = keys();
    let admitted = success(jag(&profile, &keys, &jag_body(), now()).unwrap());
    assert_eq!(admitted.assertion().subject().as_str(), "resource-facing");
    assert_eq!(admitted.requested_scopes(), ["read", "write"]);
    assert_eq!(admitted.granted_scopes(), ["read"]);
    assert_eq!(admitted.effective_expires_at(), now() + Duration::from_secs(60));
    let final_grant = success(finish(admitted, &access_body(), now() + Duration::from_secs(1)).unwrap());
    assert_eq!(final_grant.resource(), "https://mcp.example/mcp");
    assert_eq!(final_grant.requested_scopes(), ["read", "write"]);
    assert_eq!(final_grant.idp_granted_scopes(), ["read"]);
    assert_eq!(final_grant.granted_scopes(), ["read"]);
    assert_eq!(final_grant.expires_at(), now() + Duration::from_secs(601));
    fn send<T: Send>() {}
    send::<EnterpriseIdentityAssertion>();
    send::<EnterpriseIdJagResponse>();
    send::<EnterpriseAccessTokenResponse>();
}

#[test]
fn enterprise_response_scope_narrowing_needs_a_matching_explicit_idp_grant() {
    let selected = profile(&["read", "write"]);
    let (_, keys) = keys();
    for scope in [None, Some("write"), Some("read write"), Some(""), Some("read read")] {
        let mut body = jag_body();
        match scope {
            Some(scope) => { body["scope"] = json!(scope); }
            None => { body.as_object_mut().unwrap().remove("scope"); }
        }
        assert!(matches!(jag(&selected, &keys, &body, now()),
            Err(EnterpriseResponseError::ScopeRejected)));
    }
    assert!(jag(&selected, &keys, &jag_body(), now()).is_ok());
    let unchanged = profile(&["read"]);
    let mut body = jag_body();
    body.as_object_mut().unwrap().remove("scope");
    assert!(jag(&unchanged, &keys, &body, now()).is_ok());
}

#[test]
fn enterprise_final_response_requires_scalar_resource_and_explicit_scope_subset() {
    let profile = profile(&["read", "write"]);
    let (_, keys) = keys();
    let cases = [
        ("resource", Value::Null),
        ("resource", json!(["https://mcp.example/mcp"])),
        ("resource", json!("https://mcp.example/other")),
        ("resource", json!("https://MCP.example/mcp")),
        ("scope", Value::Null),
        ("scope", json!("")),
        ("scope", json!("write")),
        ("scope", json!("read write")),
        ("token_type", json!("DPoP")),
        ("refresh_token", Value::Null),
        ("authorization_details", json!([])),
    ];
    for (key, value) in cases {
        let admitted = success(jag(&profile, &keys, &jag_body(), now()).unwrap());
        let mut body = access_body();
        body[key] = value;
        assert!(finish(admitted, &body, now()).is_err(), "{key}");
    }
    for absent in ["resource", "scope"] {
        let admitted = success(jag(&profile, &keys, &jag_body(), now()).unwrap());
        let mut body = access_body();
        body.as_object_mut().unwrap().remove(absent);
        assert!(finish(admitted, &body, now()).is_err(), "{absent}");
    }
    let admitted = success(jag(&profile, &keys, &jag_body(), now()).unwrap());
    assert!(finish(admitted, &access_body(), now()).is_ok());
}

#[test]
fn enterprise_oidc_response_checks_real_signature_nonce_and_temporary_access_hash() {
    let profile = profile(&["read"]);
    let (keys, _) = keys();
    for (nonce, access, allowed) in [
        ("oidc-flow-nonce", "temporary-access", true),
        ("different-flow-nonce", "temporary-access", false),
        ("oidc-flow-nonce", "different-access", false),
    ] {
        let headers = headers();
        let body = serde_json::to_vec(&json!({
            "access_token":access, "token_type":"Bearer",
            "id_token":fixtures()["oidc"], "scope":"openid"
        })).unwrap();
        let result = profile.admit_oidc_code_response(
            EnterpriseTokenResponse { status:200, headers:&headers, body:&body },
            &keys, nonce, TenantExpectation::SingleTenant, Some(Duration::from_secs(60)),
            EnterpriseResponsePolicy::default(), now(),
        );
        if allowed {
            let assertion = success(result.unwrap());
            assert_eq!(assertion.identity().subject().as_str(), "client-facing");
            assert_eq!(assertion.identity().client_id(), "native-idp");
            assert_eq!(assertion.identity().expires_at(), now() + Duration::from_secs(240));
        } else {
            assert!(matches!(result, Err(EnterpriseResponseError::AssertionRejected)));
        }
    }
}

#[test]
fn enterprise_response_never_reinterprets_a_valid_signature_in_another_token_role() {
    let profile = profile(&["read"]);
    let (oidc_keys, jag_keys) = keys();
    let mut body = jag_body();
    body["access_token"] = fixtures()["oidc"].clone();
    assert!(matches!(jag(&profile, &jag_keys, &body, now()),
        Err(EnterpriseResponseError::AssertionRejected)));
    let headers = headers();
    let body = serde_json::to_vec(&json!({
        "access_token":"temporary-access", "token_type":"Bearer",
        "id_token":fixtures()["id_jag"], "scope":"openid"
    })).unwrap();
    assert!(matches!(profile.admit_oidc_code_response(
        EnterpriseTokenResponse { status:200, headers:&headers, body:&body },
        &oidc_keys, "oidc-flow-nonce", TenantExpectation::SingleTenant, None,
        EnterpriseResponsePolicy::default(), now(),
    ), Err(EnterpriseResponseError::AssertionRejected)));
}

#[test]
fn enterprise_response_refuses_wrong_key_generation_before_admitting_peer_data() {
    let profile = profile(&["read"]);
    let jwks = serde_json::to_vec(&fixtures()["jwks"]).unwrap();
    for (issuer, generation) in [("https://idp.example", 21), ("https://other.example", 22)] {
        let keys = IdJagVerificationKeys::from_trusted_jwks(issuer, generation, &jwks).unwrap();
        assert!(matches!(jag(&profile, &keys, &jag_body(), now()),
            Err(EnterpriseResponseError::PolicyBindingMismatch)));
    }
    let (_, keys) = keys();
    assert!(jag(&profile, &keys, &jag_body(), now()).is_ok());
}

#[test]
fn enterprise_response_expiry_is_earliest_and_final_admission_refuses_clock_rewind() {
    let profile = profile(&["read"]);
    let (_, keys) = keys();
    for time in [now() - Duration::from_secs(1), now() + Duration::from_secs(60)] {
        let admitted = success(jag(&profile, &keys, &jag_body(), now()).unwrap());
        assert!(matches!(finish(admitted, &access_body(), time),
            Err(EnterpriseResponseError::InvalidLifetime)));
    }
    let mut without_duration = jag_body();
    without_duration.as_object_mut().unwrap().remove("expires_in");
    let admitted = success(jag(&profile, &keys, &without_duration, now()).unwrap());
    assert_eq!(admitted.effective_expires_at(), now() + Duration::from_secs(240));
    let mut late = jag_body();
    late["expires_in"] = json!(300);
    assert!(matches!(jag(&profile, &keys, &late, now() + Duration::from_secs(240)),
        Err(EnterpriseResponseError::InvalidLifetime)));
}

#[test]
fn enterprise_public_step_up_surfaces_only_a_bounded_new_flow_indication() {
    let profile = profile(&["read"]);
    let (_, keys) = keys();
    let headers = headers();
    for maximum in [None, Some(0), Some(600)] {
        let mut body = json!({
            "error":"insufficient_user_authentication",
            "error_description":"Fresh login is required", "acr_values":"never-forward-this"
        });
        if let Some(value) = maximum { body["max_age"] = json!(value); }
        let body = serde_json::to_vec(&body).unwrap();
        let result = profile.admit_id_jag_response(
            EnterpriseTokenResponse { status:400, headers:&headers, body:&body },
            &keys, TenantExpectation::SingleTenant, ResourceTenantExpectation::SingleTenant,
            EnterpriseResponsePolicy::default(), now(),
        ).unwrap();
        match result {
            EnterpriseResponseOutcome::StepUpRequired { requirement, .. } => {
                assert_eq!(requirement.maximum_authentication_age(), maximum.map(Duration::from_secs));
            }
            _ => panic!("expected an explicit step-up indication"),
        }
    }
}

#[test]
fn enterprise_effective_expiry_uses_one_time_and_checked_absolute_limits() {
    let now = now();
    let signed = now + Duration::from_secs(240);
    let cap = Duration::from_secs(300);
    assert_eq!(bounded_expiry(now, Some(60), 900, cap, Some(signed)).unwrap(),
        now + Duration::from_secs(60));
    assert_eq!(bounded_expiry(now, Some(600), 900, cap, Some(signed)).unwrap(), signed);
    assert_eq!(bounded_expiry(now, None, 900, cap, Some(signed)).unwrap(), signed);
    assert_eq!(bounded_expiry(now, None, 900, cap, Some(now + Duration::from_secs(600))).unwrap(),
        now + cap);
    for invalid in [Some(0), Some(901), Some(u64::MAX)] {
        assert_eq!(bounded_expiry(now, invalid, 900, cap, Some(signed)),
            Err(EnterpriseResponseError::InvalidLifetime));
    }
    assert_eq!(bounded_expiry(now, None, 900, cap, Some(now)),
        Err(EnterpriseResponseError::InvalidLifetime));
}
