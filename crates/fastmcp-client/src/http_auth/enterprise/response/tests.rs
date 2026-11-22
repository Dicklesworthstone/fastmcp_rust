//! Real signed fixtures use the public RFC7515 Appendix A.2 test RSA key.
//! Only public key material and compact signatures are retained here.

use super::*;
use crate::http_auth::enterprise::oidc::tests::{
    grant_for_exchange, token_body as oidc_token_body,
};
use crate::http_auth::enterprise::policy::{
    EnterpriseProfileConfiguration, EnterpriseRegistrationConfiguration, ID_JAG_GRANT_PROFILE,
    ID_JAG_TOKEN_TYPE, IdJagCryptoConfiguration, JWT_BEARER_GRANT, RequestedEnterpriseScopeSet,
    TOKEN_EXCHANGE_GRANT,
};
use crate::http_auth::enterprise::replay::tests::ExchangeReplayFixture;
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
    profile_with_authentication(
        requested,
        EnterpriseClientAuthentication::ClientSecretBasic,
        EnterpriseClientAuthentication::ClientSecretPost,
    )
}

fn profile_with_authentication(
    requested: &[&str],
    idp_authentication: EnterpriseClientAuthentication,
    resource_as_authentication: EnterpriseClientAuthentication,
) -> EnterpriseProfile {
    profile_for_http_resource(
        requested,
        idp_authentication,
        resource_as_authentication,
        "https://mcp.example/mcp",
        30,
    )
}

fn profile_for_http_resource(
    requested: &[&str],
    idp_authentication: EnterpriseClientAuthentication,
    resource_as_authentication: EnterpriseClientAuthentication,
    resource: &str,
    policy_generation: u64,
) -> EnterpriseProfile {
    let url = CanonicalHttpUrl::parse(resource).unwrap();
    let cfg = EnterpriseProfileConfiguration {
        idp: EnterpriseRegistrationConfiguration {
            issuer: "https://idp.example".into(),
            token_endpoint: "https://idp.example/token".into(),
            client_id: "native-idp".into(),
            authentication: idp_authentication,
            generation: 11,
            scope_allowance: vec!["openid".into(), "read".into(), "write".into()],
        },
        resource_as: EnterpriseRegistrationConfiguration {
            issuer: "https://as.example".into(),
            token_endpoint: "https://as.example/token".into(),
            client_id: "native-resource".into(),
            authentication: resource_as_authentication,
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
            url.as_str(),
            &url,
            CanonicalResourceIdPolicy::default(),
        )
        .unwrap(),
        requested_scopes: RequestedEnterpriseScopeSet::from_literals(
            requested.iter().map(|s| (*s).to_owned()),
        )
        .unwrap(),
        deployment_scope_allowance: vec!["read".into(), "write".into()],
        policy_generation,
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
            "token_endpoint_auth_methods_supported":[idp_authentication.as_str()],
            "identity_chaining_requested_token_types_supported":[ID_JAG_TOKEN_TYPE],
            "id_token_signing_alg_values_supported":["RS256"],
            "scopes_supported":["openid","read","write"]
        }),
        json!({
            "issuer":"https://as.example", "token_endpoint":"https://as.example/token",
            "authorization_grant_profiles_supported":[ID_JAG_GRANT_PROFILE],
            "grant_types_supported":[JWT_BEARER_GRANT],
            "token_endpoint_auth_methods_supported":[resource_as_authentication.as_str()]
        }),
        json!({
            "authorization_grant_profiles_supported":[ID_JAG_GRANT_PROFILE],
            "grant_types":[TOKEN_EXCHANGE_GRANT,JWT_BEARER_GRANT]
        }),
        json!({
            "issuer":"https://idp.example", "token_endpoint":"https://idp.example/token",
            "client_id":"native-idp", "grant_types":["authorization_code",TOKEN_EXCHANGE_GRANT],
            "token_endpoint_auth_method":idp_authentication.as_str()
        }),
        json!({
            "issuer":"https://as.example", "token_endpoint":"https://as.example/token",
            "client_id":"native-resource", "grant_types":[JWT_BEARER_GRANT],
            "token_endpoint_auth_method":resource_as_authentication.as_str()
        }),
    ]
    .map(|value| serde_json::to_vec(&value).unwrap());
    EnterpriseProfile::from_documents(cfg, &docs[0], &docs[1], &docs[2], &docs[3], &docs[4])
        .unwrap()
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
    profile: &EnterpriseProfile,
    keys: &IdJagVerificationKeys,
    body: &Value,
    time: SystemTime,
) -> Result<EnterpriseResponseOutcome<EnterpriseIdJagResponse>, EnterpriseResponseError> {
    let headers = headers();
    let body = serde_json::to_vec(body).unwrap();
    profile.admit_id_jag_response(
        EnterpriseTokenResponse {
            status: 200,
            headers: &headers,
            body: &body,
        },
        keys,
        TenantExpectation::SingleTenant,
        ResourceTenantExpectation::SingleTenant,
        EnterpriseResponsePolicy::default(),
        time,
    )
}
fn finish(
    admitted: EnterpriseIdJagResponse,
    body: &Value,
    time: SystemTime,
) -> Result<EnterpriseResponseOutcome<EnterpriseAccessTokenResponse>, EnterpriseResponseError> {
    let headers = headers();
    let body = serde_json::to_vec(body).unwrap();
    admitted.admit_access_token_response(
        EnterpriseTokenResponse {
            status: 200,
            headers: &headers,
            body: &body,
        },
        time,
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
    assert_eq!(
        admitted.effective_expires_at(),
        now() + Duration::from_secs(60)
    );
    let final_grant =
        success(finish(admitted, &access_body(), now() + Duration::from_secs(1)).unwrap());
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
    for scope in [
        None,
        Some("write"),
        Some("read write"),
        Some(""),
        Some("read read"),
    ] {
        let mut body = jag_body();
        match scope {
            Some(scope) => {
                body["scope"] = json!(scope);
            }
            None => {
                body.as_object_mut().unwrap().remove("scope");
            }
        }
        assert!(matches!(
            jag(&selected, &keys, &body, now()),
            Err(EnterpriseResponseError::ScopeRejected)
        ));
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
        }))
        .unwrap();
        let result = profile.admit_oidc_code_response(
            EnterpriseTokenResponse {
                status: 200,
                headers: &headers,
                body: &body,
            },
            &keys,
            nonce,
            TenantExpectation::SingleTenant,
            Some(Duration::from_secs(60)),
            EnterpriseResponsePolicy::default(),
            now(),
        );
        if allowed {
            let assertion = success(result.unwrap());
            assert_eq!(assertion.identity().subject().as_str(), "client-facing");
            assert_eq!(assertion.identity().client_id(), "native-idp");
            assert_eq!(
                assertion.identity().expires_at(),
                now() + Duration::from_secs(240)
            );
        } else {
            assert!(matches!(
                result,
                Err(EnterpriseResponseError::AssertionRejected)
            ));
        }
    }
}

#[test]
fn enterprise_response_never_reinterprets_a_valid_signature_in_another_token_role() {
    let profile = profile(&["read"]);
    let (oidc_keys, jag_keys) = keys();
    let mut body = jag_body();
    body["access_token"] = fixtures()["oidc"].clone();
    assert!(matches!(
        jag(&profile, &jag_keys, &body, now()),
        Err(EnterpriseResponseError::AssertionRejected)
    ));
    let headers = headers();
    let body = serde_json::to_vec(&json!({
        "access_token":"temporary-access", "token_type":"Bearer",
        "id_token":fixtures()["id_jag"], "scope":"openid"
    }))
    .unwrap();
    assert!(matches!(
        profile.admit_oidc_code_response(
            EnterpriseTokenResponse {
                status: 200,
                headers: &headers,
                body: &body
            },
            &oidc_keys,
            "oidc-flow-nonce",
            TenantExpectation::SingleTenant,
            None,
            EnterpriseResponsePolicy::default(),
            now(),
        ),
        Err(EnterpriseResponseError::AssertionRejected)
    ));
}

#[test]
fn enterprise_response_refuses_wrong_key_generation_before_admitting_peer_data() {
    let profile = profile(&["read"]);
    let jwks = serde_json::to_vec(&fixtures()["jwks"]).unwrap();
    for (issuer, generation) in [("https://idp.example", 21), ("https://other.example", 22)] {
        let keys = IdJagVerificationKeys::from_trusted_jwks(issuer, generation, &jwks).unwrap();
        assert!(matches!(
            jag(&profile, &keys, &jag_body(), now()),
            Err(EnterpriseResponseError::PolicyBindingMismatch)
        ));
    }
    let (_, keys) = keys();
    assert!(jag(&profile, &keys, &jag_body(), now()).is_ok());
}

#[test]
fn enterprise_response_expiry_is_earliest_and_final_admission_refuses_clock_rewind() {
    let profile = profile(&["read"]);
    let (_, keys) = keys();
    for time in [
        now() - Duration::from_secs(1),
        now() + Duration::from_secs(60),
    ] {
        let admitted = success(jag(&profile, &keys, &jag_body(), now()).unwrap());
        assert!(matches!(
            finish(admitted, &access_body(), time),
            Err(EnterpriseResponseError::InvalidLifetime)
        ));
    }
    let mut without_duration = jag_body();
    without_duration
        .as_object_mut()
        .unwrap()
        .remove("expires_in");
    let admitted = success(jag(&profile, &keys, &without_duration, now()).unwrap());
    assert_eq!(
        admitted.effective_expires_at(),
        now() + Duration::from_secs(240)
    );
    let mut late = jag_body();
    late["expires_in"] = json!(300);
    assert!(matches!(
        jag(&profile, &keys, &late, now() + Duration::from_secs(240)),
        Err(EnterpriseResponseError::InvalidLifetime)
    ));
}

#[test]
fn enterprise_oidc_basic_400_exception_does_not_admit_id_jag_denials() {
    let selected = profile(&["read"]);
    let (oidc_keys, jag_keys) = keys();
    let body = br#"{"error":"invalid_client"}"#;
    for (status, challenged, oidc_allowed, jag_allowed) in [
        (400, false, true, false),
        (400, true, true, false),
        (401, false, false, false),
        (401, true, true, true),
    ] {
        let mut fields = headers();
        if challenged {
            fields.push(("WWW-Authenticate".into(), r#"Basic realm="issuer""#.into()));
        }
        let oidc = selected.admit_oidc_code_response(
            EnterpriseTokenResponse {
                status,
                headers: &fields,
                body,
            },
            &oidc_keys,
            "oidc-flow-nonce",
            TenantExpectation::SingleTenant,
            None,
            EnterpriseResponsePolicy::default(),
            now(),
        );
        assert_enterprise_client_denial(oidc, status, oidc_allowed);
        let exchanged = selected.admit_id_jag_response(
            EnterpriseTokenResponse {
                status,
                headers: &fields,
                body,
            },
            &jag_keys,
            TenantExpectation::SingleTenant,
            ResourceTenantExpectation::SingleTenant,
            EnterpriseResponsePolicy::default(),
            now(),
        );
        assert_enterprise_client_denial(exchanged, status, jag_allowed);
    }
}

#[test]
fn enterprise_final_client_denials_follow_the_selected_registration() {
    use EnterpriseClientAuthentication::{ClientSecretBasic, ClientSecretPost};

    let (_, jag_keys) = keys();
    let body = br#"{"error":"invalid_client"}"#;
    for (authentication, status, challenged, allowed) in [
        (ClientSecretBasic, 400, false, false),
        (ClientSecretBasic, 400, true, false),
        (ClientSecretBasic, 401, false, false),
        (ClientSecretBasic, 401, true, true),
        (ClientSecretPost, 400, false, true),
        (ClientSecretPost, 400, true, true),
        (ClientSecretPost, 401, false, false),
        (ClientSecretPost, 401, true, false),
    ] {
        // Acquire a genuine signed ID-JAG through the public profile path so
        // the final stage must retain the selected resource-AS method.
        let selected = profile_with_authentication(&["read"], ClientSecretBasic, authentication);
        let admitted = success(jag(&selected, &jag_keys, &jag_body(), now()).unwrap());
        let mut fields = headers();
        if challenged {
            fields.push(("WWW-Authenticate".into(), r#"Basic realm="issuer""#.into()));
        }
        let result = admitted.admit_access_token_response(
            EnterpriseTokenResponse {
                status,
                headers: &fields,
                body,
            },
            now(),
        );
        assert_enterprise_client_denial(result, status, allowed);
    }
}

#[test]
fn enterprise_form_authenticated_id_jag_denials_keep_oauth_400_semantics() {
    use EnterpriseClientAuthentication::ClientSecretPost;

    let selected = profile_with_authentication(&["read"], ClientSecretPost, ClientSecretPost);
    let (_, jag_keys) = keys();
    let mut fields = headers();
    fields.push(("WWW-Authenticate".into(), r#"Basic realm="issuer""#.into()));
    let body = br#"{"error":"invalid_client"}"#;
    for (status, allowed) in [(400, true), (401, false), (403, false), (500, false)] {
        let result = selected.admit_id_jag_response(
            EnterpriseTokenResponse {
                status,
                headers: &fields,
                body,
            },
            &jag_keys,
            TenantExpectation::SingleTenant,
            ResourceTenantExpectation::SingleTenant,
            EnterpriseResponsePolicy::default(),
            now(),
        );
        assert_enterprise_client_denial(result, status, allowed);
    }
}

fn assert_enterprise_client_denial<T>(
    result: Result<EnterpriseResponseOutcome<T>, EnterpriseResponseError>,
    status: u16,
    allowed: bool,
) {
    match result {
        Ok(EnterpriseResponseOutcome::Denied { denial, .. }) => {
            assert!(allowed, "unexpected typed denial at status {status}");
            assert_eq!(denial.code(), EnterpriseOAuthErrorCode::InvalidClient);
            assert_eq!(denial.status(), status);
            assert_eq!(denial.matched_basic_challenge(), status == 401);
        }
        Err(EnterpriseResponseError::UnexpectedStatus) => {
            assert!(!allowed, "expected typed denial at status {status}");
        }
        _ => panic!("unexpected enterprise response outcome at status {status}"),
    }
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
        if let Some(value) = maximum {
            body["max_age"] = json!(value);
        }
        let body = serde_json::to_vec(&body).unwrap();
        let result = profile
            .admit_id_jag_response(
                EnterpriseTokenResponse {
                    status: 400,
                    headers: &headers,
                    body: &body,
                },
                &keys,
                TenantExpectation::SingleTenant,
                ResourceTenantExpectation::SingleTenant,
                EnterpriseResponsePolicy::default(),
                now(),
            )
            .unwrap();
        match result {
            EnterpriseResponseOutcome::StepUpRequired { requirement, .. } => {
                assert_eq!(
                    requirement.maximum_authentication_age(),
                    maximum.map(Duration::from_secs)
                );
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
    assert_eq!(
        bounded_expiry(now, Some(60), 900, cap, Some(signed)).unwrap(),
        now + Duration::from_secs(60)
    );
    assert_eq!(
        bounded_expiry(now, Some(600), 900, cap, Some(signed)).unwrap(),
        signed
    );
    assert_eq!(
        bounded_expiry(now, None, 900, cap, Some(signed)).unwrap(),
        signed
    );
    assert_eq!(
        bounded_expiry(now, None, 900, cap, Some(now + Duration::from_secs(600))).unwrap(),
        now + cap
    );
    for invalid in [Some(0), Some(901), Some(u64::MAX)] {
        assert_eq!(
            bounded_expiry(now, invalid, 900, cap, Some(signed)),
            Err(EnterpriseResponseError::InvalidLifetime)
        );
    }
    assert_eq!(
        bounded_expiry(now, None, 900, cap, Some(now)),
        Err(EnterpriseResponseError::InvalidLifetime)
    );
}

fn disclosure_policy(expires_after: u64) -> IdJagDisclosurePolicy {
    use super::super::verification::disclosure::{
        IdJagDisclosureClaim, IdJagDisclosureConfiguration, IdJagDisclosureRule,
    };
    IdJagDisclosurePolicy::from_trusted_configuration(IdJagDisclosureConfiguration {
        policy_id: "reviewed-email-discard".to_owned(),
        generation: 41,
        idp_issuer: "https://idp.example".to_owned(),
        resource_as_issuer: "https://as.example".to_owned(),
        reviewed_at: now() - Duration::from_secs(1),
        review_expires_at: now() + Duration::from_secs(expires_after),
        rules: vec![IdJagDisclosureRule {
            claim: IdJagDisclosureClaim::Email,
            purpose: "Validate and discard an issuer-mandated signed disclosure".to_owned(),
        }],
    })
    .unwrap()
}

fn disclosure_body() -> Value {
    let fixture: Value = serde_json::from_str(include_str!("disclosure_assertions.json")).unwrap();
    let mut body = jag_body();
    body["access_token"] = fixture["id_jag"].clone();
    body
}

fn disclosed_jag(
    profile: &EnterpriseProfile,
    keys: &IdJagVerificationKeys,
    body: &Value,
    disclosure: &IdJagDisclosurePolicy,
    at: SystemTime,
) -> Result<EnterpriseResponseOutcome<EnterpriseIdJagResponse>, EnterpriseResponseError> {
    let headers = headers();
    let body = serde_json::to_vec(body).unwrap();
    profile.admit_id_jag_response_with_disclosure(
        EnterpriseTokenResponse {
            status: 200,
            headers: &headers,
            body: &body,
        },
        keys,
        TenantExpectation::SingleTenant,
        ResourceTenantExpectation::SingleTenant,
        EnterpriseResponsePolicy::default(),
        disclosure,
        at,
    )
}

#[test]
fn optional_signed_disclosure_requires_explicit_policy_and_preserves_final_provenance() {
    use super::super::verification::disclosure::IdJagDisclosureClaim;
    let selected = profile(&["read"]);
    let (_, keys) = keys();
    let body = disclosure_body();
    let disclosure = disclosure_policy(30);
    assert!(matches!(
        jag(&selected, &keys, &body, now()),
        Err(EnterpriseResponseError::AssertionRejected)
    ));
    let admitted = success(disclosed_jag(&selected, &keys, &body, &disclosure, now()).unwrap());
    assert_eq!(
        admitted.effective_expires_at(),
        now() + Duration::from_secs(30)
    );
    assert_eq!(admitted.granted_scopes(), ["read"]);
    let facts = admitted.assertion().disclosure().unwrap();
    assert_eq!(facts.admitted_claims(), &[IdJagDisclosureClaim::Email]);
    assert_eq!(
        facts.configuration_digest(),
        disclosure.configuration_digest()
    );
    assert_eq!(facts.generation(), 41);
    let headers = headers();
    let access = serde_json::to_vec(&access_body()).unwrap();
    let token = success(
        admitted
            .admit_access_token_response(
                EnterpriseTokenResponse {
                    status: 200,
                    headers: &headers,
                    body: &access,
                },
                now() + Duration::from_secs(1),
            )
            .unwrap(),
    );
    assert_eq!(token.expires_at(), now() + Duration::from_secs(30));
    assert_eq!(token.granted_scopes(), ["read"]);
    let retained = token.id_jag_disclosure().unwrap();
    assert_eq!(
        retained.configuration_digest(),
        disclosure.configuration_digest()
    );
    assert_eq!(retained.admitted_claims(), &[IdJagDisclosureClaim::Email]);
    let debug = format!("{retained:?}");
    assert!(!debug.contains("hidden-contact"));
    assert!(!debug.contains("reviewed-email-discard"));
}

#[test]
fn disclosure_review_expiry_cannot_cross_initial_or_final_response_admission() {
    let selected = profile(&["read"]);
    let (_, keys) = keys();
    let body = disclosure_body();
    let disclosure = disclosure_policy(30);
    for elapsed in [30, 31] {
        let time = now() + Duration::from_secs(elapsed);
        assert!(matches!(
            disclosed_jag(&selected, &keys, &body, &disclosure, time),
            Err(EnterpriseResponseError::AssertionRejected)
        ));
        let admitted = success(disclosed_jag(&selected, &keys, &body, &disclosure, now()).unwrap());
        let headers = headers();
        let access = serde_json::to_vec(&access_body()).unwrap();
        assert!(matches!(
            admitted.admit_access_token_response(
                EnterpriseTokenResponse {
                    status: 200,
                    headers: &headers,
                    body: &access
                },
                time,
            ),
            Err(EnterpriseResponseError::InvalidLifetime)
        ));
    }
}

// ============================================================================
// EnterpriseExchangeDriver tests (AUTHX-01..03, positive + RH-5 negatives)
// ============================================================================

pub(super) trait ExchangePoster: Send + Sync {
    fn post<'a>(
        &'a self,
        cx: &'a Cx,
        url: &'a GuardedHttpsUrl,
        request: &'a GuardedHttpRequest,
        lifetime: Arc<dyn Send + Sync>,
    ) -> std::pin::Pin<
        Box<
            dyn Future<Output = Result<GuardedHttpFetchResponse, GuardedHttpFetchError>>
                + Send
                + 'a,
        >,
    >;
}

struct RecordedPost {
    host: String,
    content_type: String,
    has_authorization: bool,
    body: String,
}

struct ScriptedExchangePoster {
    responses: std::sync::Mutex<
        std::collections::VecDeque<Result<GuardedHttpFetchResponse, GuardedHttpFetchError>>,
    >,
    recorded: std::sync::Mutex<Vec<RecordedPost>>,
    quarantine_before_reply: Option<Arc<ExchangeReplayFixture>>,
}

impl ScriptedExchangePoster {
    fn new(responses: Vec<Result<GuardedHttpFetchResponse, GuardedHttpFetchError>>) -> Arc<Self> {
        Arc::new(Self {
            responses: std::sync::Mutex::new(responses.into()),
            recorded: std::sync::Mutex::new(Vec::new()),
            quarantine_before_reply: None,
        })
    }

    fn take_recorded(&self) -> Vec<RecordedPost> {
        std::mem::take(&mut *self.recorded.lock().unwrap())
    }
}

impl ExchangePoster for ScriptedExchangePoster {
    fn post<'a>(
        &'a self,
        cx: &'a Cx,
        url: &'a GuardedHttpsUrl,
        request: &'a GuardedHttpRequest,
        _lifetime: Arc<dyn Send + Sync>,
    ) -> std::pin::Pin<
        Box<
            dyn Future<Output = Result<GuardedHttpFetchResponse, GuardedHttpFetchError>>
                + Send
                + 'a,
        >,
    > {
        self.recorded.lock().unwrap().push(RecordedPost {
            host: url.host().to_owned(),
            content_type: request.content_type().to_owned(),
            has_authorization: request.has_authorization(),
            body: String::from_utf8(request.body().to_vec()).expect("utf-8 form body"),
        });
        let next = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted exchange response");
        Box::pin(async move {
            if let Some(fixture) = &self.quarantine_before_reply {
                fixture.quarantine(cx).await;
            }
            next
        })
    }
}

fn test_fetcher() -> GuardedHttpFetcher {
    let policy = fastmcp_transport::GuardedHttpFetchPolicy::new(
        MAX_ENTERPRISE_EXCHANGE_RESPONSE_BYTES,
        Duration::from_secs(5),
        Duration::from_secs(2),
        "test-root-rev-1",
    )
    .expect("valid guarded fetch policy");
    GuardedHttpFetcher::new(policy).expect("webpki guarded fetcher")
}

fn ok_exchange_response(
    host: &str,
    root_identity: &str,
    body: Vec<u8>,
) -> GuardedHttpFetchResponse {
    GuardedHttpFetchResponse {
        status: 200,
        headers: headers(),
        body,
        redirect: None,
        provenance: GuardedHttpPeerProvenance {
            host: host.to_owned(),
            selected_address: std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 10)),
                443,
            ),
            root_policy_revision: root_identity.to_owned(),
            alpn: Some(b"http/1.1".to_vec()),
            tls_protocol: Some("TLSv1.3".to_owned()),
            leaf_certificate_sha256: [0x22; 32],
        },
    }
}

fn driver_with_poster(
    selected: EnterpriseProfile,
    poster: Arc<ScriptedExchangePoster>,
) -> (EnterpriseExchangeDriver, String) {
    let fetcher = test_fetcher();
    let root_id = fetcher.root_identity().to_owned();
    let idp_token_url = GuardedHttpsUrl::parse(selected.idp_token_endpoint()).unwrap();
    let resource_as_token_url =
        GuardedHttpsUrl::parse(selected.resource_as_token_endpoint()).unwrap();
    let inner = ExchangeDriverInner {
        profile: selected,
        idp_token_url,
        resource_as_token_url,
        fetcher,
        response_policy: EnterpriseResponsePolicy::default(),
        busy: Arc::new(AtomicBool::new(false)),
        test_post: Some(poster),
    };
    (
        EnterpriseExchangeDriver {
            inner: Arc::new(inner),
        },
        root_id,
    )
}

fn run_exchange_async<T>(f: impl Future<Output = T>) -> T {
    let rt = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().expect("reactor"))
        .build()
        .expect("enterprise exchange test runtime");
    rt.block_on(f)
}

#[test]
fn enterprise_oidc_code_redemption_reaches_bearer_through_both_confidential_methods() {
    let (oidc_keys, jag_keys) = keys();
    let secret = EnterpriseClientSecret::try_new("client + secret:/=").unwrap();
    for authentication in [
        EnterpriseClientAuthentication::ClientSecretBasic,
        EnterpriseClientAuthentication::ClientSecretPost,
    ] {
        let selected = profile_with_authentication(
            &["read"],
            authentication,
            EnterpriseClientAuthentication::ClientSecretPost,
        );
        let fetcher = test_fetcher();
        let poster = ScriptedExchangePoster::new(vec![
            Ok(ok_exchange_response(
                "idp.example",
                fetcher.root_identity(),
                oidc_token_body(),
            )),
            Ok(ok_exchange_response(
                "idp.example",
                fetcher.root_identity(),
                serde_json::to_vec(&jag_body()).unwrap(),
            )),
            Ok(ok_exchange_response(
                "as.example",
                fetcher.root_identity(),
                serde_json::to_vec(&access_body()).unwrap(),
            )),
        ]);
        let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
        run_exchange_async(async {
            let cx = Cx::current().unwrap();
            let (outcome, observation) = driver
                .exchange_oidc_code_for_identity(
                    &cx,
                    grant_for_exchange(selected.clone(), EnterpriseResponsePolicy::default(), 0x22),
                    &secret,
                    &oidc_keys,
                    now(),
                )
                .await
                .unwrap();
            let identity = success(outcome);
            assert_eq!(observation.endpoint(), "https://idp.example/token");
            assert_eq!(identity.identity().subject().as_str(), "client-subject");
            assert_eq!(identity.identity().client_id(), "native-idp");
            assert_eq!(identity.identity().generation(), 21);
            let replay = ExchangeReplayFixture::new(&cx);
            let reserved = replay
                .reserve(&cx, &selected, identity, now() + Duration::from_secs(1))
                .await
                .unwrap();
            let (outcome, _) = driver
                .exchange_identity_for_id_jag(
                    &cx,
                    reserved,
                    &secret,
                    &jag_keys,
                    TenantExpectation::SingleTenant,
                    ResourceTenantExpectation::SingleTenant,
                    now() + Duration::from_secs(1),
                )
                .await
                .unwrap();
            let (outcome, _) = driver
                .exchange_id_jag_for_access_token(
                    &cx,
                    success(outcome),
                    &secret,
                    now() + Duration::from_secs(2),
                )
                .await
                .unwrap();
            let bearer = success(outcome)
                .into_bound_bearer_credential(Instant::now(), now() + Duration::from_secs(3))
                .unwrap();
            assert_eq!(
                bearer
                    .authorization_for_target(
                        &CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap()
                    )
                    .as_deref(),
                Some("Bearer final-opaque-token")
            );
            assert!(
                bearer
                    .authorization_for_target(
                        &CanonicalHttpUrl::parse("https://other.example/mcp").unwrap()
                    )
                    .is_none()
            );
            assert_eq!(replay.reserved_aliases(), 2);
        });
        let recorded = poster.take_recorded();
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[0].host, "idp.example");
        assert_eq!(
            recorded[0].content_type,
            "application/x-www-form-urlencoded"
        );
        let unauthenticated_form = concat!(
            "grant_type=authorization_code&code=one-time%2Bcode%3Dvalue",
            "&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback",
            "&code_verifier=MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM"
        );
        if authentication == EnterpriseClientAuthentication::ClientSecretBasic {
            assert!(recorded[0].has_authorization);
            assert_eq!(recorded[0].body, unauthenticated_form);
        } else {
            assert!(!recorded[0].has_authorization);
            assert_eq!(
                recorded[0].body,
                format!(
                    "{unauthenticated_form}&client_id=native-idp&client_secret=client+%2B+secret%3A%2F%3D"
                )
            );
        }
        assert!(!recorded[0].body.contains("scope="));
        assert!(!recorded[0].body.contains("resource="));
        assert!(!recorded[0].body.contains("audience="));
        assert!(!driver.inner.busy.load(Ordering::Acquire));
    }
}

#[test]
fn enterprise_oidc_code_redemption_rejects_nonce_and_temporary_token_substitution() {
    let selected = profile(&["read"]);
    let (oidc_keys, _) = keys();
    let secret = EnterpriseClientSecret::try_new("confidential-canary").unwrap();
    for different_nonce in [true, false] {
        let body = if different_nonce {
            oidc_token_body()
        } else {
            let mut body: Value = serde_json::from_slice(&oidc_token_body()).unwrap();
            body["access_token"] = json!("substituted-temporary-access");
            serde_json::to_vec(&body).unwrap()
        };
        let fetcher = test_fetcher();
        let poster = ScriptedExchangePoster::new(vec![Ok(ok_exchange_response(
            "idp.example",
            fetcher.root_identity(),
            body,
        ))]);
        let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
        run_exchange_async(async {
            let cx = Cx::current().unwrap();
            let result = driver
                .exchange_oidc_code_for_identity(
                    &cx,
                    grant_for_exchange(
                        selected.clone(),
                        EnterpriseResponsePolicy::default(),
                        if different_nonce { 0x23 } else { 0x22 },
                    ),
                    &secret,
                    &oidc_keys,
                    now(),
                )
                .await;
            assert_eq!(
                result.err(),
                Some(EnterpriseExchangeError::CodeFlowRejected(
                    OidcCodeFlowError::TokenResponseRejected
                ))
            );
        });
        assert_eq!(poster.take_recorded().len(), 1);
        assert!(!driver.inner.busy.load(Ordering::Acquire));
    }
}

#[test]
fn enterprise_oidc_code_redemption_rejects_binding_drift_before_any_post() {
    let selected = profile(&["read"]);
    let (oidc_keys, _) = keys();
    let secret = EnterpriseClientSecret::try_new("confidential-canary").unwrap();
    let poster = ScriptedExchangePoster::new(vec![]);
    let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
    let different_policy = EnterpriseResponsePolicy::new(
        Duration::from_secs(1800),
        Duration::from_secs(300),
        Duration::from_secs(3600),
        Duration::from_secs(60),
        Duration::from_hours(24),
    )
    .unwrap();
    run_exchange_async(async {
        let cx = Cx::current().unwrap();
        for grant in [
            grant_for_exchange(
                profile(&["write"]),
                EnterpriseResponsePolicy::default(),
                0x22,
            ),
            grant_for_exchange(selected.clone(), different_policy, 0x22),
        ] {
            assert_eq!(
                driver
                    .exchange_oidc_code_for_identity(&cx, grant, &secret, &oidc_keys, now())
                    .await
                    .err(),
                Some(EnterpriseExchangeError::ResponseRejected(
                    EnterpriseResponseError::PolicyBindingMismatch
                ))
            );
        }
        for (issuer, generation) in [("https://other.example", 21), ("https://idp.example", 22)] {
            let wrong_keys = OidcVerificationKeys::from_trusted_jwks(
                issuer,
                generation,
                &serde_json::to_vec(&fixtures()["jwks"]).unwrap(),
            )
            .unwrap();
            assert_eq!(
                driver
                    .exchange_oidc_code_for_identity(
                        &cx,
                        grant_for_exchange(
                            selected.clone(),
                            EnterpriseResponsePolicy::default(),
                            0x22
                        ),
                        &secret,
                        &wrong_keys,
                        now(),
                    )
                    .await
                    .err(),
                Some(EnterpriseExchangeError::ResponseRejected(
                    EnterpriseResponseError::PolicyBindingMismatch
                ))
            );
        }
    });
    assert!(poster.take_recorded().is_empty());
    assert!(!driver.inner.busy.load(Ordering::Acquire));
}

#[test]
fn enterprise_oidc_code_redemption_checks_lifetime_runtime_and_singleflight_before_post() {
    let selected = profile(&["read"]);
    let (oidc_keys, _) = keys();
    let secret = EnterpriseClientSecret::try_new("confidential-canary").unwrap();
    let poster = ScriptedExchangePoster::new(vec![]);
    let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
    run_exchange_async(async {
        let cx = Cx::current().unwrap();
        for time in [
            now() - Duration::from_secs(1),
            now() + Duration::from_secs(300),
        ] {
            assert_eq!(
                driver
                    .exchange_oidc_code_for_identity(
                        &cx,
                        grant_for_exchange(
                            selected.clone(),
                            EnterpriseResponsePolicy::default(),
                            0x22
                        ),
                        &secret,
                        &oidc_keys,
                        time,
                    )
                    .await
                    .err(),
                Some(EnterpriseExchangeError::CodeFlowRejected(
                    OidcCodeFlowError::InvalidLifetime
                ))
            );
        }
        for cancelled in [false, true] {
            let unavailable = Cx::for_testing();
            unavailable.set_cancel_requested(cancelled);
            assert_eq!(
                driver
                    .exchange_oidc_code_for_identity(
                        &unavailable,
                        grant_for_exchange(
                            selected.clone(),
                            EnterpriseResponsePolicy::default(),
                            0x22
                        ),
                        &secret,
                        &oidc_keys,
                        now(),
                    )
                    .await
                    .err(),
                Some(if cancelled {
                    EnterpriseExchangeError::Cancelled
                } else {
                    EnterpriseExchangeError::RuntimeUnavailable
                })
            );
        }
        let held = ExchangePermit::acquire(Arc::clone(&driver.inner.busy)).unwrap();
        assert_eq!(
            driver
                .exchange_oidc_code_for_identity(
                    &cx,
                    grant_for_exchange(selected.clone(), EnterpriseResponsePolicy::default(), 0x22),
                    &secret,
                    &oidc_keys,
                    now(),
                )
                .await
                .err(),
            Some(EnterpriseExchangeError::ExchangeInProgress)
        );
        drop(held);
    });
    assert!(poster.take_recorded().is_empty());
    assert!(!driver.inner.busy.load(Ordering::Acquire));
}

#[test]
fn enterprise_oidc_code_redemption_refuses_redirect_and_peer_substitution_without_retry() {
    let selected = profile(&["read"]);
    let (oidc_keys, _) = keys();
    let secret = EnterpriseClientSecret::try_new("confidential-canary").unwrap();
    for redirect in [true, false] {
        let fetcher = test_fetcher();
        let mut response =
            ok_exchange_response("idp.example", fetcher.root_identity(), oidc_token_body());
        let expected = if redirect {
            response.status = 302;
            response.redirect = Some(fastmcp_transport::GuardedHttpRedirect {
                status: 302,
                location: Some("https://other.example/token".to_owned()),
            });
            EnterpriseExchangeError::RedirectRefused
        } else {
            response.provenance.host = "other.example".to_owned();
            EnterpriseExchangeError::EvidenceMismatch
        };
        let poster = ScriptedExchangePoster::new(vec![Ok(response)]);
        let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
        run_exchange_async(async {
            let cx = Cx::current().unwrap();
            assert_eq!(
                driver
                    .exchange_oidc_code_for_identity(
                        &cx,
                        grant_for_exchange(
                            selected.clone(),
                            EnterpriseResponsePolicy::default(),
                            0x22
                        ),
                        &secret,
                        &oidc_keys,
                        now(),
                    )
                    .await
                    .err(),
                Some(expected)
            );
        });
        assert_eq!(poster.take_recorded().len(), 1);
        assert!(!driver.inner.busy.load(Ordering::Acquire));
    }
}

#[test]
fn enterprise_oidc_code_redemption_preserves_typed_denial_without_retry() {
    let selected = profile(&["read"]);
    let (oidc_keys, _) = keys();
    let secret = EnterpriseClientSecret::try_new("confidential-canary").unwrap();
    let fetcher = test_fetcher();
    let mut response = ok_exchange_response(
        "idp.example",
        fetcher.root_identity(),
        br#"{"error":"invalid_grant"}"#.to_vec(),
    );
    response.status = 400;
    let poster = ScriptedExchangePoster::new(vec![Ok(response)]);
    let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
    run_exchange_async(async {
        let cx = Cx::current().unwrap();
        let (outcome, observation) = driver
            .exchange_oidc_code_for_identity(
                &cx,
                grant_for_exchange(selected.clone(), EnterpriseResponsePolicy::default(), 0x22),
                &secret,
                &oidc_keys,
                now(),
            )
            .await
            .unwrap();
        assert_eq!(observation.endpoint(), "https://idp.example/token");
        assert!(matches!(
            outcome,
            EnterpriseResponseOutcome::Denied { denial, .. }
                if denial.code() == EnterpriseOAuthErrorCode::InvalidGrant
                    && denial.status() == 400
        ));
    });
    assert_eq!(poster.take_recorded().len(), 1);
    assert!(!driver.inner.busy.load(Ordering::Acquire));
}

struct ParkedCodePoster {
    calls: std::sync::atomic::AtomicUsize,
    held_lifetime: std::sync::Mutex<Option<Arc<dyn Send + Sync>>>,
}

impl ExchangePoster for ParkedCodePoster {
    fn post<'a>(
        &'a self,
        _cx: &'a Cx,
        _url: &'a GuardedHttpsUrl,
        _request: &'a GuardedHttpRequest,
        lifetime: Arc<dyn Send + Sync>,
    ) -> std::pin::Pin<
        Box<
            dyn Future<Output = Result<GuardedHttpFetchResponse, GuardedHttpFetchError>>
                + Send
                + 'a,
        >,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.held_lifetime.lock().unwrap() = Some(lifetime);
        Box::pin(std::future::pending())
    }
}

#[test]
fn enterprise_oidc_code_redemption_cancellation_and_deadline_retain_dispatch_custody() {
    let selected = profile(&["read"]);
    let (oidc_keys, _) = keys();
    let secret = EnterpriseClientSecret::try_new("confidential-canary").unwrap();
    for cancelled in [false, true] {
        let clock = Arc::new(asupersync::time::VirtualClock::new());
        let timer = asupersync::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .with_timer_driver(timer)
            .build()
            .unwrap();
        let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let poster = Arc::new(ParkedCodePoster {
            calls: std::sync::atomic::AtomicUsize::new(0),
            held_lifetime: std::sync::Mutex::new(None),
        });
        let mut driver = EnterpriseExchangeDriver::new(
            selected.clone(),
            test_fetcher(),
            EnterpriseResponsePolicy::default(),
        )
        .unwrap();
        Arc::get_mut(&mut driver.inner).unwrap().test_post = Some(poster.clone());
        runtime.block_on(async {
            let mut exchange = std::pin::pin!(driver.exchange_oidc_code_for_identity(
                &cx,
                grant_for_exchange(selected.clone(), EnterpriseResponsePolicy::default(), 0x22),
                &secret,
                &oidc_keys,
                now(),
            ));
            poll_fn(|task| {
                assert!(exchange.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(poster.calls.load(Ordering::SeqCst), 1);
            if cancelled {
                cx.set_cancel_requested(true);
            } else {
                clock.advance(6_000_000_000);
            }
            assert_eq!(
                exchange.await.err(),
                Some(if cancelled {
                    EnterpriseExchangeError::Cancelled
                } else {
                    EnterpriseExchangeError::TimedOut
                })
            );
        });
        assert_eq!(poster.calls.load(Ordering::SeqCst), 1);
        assert!(driver.inner.busy.load(Ordering::Acquire));
        // The external HTTP owner still retains its dispatch lifetime even
        // though the caller was released. Only actual quiescence frees it.
        drop(poster.held_lifetime.lock().unwrap().take());
        assert!(!driver.inner.busy.load(Ordering::Acquire));
    }
}

enum VerifiedExchangeGrant {
    Identity(EnterpriseIdentityAssertion),
    IdJag(EnterpriseIdJagResponse),
    Access(EnterpriseAccessTokenResponse),
}

impl VerifiedExchangeGrant {
    fn decode(stage: usize) -> Result<Self, EnterpriseExchangeError> {
        let selected = profile(&["read"]);
        if stage == 0 {
            return Ok(Self::Identity(identity_for_exchange(&selected)));
        }
        let (_, keys) = keys();
        let id_jag = success(
            jag(&selected, &keys, &jag_body(), now())
                .map_err(EnterpriseExchangeError::ResponseRejected)?,
        );
        if stage == 1 {
            Ok(Self::IdJag(id_jag))
        } else {
            finish(id_jag, &access_body(), now() + Duration::from_secs(1))
                .map(success)
                .map(Self::Access)
                .map_err(EnterpriseExchangeError::ResponseRejected)
        }
    }

    fn assert_signed_authority(&self) {
        match self {
            Self::Identity(value) => {
                assert_eq!(value.identity().subject().as_str(), "client-subject");
                assert_eq!(value.identity().client_id(), "native-idp");
            }
            Self::IdJag(value) => {
                assert_eq!(value.assertion().subject().as_str(), "resource-facing");
                assert_eq!(value.granted_scopes(), ["read"]);
            }
            Self::Access(value) => {
                assert_eq!(value.resource(), "https://mcp.example/mcp");
                assert_eq!(value.granted_scopes(), ["read"]);
            }
        }
    }
}

/// Tracks destruction of the actual protected response, not a replacement
/// token. The contained grant's own Drop/zeroization still runs on every path.
struct ObservedExchangeGrant {
    value: VerifiedExchangeGrant,
    dropped: Arc<AtomicBool>,
}

impl Drop for ObservedExchangeGrant {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

#[test]
fn enterprise_exchange_response_admission_keeps_live_verified_grants() {
    let virtual_clock = Arc::new(asupersync::time::VirtualClock::new());
    let timer = asupersync::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&virtual_clock));
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_timer_driver(timer)
        .build()
        .unwrap();
    for stage in 0..3 {
        let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let clock = ExchangeClock::new(now(), cx.now());
        let deadline = ExchangeDeadline::new(
            &cx,
            &clock,
            clock.monotonic + Duration::from_secs(60),
            Duration::from_secs(5),
        )
        .unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let grant = deadline
            .admit_response(&cx, || {
                let value = VerifiedExchangeGrant::decode(stage)?;
                value.assert_signed_authority();
                virtual_clock.advance(1_000_000_000);
                Ok(ObservedExchangeGrant {
                    value,
                    dropped: Arc::clone(&dropped),
                })
            })
            .unwrap();
        grant.value.assert_signed_authority();
        assert!(!dropped.load(Ordering::Acquire));
        drop(grant);
        assert!(dropped.load(Ordering::Acquire));
    }
}

#[test]
fn enterprise_exchange_response_admission_discards_verified_grants_after_cancellation_or_expiry() {
    // Same signed inputs and decoder as the positive. Only a terminal event
    // after successful verification changes: caller cancellation, policy
    // deadline, earlier caller budget, or earlier protected-input expiry.
    for stage in 0..3 {
        for terminal in 0..4 {
            let virtual_clock = Arc::new(asupersync::time::VirtualClock::new());
            let timer =
                asupersync::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&virtual_clock));
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .with_timer_driver(timer)
                .build()
                .unwrap();
            let budget = if terminal == 2 {
                asupersync::Budget::INFINITE.with_deadline(Time::from_nanos(2_000_000_000))
            } else {
                asupersync::Budget::INFINITE
            };
            let cx = runtime.request_cx_with_budget(budget);
            let clock = ExchangeClock::new(now(), cx.now());
            let input_lifetime = if terminal == 3 { 2 } else { 60 };
            let deadline = ExchangeDeadline::new(
                &cx,
                &clock,
                clock.monotonic + Duration::from_secs(input_lifetime),
                Duration::from_secs(5),
            )
            .unwrap();
            let dropped = Arc::new(AtomicBool::new(false));
            let decoded = AtomicBool::new(false);
            let result = deadline.admit_response(&cx, || {
                let value = VerifiedExchangeGrant::decode(stage)?;
                value.assert_signed_authority();
                decoded.store(true, Ordering::Release);
                if terminal == 0 {
                    cx.set_cancel_requested(true);
                } else {
                    virtual_clock.advance(if terminal == 1 {
                        6_000_000_000
                    } else {
                        3_000_000_000
                    });
                }
                Ok(ObservedExchangeGrant {
                    value,
                    dropped: Arc::clone(&dropped),
                })
            });
            assert_eq!(
                result.err(),
                // asupersync delivers caller-budget exhaustion through its
                // checkpoint cancellation channel; this preserves that
                // existing public classification for terminal == 2.
                Some(if terminal == 0 || terminal == 2 {
                    EnterpriseExchangeError::Cancelled
                } else {
                    EnterpriseExchangeError::TimedOut
                }),
                "stage {stage}, terminal {terminal}"
            );
            assert!(decoded.load(Ordering::Acquire));
            assert!(dropped.load(Ordering::Acquire));
        }
    }
}

#[test]
fn enterprise_exchange_response_deadline_does_not_restart_after_preparation() {
    for expired in [false, true] {
        let virtual_clock = Arc::new(asupersync::time::VirtualClock::new());
        let timer =
            asupersync::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&virtual_clock));
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_timer_driver(timer)
            .build()
            .unwrap();
        let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let clock = ExchangeClock::new(now(), cx.now());
        // Preparation consumes four seconds before HTTP can start. The same
        // absolute five-second policy must still govern response verification.
        virtual_clock.advance(4_000_000_000);
        let deadline = ExchangeDeadline::new(
            &cx,
            &clock,
            clock.monotonic + Duration::from_secs(60),
            Duration::from_secs(5),
        )
        .unwrap();
        let result = deadline.admit_response(&cx, || {
            let value = VerifiedExchangeGrant::decode(1)?;
            virtual_clock.advance(if expired { 2_000_000_000 } else { 500_000_000 });
            Ok(value)
        });
        if expired {
            assert_eq!(result.err(), Some(EnterpriseExchangeError::TimedOut));
        } else {
            result.unwrap().assert_signed_authority();
        }
    }
}

#[test]
fn enterprise_exchange_driver_confidential_response_preserves_verification_and_redacts_diagnostics()
{
    let selected = profile(&["read"]);
    let (_, keys) = keys();
    let body = serde_json::to_vec(&jag_body()).unwrap();
    let fixture = fixtures();
    let compact = fixture["id_jag"].as_str().unwrap();
    for redirected in [false, true] {
        let root = test_fetcher().root_identity().to_owned();
        let mut response = ok_exchange_response("idp.example", &root, body.clone());
        if redirected {
            response.status = 307;
            response.redirect = Some(fastmcp_transport::GuardedHttpRedirect {
                status: 307,
                location: Some("https://elsewhere.example/?code=redirect-secret".to_owned()),
            });
        }
        let poster = ScriptedExchangePoster::new(vec![Ok(response)]);
        let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
        let request = GuardedHttpRequest::new(
            "application/x-www-form-urlencoded",
            b"grant_type=opaque&client_secret=request-secret".to_vec(),
        )
        .unwrap();
        run_exchange_async(async {
            let cx = Cx::current().unwrap();
            let clock = ExchangeClock::new(now(), cx.now());
            let deadline = ExchangeDeadline::new(
                &cx,
                &clock,
                clock.monotonic + Duration::from_secs(60),
                Duration::from_secs(5),
            )
            .unwrap();
            let permit = Arc::new(ExchangePermit::acquire(Arc::clone(&driver.inner.busy)).unwrap());
            let result = driver
                .dispatch_post(
                    &cx,
                    &driver.inner.idp_token_url,
                    &request,
                    deadline,
                    Arc::clone(&permit),
                    || Ok(()),
                )
                .await;
            if redirected {
                assert_eq!(
                    result.unwrap_err(),
                    EnterpriseExchangeError::RedirectRefused
                );
            } else {
                // The real dispatcher transfers its response owner directly to
                // the verifier. The transport unit tests separately exercise
                // this owner over authenticated native TLS.
                let response: GuardedHttpConfidentialResponse = result.unwrap();
                assert_eq!(response.body(), body);
                assert!(!format!("{response:?}").contains(compact));
                let admitted = selected
                    .admit_id_jag_response(
                        EnterpriseTokenResponse {
                            status: response.status(),
                            headers: response.headers(),
                            body: response.body(),
                        },
                        &keys,
                        TenantExpectation::SingleTenant,
                        ResourceTenantExpectation::SingleTenant,
                        EnterpriseResponsePolicy::default(),
                        now(),
                    )
                    .unwrap();
                assert_eq!(success(admitted).granted_scopes(), ["read"]);
                assert!(driver.inner.busy.load(Ordering::Acquire));
                drop(response);
            }
            drop(permit);
            assert!(!driver.inner.busy.load(Ordering::Acquire));
        });
        assert_eq!(poster.take_recorded().len(), 1);
    }
}

#[test]
fn enterprise_exchange_driver_full_two_stage_flow_positive_and_planted_negatives() {
    let selected = profile(&["read"]);
    let (oidc_keys, jag_keys) = keys();
    let oidc_body = serde_json::to_vec(&json!({
        "access_token": "temporary-access",
        "token_type": "Bearer",
        "scope": "openid",
        "id_token": fixtures()["oidc"],
    }))
    .unwrap();
    let headers_val = headers();
    let identity_assertion = success(
        selected
            .admit_oidc_code_response(
                EnterpriseTokenResponse {
                    status: 200,
                    headers: &headers_val,
                    body: &oidc_body,
                },
                &oidc_keys,
                "oidc-flow-nonce",
                TenantExpectation::SingleTenant,
                None,
                EnterpriseResponsePolicy::default(),
                now(),
            )
            .expect("admit OIDC identity assertion"),
    );

    let jag_body_bytes = serde_json::to_vec(&jag_body()).unwrap();
    let access_body_bytes = serde_json::to_vec(&json!({
        "access_token": "enterprise-final-bearer-token-2026",
        "token_type": "Bearer",
        "scope": "read",
        "resource": "https://mcp.example/mcp",
        "expires_in": 600,
    }))
    .unwrap();

    let fetcher = test_fetcher();
    let root_id = fetcher.root_identity().to_owned();
    let poster = ScriptedExchangePoster::new(vec![
        Ok(ok_exchange_response(
            "idp.example",
            &root_id,
            jag_body_bytes.clone(),
        )),
        Ok(ok_exchange_response(
            "as.example",
            &root_id,
            access_body_bytes,
        )),
    ]);
    let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
    let idp_secret = EnterpriseClientSecret::try_new("idp-secret-val").unwrap();
    let as_secret = EnterpriseClientSecret::try_new("as-secret-val").unwrap();
    assert!(!format!("{idp_secret:?}").contains("idp-secret-val"));

    // Positive: execute both RFC 8693 (Basic auth) and RFC 7523 (Post auth)
    // stages end to end and verify exact resource-bound Bearer credential.
    run_exchange_async(async {
        let cx = Cx::current().expect("runtime cx");
        let replay = ExchangeReplayFixture::new(&cx);
        let reserved = replay
            .reserve(&cx, &selected, identity_assertion, now())
            .await
            .unwrap();
        let (jag_outcome, jag_obs) = driver
            .exchange_identity_for_id_jag(
                &cx,
                reserved,
                &idp_secret,
                &jag_keys,
                TenantExpectation::SingleTenant,
                ResourceTenantExpectation::SingleTenant,
                now(),
            )
            .await
            .expect("stage 1 RFC 8693 exchange succeeds");
        assert_eq!(jag_obs.endpoint(), "https://idp.example/token");
        let id_jag = success(jag_outcome);
        assert_eq!(id_jag.granted_scopes(), ["read"]);

        let (token_outcome, token_obs) = driver
            .exchange_id_jag_for_access_token(
                &cx,
                id_jag,
                &as_secret,
                now() + Duration::from_secs(1),
            )
            .await
            .expect("stage 2 RFC 7523 exchange succeeds");
        assert_eq!(token_obs.endpoint(), "https://as.example/token");
        let bound_token = success(token_outcome);
        assert_eq!(bound_token.response().resource(), "https://mcp.example/mcp");
        assert_eq!(bound_token.response().granted_scopes(), ["read"]);

        let credential = bound_token
            .into_bound_bearer_credential(Instant::now(), now() + Duration::from_secs(1))
            .expect("bind final enterprise access token to HTTPS resource");
        let target = CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap();
        let other = CanonicalHttpUrl::parse("https://other.example/mcp").unwrap();
        assert_eq!(
            credential.authorization_for_target(&target).as_deref(),
            Some("Bearer enterprise-final-bearer-token-2026")
        );
        assert!(
            credential.authorization_for_target(&other).is_none(),
            "bound credential must never attach to a different HTTPS origin"
        );
    });

    let recorded = poster.take_recorded();
    assert_eq!(recorded.len(), 2);
    // Stage 1: IdP uses ClientSecretBasic -> Authorization header present, NO client_secret in body.
    assert_eq!(recorded[0].host, "idp.example");
    assert_eq!(
        recorded[0].content_type,
        "application/x-www-form-urlencoded"
    );
    assert!(recorded[0].has_authorization);
    assert!(
        recorded[0]
            .body
            .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange")
    );
    assert!(!recorded[0].body.contains("client_secret="));
    // Stage 2: Resource AS uses ClientSecretPost -> NO Authorization header, client_id & client_secret in body.
    assert_eq!(recorded[1].host, "as.example");
    assert!(!recorded[1].has_authorization);
    assert!(
        recorded[1]
            .body
            .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer")
    );
    assert!(recorded[1].body.contains("client_id=native-resource"));
    assert!(recorded[1].body.contains("client_secret=as-secret-val"));
    let second_fields = recorded[1]
        .body
        .split('&')
        .map(|field| field.split_once('=').unwrap().0)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        second_fields,
        std::collections::BTreeSet::from(
            ["grant_type", "assertion", "client_id", "client_secret",]
        ),
        "JWT-bearer redemption must not repeat scope or resource"
    );

    // Planted negatives (RH-5):
    // 1. Invalid client secret refused.
    assert_eq!(
        EnterpriseClientSecret::try_new("").unwrap_err(),
        EnterpriseExchangeError::InvalidConfiguration
    );
    assert_eq!(
        EnterpriseClientSecret::try_new("bad\nsecret").unwrap_err(),
        EnterpriseExchangeError::InvalidConfiguration
    );

    // 2. HTTP redirect refused without following.
    let mut redirect_resp = ok_exchange_response("idp.example", &root_id, jag_body_bytes.clone());
    redirect_resp.status = 302;
    redirect_resp.redirect = Some(fastmcp_transport::GuardedHttpRedirect {
        status: 302,
        location: Some("https://evil.example/token".to_owned()),
    });
    let redirect_poster = ScriptedExchangePoster::new(vec![Ok(redirect_resp)]);
    let (redirect_driver, _) = driver_with_poster(selected.clone(), redirect_poster);
    let assertion_for_redirect = success(
        selected
            .admit_oidc_code_response(
                EnterpriseTokenResponse {
                    status: 200,
                    headers: &headers_val,
                    body: &oidc_body,
                },
                &oidc_keys,
                "oidc-flow-nonce",
                TenantExpectation::SingleTenant,
                None,
                EnterpriseResponsePolicy::default(),
                now(),
            )
            .unwrap(),
    );
    run_exchange_async(async {
        let cx = Cx::current().unwrap();
        let replay = ExchangeReplayFixture::new(&cx);
        let reserved = replay
            .reserve(&cx, &selected, assertion_for_redirect, now())
            .await
            .unwrap();
        let err = match redirect_driver
            .exchange_identity_for_id_jag(
                &cx,
                reserved,
                &idp_secret,
                &jag_keys,
                TenantExpectation::SingleTenant,
                ResourceTenantExpectation::SingleTenant,
                now(),
            )
            .await
        {
            Err(err) => err,
            Ok(_) => panic!("redirect response must be refused"),
        };
        assert_eq!(err, EnterpriseExchangeError::RedirectRefused);
    });

    // 3. Peer provenance host mismatch refused (EvidenceMismatch).
    let wrong_host_poster = ScriptedExchangePoster::new(vec![Ok(ok_exchange_response(
        "attacker.example",
        &root_id,
        jag_body_bytes,
    ))]);
    let (wrong_host_driver, _) = driver_with_poster(selected.clone(), wrong_host_poster);
    let assertion_for_host = success(
        selected
            .admit_oidc_code_response(
                EnterpriseTokenResponse {
                    status: 200,
                    headers: &headers_val,
                    body: &oidc_body,
                },
                &oidc_keys,
                "oidc-flow-nonce",
                TenantExpectation::SingleTenant,
                None,
                EnterpriseResponsePolicy::default(),
                now(),
            )
            .unwrap(),
    );
    run_exchange_async(async {
        let cx = Cx::current().unwrap();
        let replay = ExchangeReplayFixture::new(&cx);
        let reserved = replay
            .reserve(&cx, &selected, assertion_for_host, now())
            .await
            .unwrap();
        let err = match wrong_host_driver
            .exchange_identity_for_id_jag(
                &cx,
                reserved,
                &idp_secret,
                &jag_keys,
                TenantExpectation::SingleTenant,
                ResourceTenantExpectation::SingleTenant,
                now(),
            )
            .await
        {
            Err(err) => err,
            Ok(_) => panic!("provenance host mismatch must be refused"),
        };
        assert_eq!(err, EnterpriseExchangeError::EvidenceMismatch);
    });
}

fn identity_for_exchange(selected: &EnterpriseProfile) -> EnterpriseIdentityAssertion {
    let (oidc_keys, _) = keys();
    let body = serde_json::to_vec(&json!({
        "access_token": "temporary-access", "token_type": "Bearer",
        "scope": "openid", "id_token": fixtures()["oidc"],
    }))
    .unwrap();
    success(
        selected
            .admit_oidc_code_response(
                EnterpriseTokenResponse {
                    status: 200,
                    headers: &headers(),
                    body: &body,
                },
                &oidc_keys,
                "oidc-flow-nonce",
                TenantExpectation::SingleTenant,
                None,
                EnterpriseResponsePolicy::default(),
                now(),
            )
            .unwrap(),
    )
}

async fn reserved_for_exchange(cx: &Cx, selected: &EnterpriseProfile) -> ReservedIdentityAssertion {
    ExchangeReplayFixture::new(cx)
        .reserve(cx, selected, identity_for_exchange(selected), now())
        .await
        .unwrap()
}

/// Runs the production reservation and first-stage driver with the explicitly
/// scripted HTTP seam; never constructs a stage-two owner directly.
async fn exchanged_for_test(
    cx: &Cx,
    selected: &EnterpriseProfile,
) -> (EnterpriseExchangedIdJag, ExchangeReplayFixture) {
    let replay = ExchangeReplayFixture::new(cx);
    let reserved = replay
        .reserve(cx, selected, identity_for_exchange(selected), now())
        .await
        .unwrap();
    let fetcher = test_fetcher();
    let poster = ScriptedExchangePoster::new(vec![Ok(ok_exchange_response(
        "idp.example",
        fetcher.root_identity(),
        serde_json::to_vec(&jag_body()).unwrap(),
    ))]);
    let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
    let (_, jag_keys) = keys();
    let secret = EnterpriseClientSecret::try_new("fixture-idp-secret").unwrap();
    let (outcome, _) = driver
        .exchange_identity_for_id_jag(
            cx,
            reserved,
            &secret,
            &jag_keys,
            TenantExpectation::SingleTenant,
            ResourceTenantExpectation::SingleTenant,
            now(),
        )
        .await
        .unwrap();
    assert_eq!(poster.take_recorded().len(), 1);
    (success(outcome), replay)
}

#[test]
fn enterprise_exchange_preflight_binds_profile_keys_and_tenancy_before_post() {
    let selected = profile(&["read"]);
    let (_, jag_keys) = keys();
    let secret = EnterpriseClientSecret::try_new("confidential-canary").unwrap();
    let denied =
        EnterpriseExchangeError::ResponseRejected(EnterpriseResponseError::PolicyBindingMismatch);
    run_exchange_async(async {
        let cx = Cx::current().unwrap();
        // Only the selected IdP authentication method changes. The original
        // issuer/client/token are otherwise valid, but must never be disclosed
        // under another registration/profile.
        let changed = profile_with_authentication(
            &["read"],
            EnterpriseClientAuthentication::ClientSecretPost,
            EnterpriseClientAuthentication::ClientSecretPost,
        );
        let poster = ScriptedExchangePoster::new(vec![]);
        let (driver, _) = driver_with_poster(changed, Arc::clone(&poster));
        let result = driver
            .exchange_identity_for_id_jag(
                &cx,
                reserved_for_exchange(&cx, &selected).await,
                &secret,
                &jag_keys,
                TenantExpectation::SingleTenant,
                ResourceTenantExpectation::SingleTenant,
                now(),
            )
            .await;
        assert!(matches!(result, Err(error) if error == denied));
        assert!(poster.take_recorded().is_empty());

        let poster = ScriptedExchangePoster::new(vec![]);
        let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
        let wrong_keys = IdJagVerificationKeys::from_trusted_jwks(
            "https://idp.example",
            23,
            &serde_json::to_vec(&fixtures()["jwks"]).unwrap(),
        )
        .unwrap();
        let result = driver
            .exchange_identity_for_id_jag(
                &cx,
                reserved_for_exchange(&cx, &selected).await,
                &secret,
                &wrong_keys,
                TenantExpectation::SingleTenant,
                ResourceTenantExpectation::SingleTenant,
                now(),
            )
            .await;
        assert!(matches!(result, Err(error) if error == denied));
        let result = driver
            .exchange_identity_for_id_jag(
                &cx,
                reserved_for_exchange(&cx, &selected).await,
                &secret,
                &jag_keys,
                TenantExpectation::Exact("different-tenant"),
                ResourceTenantExpectation::SingleTenant,
                now(),
            )
            .await;
        assert!(matches!(result, Err(error) if error == denied));
        assert!(poster.take_recorded().is_empty());

        // Only the final endpoint's authentication method changes; even a
        // correctly signed ID-JAG cannot authorize that different profile.
        let changed = profile_with_authentication(
            &["read"],
            EnterpriseClientAuthentication::ClientSecretBasic,
            EnterpriseClientAuthentication::ClientSecretBasic,
        );
        let poster = ScriptedExchangePoster::new(vec![]);
        let (driver, _) = driver_with_poster(changed, Arc::clone(&poster));
        let (original, _) = exchanged_for_test(&cx, &selected).await;
        let result = driver
            .exchange_id_jag_for_access_token(
                &cx,
                original,
                &secret,
                now() + Duration::from_secs(1),
            )
            .await;
        assert!(matches!(result, Err(error) if error == denied));
        assert!(poster.take_recorded().is_empty());
    });
}

#[test]
fn enterprise_exchange_preflight_checks_input_lifetime_and_singleflight_before_post() {
    let selected = profile(&["read"]);
    let (_, jag_keys) = keys();
    let secret = EnterpriseClientSecret::try_new("confidential-canary").unwrap();
    let poster = ScriptedExchangePoster::new(vec![]);
    let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
    let invalid_lifetime =
        EnterpriseExchangeError::ResponseRejected(EnterpriseResponseError::InvalidLifetime);
    run_exchange_async(async {
        let cx = Cx::current().unwrap();
        for time in [
            now() - Duration::from_secs(1),
            now() + Duration::from_secs(240),
        ] {
            let result = driver
                .exchange_identity_for_id_jag(
                    &cx,
                    reserved_for_exchange(&cx, &selected).await,
                    &secret,
                    &jag_keys,
                    TenantExpectation::SingleTenant,
                    ResourceTenantExpectation::SingleTenant,
                    time,
                )
                .await;
            assert!(matches!(result, Err(error) if error == invalid_lifetime));
        }
        for expired in [false, true] {
            let (original, _) = exchanged_for_test(&cx, &selected).await;
            let time = if expired {
                original.effective_expires_at()
            } else {
                now() - Duration::from_secs(1)
            };
            let result = driver
                .exchange_id_jag_for_access_token(&cx, original, &secret, time)
                .await;
            assert!(matches!(result, Err(error) if error == invalid_lifetime));
        }
        let held = ExchangePermit::acquire(Arc::clone(&driver.inner.busy)).unwrap();
        let result = driver
            .exchange_identity_for_id_jag(
                &cx,
                reserved_for_exchange(&cx, &selected).await,
                &secret,
                &jag_keys,
                TenantExpectation::SingleTenant,
                ResourceTenantExpectation::SingleTenant,
                now(),
            )
            .await;
        assert!(matches!(
            result,
            Err(EnterpriseExchangeError::ExchangeInProgress)
        ));
        drop(held);
        assert!(!driver.inner.busy.load(Ordering::Acquire));
        assert!(
            poster.take_recorded().is_empty(),
            "rejected inputs never disclose a form or secret"
        );
    });
}

#[test]
fn enterprise_exchange_bearer_conversion_cannot_restart_or_backdate_lifetime() {
    let selected = profile(&["read"]);
    let secret = EnterpriseClientSecret::try_new("as-secret").unwrap();
    let fetcher = test_fetcher();
    let poster = ScriptedExchangePoster::new(vec![
        Ok(ok_exchange_response(
            "as.example",
            fetcher.root_identity(),
            serde_json::to_vec(&access_body()).unwrap(),
        )),
        Ok(ok_exchange_response(
            "as.example",
            fetcher.root_identity(),
            serde_json::to_vec(&access_body()).unwrap(),
        )),
    ]);
    let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
    run_exchange_async(async {
        let cx = Cx::current().unwrap();
        let (original, _) = exchanged_for_test(&cx, &selected).await;
        let stage_two_at = now() + Duration::from_secs(1);
        let (outcome, _) = driver
            .exchange_id_jag_for_access_token(&cx, original, &secret, stage_two_at)
            .await
            .unwrap();
        let token = success(outcome);
        let original_deadline = token.expires_at_monotonic;
        let credential = token
            .into_bound_bearer_credential(Instant::now() + Duration::from_hours(1), stage_two_at)
            .unwrap();
        assert_eq!(credential.expires_at(), Some(original_deadline));

        let (original, _) = exchanged_for_test(&cx, &selected).await;
        let (outcome, _) = driver
            .exchange_id_jag_for_access_token(&cx, original, &secret, stage_two_at)
            .await
            .unwrap();
        assert!(matches!(
            success(outcome)
                .into_bound_bearer_credential(Instant::now(), now() - Duration::from_secs(1),),
            Err(EnterpriseExchangeError::CredentialBindingFailed)
        ));
        assert_eq!(poster.take_recorded().len(), 2);
    });
}

#[test]
fn enterprise_exchange_terminal_or_unknown_post_never_reopens_reserved_identity() {
    let selected = profile(&["read"]);
    let (_, jag_keys) = keys();
    let secret = EnterpriseClientSecret::try_new("fixture-idp-secret").unwrap();
    let fetcher = test_fetcher();
    let mut denial = ok_exchange_response(
        "idp.example",
        fetcher.root_identity(),
        serde_json::to_vec(&json!({ "error": "invalid_grant" })).unwrap(),
    );
    denial.status = 400;
    run_exchange_async(async {
        let cx = Cx::current().unwrap();
        for (response, denied) in [
            (Ok(denial), true),
            (Err(GuardedHttpFetchError::DeadlineExceeded), false),
        ] {
            let replay = ExchangeReplayFixture::new(&cx);
            let reserved = replay
                .reserve(&cx, &selected, identity_for_exchange(&selected), now())
                .await
                .unwrap();
            let poster = ScriptedExchangePoster::new(vec![response]);
            let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
            let result = driver
                .exchange_identity_for_id_jag(
                    &cx,
                    reserved,
                    &secret,
                    &jag_keys,
                    TenantExpectation::SingleTenant,
                    ResourceTenantExpectation::SingleTenant,
                    now(),
                )
                .await;
            if denied {
                assert!(matches!(
                    result,
                    Ok((EnterpriseResponseOutcome::Denied { .. }, _))
                ));
            } else {
                assert!(matches!(result, Err(EnterpriseExchangeError::TimedOut)));
            }
            assert_eq!(poster.take_recorded().len(), 1);
            assert_eq!(replay.reserved_aliases(), 2);
            assert!(matches!(
                replay
                    .reserve(&cx, &selected, identity_for_exchange(&selected), now())
                    .await,
                Err(IdentityAssertionReplayError::AlreadyReserved)
            ));
            assert_eq!(replay.reserved_aliases(), 2);
        }
    });
}

#[test]
fn enterprise_exchange_restore_quarantine_fences_each_disclosure_and_credential_release() {
    let selected = profile(&["read"]);
    let (_, jag_keys) = keys();
    let secret = EnterpriseClientSecret::try_new("confidential-canary").unwrap();
    run_exchange_async(async {
        let cx = Cx::current().unwrap();
        let replay = ExchangeReplayFixture::new(&cx);
        let reserved = replay
            .reserve(&cx, &selected, identity_for_exchange(&selected), now())
            .await
            .unwrap();
        replay.quarantine(&cx).await;
        let poster = ScriptedExchangePoster::new(vec![]);
        let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
        assert!(matches!(
            driver
                .exchange_identity_for_id_jag(
                    &cx,
                    reserved,
                    &secret,
                    &jag_keys,
                    TenantExpectation::SingleTenant,
                    ResourceTenantExpectation::SingleTenant,
                    now(),
                )
                .await,
            Err(EnterpriseExchangeError::ReservationRejected)
        ));
        assert!(poster.take_recorded().is_empty());
        assert_eq!(replay.reserved_aliases(), 2);

        let (exchanged, replay) = exchanged_for_test(&cx, &selected).await;
        replay.quarantine(&cx).await;
        assert!(matches!(
            driver
                .exchange_id_jag_for_access_token(
                    &cx,
                    exchanged,
                    &secret,
                    now() + Duration::from_secs(1),
                )
                .await,
            Err(EnterpriseExchangeError::ReservationRejected)
        ));
        assert!(poster.take_recorded().is_empty());
        assert_eq!(replay.reserved_aliases(), 2);

        let (exchanged, replay) = exchanged_for_test(&cx, &selected).await;
        let fetcher = test_fetcher();
        let poster = ScriptedExchangePoster::new(vec![Ok(ok_exchange_response(
            "as.example",
            fetcher.root_identity(),
            serde_json::to_vec(&access_body()).unwrap(),
        ))]);
        let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
        let (outcome, _) = driver
            .exchange_id_jag_for_access_token(
                &cx,
                exchanged,
                &secret,
                now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
        let bound = success(outcome);
        replay.quarantine(&cx).await;
        assert!(matches!(
            bound.into_bound_bearer_credential(Instant::now(), now() + Duration::from_secs(1)),
            Err(EnterpriseExchangeError::ReservationRejected)
        ));
        assert_eq!(poster.take_recorded().len(), 1);
        assert_eq!(replay.reserved_aliases(), 2);
    });
}

/// Post-exchange fixture for the real local-TLS HTTP-client test. This does not
/// pretend that the separate scripted IdP fixtures ran against the local peer.
pub(in crate::http_auth) fn http_policy_credential_for_test(
    resource: &CanonicalHttpUrl,
) -> (
    super::super::http::EnterpriseHttpPolicy,
    BoundBearerCredential,
) {
    use super::super::http::EnterpriseHttpPolicy;
    let selected = profile_for_http_resource(
        &["read"],
        EnterpriseClientAuthentication::ClientSecretBasic,
        EnterpriseClientAuthentication::ClientSecretPost,
        resource.as_str(),
        30,
    );
    let expiry = Instant::now() + Duration::from_secs(90);
    let owner = EnterpriseHttpPolicy::new(selected, expiry, expiry).unwrap();
    let mut credential =
        BoundBearerCredential::bind_with_expiry(resource.clone(), "enterprise-http-secret", expiry)
            .unwrap()
            .for_owner(owner.cancellation())
            .unwrap();
    credential.enterprise_request_binding = true;
    (owner, credential)
}

fn enterprise_http_request_body(settings: Value) -> Vec<u8> {
    use super::super::http::ENTERPRISE_AUTHORIZATION_EXTENSION_ID;
    serde_json::to_vec(&json!({
        "jsonrpc":"2.0", "id":1, "method":"tools/list",
        "params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{
                "extensions":{ENTERPRISE_AUTHORIZATION_EXTENSION_ID:settings}
            }
        }}
    }))
    .unwrap()
}

fn enterprise_raw_request(
    resource: &str,
    body: Vec<u8>,
    credential: &BoundBearerCredential,
) -> crate::http_executor::ModernHttpRequest {
    crate::http_executor::ModernHttpRequest::new(
        resource,
        body,
        fastmcp_protocol::FINAL_PROTOCOL_VERSION,
        "tools/list",
        None,
    )
    .unwrap()
    .with_authorization(credential)
}

fn has_enterprise_header(request: &crate::http_executor::ModernHttpRequest) -> bool {
    request
        .headers()
        .iter()
        .any(|(name, value)| name == "Authorization" && value == "Bearer enterprise-http-secret")
}

#[test]
fn enterprise_http_headers_require_the_current_exact_raw_declaration() {
    let resource = CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap();
    let (_owner, credential) = http_policy_credential_for_test(&resource);
    let positive = enterprise_raw_request(
        resource.as_str(),
        enterprise_http_request_body(json!({})),
        &credential,
    );
    assert!(has_enterprise_header(&positive));
    assert!(credential.authorization_for_target(&resource).is_none());
    for settings in [
        Value::Null,
        json!(true),
        json!([]),
        json!("{}"),
        json!({"enabled":true}),
    ] {
        assert!(!has_enterprise_header(&enterprise_raw_request(
            resource.as_str(),
            enterprise_http_request_body(settings),
            &credential,
        )));
    }
    for raw in [
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"extensions":{"example.com/enterprise-managed-authorization":{}}}}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2024-11-05","io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/enterprise-managed-authorization":{}}}}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/enterprise-managed-authorization":{},"io.modelcontextprotocol/enterprise-managed-authorization":{}}}}}}"#,
    ] {
        assert!(!has_enterprise_header(&enterprise_raw_request(
            resource.as_str(),
            raw.as_bytes().to_vec(),
            &credential,
        )));
    }
    for target in [
        "https://mcp.example/other",
        "https://other.example/mcp",
        "http://mcp.example/mcp",
    ] {
        assert!(!has_enterprise_header(&enterprise_raw_request(
            target,
            enterprise_http_request_body(json!({})),
            &credential,
        )));
    }
    let wrong_header_era = crate::http_executor::ModernHttpRequest::new(
        resource.as_str(),
        enterprise_http_request_body(json!({})),
        "2024-11-05",
        "tools/list",
        None,
    )
    .unwrap()
    .with_authorization(&credential);
    assert!(!has_enterprise_header(&wrong_header_era));
    let wrong_method = crate::http_executor::ModernHttpRequest::new(
        resource.as_str(),
        enterprise_http_request_body(json!({})),
        fastmcp_protocol::FINAL_PROTOCOL_VERSION,
        "tools/call",
        None,
    )
    .unwrap()
    .with_authorization(&credential);
    assert!(!has_enterprise_header(&wrong_method));
    let mut call: Value = serde_json::from_slice(&enterprise_http_request_body(json!({}))).unwrap();
    call["method"] = json!("tools/call");
    call["params"]["name"] = json!("lookup");
    let call = serde_json::to_vec(&call).unwrap();
    for name in [None, Some("other")] {
        let wrong_name = crate::http_executor::ModernHttpRequest::new(
            resource.as_str(),
            call.clone(),
            fastmcp_protocol::FINAL_PROTOCOL_VERSION,
            "tools/call",
            name.map(str::to_owned),
        )
        .unwrap()
        .with_authorization(&credential);
        assert!(!has_enterprise_header(&wrong_name));
    }
    let matching_name = crate::http_executor::ModernHttpRequest::new(
        resource.as_str(),
        call,
        fastmcp_protocol::FINAL_PROTOCOL_VERSION,
        "tools/call",
        Some("lookup".to_owned()),
    )
    .unwrap()
    .with_authorization(&credential);
    assert!(has_enterprise_header(&matching_name));
    // Responses and notifications carry neither request-local metadata nor
    // request routing headers. The raw request constructor cannot disguise a
    // control envelope using unrelated Mcp-Method/Mcp-Name headers.
    for control in [
        br#"{"jsonrpc":"2.0","id":2,"result":{}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","method":"notifications/example"}"#.as_slice(),
    ] {
        assert!(!has_enterprise_header(&enterprise_raw_request(
            resource.as_str(),
            control.to_vec(),
            &credential,
        )));
        let control =
            crate::http_executor::ModernHttpRequest::control(resource.as_str(), control.to_vec())
                .unwrap()
                .with_authorization(&credential);
        assert!(has_enterprise_header(&control));
        assert!(!control.headers().iter().any(|(name, _)| {
            name.eq_ignore_ascii_case("mcp-method")
                || name.eq_ignore_ascii_case("mcp-name")
                || name.eq_ignore_ascii_case("mcp-protocol-version")
        }));
    }
    assert!(
        crate::http_executor::ModernHttpRequest::control(
            resource.as_str(),
            enterprise_http_request_body(json!({})),
        )
        .is_err()
    );
    let notification = crate::http_executor::ModernHttpRequest::notification(
        resource.as_str(),
        "notifications/example",
        json!({}),
    )
    .unwrap()
    .with_authorization(&credential);
    assert!(has_enterprise_header(&notification));
    assert!(
        has_enterprise_header(&positive),
        "every refused twin leaves the owner unchanged"
    );
}

#[test]
fn enterprise_http_policy_rotation_and_drop_revoke_prepared_requests_and_clones() {
    use super::super::http::{EnterpriseHttpPolicy, EnterpriseHttpPolicyError};
    let resource = CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap();
    let (mut owner, credential) = http_policy_credential_for_test(&resource);
    let debug = format!("{owner:?}");
    for identity in ["mcp.example", "idp.example", "as.example", "client-at-idp"] {
        assert!(!debug.contains(identity));
    }
    let request = enterprise_raw_request(
        resource.as_str(),
        enterprise_http_request_body(json!({})),
        &credential,
    );
    drop(credential.clone());
    drop(request.clone());
    assert!(has_enterprise_header(&request));
    let fresh = Instant::now() + Duration::from_secs(90);
    for (idp_deadline, as_deadline) in [(Instant::now(), fresh), (fresh, Instant::now())] {
        assert_eq!(
            EnterpriseHttpPolicy::new(owner.profile().clone(), idp_deadline, as_deadline).err(),
            Some(EnterpriseHttpPolicyError::StaleMetadata)
        );
    }
    assert_eq!(
        owner.replace(owner.profile().clone(), fresh, fresh),
        Err(EnterpriseHttpPolicyError::GenerationRollback)
    );
    assert!(has_enterprise_header(&request));
    let replacement = profile_for_http_resource(
        &["read"],
        EnterpriseClientAuthentication::ClientSecretBasic,
        EnterpriseClientAuthentication::ClientSecretPost,
        resource.as_str(),
        31,
    );
    assert_eq!(
        owner.replace(replacement.clone(), Instant::now(), fresh),
        Err(EnterpriseHttpPolicyError::StaleMetadata)
    );
    assert!(has_enterprise_header(&request));
    owner.replace(replacement, fresh, fresh).unwrap();
    assert!(credential.is_revoked());
    assert!(!has_enterprise_header(&request));

    let (owner, credential) = http_policy_credential_for_test(&resource);
    let request = enterprise_raw_request(
        resource.as_str(),
        enterprise_http_request_body(json!({})),
        &credential,
    );
    owner.revoke();
    assert!(!has_enterprise_header(&request));
    let (owner, credential) = http_policy_credential_for_test(&resource);
    let request = enterprise_raw_request(
        resource.as_str(),
        enterprise_http_request_body(json!({})),
        &credential,
    );
    drop(owner);
    assert!(credential.is_revoked());
    assert!(!has_enterprise_header(&request));

    let exhausted_profile = profile_for_http_resource(
        &["read"],
        EnterpriseClientAuthentication::ClientSecretBasic,
        EnterpriseClientAuthentication::ClientSecretPost,
        resource.as_str(),
        u64::MAX,
    );
    let mut exhausted = EnterpriseHttpPolicy::new(exhausted_profile, fresh, fresh).unwrap();
    assert_eq!(
        exhausted.replace(profile(&["read"]), fresh, fresh),
        Err(EnterpriseHttpPolicyError::GenerationRollback)
    );
}

async fn final_token_for_http_binding(
    cx: &Cx,
    selected: &EnterpriseProfile,
) -> EnterpriseBoundAccessToken {
    final_token_and_replay_for_http_binding(cx, selected)
        .await
        .0
}

async fn final_token_and_replay_for_http_binding(
    cx: &Cx,
    selected: &EnterpriseProfile,
) -> (EnterpriseBoundAccessToken, ExchangeReplayFixture) {
    let (exchanged, replay) = exchanged_for_test(cx, selected).await;
    let fetcher = test_fetcher();
    let poster = ScriptedExchangePoster::new(vec![Ok(ok_exchange_response(
        "as.example",
        fetcher.root_identity(),
        serde_json::to_vec(&access_body()).unwrap(),
    ))]);
    let (driver, _) = driver_with_poster(selected.clone(), Arc::clone(&poster));
    let secret = EnterpriseClientSecret::try_new("fixture-resource-secret").unwrap();
    let (outcome, _) = driver
        .exchange_id_jag_for_access_token(cx, exchanged, &secret, now())
        .await
        .unwrap();
    assert_eq!(poster.take_recorded().len(), 1);
    (success(outcome), replay)
}

/// Retains the real exchange guard while a local TLS test exercises HTTP and
/// cache admission. The scripted signed exchange still targets `mcp.example`;
/// only the already-converted credential's test endpoint is localized here.
/// This fixture does not claim that the IdP exchange ran against the TLS peer.
pub(in crate::http_auth) struct HttpExchangeCredentialFixture {
    credential: BoundBearerCredential,
    replay: ExchangeReplayFixture,
}

impl HttpExchangeCredentialFixture {
    pub(in crate::http_auth) fn credential(&self) -> BoundBearerCredential {
        self.credential.clone()
    }

    pub(in crate::http_auth) async fn quarantine(&self, cx: &Cx) {
        self.replay.quarantine(cx).await;
    }
}

pub(in crate::http_auth) async fn http_exchange_credential_for_test(
    cx: &Cx,
    resource: &CanonicalHttpUrl,
) -> HttpExchangeCredentialFixture {
    let (token, replay) = final_token_and_replay_for_http_binding(cx, &profile(&["read"])).await;
    let mut credential = token
        .into_bound_bearer_credential(Instant::now(), now())
        .unwrap();
    credential.resource = resource.clone();
    assert!(!credential.requires_enterprise_declaration());
    HttpExchangeCredentialFixture { credential, replay }
}

#[test]
fn enterprise_exchange_bearer_conversion_retains_restore_fence_across_clones() {
    use crate::http_executor::{ModernHttpExecutor, ModernHttpExecutorError};

    let selected = profile(&["read"]);
    let resource = CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap();
    let other_resource = CanonicalHttpUrl::parse("https://other.example/mcp").unwrap();
    run_exchange_async(async {
        let cx = Cx::current().unwrap();
        let (token, replay) = final_token_and_replay_for_http_binding(&cx, &selected).await;
        let original = token
            .into_bound_bearer_credential(Instant::now(), now())
            .unwrap();
        let sibling = original.clone();
        let owner = fastmcp_core::McpRequestCancellation::new();
        let owned = original.for_owner(&owner).unwrap();
        let prepared = enterprise_raw_request(
            resource.as_str(),
            enterprise_http_request_body(json!({})),
            &original,
        );
        let prepared_clone = prepared.clone();
        drop(original);

        let (other_token, other_replay) =
            final_token_and_replay_for_http_binding(&cx, &selected).await;
        let independent = other_token
            .into_bound_bearer_credential(Instant::now(), now())
            .unwrap();
        for credential in [&sibling, &owned, &independent] {
            assert!(!credential.is_revoked());
            assert_eq!(
                credential.authorization_for_target(&resource).as_deref(),
                Some("Bearer final-opaque-token")
            );
            assert!(
                credential
                    .authorization_for_target(&other_resource)
                    .is_none()
            );
        }
        assert!(
            prepared.headers().iter().any(
                |(name, value)| name == "Authorization" && value == "Bearer final-opaque-token"
            )
        );

        // Change only the original reservation's restore state after conversion.
        // Dropping the original credential must not detach any surviving lease.
        replay.quarantine(&cx).await;
        for credential in [&sibling, &owned] {
            assert!(credential.is_revoked());
            assert!(credential.authorization_for_target(&resource).is_none());
            assert!(!format!("{credential:?}").contains("final-opaque-token"));
        }
        for request in [&prepared, &prepared_clone] {
            assert!(
                !request
                    .headers()
                    .iter()
                    .any(|(name, _)| name == "Authorization")
            );
            assert!(matches!(
                ModernHttpExecutor::new().execute(&cx, request).await,
                Err(ModernHttpExecutorError::CredentialUnavailable)
            ));
        }
        let cloned_after_quarantine = sibling.clone();
        let owned_after_quarantine = sibling
            .for_owner(&fastmcp_core::McpRequestCancellation::new())
            .unwrap();
        for credential in [&cloned_after_quarantine, &owned_after_quarantine] {
            assert!(credential.is_revoked());
            assert!(credential.authorization_for_target(&resource).is_none());
        }
        assert!(!independent.is_revoked());
        assert_eq!(
            independent.authorization_for_target(&resource).as_deref(),
            Some("Bearer final-opaque-token")
        );
        assert_eq!(replay.reserved_aliases(), 2);
        assert_eq!(other_replay.reserved_aliases(), 2);
    });
}

#[test]
fn enterprise_exchange_bearer_conversion_preserves_owner_isolation_and_redaction() {
    let selected = profile(&["read"]);
    let resource = CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap();
    run_exchange_async(async {
        let cx = Cx::current().unwrap();
        let (token, replay) = final_token_and_replay_for_http_binding(&cx, &selected).await;
        assert!(!format!("{token:?}").contains("final-opaque-token"));
        let credential = token
            .into_bound_bearer_credential(Instant::now(), now())
            .unwrap();
        let owner = fastmcp_core::McpRequestCancellation::new();
        let owned = credential.for_owner(&owner).unwrap();
        let owned_clone = owned.clone();
        assert!(owned.for_owner(&owner).is_none());
        for lease in [&credential, &owned, &owned_clone] {
            assert_eq!(
                lease.authorization_for_target(&resource).as_deref(),
                Some("Bearer final-opaque-token")
            );
            assert!(!format!("{lease:?}").contains("final-opaque-token"));
        }

        owner.cancel();
        for lease in [&owned, &owned_clone] {
            assert!(lease.is_revoked());
            assert!(lease.authorization_for_target(&resource).is_none());
        }
        assert!(!credential.is_revoked());
        assert_eq!(
            credential.authorization_for_target(&resource).as_deref(),
            Some("Bearer final-opaque-token")
        );
        credential.revoke();
        assert!(credential.authorization_for_target(&resource).is_none());
        assert_eq!(replay.reserved_aliases(), 2);
    });
}

#[test]
fn enterprise_http_binding_retains_exchange_profile_scope_and_original_deadlines() {
    use super::super::http::{EnterpriseHttpPolicy, EnterpriseHttpPolicyError};
    let selected = profile(&["read"]);
    run_exchange_async(async {
        let cx = Cx::current().unwrap();
        let idp_expiry = Instant::now() + Duration::from_secs(20);
        let as_expiry = idp_expiry + Duration::from_secs(10);
        let owner = EnterpriseHttpPolicy::new(selected.clone(), idp_expiry, as_expiry).unwrap();
        let token = final_token_for_http_binding(&cx, &selected).await;
        let credential = token
            .into_http_credential(&owner, Instant::now() + Duration::from_hours(1), now())
            .unwrap();
        assert_eq!(credential.expires_at(), Some(idp_expiry));
        let request = enterprise_raw_request(
            "https://mcp.example/mcp",
            enterprise_http_request_body(json!({})),
            &credential,
        );
        assert!(
            request.headers().iter().any(
                |(name, value)| name == "Authorization" && value == "Bearer final-opaque-token"
            )
        );

        for wrong_profile in [
            profile(&["read", "write"]),
            profile_for_http_resource(
                &["read"],
                EnterpriseClientAuthentication::ClientSecretBasic,
                EnterpriseClientAuthentication::ClientSecretPost,
                "https://other.example/mcp",
                30,
            ),
            profile_for_http_resource(
                &["read"],
                EnterpriseClientAuthentication::ClientSecretBasic,
                EnterpriseClientAuthentication::ClientSecretPost,
                "https://mcp.example/mcp",
                31,
            ),
        ] {
            let other_owner =
                EnterpriseHttpPolicy::new(wrong_profile, idp_expiry, as_expiry).unwrap();
            let token = final_token_for_http_binding(&cx, &selected).await;
            assert_eq!(
                token
                    .into_http_credential(&other_owner, Instant::now(), now())
                    .err(),
                Some(EnterpriseHttpPolicyError::ProfileMismatch)
            );
        }
        let token = final_token_for_http_binding(&cx, &selected).await;
        assert_eq!(
            token
                .into_http_credential(&owner, Instant::now(), now() - Duration::from_secs(1))
                .err(),
            Some(EnterpriseHttpPolicyError::CredentialUnavailable)
        );
        let mut expired = final_token_for_http_binding(&cx, &selected).await;
        expired.expires_at_monotonic = Instant::now();
        assert_eq!(
            expired
                .into_http_credential(&owner, Instant::now() - Duration::from_secs(60), now())
                .err(),
            Some(EnterpriseHttpPolicyError::CredentialUnavailable)
        );
        let (token, replay) = final_token_and_replay_for_http_binding(&cx, &selected).await;
        replay.quarantine(&cx).await;
        assert_eq!(
            token
                .into_http_credential(&owner, Instant::now(), now())
                .err(),
            Some(EnterpriseHttpPolicyError::CredentialUnavailable)
        );
        assert_eq!(
            replay.reserved_aliases(),
            2,
            "HTTP binding never reopens consumed identity aliases"
        );
        let (token, replay) = final_token_and_replay_for_http_binding(&cx, &selected).await;
        let guarded = token
            .into_http_credential(&owner, Instant::now(), now())
            .unwrap();
        let guarded_request = enterprise_raw_request(
            "https://mcp.example/mcp",
            enterprise_http_request_body(json!({})),
            &guarded,
        );
        assert!(
            guarded_request
                .headers()
                .iter()
                .any(|(name, _)| name == "Authorization")
        );
        replay.quarantine(&cx).await;
        assert!(guarded.is_revoked());
        assert!(
            !guarded_request
                .headers()
                .iter()
                .any(|(name, _)| name == "Authorization")
        );
        assert_eq!(replay.reserved_aliases(), 2);
        owner.revoke();
        assert!(
            !request
                .headers()
                .iter()
                .any(|(name, _)| name == "Authorization")
        );
        let token = final_token_for_http_binding(&cx, &selected).await;
        assert_eq!(
            token
                .into_http_credential(&owner, Instant::now(), now())
                .err(),
            Some(EnterpriseHttpPolicyError::Revoked)
        );
    });
}

#[test]
fn enterprise_http_raw_missing_declaration_refuses_before_opening_a_connection() {
    use crate::http_executor::{ModernHttpExecutor, ModernHttpExecutorError};
    let resource = CanonicalHttpUrl::parse("https://127.0.0.1:9/mcp").unwrap();
    let (_owner, credential) = http_policy_credential_for_test(&resource);
    let request = enterprise_raw_request(
        resource.as_str(),
        enterprise_http_request_body(json!({"not":"empty"})),
        &credential,
    );
    run_exchange_async(async {
        let cx = Cx::current().unwrap();
        assert!(matches!(
            ModernHttpExecutor::new().execute(&cx, &request).await,
            Err(ModernHttpExecutorError::CredentialUnavailable)
        ));
    });
}

#[test]
fn enterprise_exchange_restore_quarantine_during_post_discards_the_reply() {
    let selected = profile(&["read"]);
    let (_, jag_keys) = keys();
    let secret = EnterpriseClientSecret::try_new("fixture-idp-secret").unwrap();
    let fetcher = test_fetcher();
    run_exchange_async(async {
        let cx = Cx::current().unwrap();
        let replay = Arc::new(ExchangeReplayFixture::new(&cx));
        let reserved = replay
            .reserve(&cx, &selected, identity_for_exchange(&selected), now())
            .await
            .unwrap();
        let mut poster = ScriptedExchangePoster::new(vec![Ok(ok_exchange_response(
            "idp.example",
            fetcher.root_identity(),
            serde_json::to_vec(&jag_body()).unwrap(),
        ))]);
        Arc::get_mut(&mut poster).unwrap().quarantine_before_reply = Some(Arc::clone(&replay));
        let (driver, _) = driver_with_poster(selected, Arc::clone(&poster));
        assert!(matches!(
            driver
                .exchange_identity_for_id_jag(
                    &cx,
                    reserved,
                    &secret,
                    &jag_keys,
                    TenantExpectation::SingleTenant,
                    ResourceTenantExpectation::SingleTenant,
                    now(),
                )
                .await,
            Err(EnterpriseExchangeError::ReservationRejected)
        ));
        assert_eq!(poster.take_recorded().len(), 1);
        assert_eq!(replay.reserved_aliases(), 2);
        assert!(!driver.inner.busy.load(Ordering::Acquire));
    });
}
