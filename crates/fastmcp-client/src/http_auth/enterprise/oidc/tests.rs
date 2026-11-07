//! Producer/consumer regression tests for the local OIDC code-flow codecs.
//! The additional compact fixture is a real RS256 signature under the public
//! RFC7515 Appendix A.2 example key. Fixture construction reproduced that RFC's
//! published signature first; no private key or signer ships in this module.

use super::*;
use super::super::policy::{
    EnterpriseClientAuthentication, EnterpriseProfileConfiguration,
    EnterpriseRegistrationConfiguration, IdJagCryptoConfiguration,
    ID_JAG_GRANT_PROFILE, ID_JAG_TOKEN_TYPE, JWT_BEARER_GRANT,
};
use asupersync::Budget;
use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
use asupersync::types::Time;
use fastmcp_core::{CanonicalResourceId, CanonicalResourceIdPolicy};
use serde_json::json;

const REDIRECT: &str = "https://client.example/callback";

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000)
}

fn profile_and_documents() -> (EnterpriseProfile, [Value; 5]) {
    profile_and_documents_with_openid(true)
}

fn profile_and_documents_with_openid(permit_openid: bool) -> (EnterpriseProfile, [Value; 5]) {
    let resource = CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap();
    let config = EnterpriseProfileConfiguration {
        idp: EnterpriseRegistrationConfiguration {
            issuer: "https://idp.example".into(),
            token_endpoint: "https://idp.example/token".into(),
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
        idp_authorization_endpoint: "https://idp.example/authorize".into(),
        oidc_jwks_uri: "https://idp.example/oidc-keys".into(),
        oidc_key_generation: 21,
        id_jag_crypto: IdJagCryptoConfiguration {
            issuer: "https://idp.example".into(),
            jwks_uri: "https://idp.example/id-jag-keys".into(),
            resource_as_issuer: "https://as.example".into(),
            algorithm: "RS256".into(), key_generation: 22, policy_generation: 23,
        },
        resource: CanonicalResourceId::parse_for_endpoint(
            resource.as_str(), &resource, CanonicalResourceIdPolicy::default(),
        ).unwrap(),
        requested_scopes: RequestedEnterpriseScopeSet::from_literals(["read".to_owned()]).unwrap(),
        deployment_scope_allowance: vec!["read".into()],
        policy_generation: 30, idp_metadata_generation: 31, resource_as_metadata_generation: 32,
        aggregate_registration_generation: 33,
    };
    let mut documents = [
        json!({
            "issuer":"https://idp.example", "token_endpoint":"https://idp.example/token",
            "authorization_endpoint":"https://idp.example/authorize",
            "jwks_uri":"https://idp.example/oidc-keys",
            "grant_types_supported":["authorization_code",TOKEN_EXCHANGE_GRANT],
            "response_types_supported":["code"], "response_modes_supported":["query"],
            "code_challenge_methods_supported":["S256"], "scopes_supported":["openid","read"],
            "subject_types_supported":["public","pairwise"],
            "token_endpoint_auth_methods_supported":["client_secret_basic"],
            "identity_chaining_requested_token_types_supported":[ID_JAG_TOKEN_TYPE],
            "id_token_signing_alg_values_supported":["RS256"],
            "authorization_response_iss_parameter_supported":true
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
            "token_endpoint_auth_method":"client_secret_basic", "application_type":"web",
            "response_types":["code"], "redirect_uris":[REDIRECT], "subject_type":"public",
            "scope":"openid read"
        }),
        json!({
            "issuer":"https://as.example", "token_endpoint":"https://as.example/token",
            "client_id":"native-resource", "grant_types":[JWT_BEARER_GRANT],
            "token_endpoint_auth_method":"client_secret_post"
        }),
    ];
    if !permit_openid {
        documents[0]["scopes_supported"] = json!(["read"]);
    }
    let encoded = documents.each_ref().map(|value| serde_json::to_vec(value).unwrap());
    let profile = EnterpriseProfile::from_documents(
        config, &encoded[0], &encoded[1], &encoded[2], &encoded[3], &encoded[4],
    ).unwrap();
    (profile, documents)
}

fn admit_configuration(
    profile: EnterpriseProfile,
    metadata: &Value,
    registration: &Value,
    subject_type: EnterpriseOidcSubjectType,
) -> Result<OidcCodeFlowConfiguration, OidcCodeFlowError> {
    OidcCodeFlowConfiguration::from_documents(
        profile, REDIRECT, subject_type, TenantExpectation::SingleTenant,
        &serde_json::to_vec(metadata).unwrap(), &serde_json::to_vec(registration).unwrap(),
    )
}

fn configuration() -> OidcCodeFlowConfiguration {
    let (profile, documents) = profile_and_documents();
    admit_configuration(profile, &documents[0], &documents[3], EnterpriseOidcSubjectType::Public).unwrap()
}

fn prepared() -> PreparedOidcAuthorization {
    configuration().prepare(&Cx::for_testing(), now(), Duration::from_secs(300)).unwrap()
}

fn seeded() -> PreparedOidcAuthorization {
    // The production serializer is exercised with fixed valid 256-bit draws
    // solely to use an independently signed deterministic RS256 fixture. The
    // public prepare path's actual OS draws are exercised separately below.
    configuration().prepare_from_draws(
        &[0x11; 32], &[0x22; 32], &[0x33; 32], now(), now() + Duration::from_secs(300),
    ).unwrap()
}

fn callback(prepared: &PreparedOidcAuthorization, suffix: &str) -> String {
    format!(
        "{REDIRECT}?state={}&iss=https%3A%2F%2Fidp.example&{suffix}",
        prepared.state.as_str(),
    )
}

fn code(outcome: OidcCallbackOutcome) -> OidcCodeGrant {
    match outcome {
        OidcCallbackOutcome::Code(code) => code,
        OidcCallbackOutcome::Denied(_) => panic!("expected a locally admitted code"),
    }
}

fn headers() -> Vec<(String, String)> {
    vec![
        ("Content-Type".into(), "application/json".into()),
        ("Cache-Control".into(), "no-store".into()),
    ]
}

fn keys() -> OidcVerificationKeys {
    let fixture: Value = serde_json::from_str(include_str!("../response/assertions.json")).unwrap();
    OidcVerificationKeys::from_trusted_jwks(
        "https://idp.example", 21, &serde_json::to_vec(&fixture["jwks"]).unwrap(),
    ).unwrap()
}

#[test]
fn oidc_code_request_uses_independent_os_draws_and_exact_closed_get() {
    let first = prepared();
    let second = prepared();
    assert_eq!(first.method(), "GET");
    let query = first.authorization_url().split_once('?').unwrap().1;
    let names: Vec<_> = query.split('&').map(|field| field.split_once('=').unwrap().0).collect();
    assert_eq!(names, [
        "response_type", "client_id", "redirect_uri", "scope",
        "state", "nonce", "code_challenge", "code_challenge_method",
    ]);
    let fields = callback_fields(query).unwrap();
    assert_eq!(fields["scope"].as_str(), "openid");
    assert_eq!(fields["response_type"].as_str(), "code");
    assert_eq!(fields["code_challenge_method"].as_str(), "S256");
    assert_eq!(fields["client_id"].as_str(), "native-idp");
    assert_eq!(fields["redirect_uri"].as_str(), REDIRECT);
    for secret in [&first.state, &first.nonce, &first.verifier] {
        assert_eq!(secret.len(), 43);
        assert!(secret.as_str().bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')));
    }
    assert_ne!(first.state, first.nonce);
    assert_ne!(first.nonce, first.verifier);
    assert_ne!(first.state, first.verifier);
    assert_ne!(first.state, second.state);
    assert_ne!(first.nonce, second.nonce);
    assert_ne!(first.verifier, second.verifier);
    assert_eq!(
        fields["code_challenge"],
        base64url32(&digest(first.verifier.as_bytes(), 43).unwrap()),
    );
    assert!(!first.authorization_url().contains(first.verifier.as_str()));
    assert_eq!(first.request_target(), format!("/authorize?{query}"));
    assert_eq!(
        first.authorization_url_digest(),
        &digest(first.authorization_url().as_bytes(), MAX_LAUNCH_BYTES).unwrap(),
    );
    assert_eq!(
        first.request_target_digest(),
        &digest(first.request_target().as_bytes(), MAX_LAUNCH_BYTES).unwrap(),
    );
    assert_ne!(first.authorization_url_digest(), first.request_target_digest());
}

#[test]
fn oidc_code_configuration_requires_every_explicit_discovery_intersection() {
    let (profile, documents) = profile_and_documents();
    assert!(profile.permits_oidc_openid());
    assert!(admit_configuration(profile.clone(), &documents[0], &documents[3], EnterpriseOidcSubjectType::Public).is_ok());
    // A later document cannot add openid to the originally admitted role's
    // allowance, even if it independently passes this codec's discovery checks.
    let (limited_profile, limited_documents) = profile_and_documents_with_openid(false);
    assert!(!limited_profile.permits_oidc_openid());
    let mut broadened_metadata = limited_documents[0].clone();
    broadened_metadata["scopes_supported"] = json!(["openid", "read"]);
    assert_eq!(
        admit_configuration(
            limited_profile, &broadened_metadata, &limited_documents[3],
            EnterpriseOidcSubjectType::Public,
        ).err(),
        Some(OidcCodeFlowError::InvalidConfiguration),
    );
    for field in [
        "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
        "grant_types_supported", "response_types_supported", "response_modes_supported",
        "scopes_supported", "subject_types_supported", "code_challenge_methods_supported",
        "token_endpoint_auth_methods_supported", "id_token_signing_alg_values_supported",
    ] {
        let mut metadata = documents[0].clone();
        metadata.as_object_mut().unwrap().remove(field);
        assert!(
            admit_configuration(profile.clone(), &metadata, &documents[3], EnterpriseOidcSubjectType::Public).is_err(),
            "omitted required field {field}",
        );
    }
    for (field, value) in [
        ("scopes_supported", json!(["read"])),
        ("subject_types_supported", json!(["pairwise"])),
        ("response_modes_supported", json!(["form_post"])),
        ("code_challenge_methods_supported", json!(["plain"])),
        ("grant_types_supported", json!([TOKEN_EXCHANGE_GRANT])),
        ("token_endpoint_auth_methods_supported", json!(["none"])),
        ("id_token_signing_alg_values_supported", json!(["ES256"])),
        ("authorization_response_iss_parameter_supported", Value::Null),
    ] {
        let mut metadata = documents[0].clone();
        metadata[field] = value;
        assert!(admit_configuration(profile.clone(), &metadata, &documents[3], EnterpriseOidcSubjectType::Public).is_err());
    }
}

#[test]
fn oidc_code_configuration_rejects_registration_and_scope_substitution() {
    let (profile, documents) = profile_and_documents();
    for (field, value) in [
        ("application_type", json!("native")),
        ("client_id", json!("native-resource")),
        ("subject_type", json!("pairwise")),
        ("response_types", json!(["code", "id_token"])),
        ("grant_types", json!(["authorization_code"])),
        ("redirect_uris", json!([REDIRECT, "https://client.example/other"])),
        ("token_endpoint_auth_method", json!("none")),
        ("id_token_signed_response_alg", json!("ES256")),
        ("id_token_encrypted_response_alg", Value::Null),
        ("id_token_encrypted_response_enc", json!("A256GCM")),
        ("scope", json!("read")),
        ("scope", json!("openid openid")),
        ("client_secret", Value::Null),
        ("registration_client_uri", json!("https://idp.example/manage")),
    ] {
        let mut registration = documents[3].clone();
        registration[field] = value;
        assert!(admit_configuration(profile.clone(), &documents[0], &registration, EnterpriseOidcSubjectType::Public).is_err());
    }
    let mut registration = documents[3].clone();
    registration["id_token_signed_response_alg"] = json!("RS256");
    assert!(admit_configuration(profile, &documents[0], &registration, EnterpriseOidcSubjectType::Public).is_ok());
}

#[test]
fn oidc_code_configuration_preserves_public_and_pairwise_namespaces() {
    let (profile, documents) = profile_and_documents();
    let public = admit_configuration(profile.clone(), &documents[0], &documents[3], EnterpriseOidcSubjectType::Public).unwrap();
    assert_eq!(public.subject_namespace().issuer(), "https://idp.example");
    assert_eq!(public.subject_namespace().sector_host(), None);
    let mut registration = documents[3].clone();
    registration["subject_type"] = json!("pairwise");
    let pairwise = admit_configuration(profile.clone(), &documents[0], &registration, EnterpriseOidcSubjectType::Pairwise).unwrap();
    assert_eq!(pairwise.subject_namespace().sector_host(), Some("client.example"));
    assert_eq!(pairwise.subject_namespace().registration_generation(), Some(11));
    registration["sector_identifier_uri"] = json!("https://sector.example/redirects.json");
    assert_eq!(
        admit_configuration(profile, &documents[0], &registration, EnterpriseOidcSubjectType::Pairwise).err(),
        Some(OidcCodeFlowError::UnsupportedSubjectNamespace),
    );
}

#[test]
fn oidc_code_request_respects_entropy_ceiling_and_finite_caller_budget() {
    let config = configuration();
    let cx = Cx::for_testing();
    {
        let _caller = Cx::set_current(Some(cx.clone()));
        let _no_entropy = Cx::push_restriction(CapSet::<true, true, false, true, true>::MASK);
        assert_eq!(
            config.prepare(&cx, now(), Duration::from_secs(300)).err(),
            Some(OidcCodeFlowError::CapabilityUnavailable),
        );
    }
    assert!(config.prepare(&cx, now(), Duration::from_secs(300)).is_ok());
    for lifetime in [Duration::ZERO, Duration::from_secs(901)] {
        assert_eq!(config.prepare(&cx, now(), lifetime).err(), Some(OidcCodeFlowError::InvalidLifetime));
    }
    let timed = Cx::for_testing_with_budget(
        Budget::new().with_deadline(Time::from_nanos(cx.now().as_nanos() + 5_000_000_000)),
    );
    let request = config.prepare(&timed, now(), Duration::from_secs(300)).unwrap();
    assert!(request.expires_at() > now());
    assert!(request.expires_at() <= now() + Duration::from_secs(5));
    let expired = Cx::for_testing_with_budget(Budget::new().with_deadline(Time::ZERO));
    assert!(config.prepare(&expired, now(), Duration::from_secs(300)).is_err());
}

#[test]
fn oidc_code_callback_admits_escaped_code_and_ignores_bounded_unknown_values() {
    let pending = prepared();
    let verifier = SecretString::new(pending.verifier.as_str());
    let expected_url_digest = *pending.authorization_url_digest();
    let response = callback(&pending, "code=a%2Bb+c%26d%3D&custom=%E2%82%AC");
    let expected_callback_digest = digest(response.as_bytes(), MAX_CALLBACK_BYTES).unwrap();
    let grant = code(pending.admit_callback(&response, now() + Duration::from_secs(1)).unwrap());
    assert_eq!(grant.token_endpoint(), "https://idp.example/token");
    let mut encoded = Vec::new();
    let admission = grant.write_token_form(&mut encoded, now() + Duration::from_secs(2)).unwrap();
    let encoded = SecretString::from_string(String::from_utf8(encoded).unwrap());
    let fields = callback_fields(encoded.as_str()).unwrap();
    assert_eq!(fields.len(), 4);
    assert_eq!(fields["grant_type"].as_str(), "authorization_code");
    assert_eq!(fields["code"].as_str(), "a+b c&d=");
    assert_eq!(fields["redirect_uri"].as_str(), REDIRECT);
    assert_eq!(fields["code_verifier"], verifier);
    assert!(!fields.contains_key("resource"));
    assert!(!fields.contains_key("scope"));
    assert!(!fields.contains_key("nonce"));
    assert!(!fields.contains_key("client_secret"));
    assert_eq!(admission.launch_url_digest(), &expected_url_digest);
    assert_eq!(admission.callback_digest(), &expected_callback_digest);
    assert_eq!(admission.request_digest(), &digest(encoded.as_bytes(), MAX_CODE_FORM_BYTES).unwrap());
}

#[test]
fn oidc_code_callback_refuses_route_state_fragment_and_response_mode_confusion() {
    for suffix in [
        "code=", "code=%0A", "code=%C3%A9", "code=x&code=y", "code=x&%63ode=y",
        "code=x&error=access_denied", "code=x&id_token=", "code=x&access_token=front-token",
        "code=x&refresh_token=refresh", "code=x&token_type=Bearer", "code=x&response_mode=query",
        "code=x&response_type=code", "code=x&expires_in=1", "code=x&error_description=detail",
        "code=x&unknown=%C0%80", "code=x&unknown=%", "code=x&unknown=%G0", "code=x#fragment",
    ] {
        let pending = prepared();
        let response = callback(&pending, suffix);
        assert!(pending.admit_callback(&response, now()).is_err(), "accepted {suffix}");
    }
    let pending = prepared();
    let response = format!("{REDIRECT}?state=wrong&iss=https%3A%2F%2Fidp.example&code=x");
    assert!(pending.admit_callback(&response, now()).is_err());
    let pending = prepared();
    let response = callback(&pending, "code=x").replace("client.example", "other.example");
    assert!(pending.admit_callback(&response, now()).is_err());
    let pending = prepared();
    let response = callback(&pending, "code=x").replace("/callback?", "/other/../callback?");
    assert!(pending.admit_callback(&response, now()).is_err());
    let pending = prepared();
    let response = callback(&pending, &format!("code=x&%73tate={}", pending.state.as_str()));
    assert!(pending.admit_callback(&response, now()).is_err());
    let pending = prepared();
    let response = callback(&pending, &format!("code={}", "x".repeat(MAX_FIELD_BYTES + 1)));
    assert!(pending.admit_callback(&response, now()).is_err());
}

#[test]
fn oidc_code_callback_issuer_is_conditional_but_unsolicited_issuer_still_binds() {
    let (profile, documents) = profile_and_documents();
    let pending = prepared();
    let no_issuer = format!("{REDIRECT}?state={}&code=x", pending.state.as_str());
    assert_eq!(pending.admit_callback(&no_issuer, now()).err(), Some(OidcCodeFlowError::IssuerMismatch));
    for advertised in [None, Some(false)] {
        let mut metadata = documents[0].clone();
        if let Some(value) = advertised {
            metadata["authorization_response_iss_parameter_supported"] = json!(value);
        } else {
            metadata.as_object_mut().unwrap().remove("authorization_response_iss_parameter_supported");
        }
        let config = admit_configuration(profile.clone(), &metadata, &documents[3], EnterpriseOidcSubjectType::Public).unwrap();
        assert!(!config.requires_callback_issuer());
        let pending = config.prepare(&Cx::for_testing(), now(), Duration::from_secs(300)).unwrap();
        let response = format!("{REDIRECT}?state={}&code=x", pending.state.as_str());
        assert!(matches!(pending.admit_callback(&response, now()), Ok(OidcCallbackOutcome::Code(_))));
        for error_arm in [false, true] {
            let pending = config.prepare(&Cx::for_testing(), now(), Duration::from_secs(300)).unwrap();
            let response = format!(
                "{REDIRECT}?state={}&iss=https%3A%2F%2Fother.example&{}",
                pending.state.as_str(), if error_arm { "error=access_denied" } else { "code=x" },
            );
            assert_eq!(pending.admit_callback(&response, now()).err(), Some(OidcCodeFlowError::IssuerMismatch));
        }
    }
}

#[test]
fn oidc_code_authorization_errors_are_closed_redacted_and_terminal() {
    for (wire, expected) in [
        ("invalid_request", OidcAuthorizationError::InvalidRequest),
        ("unauthorized_client", OidcAuthorizationError::UnauthorizedClient),
        ("access_denied", OidcAuthorizationError::AccessDenied),
        ("unsupported_response_type", OidcAuthorizationError::UnsupportedResponseType),
        ("invalid_scope", OidcAuthorizationError::InvalidScope),
        ("server_error", OidcAuthorizationError::ServerError),
        ("temporarily_unavailable", OidcAuthorizationError::TemporarilyUnavailable),
        ("interaction_required", OidcAuthorizationError::InteractionRequired),
        ("login_required", OidcAuthorizationError::LoginRequired),
        ("account_selection_required", OidcAuthorizationError::AccountSelectionRequired),
        ("consent_required", OidcAuthorizationError::ConsentRequired),
        ("invalid_request_uri", OidcAuthorizationError::InvalidRequestUri),
        ("invalid_request_object", OidcAuthorizationError::InvalidRequestObject),
        ("request_not_supported", OidcAuthorizationError::RequestNotSupported),
        ("request_uri_not_supported", OidcAuthorizationError::RequestUriNotSupported),
        ("registration_not_supported", OidcAuthorizationError::RegistrationNotSupported),
        ("vendor_condition", OidcAuthorizationError::Extension),
    ] {
        let pending = prepared();
        let response = callback(&pending, &format!(
            "error={wire}&error_description=Sensitive+peer+detail&error_uri=https%3A%2F%2Fidp.example%2Fdiagnostic&custom=ignored",
        ));
        match pending.admit_callback(&response, now()).unwrap() {
            OidcCallbackOutcome::Denied(error) => {
                assert_eq!(error, expected);
                assert!(!format!("{error:?}").contains("Sensitive"));
            }
            OidcCallbackOutcome::Code(_) => panic!("error created code authority"),
        }
    }
    for suffix in [
        "error=", "error=access_denied&error_description=%22quoted%22",
        "error=access_denied&error_uri=has+space", "error=access_denied&code=",
        "error=access_denied&error_uri=%25XX", "error=access_denied&error_uri=https%3A%2F%2F%5Bbroken",
        "error=access_denied&error=login_required",
    ] {
        let pending = prepared();
        let response = callback(&pending, suffix);
        assert!(pending.admit_callback(&response, now()).is_err());
    }
}

#[test]
fn oidc_code_flow_expiry_and_backwards_time_refuse_before_form_output() {
    for at in [now() - Duration::from_secs(1), now() + Duration::from_secs(300)] {
        let pending = seeded();
        let response = callback(&pending, "code=x");
        assert_eq!(pending.admit_callback(&response, at).err(), Some(OidcCodeFlowError::InvalidLifetime));
    }
    for at in [now(), now() + Duration::from_secs(300)] {
        let pending = seeded();
        let response = callback(&pending, "code=x");
        let grant = code(pending.admit_callback(&response, now() + Duration::from_secs(1)).unwrap());
        let mut output = Vec::new();
        assert_eq!(grant.write_token_form(&mut output, at).err(), Some(OidcCodeFlowError::InvalidLifetime));
        assert!(output.is_empty());
    }
}

#[test]
fn oidc_code_partial_form_write_cannot_produce_response_admission_owner() {
    struct PartialSink { written: usize }
    impl Write for PartialSink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.written != 0 { return Err(std::io::Error::other("sink unavailable")); }
            let count = bytes.len().min(7);
            self.written += count;
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    let pending = prepared();
    let response = callback(&pending, "code=x");
    let grant = code(pending.admit_callback(&response, now()).unwrap());
    let mut sink = PartialSink { written: 0 };
    assert_eq!(grant.write_token_form(&mut sink, now()).err(), Some(OidcCodeFlowError::EncodingFailed));
    assert_eq!(sink.written, 7);
}

#[test]
fn oidc_code_form_encoding_preserves_oauth_octets_and_rejects_ambiguity() {
    let encoded = form(&[("value", " %&+£€~*")], 128).unwrap();
    assert_eq!(encoded.as_str(), "value=+%25%26%2B%C2%A3%E2%82%AC%7E*");
    assert_eq!(callback_fields(encoded.as_str()).unwrap()["value"].as_str(), " %&+£€~*");
    assert!(form(&[("value", " ")], 6).is_err());
    assert!(callback_fields("state=one&%73tate=two").is_err());
    assert!(callback_fields("unknown=%ED%A0%80").is_err());
    assert!(callback_fields("unknown=%F4%90%80%80").is_err());
    assert!(callback_fields("unknown=%E2%82").is_err());
    assert!(callback_fields("unknown=%7F").is_err());
}

#[test]
fn oidc_code_error_uri_accepts_absolute_and_relative_references_without_fetching() {
    for uri in ["https://idp.example/help", "/help?kind=denied", "../help#section", "?error=denied", "#denied", "custom:diagnostic"] {
        assert!(error_uri(uri), "refused valid diagnostic reference");
    }
    for uri in ["%XX", "https://[broken", "has space", "bad[segment]", "1:invalid-scheme"] {
        assert!(!error_uri(uri), "accepted malformed diagnostic reference");
    }
    let pending = prepared();
    let response = callback(&pending, "error=access_denied&error_uri=..%2Fhelp%23section");
    assert!(matches!(pending.admit_callback(&response, now()), Ok(OidcCallbackOutcome::Denied(OidcAuthorizationError::AccessDenied))));
}

#[test]
fn oidc_code_metadata_raw_duplicates_cannot_reach_flow_generation() {
    let (profile, documents) = profile_and_documents();
    let original = serde_json::to_string(&documents[0]).unwrap();
    let duplicated = format!(
        "{},\"issuer\":\"https://idp.example\"}}",
        original.strip_suffix('}').unwrap(),
    );
    assert!(
        OidcCodeFlowConfiguration::from_documents(
            profile, REDIRECT, EnterpriseOidcSubjectType::Public, TenantExpectation::SingleTenant,
            duplicated.as_bytes(), &serde_json::to_vec(&documents[3]).unwrap(),
        ).is_err()
    );
}

fn response_owner(pending: PreparedOidcAuthorization) -> OidcCodeResponseAdmission {
    let response = callback(&pending, "code=one-time-code");
    let grant = code(pending.admit_callback(&response, now()).unwrap());
    let mut output = Vec::new();
    let owner = grant.write_token_form(&mut output, now() + Duration::from_secs(1)).unwrap();
    drop(SecretString::from_string(String::from_utf8(output).unwrap()));
    owner
}

fn token_body() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "access_token":"temporary-access", "token_type":"Bearer",
        "id_token":SIGNED_CODE_TOKEN, "scope":"openid"
    })).unwrap()
}

#[test]
fn oidc_code_pipeline_admits_real_signed_response_for_its_generated_nonce() {
    let owner = response_owner(seeded());
    let headers = headers();
    let body = token_body();
    let response = owner.admit_token_response(
        EnterpriseTokenResponse { status: 200, headers: &headers, body: &body },
        &keys(), now() + Duration::from_secs(2),
    ).unwrap();
    match response {
        EnterpriseResponseOutcome::Success { value, cache } => {
            assert_eq!(value.identity().issuer(), "https://idp.example");
            assert_eq!(value.identity().client_id(), "native-idp");
            assert_eq!(value.identity().subject().as_str(), "client-subject");
            assert_eq!(value.identity().expires_at(), now() + Duration::from_secs(240));
            assert_eq!(value.identity().generation(), 21);
            assert!(!cache.missing_no_store());
            assert!(!cache.missing_pragma_no_cache());
        }
        _ => panic!("real code-flow fixture did not produce verified identity facts"),
    }
}

#[test]
fn oidc_code_pipeline_refuses_signed_token_from_different_nonce_or_access_token() {
    let different = configuration().prepare_from_draws(
        &[0x11; 32], &[0x23; 32], &[0x33; 32], now(), now() + Duration::from_secs(300),
    ).unwrap();
    let headers = headers();
    let body = token_body();
    assert_eq!(
        response_owner(different).admit_token_response(
            EnterpriseTokenResponse { status: 200, headers: &headers, body: &body },
            &keys(), now() + Duration::from_secs(2),
        ).err(),
        Some(OidcCodeFlowError::TokenResponseRejected),
    );
    let mut substituted: Value = serde_json::from_slice(&body).unwrap();
    substituted["access_token"] = json!("different-temporary-access");
    let substituted = serde_json::to_vec(&substituted).unwrap();
    assert_eq!(
        response_owner(seeded()).admit_token_response(
            EnterpriseTokenResponse { status: 200, headers: &headers, body: &substituted },
            &keys(), now() + Duration::from_secs(2),
        ).err(),
        Some(OidcCodeFlowError::TokenResponseRejected),
    );
}

#[test]
fn oidc_code_pipeline_tenancy_response_status_and_scope_cannot_be_reselected() {
    let (profile, documents) = profile_and_documents();
    let tenant_config = OidcCodeFlowConfiguration::from_documents(
        profile, REDIRECT, EnterpriseOidcSubjectType::Public, TenantExpectation::Exact("tenant-a"),
        &serde_json::to_vec(&documents[0]).unwrap(), &serde_json::to_vec(&documents[3]).unwrap(),
    ).unwrap();
    let pending = tenant_config.prepare_from_draws(
        &[0x11; 32], &[0x22; 32], &[0x33; 32], now(), now() + Duration::from_secs(300),
    ).unwrap();
    let headers = headers();
    let body = token_body();
    assert_eq!(
        response_owner(pending).admit_token_response(
            EnterpriseTokenResponse { status: 200, headers: &headers, body: &body },
            &keys(), now() + Duration::from_secs(2),
        ).err(),
        Some(OidcCodeFlowError::TokenResponseRejected),
    );
    for status in [201, 202, 204, 400, 401] {
        assert!(response_owner(seeded()).admit_token_response(
            EnterpriseTokenResponse { status, headers: &headers, body: &body },
            &keys(), now() + Duration::from_secs(2),
        ).is_err());
    }
    let mut expanded: Value = serde_json::from_slice(&body).unwrap();
    expanded["scope"] = json!("openid read");
    let expanded = serde_json::to_vec(&expanded).unwrap();
    assert!(response_owner(seeded()).admit_token_response(
        EnterpriseTokenResponse { status: 200, headers: &headers, body: &expanded },
        &keys(), now() + Duration::from_secs(2),
    ).is_err());
}

#[test]
fn oidc_code_pipeline_returns_typed_denial_without_resurrecting_code() {
    let headers = headers();
    let result = response_owner(seeded()).admit_token_response(
        EnterpriseTokenResponse { status: 400, headers: &headers, body: br#"{"error":"invalid_grant"}"# },
        &keys(), now() + Duration::from_secs(2),
    ).unwrap();
    match result {
        EnterpriseResponseOutcome::Denied { denial, .. } => {
            assert_eq!(denial.code(), super::super::response::EnterpriseOAuthErrorCode::InvalidGrant);
        }
        _ => panic!("OAuth denial produced an assertion"),
    }
    assert_eq!(
        response_owner(seeded()).admit_token_response(
            EnterpriseTokenResponse { status: 400, headers: &headers, body: br#"{"error":"invalid_grant"}"# },
            &keys(), now() + Duration::from_secs(300),
        ).err(),
        Some(OidcCodeFlowError::InvalidLifetime),
    );
}

const SIGNED_CODE_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImVudGVycHJpc2UtcmZjNzUxNSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiY2xpZW50LXN1YmplY3QiLCJhdWQiOiJuYXRpdmUtaWRwIiwiaWF0IjoyMDAwMDAwMDAwLCJleHAiOjIwMDAwMDAyNDAsIm5vbmNlIjoiSWlJaUlpSWlJaUlpSWlJaUlpSWlJaUlpSWlJaUlpSWlJaUlpSWlJaUlpSSIsImF0X2hhc2giOiJxSUJDX1p0VFlYdTJFbHY5OUQ5Qy1BIn0.XYRm25jK7AKhR4L17_3tQF_eN3I5mMhAhQ88HwcT2nkYN9pBqof1yAdTPMpN4c5vEmVsl_LlrStyqt-Rpq77SVJU0sOBO949TDn1qs9-Uz9VJZQ2LzGcciBwmcTUX0pAGTfGLzvCLxRoIgUJ101V92cBziPalTuRNoHUcnqftPcMsadbph8_JKoTBEjZjvKFzZz7QiswPCn4IcCnuKWkmB116wDv4DxRdEk91yawQrXu7pNPuidBUYQGQ95iqwHyTwV9tUl7TAUnfW9ldTbxJKXmkVtPCI6WTD8QGMvU_HLMfBBfOEhFQr-smHYGoml9jXCz0T4Gs9MG3R48sDVJqg";
