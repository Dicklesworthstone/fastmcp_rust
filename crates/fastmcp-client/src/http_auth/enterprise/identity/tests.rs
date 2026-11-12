//! Public producer/consumer tests use real RS256-signed public RFC7515 fixtures.
//! No verifier result, subject key or mapping result is fabricated by a test.

use super::*;
use super::super::policy::{
    EnterpriseClientAuthentication, EnterpriseProfileConfiguration,
    EnterpriseRegistrationConfiguration, IdJagCryptoConfiguration,
    RequestedEnterpriseScopeSet, ID_JAG_GRANT_PROFILE, ID_JAG_TOKEN_TYPE,
    JWT_BEARER_GRANT, TOKEN_EXCHANGE_GRANT,
};
use fastmcp_core::{CanonicalResourceIdPolicy, CanonicalHttpUrl};
use fastmcp_protocol::jose::enterprise::{
    IdJagExpectations, IdJagVerificationKeys, JwtTimePolicy, OidcIdTokenExpectations,
    OidcVerificationKeys, ResourceTenantExpectation, TenantExpectation,
    verify_id_jag, verify_oidc_id_token, verify_id_jag_with_disclosure,
    disclosure::{IdJagDisclosureConfiguration, IdJagDisclosurePolicy},
};
use serde_json::{Value, json};
use std::sync::OnceLock;

const ISSUED: u64 = 2_000_000_000;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}
fn now() -> SystemTime {
    at(ISSUED + 120)
}
fn fixtures() -> &'static Value {
    static FIXTURES: OnceLock<Value> = OnceLock::new();
    FIXTURES.get_or_init(|| serde_json::from_str(
        include_str!("../response/assertions.json"),
    ).unwrap())
}
fn tenant_fixtures() -> &'static Value {
    static FIXTURES: OnceLock<Value> = OnceLock::new();
    FIXTURES.get_or_init(|| serde_json::from_str(include_str!("assertions.json")).unwrap())
}
fn fixture(name: &str) -> &'static str {
    fixtures()[name].as_str().unwrap()
}
fn tenant_fixture(name: &str) -> &'static str {
    tenant_fixtures()[name].as_str().unwrap()
}
fn resource() -> CanonicalResourceId {
    let url = CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap();
    CanonicalResourceId::parse_for_endpoint(
        url.as_str(), &url, CanonicalResourceIdPolicy::default(),
    ).unwrap()
}
fn profile_configuration() -> EnterpriseProfileConfiguration {
    EnterpriseProfileConfiguration {
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
        resource: resource(),
        requested_scopes: RequestedEnterpriseScopeSet::from_literals(["read".to_owned()]).unwrap(),
        deployment_scope_allowance: vec!["read".into(), "write".into()],
        policy_generation: 30,
        idp_metadata_generation: 31,
        resource_as_metadata_generation: 32,
        aggregate_registration_generation: 33,
    }
}
fn admit_profile(configuration: EnterpriseProfileConfiguration) -> EnterpriseProfile {
    let docs = [
        json!({
            "issuer":configuration.idp.issuer,
            "token_endpoint":configuration.idp.token_endpoint,
            "authorization_endpoint":configuration.idp_authorization_endpoint,
            "jwks_uri":configuration.oidc_jwks_uri,
            "grant_types_supported":["authorization_code",TOKEN_EXCHANGE_GRANT],
            "response_types_supported":["code"], "code_challenge_methods_supported":["S256"],
            "token_endpoint_auth_methods_supported":[configuration.idp.authentication.as_str()],
            "identity_chaining_requested_token_types_supported":[ID_JAG_TOKEN_TYPE],
            "id_token_signing_alg_values_supported":["RS256"],
            "scopes_supported":["openid","read","write"]
        }),
        json!({
            "issuer":configuration.resource_as.issuer,
            "token_endpoint":configuration.resource_as.token_endpoint,
            "authorization_grant_profiles_supported":[ID_JAG_GRANT_PROFILE],
            "grant_types_supported":[JWT_BEARER_GRANT],
            "token_endpoint_auth_methods_supported":[configuration.resource_as.authentication.as_str()]
        }),
        json!({
            "authorization_grant_profiles_supported":[ID_JAG_GRANT_PROFILE],
            "grant_types":[TOKEN_EXCHANGE_GRANT,JWT_BEARER_GRANT]
        }),
        json!({
            "issuer":configuration.idp.issuer,
            "token_endpoint":configuration.idp.token_endpoint,
            "client_id":configuration.idp.client_id,
            "grant_types":["authorization_code",TOKEN_EXCHANGE_GRANT],
            "token_endpoint_auth_method":configuration.idp.authentication.as_str()
        }),
        json!({
            "issuer":configuration.resource_as.issuer,
            "token_endpoint":configuration.resource_as.token_endpoint,
            "client_id":configuration.resource_as.client_id,
            "grant_types":[JWT_BEARER_GRANT],
            "token_endpoint_auth_method":configuration.resource_as.authentication.as_str()
        }),
    ].map(|doc| serde_json::to_vec(&doc).unwrap());
    EnterpriseProfile::from_documents(
        configuration, &docs[0], &docs[1], &docs[2], &docs[3], &docs[4],
    ).unwrap()
}
fn profile() -> EnterpriseProfile {
    admit_profile(profile_configuration())
}
fn configuration(profile: &EnterpriseProfile) -> EnterpriseIdentityConfiguration {
    EnterpriseIdentityConfiguration {
        snapshot: EnterpriseIdentitySnapshotConfiguration {
            id: "reviewed-directory".into(),
            generation: 41,
            reviewed_at: at(ISSUED),
            review_expires_at: at(ISSUED + 600),
        },
        profile_policy_generation: profile.policy_generation(),
        trust_domains: EnterpriseIdentityTrustDomains {
            // The client may share the IdP's administrative trust domain.
            client: "idp-organization".into(),
            idp: "idp-organization".into(),
            resource_as: "resource-organization".into(),
        },
        idp_tenancy: EnterpriseIdpTenancyConfiguration::SingleTenant,
        resource_as_tenancy: EnterpriseResourceAsTenancyConfiguration::SingleTenant {
            identity: "resource-single".into(),
        },
        client_id_model: EnterpriseClientIdModel::Global {
            registrations: vec![EnterpriseGlobalClientRegistration {
                client_id: profile.resource_as_client_id().into(),
                resource_as_tenant: "resource-single".into(),
                registration_generation: profile.resource_as_registration_generation(),
            }],
        },
        client_relying_party: EnterpriseOidcRelyingPartyConfiguration {
            issuer: profile.idp_issuer().into(),
            tenant: None,
            client_id: profile.idp_client_id().into(),
            registration_generation: profile.idp_registration_generation(),
            subject_type: EnterpriseOidcSubjectType::Pairwise,
            redirect_uris: vec!["https://client.example/callback".into()],
        },
        resource_as_relying_party: ResourceAsIdpRelyingPartyConfiguration {
            relying_party: EnterpriseOidcRelyingPartyConfiguration {
                issuer: profile.idp_issuer().into(),
                tenant: None,
                client_id: "resource-as-sso-rp".into(),
                registration_generation: 51,
                subject_type: EnterpriseOidcSubjectType::Pairwise,
                redirect_uris: vec!["https://as.example/oidc/callback".into()],
            },
            resource_as_issuer: profile.resource_as_issuer().into(),
            resource_as_tenant: "resource-single".into(),
        },
        tenant_relationship: EnterpriseTenantRelationshipConfiguration {
            idp_tenant: None,
            resource_as_tenant: "resource-single".into(),
            generation: 52,
        },
        cross_domain_binding_generation: 53,
        subject_continuity_generation: 54,
    }
}
fn multi_tenant_configuration(profile: &EnterpriseProfile) -> EnterpriseIdentityConfiguration {
    let mut configuration = configuration(profile);
    configuration.idp_tenancy = EnterpriseIdpTenancyConfiguration::MultiTenant {
        tenant: "idp-tenant".into(),
    };
    configuration.resource_as_tenancy = EnterpriseResourceAsTenancyConfiguration::MultiTenant {
        tenant: "resource-tenant".into(),
    };
    configuration.client_id_model = EnterpriseClientIdModel::TenantScoped;
    configuration.client_relying_party.tenant = Some("idp-tenant".into());
    configuration.resource_as_relying_party.relying_party.tenant = Some("idp-tenant".into());
    configuration.resource_as_relying_party.resource_as_tenant = "resource-tenant".into();
    configuration.tenant_relationship.idp_tenant = Some("idp-tenant".into());
    configuration.tenant_relationship.resource_as_tenant = "resource-tenant".into();
    configuration
}
fn row() -> PreexistingEnterpriseSubjectMapping {
    PreexistingEnterpriseSubjectMapping {
        client_subject: "client-facing".into(),
        resource_subject: "resource-facing".into(),
        resource_audience_subject: None,
        local_subject: "preexisting-local-account".into(),
    }
}
fn verify_pair(
    oidc: &str,
    jag: &str,
    generations: (u64, u64),
    tenants: (Option<&str>, Option<&str>),
) -> (VerifiedOidcIdToken, VerifiedIdJag) {
    let jwks = serde_json::to_vec(&fixtures()["jwks"]).unwrap();
    let oidc_keys = OidcVerificationKeys::from_trusted_jwks(
        "https://idp.example", generations.0, &jwks,
    ).unwrap();
    let jag_keys = IdJagVerificationKeys::from_trusted_jwks(
        "https://idp.example", generations.1, &jwks,
    ).unwrap();
    let oidc = verify_oidc_id_token(oidc, &oidc_keys, &OidcIdTokenExpectations {
        client_id: "native-idp", nonce: "oidc-flow-nonce",
        access_token: Some("temporary-access"),
        tenant: tenants.0.map_or(TenantExpectation::SingleTenant, TenantExpectation::Exact),
        max_authentication_age: None, time: JwtTimePolicy::oidc_default(),
    }, now()).unwrap();
    let jag = verify_id_jag(jag, &jag_keys, &IdJagExpectations {
        audience: "https://as.example", client_id: "native-resource",
        resource: "https://mcp.example/mcp", require_resource: true,
        idp_tenant: tenants.0.map_or(TenantExpectation::SingleTenant, TenantExpectation::Exact),
        resource_tenant: tenants.1.map_or(
            ResourceTenantExpectation::SingleTenant, ResourceTenantExpectation::Exact,
        ),
        time: JwtTimePolicy::id_jag_default(),
    }, now()).unwrap();
    (oidc, jag)
}
fn facts() -> (VerifiedOidcIdToken, VerifiedIdJag) {
    verify_pair(fixture("oidc"), fixture("id_jag"), (21, 22), (None, None))
}

#[test]
fn signed_pairwise_subjects_resolve_only_the_preexisting_three_registration_mapping() {
    let profile = profile();
    let table = EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, configuration(&profile), vec![row()], now(),
    ).unwrap();
    let (oidc, jag) = facts();
    let resolved = table.resolve(&profile, &oidc, &jag, table.snapshot(), now()).unwrap();
    assert_eq!(resolved.local_subject().as_str(), "preexisting-local-account");
    assert_eq!(resolved.client_subject().subject().as_str(), "client-facing");
    assert_eq!(resolved.enterprise_subject().subject().as_str(), "resource-facing");
    assert_eq!(resolved.client_subject().registration().client_id(), "native-idp");
    assert_eq!(resolved.resource_client().client_id(), "native-resource");
    assert_eq!(resolved.enterprise_subject().registration().relying_party_client_id(), "resource-as-sso-rp");
    assert_eq!(resolved.client_subject().namespace().sector_host(), Some("client.example"));
    assert_eq!(resolved.enterprise_subject().namespace().sector_host(), Some("as.example"));
    assert_eq!(resolved.resource().as_str(), "https://mcp.example/mcp");
    assert_eq!(resolved.oidc_digest(), oidc.compact_digest());
    assert_eq!(resolved.id_jag_digest(), jag.compact_digest());
    assert_eq!(resolved.expires_at(), at(ISSUED + 240));
    assert!(resolved.resource_client().tenant().is_none());
    assert!(resolved.audience_subject().is_none());
    assert_eq!(resolved.snapshot(), table.snapshot());
    let diagnostic = format!("{table:?} {resolved:?} {:?} {:?} {:?} {:?}",
        resolved.client_subject(), resolved.enterprise_subject(),
        resolved.local_subject(), configuration(&profile));
    for sensitive in ["client-facing", "resource-facing", "preexisting-local-account",
        "idp.example", "native-resource", "resource-as-sso-rp", "resource-single"] {
        assert!(!diagnostic.contains(sensitive));
    }
}

#[test]
fn signed_equal_subject_text_cannot_create_or_repair_a_mapping() {
    let profile = profile();
    let (oidc, equal_jag) = verify_pair(
        fixture("oidc"), tenant_fixture("id_jag_equal_subject"), (21, 22), (None, None),
    );
    assert_eq!(oidc.subject().as_str(), equal_jag.subject().as_str());
    let empty = EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, configuration(&profile), vec![], now(),
    ).unwrap();
    let before = empty.snapshot().clone();
    assert_eq!(empty.resolve(&profile, &oidc, &equal_jag, &before, now()).unwrap_err(),
        EnterpriseIdentityError::MappingUnavailable);
    assert_eq!(empty.snapshot(), &before);
    assert!(empty.records.is_empty());

    let table = EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, configuration(&profile), vec![row()], now(),
    ).unwrap();
    let before = table.snapshot().clone();
    assert_eq!(table.resolve(&profile, &oidc, &equal_jag, &before, now()).unwrap_err(),
        EnterpriseIdentityError::MappingUnavailable);
    let (_, correct_jag) = facts();
    assert!(table.resolve(&profile, &oidc, &correct_jag, &before, now()).is_ok());
    assert_eq!(table.records.len(), 1);
    assert_eq!(table.snapshot(), &before);
}

#[test]
fn signed_multi_tenant_subjects_require_the_exact_explicit_relationship_and_audience_account() {
    let profile = profile();
    let mut mapping = row();
    mapping.resource_audience_subject = Some("opaque/account".into());
    let table = EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, multi_tenant_configuration(&profile), vec![mapping.clone()], now(),
    ).unwrap();
    let (oidc, jag) = verify_pair(tenant_fixture("oidc"), tenant_fixture("id_jag"),
        (21, 22), (Some("idp-tenant"), Some("resource-tenant")));
    let resolved = table.resolve(&profile, &oidc, &jag, table.snapshot(), now()).unwrap();
    assert_eq!(resolved.client_subject().registration().tenant().unwrap().as_str(), "idp-tenant");
    assert_eq!(resolved.resource_client().tenant().unwrap().as_str(), "resource-tenant");
    assert_eq!(resolved.resource_client().scope(), EnterpriseClientIdScope::TenantScoped);
    assert_eq!(resolved.audience_subject().unwrap().as_str(), "opaque/account");
    assert_eq!(resolved.enterprise_subject().registration().resource_as_tenant().as_str(), "resource-tenant");

    mapping.resource_audience_subject = Some("different-preexisting-account".into());
    let other = EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, multi_tenant_configuration(&profile), vec![mapping], now(),
    ).unwrap();
    assert_eq!(other.resolve(&profile, &oidc, &jag, other.snapshot(), now()).unwrap_err(),
        EnterpriseIdentityError::MappingUnavailable);

    let mut changed = multi_tenant_configuration(&profile);
    changed.resource_as_tenancy = EnterpriseResourceAsTenancyConfiguration::MultiTenant {
        tenant: "idp-tenant".into(),
    };
    // Matching the IdP's tenant spelling cannot manufacture the missing bridge.
    assert_eq!(EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, changed, vec![], now(),
    ).unwrap_err(), EnterpriseIdentityError::TenantMismatch);
}

#[test]
fn single_tenant_resource_clients_can_use_an_explicit_tenant_scoped_registration_key() {
    let profile = profile();
    let mut configuration = configuration(&profile);
    configuration.client_id_model = EnterpriseClientIdModel::TenantScoped;
    let table = EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, configuration, vec![row()], now(),
    ).unwrap();
    let (oidc, jag) = facts();
    let resolved = table.resolve(&profile, &oidc, &jag, table.snapshot(), now()).unwrap();
    assert_eq!(resolved.resource_client().scope(), EnterpriseClientIdScope::TenantScoped);
    assert_eq!(resolved.resource_client().tenant().unwrap().as_str(), "resource-single");
    assert!(resolved.audience_subject().is_none());
}

#[test]
fn registration_role_generation_and_trust_domain_substitution_fail_before_lookup() {
    let profile = profile();
    let cases: Vec<(EnterpriseIdentityConfiguration, EnterpriseIdentityError)> = [
        {
            let mut c = configuration(&profile);
            c.client_relying_party.client_id = "native-resource".into();
            (c, EnterpriseIdentityError::RegistrationMismatch)
        },
        {
            let mut c = configuration(&profile);
            c.client_relying_party.registration_generation += 1;
            (c, EnterpriseIdentityError::RegistrationMismatch)
        },
        {
            let mut c = configuration(&profile);
            c.resource_as_relying_party.resource_as_issuer = "https://other.example".into();
            (c, EnterpriseIdentityError::RegistrationMismatch)
        },
        {
            let mut c = configuration(&profile);
            c.resource_as_relying_party.relying_party.client_id = "https://cimd.example/client".into();
            (c, EnterpriseIdentityError::RegistrationMismatch)
        },
        {
            let mut c = configuration(&profile);
            c.trust_domains.resource_as = c.trust_domains.idp.clone();
            (c, EnterpriseIdentityError::TrustDomainMismatch)
        },
        {
            let mut c = configuration(&profile);
            c.tenant_relationship.generation = 0;
            (c, EnterpriseIdentityError::TenantMismatch)
        },
    ].into();
    for (configuration, expected) in cases {
        assert_eq!(EnterpriseSubjectMappingTable::from_trusted_configuration(
            &profile, configuration, vec![row()], now(),
        ).unwrap_err(), expected);
    }
}

#[test]
fn global_client_inventory_rejects_cross_tenant_aliases_and_stale_selected_registration() {
    let profile = profile();
    for duplicate_tenant in ["resource-single", "another-tenant"] {
        let mut configuration = configuration(&profile);
        let EnterpriseClientIdModel::Global { registrations } = &mut configuration.client_id_model
            else { unreachable!() };
        registrations.push(EnterpriseGlobalClientRegistration {
            client_id: "native-resource".into(),
            resource_as_tenant: duplicate_tenant.into(),
            registration_generation: 12,
        });
        assert_eq!(EnterpriseSubjectMappingTable::from_trusted_configuration(
            &profile, configuration, vec![row()], now(),
        ).unwrap_err(), EnterpriseIdentityError::DuplicateMapping);
    }
    let mut configuration = configuration(&profile);
    let EnterpriseClientIdModel::Global { registrations } = &mut configuration.client_id_model
        else { unreachable!() };
    registrations[0].registration_generation += 1;
    assert_eq!(EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, configuration, vec![row()], now(),
    ).unwrap_err(), EnterpriseIdentityError::RegistrationMismatch);
}

#[test]
fn oidc_namespace_identity_uses_exact_public_or_redirect_host_pairwise_rules() {
    let issuer = "https://idp.example";
    let namespace = |kind, generation, redirects: &[&str]| {
        OidcSubjectNamespace::from_preregistered_redirects(
            issuer, kind, generation,
            &redirects.iter().map(|value| (*value).to_owned()).collect::<Vec<_>>(),
        )
    };
    let public = namespace(EnterpriseOidcSubjectType::Public, 11,
        &["https://client.example/a", "https://other.example/b"]).unwrap();
    assert!(public.sector_host().is_none());
    assert!(public.registration_generation().is_none());
    assert_eq!(public, namespace(EnterpriseOidcSubjectType::Public, 99,
        &["https://third.example/c"]).unwrap());
    let pairwise = namespace(EnterpriseOidcSubjectType::Pairwise, 11,
        &["https://client.example/a", "https://client.example/b"]).unwrap();
    assert_eq!(pairwise.sector_host(), Some("client.example"));
    assert_eq!(pairwise.registration_generation(), Some(11));
    assert_ne!(pairwise, namespace(EnterpriseOidcSubjectType::Pairwise, 12,
        &["https://client.example/a"]).unwrap());
    for redirects in [
        vec!["https://client.example/a", "https://other.example/b"],
        vec!["https://client.example/a", "https://client.example/a"],
        vec!["http://client.example/a"],
        vec!["https://user@client.example/a"],
        vec!["https://client.example/a?state=x"],
        vec!["https://client.example/a#fragment"],
        vec!["https://CLIENT.example/a"],
        vec![],
    ] {
        assert_eq!(namespace(EnterpriseOidcSubjectType::Pairwise, 11, &redirects).unwrap_err(),
            EnterpriseIdentityError::InvalidNamespace);
    }
}

#[test]
fn snapshot_digest_is_order_independent_but_binds_reviewed_policy_and_mapping_content() {
    let profile = profile();
    let mut first_configuration = configuration(&profile);
    first_configuration.client_relying_party.redirect_uris.push("https://client.example/other".into());
    let EnterpriseClientIdModel::Global { registrations } = &mut first_configuration.client_id_model
        else { unreachable!() };
    registrations.push(EnterpriseGlobalClientRegistration {
        client_id: "another-client".into(), resource_as_tenant: "another-tenant".into(),
        registration_generation: 17,
    });
    let extra = PreexistingEnterpriseSubjectMapping {
        client_subject: "another-client-subject".into(),
        resource_subject: "another-resource-subject".into(),
        resource_audience_subject: None, local_subject: "another-local-account".into(),
    };
    let first = EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, first_configuration.clone(), vec![row(), extra.clone()], now(),
    ).unwrap();
    let mut reordered = first_configuration.clone();
    reordered.client_relying_party.redirect_uris.reverse();
    let EnterpriseClientIdModel::Global { registrations } = &mut reordered.client_id_model
        else { unreachable!() };
    registrations.reverse();
    let second = EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, reordered, vec![extra.clone(), row()], now(),
    ).unwrap();
    assert_eq!(first.snapshot(), second.snapshot());

    first_configuration.subject_continuity_generation += 1;
    let changed = EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, first_configuration, vec![row(), extra], now(),
    ).unwrap();
    assert_ne!(first.snapshot().digest(), changed.snapshot().digest());
    let (oidc, jag) = facts();
    assert_eq!(changed.resolve(&profile, &oidc, &jag, first.snapshot(), now()).unwrap_err(),
        EnterpriseIdentityError::SnapshotMismatch);
    assert!(changed.resolve(&profile, &oidc, &jag, changed.snapshot(), now()).is_ok());
}

#[test]
fn review_and_signed_expiry_boundaries_never_extend_a_resolved_identity() {
    let profile = profile();
    let mut cfg = configuration(&profile);
    cfg.snapshot.review_expires_at = now() + Duration::from_secs(10);
    let table = EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, cfg.clone(), vec![row()], now(),
    ).unwrap();
    let (oidc, jag) = facts();
    let resolved = table.resolve(&profile, &oidc, &jag, table.snapshot(), now()).unwrap();
    assert_eq!(resolved.expires_at(), now() + Duration::from_secs(10));
    assert_eq!(table.resolve(&profile, &oidc, &jag, table.snapshot(),
        now() + Duration::from_secs(10)).unwrap_err(), EnterpriseIdentityError::ExpiredSnapshot);
    assert_eq!(EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, cfg.clone(), vec![row()], cfg.snapshot.review_expires_at,
    ).unwrap_err(), EnterpriseIdentityError::ExpiredSnapshot);
    cfg.snapshot.review_expires_at = cfg.snapshot.reviewed_at
        + MAX_ENTERPRISE_IDENTITY_REVIEW_LIFETIME + Duration::from_nanos(1);
    assert_eq!(EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, cfg, vec![row()], now(),
    ).unwrap_err(), EnterpriseIdentityError::InvalidSnapshot);

    let table = EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, configuration(&profile), vec![row()], now(),
    ).unwrap();
    assert_eq!(table.resolve(&profile, &oidc, &jag, table.snapshot(), at(ISSUED + 240)).unwrap_err(),
        EnterpriseIdentityError::TokenTimeInvalid);
}

#[test]
fn current_profile_and_purpose_key_generations_are_rechecked_for_every_resolution() {
    let profile = profile();
    let table = EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, configuration(&profile), vec![row()], now(),
    ).unwrap();
    let (oidc, jag) = facts();
    let mut changed = profile_configuration();
    changed.idp_metadata_generation += 1;
    assert_eq!(table.resolve(&admit_profile(changed), &oidc, &jag, table.snapshot(), now()).unwrap_err(),
        EnterpriseIdentityError::ProfileMismatch);
    let mut changed = profile_configuration();
    changed.idp.scope_allowance = vec!["read".into(), "write".into()];
    let changed = admit_profile(changed);
    assert!(!changed.permits_oidc_openid());
    assert_eq!(table.resolve(&changed, &oidc, &jag, table.snapshot(), now()).unwrap_err(),
        EnterpriseIdentityError::ProfileMismatch);
    for generations in [(22, 22), (21, 23)] {
        let (oidc, jag) = verify_pair(fixture("oidc"), fixture("id_jag"), generations, (None, None));
        assert_eq!(table.resolve(&profile, &oidc, &jag, table.snapshot(), now()).unwrap_err(),
            EnterpriseIdentityError::TokenBindingMismatch);
    }
    assert!(table.resolve(&profile, &oidc, &jag, table.snapshot(), now()).is_ok());
}

#[test]
fn ambiguous_or_oversized_mapping_inputs_never_modify_an_existing_snapshot() {
    let profile = profile();
    let table = EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, configuration(&profile), vec![row()], now(),
    ).unwrap();
    let snapshot = table.snapshot().clone();
    for rows in [
        vec![row(), row()],
        vec![row(), PreexistingEnterpriseSubjectMapping {
            client_subject: "different".into(), ..row()
        }],
    ] {
        assert_eq!(EnterpriseSubjectMappingTable::from_trusted_configuration(
            &profile, configuration(&profile), rows, now(),
        ).unwrap_err(), EnterpriseIdentityError::DuplicateMapping);
    }
    let mut invalid = row();
    invalid.client_subject = "x".repeat(256);
    assert_eq!(EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, configuration(&profile), vec![invalid], now(),
    ).unwrap_err(), EnterpriseIdentityError::InvalidMapping);
    assert_eq!(EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, configuration(&profile), vec![row(); MAX_ENTERPRISE_SUBJECT_MAPPINGS + 1], now(),
    ).unwrap_err(), EnterpriseIdentityError::CapacityExceeded);
    assert_eq!(table.snapshot(), &snapshot);
    let (oidc, jag) = facts();
    assert!(table.resolve(&profile, &oidc, &jag, &snapshot, now()).is_ok());
}

#[test]
fn disclosure_review_expiry_and_policy_identity_survive_subject_resolution() {
    let profile = profile();
    let table = EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, configuration(&profile), vec![row()], now(),
    ).unwrap();
    let (oidc, closed_jag) = facts();
    let jwks = serde_json::to_vec(&fixtures()["jwks"]).unwrap();
    let keys = IdJagVerificationKeys::from_trusted_jwks("https://idp.example", 22, &jwks).unwrap();
    let policy = IdJagDisclosurePolicy::from_trusted_configuration(IdJagDisclosureConfiguration {
        policy_id: "reviewed-empty-disclosure".into(), generation: 71,
        idp_issuer: "https://idp.example".into(), resource_as_issuer: "https://as.example".into(),
        reviewed_at: at(ISSUED), review_expires_at: now() + Duration::from_secs(5),
        rules: vec![],
    }).unwrap();
    let jag = verify_id_jag_with_disclosure(fixture("id_jag"), &keys, &IdJagExpectations {
        audience: "https://as.example", client_id: "native-resource",
        resource: "https://mcp.example/mcp", require_resource: true,
        idp_tenant: TenantExpectation::SingleTenant,
        resource_tenant: ResourceTenantExpectation::SingleTenant,
        time: JwtTimePolicy::id_jag_default(),
    }, &policy, now()).unwrap();
    assert_eq!(jag.compact_digest(), closed_jag.compact_digest());
    let resolved = table.resolve(&profile, &oidc, &jag, table.snapshot(), now()).unwrap();
    let closed = table.resolve(&profile, &oidc, &closed_jag, table.snapshot(), now()).unwrap();
    assert_ne!(resolved.binding_digest(), closed.binding_digest());
    assert_eq!(resolved.expires_at(), policy.review_expires_at());
    assert_eq!(table.resolve(&profile, &oidc, &jag, table.snapshot(),
        policy.review_expires_at()).unwrap_err(), EnterpriseIdentityError::TokenTimeInvalid);
    assert!(table.resolve(&profile, &oidc, &closed_jag, table.snapshot(),
        policy.review_expires_at()).is_ok());
}


#[test]
fn reviewed_sector_documents_bind_both_mapping_roles_and_resolve_signed_subjects() {
    // Sector responses are unit fixtures; the consumer still verifies real
    // RS256 token facts. This is not evidence of a public-network fetch.
    let profile = profile();
    let mut configuration = configuration(&profile);
    configuration.client_relying_party.redirect_uris.push(
        "https://alternate-client.example/callback".into(),
    );
    configuration.resource_as_relying_party.relying_party.redirect_uris.push(
        "https://alternate-as.example/callback".into(),
    );
    assert!(EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, configuration.clone(), vec![row()], now(),
    ).is_err());
    let client = sector::tests::reviewed_fixture(
        OidcSectorRegistrationRole::Client, &configuration.client_relying_party,
        "https://client-sector.example/redirects.json",
        &["https://document-only.example/callback"],
    );
    let resource = sector::tests::reviewed_fixture(
        OidcSectorRegistrationRole::ResourceAuthorizationServer,
        &configuration.resource_as_relying_party.relying_party,
        "https://resource-sector.example/redirects.json", &[],
    );
    let table = EnterpriseSubjectMappingTable::from_trusted_configuration_with_sector_reviews(
        &profile, configuration.clone(), vec![row()], Some(&client), Some(&resource), now(),
    ).unwrap();
    let (oidc, jag) = facts();
    let resolved = table.resolve(&profile, &oidc, &jag, table.snapshot(), now()).unwrap();
    assert_eq!(resolved.local_subject().as_str(), "preexisting-local-account");
    assert_eq!(resolved.client_subject().subject().as_str(), "client-facing");
    assert_eq!(resolved.enterprise_subject().subject().as_str(), "resource-facing");
    assert_eq!(resolved.client_subject().namespace().sector_host(), Some("client-sector.example"));
    assert_eq!(resolved.enterprise_subject().namespace().sector_host(), Some("resource-sector.example"));
    assert_eq!(table.client_namespace().sector_review_digest(), Some(client.binding_digest()));
    assert_eq!(table.resource_namespace().sector_review_digest(), Some(resource.binding_digest()));

    let before = table.snapshot().clone();
    let wrong_role = sector::tests::reviewed_fixture(
        OidcSectorRegistrationRole::ResourceAuthorizationServer,
        &configuration.client_relying_party,
        "https://client-sector.example/redirects.json", &[],
    );
    assert_eq!(EnterpriseSubjectMappingTable::from_trusted_configuration_with_sector_reviews(
        &profile, configuration.clone(), vec![row()], Some(&wrong_role), Some(&resource), now(),
    ).err(), Some(EnterpriseIdentityError::RegistrationMismatch));
    for mutation in 0..3 {
        let mut changed = configuration.clone();
        match mutation {
            0 => changed.resource_as_relying_party.relying_party.registration_generation += 1,
            1 => { changed.resource_as_relying_party.relying_party.redirect_uris.pop(); }
            2 => changed.client_relying_party.redirect_uris.push(
                "https://document-only.example/callback".into(),
            ),
            _ => unreachable!(),
        }
        assert_eq!(EnterpriseSubjectMappingTable::from_trusted_configuration_with_sector_reviews(
            &profile, changed, vec![row()], Some(&client), Some(&resource), now(),
        ).err(), Some(EnterpriseIdentityError::RegistrationMismatch));
        assert_eq!(table.snapshot(), &before);
    }
    assert!(table.resolve(&profile, &oidc, &jag, &before, now()).is_ok());
}

#[test]
fn reviewed_sector_content_and_final_url_changes_invalidate_the_identity_snapshot() {
    let profile = profile();
    let configuration = configuration(&profile);
    let original = sector::tests::reviewed_fixture(
        OidcSectorRegistrationRole::Client, &configuration.client_relying_party,
        "https://sector.example/redirects.json", &[],
    );
    let table = EnterpriseSubjectMappingTable::from_trusted_configuration_with_sector_reviews(
        &profile, configuration.clone(), vec![row()], Some(&original), None, now(),
    ).unwrap();
    let (oidc, jag) = facts();
    assert!(table.resolve(&profile, &oidc, &jag, table.snapshot(), now()).is_ok());
    for changed in [
        sector::tests::reviewed_fixture(
            OidcSectorRegistrationRole::Client, &configuration.client_relying_party,
            "https://sector.example/redirects.json", &["https://extra.example/callback"],
        ),
        sector::tests::reviewed_fixture(
            OidcSectorRegistrationRole::Client, &configuration.client_relying_party,
            "https://sector.example/other.json", &[],
        ),
    ] {
        let revised = EnterpriseSubjectMappingTable::from_trusted_configuration_with_sector_reviews(
            &profile, configuration.clone(), vec![row()], Some(&changed), None, now(),
        ).unwrap();
        assert_eq!(table.client_namespace().sector_host(), revised.client_namespace().sector_host());
        assert_ne!(table.snapshot().digest(), revised.snapshot().digest());
        assert_eq!(revised.resolve(&profile, &oidc, &jag, table.snapshot(), now()).err(),
            Some(EnterpriseIdentityError::SnapshotMismatch));
        assert!(revised.resolve(&profile, &oidc, &jag, revised.snapshot(), now()).is_ok());
    }
    let ordinary = EnterpriseSubjectMappingTable::from_trusted_configuration(
        &profile, configuration.clone(), vec![row()], now(),
    ).unwrap();
    let no_reviews = EnterpriseSubjectMappingTable::from_trusted_configuration_with_sector_reviews(
        &profile, configuration, vec![row()], None, None, now(),
    ).unwrap();
    assert_eq!(ordinary.snapshot(), no_reviews.snapshot());
    assert!(ordinary.client_namespace().sector_review_digest().is_none());
}
