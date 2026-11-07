//! Immutable, preexisting enterprise subject mappings over verified token facts.
//!
//! An operator imports one reviewed configuration snapshot, three independent
//! registrations and an explicit subject table. Resolution performs no I/O and
//! cannot create, link, merge or update an account. Unequal pairwise subjects
//! work when an exact row exists; equal subject text never supplies a row.
//!
//! This is local configuration admission and read-only identity resolution. A
//! snapshot digest is not a deployment attestation, a rollback-resistant fence,
//! a durable replay reservation or evidence that two responses share a network
//! exchange. The eventual enterprise flow must obtain those independently. No
//! result here converts into a principal, bearer credential or EMA activation.
//! In particular, callers must not interpret a successful lookup as proof of
//! browser/nonce provenance or authorization to redeem either assertion.
//!
//! This bounded namespace subset supports public subjects and pairwise sectors
//! derived from registered redirect hosts. A floating sector document is not an
//! input; supporting it requires independently admitted guarded-fetch evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fastmcp_core::{CanonicalHttpUrl, CanonicalResourceId, Sha256Digest, crypto::sha256_bounded};
use fastmcp_protocol::jose::enterprise::{
    ClientFacingSubjectId, ResourceAudienceSubjectId, ResourceFacingSubjectId,
    VerifiedIdJag, VerifiedOidcIdToken,
};

use super::policy::EnterpriseProfile;

/// Each imported table and global client inventory has a finite cardinality.
pub const MAX_ENTERPRISE_SUBJECT_MAPPINGS: usize = 4096;
/// A local review is never accepted indefinitely, even if assertions expire.
pub const MAX_ENTERPRISE_IDENTITY_REVIEW_LIFETIME: Duration = Duration::from_secs(366 * 86_400);
const MAX_REDIRECTS: usize = 16;
const MAX_IDENTIFIER_BYTES: usize = 1024;
const MAX_TENANT_BYTES: usize = 256;
const MAX_SUBJECT_BYTES: usize = 255;
const MAX_URL_BYTES: usize = 4096;
const MAX_CONFIGURATION_BYTES: usize = 16 * 1024 * 1024;
const MAX_UNIX_SECONDS: u64 = 253_402_300_799;

/// Fixed diagnostics contain no issuer, client, subject, tenant or local account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseIdentityError {
    InvalidConfiguration,
    InvalidNamespace,
    InvalidSnapshot,
    ExpiredSnapshot,
    SnapshotMismatch,
    ProfileMismatch,
    RegistrationMismatch,
    TrustDomainMismatch,
    TenantMismatch,
    DuplicateMapping,
    InvalidMapping,
    MappingUnavailable,
    TokenBindingMismatch,
    TokenTimeInvalid,
    CapacityExceeded,
}

impl fmt::Display for EnterpriseIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid enterprise identity configuration",
            Self::InvalidNamespace => "invalid enterprise subject namespace",
            Self::InvalidSnapshot => "invalid enterprise identity review snapshot",
            Self::ExpiredSnapshot => "enterprise identity review is not current",
            Self::SnapshotMismatch => "enterprise identity snapshot differs from the expected snapshot",
            Self::ProfileMismatch => "enterprise profile differs from the identity snapshot",
            Self::RegistrationMismatch => "enterprise identity registration differs from its role",
            Self::TrustDomainMismatch => "enterprise issuer and redeemer trust domains are not distinct",
            Self::TenantMismatch => "enterprise tenant relationship is not explicitly configured",
            Self::DuplicateMapping => "enterprise identity configuration contains ambiguous mappings",
            Self::InvalidMapping => "invalid preexisting enterprise subject mapping",
            Self::MappingUnavailable => "enterprise subject mapping is unavailable",
            Self::TokenBindingMismatch => "verified enterprise facts differ from their configured binding",
            Self::TokenTimeInvalid => "verified enterprise facts are not current",
            Self::CapacityExceeded => "enterprise identity configuration exceeds its bound",
        })
    }
}

impl std::error::Error for EnterpriseIdentityError {}

/// The two exact OIDC subject namespaces supported by local admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseOidcSubjectType {
    Public,
    Pairwise,
}

/// A locally derived namespace. No caller supplies an arbitrary sector name.
#[derive(Clone, Eq, PartialEq)]
pub struct OidcSubjectNamespace {
    issuer: String,
    subject_type: EnterpriseOidcSubjectType,
    sector_host: Option<String>,
    registration_generation: Option<u64>,
}

impl OidcSubjectNamespace {
    /// Derives a namespace from explicitly trusted preregistration inputs.
    ///
    /// Redirects must be unique exact canonical HTTPS URLs, with no query,
    /// fragment, userinfo or parser repair. Pairwise redirects must share one
    /// host. Public subjects have no sector or namespace generation; their
    /// registration generation remains part of the separate RP key.
    pub fn from_preregistered_redirects(
        issuer: &str,
        subject_type: EnterpriseOidcSubjectType,
        registration_generation: u64,
        registered_redirects: &[String],
    ) -> Result<Self, EnterpriseIdentityError> {
        admit_issuer(issuer)?;
        if registration_generation == 0
            || registered_redirects.is_empty()
            || registered_redirects.len() > MAX_REDIRECTS
        {
            return Err(EnterpriseIdentityError::InvalidNamespace);
        }
        let mut redirects = BTreeSet::new();
        let mut hosts = BTreeSet::new();
        for redirect in registered_redirects {
            let parsed = admit_redirect(redirect)?;
            if !redirects.insert(redirect.as_str()) {
                return Err(EnterpriseIdentityError::InvalidNamespace);
            }
            hosts.insert(parsed.host().to_owned());
        }
        let (sector_host, generation) = match subject_type {
            EnterpriseOidcSubjectType::Public => (None, None),
            EnterpriseOidcSubjectType::Pairwise => {
                if hosts.len() != 1 {
                    return Err(EnterpriseIdentityError::InvalidNamespace);
                }
                (hosts.into_iter().next(), Some(registration_generation))
            }
        };
        Ok(Self {
            issuer: issuer.to_owned(),
            subject_type,
            sector_host,
            registration_generation: generation,
        })
    }

    #[must_use]
    pub fn issuer(&self) -> &str { &self.issuer }
    #[must_use]
    pub const fn subject_type(&self) -> EnterpriseOidcSubjectType { self.subject_type }
    #[must_use]
    pub fn sector_host(&self) -> Option<&str> { self.sector_host.as_deref() }
    #[must_use]
    pub const fn registration_generation(&self) -> Option<u64> { self.registration_generation }
}

/// Exact, independently reviewed Client-to-IdP or resource-AS-to-IdP RP inputs.
#[derive(Clone)]
pub struct EnterpriseOidcRelyingPartyConfiguration {
    pub issuer: String,
    pub tenant: Option<String>,
    pub client_id: String,
    pub registration_generation: u64,
    pub subject_type: EnterpriseOidcSubjectType,
    pub redirect_uris: Vec<String>,
}

/// The third registration has its own RP client ID and generation. Its resource
/// tenant is a configured registration identity, not an assertion-selected one.
#[derive(Clone)]
pub struct ResourceAsIdpRelyingPartyConfiguration {
    pub relying_party: EnterpriseOidcRelyingPartyConfiguration,
    pub resource_as_issuer: String,
    pub resource_as_tenant: String,
}

#[derive(Clone)]
pub enum EnterpriseIdpTenancyConfiguration {
    SingleTenant,
    MultiTenant { tenant: String },
}

/// A single-tenant AS still has an explicit local registration identity for
/// tenant-scoped client IDs. It must not emit aud_tenant or aud_sub claims.
#[derive(Clone)]
pub enum EnterpriseResourceAsTenancyConfiguration {
    SingleTenant { identity: String },
    MultiTenant { tenant: String },
}

/// One entry in the complete operator-supplied global client-ID inventory for
/// this resource-AS issuer. Import checks uniqueness across all supplied tenants;
/// completeness of that inventory remains the configuration provider's duty.
#[derive(Clone)]
pub struct EnterpriseGlobalClientRegistration {
    pub client_id: String,
    pub resource_as_tenant: String,
    pub registration_generation: u64,
}

#[derive(Clone)]
pub enum EnterpriseClientIdModel {
    /// The selected registration must appear exactly once in this inventory.
    Global { registrations: Vec<EnterpriseGlobalClientRegistration> },
    /// The selected configured tenant is part of the resource-domain key.
    TenantScoped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseClientIdScope {
    Global,
    TenantScoped,
}

/// One explicit, revisioned tenant relationship for this fixed profile.
/// Identical tenant text on the two sides never constructs this relationship.
#[derive(Clone)]
pub struct EnterpriseTenantRelationshipConfiguration {
    pub idp_tenant: Option<String>,
    pub resource_as_tenant: String,
    pub generation: u64,
}

#[derive(Clone)]
pub struct EnterpriseIdentityTrustDomains {
    pub client: String,
    pub idp: String,
    pub resource_as: String,
}

/// An immutable local review window, not proof of an external snapshot fence.
#[derive(Clone)]
pub struct EnterpriseIdentitySnapshotConfiguration {
    pub id: String,
    pub generation: u64,
    pub reviewed_at: SystemTime,
    pub review_expires_at: SystemTime,
}

/// Trusted configuration used only by the local read-only resolver. Importing
/// it proves internal consistency, not deployment attestation or remote policy.
#[derive(Clone)]
pub struct EnterpriseIdentityConfiguration {
    pub snapshot: EnterpriseIdentitySnapshotConfiguration,
    pub profile_policy_generation: u64,
    pub trust_domains: EnterpriseIdentityTrustDomains,
    pub idp_tenancy: EnterpriseIdpTenancyConfiguration,
    pub resource_as_tenancy: EnterpriseResourceAsTenancyConfiguration,
    pub client_id_model: EnterpriseClientIdModel,
    pub client_relying_party: EnterpriseOidcRelyingPartyConfiguration,
    pub resource_as_relying_party: ResourceAsIdpRelyingPartyConfiguration,
    pub tenant_relationship: EnterpriseTenantRelationshipConfiguration,
    pub cross_domain_binding_generation: u64,
    pub subject_continuity_generation: u64,
}

/// An explicit preexisting reviewed association. No email, display name,
/// assertion claim or matching string creates a missing record.
#[derive(Clone)]
pub struct PreexistingEnterpriseSubjectMapping {
    pub client_subject: String,
    pub resource_subject: String,
    pub resource_audience_subject: Option<String>,
    pub local_subject: String,
}

/// A configured IdP tenant, distinct from the resource-AS tenant namespace.
#[derive(Clone, Eq, PartialEq)]
pub struct ConfiguredIdpTenantId(String);
impl ConfiguredIdpTenantId {
    #[must_use]
    pub fn as_str(&self) -> &str { &self.0 }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConfiguredResourceAsTenantId(String);
impl ConfiguredResourceAsTenantId {
    #[must_use]
    pub fn as_str(&self) -> &str { &self.0 }
}

/// An identifier for an existing local account; it has no principal conversion.
pub struct LocalEnterpriseSubjectId(String);
impl LocalEnterpriseSubjectId {
    #[must_use]
    pub fn as_str(&self) -> &str { &self.0 }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ClientIdpRelyingPartyKey {
    issuer: String,
    tenant: Option<ConfiguredIdpTenantId>,
    client_id: String,
    registration_generation: u64,
}
impl ClientIdpRelyingPartyKey {
    #[must_use]
    pub fn issuer(&self) -> &str { &self.issuer }
    #[must_use]
    pub fn tenant(&self) -> Option<&ConfiguredIdpTenantId> { self.tenant.as_ref() }
    #[must_use]
    pub fn client_id(&self) -> &str { &self.client_id }
    #[must_use]
    pub const fn registration_generation(&self) -> u64 { self.registration_generation }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EnterpriseClientKey {
    resource_as_issuer: String,
    resource_as_tenant: Option<ConfiguredResourceAsTenantId>,
    client_id: String,
    registration_generation: u64,
    scope: EnterpriseClientIdScope,
}
impl EnterpriseClientKey {
    #[must_use]
    pub fn issuer(&self) -> &str { &self.resource_as_issuer }
    #[must_use]
    pub fn tenant(&self) -> Option<&ConfiguredResourceAsTenantId> { self.resource_as_tenant.as_ref() }
    #[must_use]
    pub fn client_id(&self) -> &str { &self.client_id }
    #[must_use]
    pub const fn registration_generation(&self) -> u64 { self.registration_generation }
    #[must_use]
    pub const fn scope(&self) -> EnterpriseClientIdScope { self.scope }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ResourceAsIdpRelyingPartyKey {
    idp_issuer: String,
    idp_tenant: Option<ConfiguredIdpTenantId>,
    resource_as_issuer: String,
    resource_as_tenant: ConfiguredResourceAsTenantId,
    relying_party_client_id: String,
    registration_generation: u64,
}
impl ResourceAsIdpRelyingPartyKey {
    #[must_use]
    pub fn idp_issuer(&self) -> &str { &self.idp_issuer }
    #[must_use]
    pub fn idp_tenant(&self) -> Option<&ConfiguredIdpTenantId> { self.idp_tenant.as_ref() }
    #[must_use]
    pub fn resource_as_issuer(&self) -> &str { &self.resource_as_issuer }
    #[must_use]
    pub fn resource_as_tenant(&self) -> &ConfiguredResourceAsTenantId { &self.resource_as_tenant }
    #[must_use]
    pub fn relying_party_client_id(&self) -> &str { &self.relying_party_client_id }
    #[must_use]
    pub const fn registration_generation(&self) -> u64 { self.registration_generation }
}

/// A locally derived snapshot identity. The digest covers the exact profile,
/// configuration, sorted registration inventory and sorted subject records.
#[derive(Clone, Eq, PartialEq)]
pub struct EnterpriseIdentitySnapshotKey {
    id: String,
    generation: u64,
    digest: Sha256Digest,
}
impl EnterpriseIdentitySnapshotKey {
    #[must_use]
    pub fn id(&self) -> &str { &self.id }
    #[must_use]
    pub const fn generation(&self) -> u64 { self.generation }
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest { self.digest }
}

struct MappingRecord {
    resource_subject: String,
    audience_subject: Option<String>,
    local_subject: LocalEnterpriseSubjectId,
}

/// A bounded immutable table for one fixed profile and reviewed relationship.
/// Construction refuses ambiguous records. Lookup is O(log n) and performs no
/// allocation until an exact row and all token/profile bindings have matched.
pub struct EnterpriseSubjectMappingTable {
    profile: EnterpriseProfile,
    snapshot: EnterpriseIdentitySnapshotKey,
    reviewed_at: SystemTime,
    review_expires_at: SystemTime,
    client_rp: ClientIdpRelyingPartyKey,
    resource_client: EnterpriseClientKey,
    resource_rp: ResourceAsIdpRelyingPartyKey,
    client_namespace: OidcSubjectNamespace,
    resource_namespace: OidcSubjectNamespace,
    expected_resource_claim_tenant: Option<ConfiguredResourceAsTenantId>,
    records: BTreeMap<String, MappingRecord>,
}

impl EnterpriseSubjectMappingTable {
    /// Imports a finite, reviewed snapshot without reading a secret or making
    /// any network/database call. Global-ID uniqueness is checked across the
    /// complete supplied inventory. The source's completeness and attestation
    /// must be established separately before an operational EMA flow uses it.
    pub fn from_trusted_configuration(
        profile: &EnterpriseProfile,
        configuration: EnterpriseIdentityConfiguration,
        mappings: Vec<PreexistingEnterpriseSubjectMapping>,
        now: SystemTime,
    ) -> Result<Self, EnterpriseIdentityError> {
        admit_review(&configuration.snapshot, now)?;
        if configuration.profile_policy_generation != profile.policy_generation()
            || configuration.cross_domain_binding_generation == 0
            || configuration.subject_continuity_generation == 0
        {
            return Err(EnterpriseIdentityError::InvalidConfiguration);
        }
        for domain in [
            &configuration.trust_domains.client,
            &configuration.trust_domains.idp,
            &configuration.trust_domains.resource_as,
        ] {
            admit_text(domain, MAX_TENANT_BYTES)?;
        }
        if configuration.trust_domains.idp == configuration.trust_domains.resource_as {
            return Err(EnterpriseIdentityError::TrustDomainMismatch);
        }
        let idp_tenant = match &configuration.idp_tenancy {
            EnterpriseIdpTenancyConfiguration::SingleTenant => None,
            EnterpriseIdpTenancyConfiguration::MultiTenant { tenant } => {
                admit_text(tenant, MAX_TENANT_BYTES)?;
                Some(ConfiguredIdpTenantId(tenant.clone()))
            }
        };
        let (resource_tenant, resource_claim_tenant) = match &configuration.resource_as_tenancy {
            EnterpriseResourceAsTenancyConfiguration::SingleTenant { identity } => {
                admit_text(identity, MAX_TENANT_BYTES)?;
                (ConfiguredResourceAsTenantId(identity.clone()), None)
            }
            EnterpriseResourceAsTenancyConfiguration::MultiTenant { tenant } => {
                admit_text(tenant, MAX_TENANT_BYTES)?;
                let tenant = ConfiguredResourceAsTenantId(tenant.clone());
                (tenant.clone(), Some(tenant))
            }
        };
        let expected_idp_tenant = idp_tenant.as_ref().map(ConfiguredIdpTenantId::as_str);
        let relationship = &configuration.tenant_relationship;
        if relationship.generation == 0
            || relationship.idp_tenant.as_deref() != expected_idp_tenant
            || relationship.resource_as_tenant != resource_tenant.as_str()
        {
            return Err(EnterpriseIdentityError::TenantMismatch);
        }
        let client = &configuration.client_relying_party;
        let resource = &configuration.resource_as_relying_party;
        if client.issuer != profile.idp_issuer()
            || client.client_id != profile.idp_client_id()
            || client.registration_generation != profile.idp_registration_generation()
            || client.tenant.as_deref() != expected_idp_tenant
            || resource.relying_party.issuer != profile.idp_issuer()
            || resource.relying_party.tenant.as_deref() != expected_idp_tenant
            || resource.resource_as_issuer != profile.resource_as_issuer()
            || resource.resource_as_tenant != resource_tenant.as_str()
        {
            return Err(EnterpriseIdentityError::RegistrationMismatch);
        }
        admit_client_id(&resource.relying_party.client_id)?;
        let client_namespace = namespace(client)?;
        let resource_namespace = namespace(&resource.relying_party)?;
        let inventory = admit_inventory(&configuration.client_id_model, profile, &resource_tenant)?;
        let scope = match &configuration.client_id_model {
            EnterpriseClientIdModel::Global { .. } => EnterpriseClientIdScope::Global,
            EnterpriseClientIdModel::TenantScoped => EnterpriseClientIdScope::TenantScoped,
        };
        let records = admit_mappings(mappings, resource_claim_tenant.is_some())?;
        let digest = snapshot_digest(&configuration, profile_digest(profile)?, &inventory, &records)?;
        Ok(Self {
            profile: profile.clone(),
            snapshot: EnterpriseIdentitySnapshotKey {
                id: configuration.snapshot.id,
                generation: configuration.snapshot.generation,
                digest,
            },
            reviewed_at: configuration.snapshot.reviewed_at,
            review_expires_at: configuration.snapshot.review_expires_at,
            client_rp: ClientIdpRelyingPartyKey {
                issuer: client.issuer.clone(),
                tenant: idp_tenant.clone(),
                client_id: client.client_id.clone(),
                registration_generation: client.registration_generation,
            },
            resource_client: EnterpriseClientKey {
                resource_as_issuer: profile.resource_as_issuer().to_owned(),
                resource_as_tenant: (scope == EnterpriseClientIdScope::TenantScoped)
                    .then(|| resource_tenant.clone()),
                client_id: profile.resource_as_client_id().to_owned(),
                registration_generation: profile.resource_as_registration_generation(),
                scope,
            },
            resource_rp: ResourceAsIdpRelyingPartyKey {
                idp_issuer: resource.relying_party.issuer.clone(),
                idp_tenant,
                resource_as_issuer: resource.resource_as_issuer.clone(),
                resource_as_tenant: resource_tenant,
                relying_party_client_id: resource.relying_party.client_id.clone(),
                registration_generation: resource.relying_party.registration_generation,
            },
            client_namespace,
            resource_namespace,
            expected_resource_claim_tenant: resource_claim_tenant,
            records,
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> &EnterpriseIdentitySnapshotKey { &self.snapshot }
    #[must_use]
    pub fn client_relying_party(&self) -> &ClientIdpRelyingPartyKey { &self.client_rp }
    #[must_use]
    pub fn resource_client(&self) -> &EnterpriseClientKey { &self.resource_client }
    #[must_use]
    pub fn resource_as_relying_party(&self) -> &ResourceAsIdpRelyingPartyKey { &self.resource_rp }
    #[must_use]
    pub fn client_namespace(&self) -> &OidcSubjectNamespace { &self.client_namespace }
    #[must_use]
    pub fn resource_namespace(&self) -> &OidcSubjectNamespace { &self.resource_namespace }

    /// Resolves one pair of already cryptographically verified facts against a
    /// caller-selected current snapshot and profile. This never infers that the
    /// two assertions were obtained in the same flow; the caller's operational
    /// owner must establish that separately, even when this mapping succeeds.
    ///
    /// Both signed expiries and the review window are enforced again. This
    /// local resolver grants no additional clock skew and refuses future iat.
    /// Every missing/mismatched subject row has the same redacted error, with
    /// zero mutation. The returned borrowed result cannot outlive its exact
    /// table or verified facts.
    pub fn resolve<'a>(
        &'a self,
        current_profile: &EnterpriseProfile,
        oidc: &'a VerifiedOidcIdToken,
        id_jag: &'a VerifiedIdJag,
        expected_snapshot: &EnterpriseIdentitySnapshotKey,
        now: SystemTime,
    ) -> Result<ResolvedEnterpriseSubject<'a>, EnterpriseIdentityError> {
        if expected_snapshot != &self.snapshot {
            return Err(EnterpriseIdentityError::SnapshotMismatch);
        }
        if now < self.reviewed_at || now >= self.review_expires_at {
            return Err(EnterpriseIdentityError::ExpiredSnapshot);
        }
        if profile_names(current_profile) != profile_names(&self.profile)
            || profile_generations(current_profile) != profile_generations(&self.profile)
            || current_profile.requested_scopes().as_slice() != self.profile.requested_scopes().as_slice()
            || current_profile.permits_oidc_openid() != self.profile.permits_oidc_openid()
        {
            return Err(EnterpriseIdentityError::ProfileMismatch);
        }
        if now < oidc.issued_at() || now < id_jag.issued_at()
            || now >= oidc.expires_at() || now >= id_jag.expires_at()
            || id_jag.disclosure().is_some_and(|policy| now >= policy.review_expires_at())
        {
            return Err(EnterpriseIdentityError::TokenTimeInvalid);
        }
        let idp_tenant = self.client_rp.tenant().map(ConfiguredIdpTenantId::as_str);
        let resource_tenant = self.expected_resource_claim_tenant.as_ref()
            .map(ConfiguredResourceAsTenantId::as_str);
        if oidc.issuer() != self.client_rp.issuer()
            || oidc.client_id() != self.client_rp.client_id()
            || oidc.tenant().map(|tenant| tenant.as_str()) != idp_tenant
            || oidc.generation() != self.profile.oidc_key_generation()
            || id_jag.issuer() != self.resource_rp.idp_issuer()
            || id_jag.audience() != self.resource_client.issuer()
            || id_jag.client_id() != self.resource_client.client_id()
            || id_jag.idp_tenant().map(|tenant| tenant.as_str()) != idp_tenant
            || id_jag.resource_tenant().map(|tenant| tenant.as_str()) != resource_tenant
            || id_jag.generation() != self.profile.id_jag_key_generation()
            || id_jag.resource() != Some(self.profile.resource().as_str())
        {
            return Err(EnterpriseIdentityError::TokenBindingMismatch);
        }
        let row = self.records.get(oidc.subject().as_str())
            .filter(|row| row.resource_subject == id_jag.subject().as_str()
                && row.audience_subject.as_deref()
                    == id_jag.audience_subject().map(|subject| subject.as_str()))
            .ok_or(EnterpriseIdentityError::MappingUnavailable)?;
        let expires_at = self.review_expires_at.min(oidc.expires_at()).min(id_jag.expires_at());
        let expires_at = id_jag.disclosure()
            .map_or(expires_at, |policy| expires_at.min(policy.review_expires_at()));
        let mut binding = IdentityEncoding::new(b"fastmcp-enterprise-subject-resolution-v1");
        binding.field(self.snapshot.digest.as_bytes())?;
        binding.field(oidc.compact_digest().as_bytes())?;
        binding.field(id_jag.compact_digest().as_bytes())?;
        binding.field(&[u8::from(id_jag.disclosure().is_some())])?;
        if let Some(policy) = id_jag.disclosure() {
            binding.field(policy.configuration_digest().as_bytes())?;
        }
        binding.field(row.local_subject.as_str().as_bytes())?;
        Ok(ResolvedEnterpriseSubject {
            local_subject: &row.local_subject,
            client_subject: ClientSessionSubjectKey {
                registration: &self.client_rp,
                namespace: &self.client_namespace,
                subject: oidc.subject(),
            },
            enterprise_subject: EnterpriseSubjectKey {
                registration: &self.resource_rp,
                namespace: &self.resource_namespace,
                subject: id_jag.subject(),
            },
            audience_subject: id_jag.audience_subject(),
            resource_client: &self.resource_client,
            resource: self.profile.resource(),
            snapshot: &self.snapshot,
            oidc_digest: oidc.compact_digest(),
            id_jag_digest: id_jag.compact_digest(),
            binding_digest: binding.finish()?,
            expires_at,
        })
    }
}

pub struct ClientSessionSubjectKey<'a> {
    registration: &'a ClientIdpRelyingPartyKey,
    namespace: &'a OidcSubjectNamespace,
    subject: &'a ClientFacingSubjectId,
}
impl<'a> ClientSessionSubjectKey<'a> {
    #[must_use]
    pub const fn registration(&self) -> &'a ClientIdpRelyingPartyKey { self.registration }
    #[must_use]
    pub const fn namespace(&self) -> &'a OidcSubjectNamespace { self.namespace }
    #[must_use]
    pub const fn subject(&self) -> &'a ClientFacingSubjectId { self.subject }
}

pub struct EnterpriseSubjectKey<'a> {
    registration: &'a ResourceAsIdpRelyingPartyKey,
    namespace: &'a OidcSubjectNamespace,
    subject: &'a ResourceFacingSubjectId,
}
impl<'a> EnterpriseSubjectKey<'a> {
    #[must_use]
    pub const fn registration(&self) -> &'a ResourceAsIdpRelyingPartyKey { self.registration }
    #[must_use]
    pub const fn namespace(&self) -> &'a OidcSubjectNamespace { self.namespace }
    #[must_use]
    pub const fn subject(&self) -> &'a ResourceFacingSubjectId { self.subject }
}

/// A successful local table lookup bound to both exact signed-token digests.
/// This is not a signed mapping receipt or an authorization/session object.
pub struct ResolvedEnterpriseSubject<'a> {
    local_subject: &'a LocalEnterpriseSubjectId,
    client_subject: ClientSessionSubjectKey<'a>,
    enterprise_subject: EnterpriseSubjectKey<'a>,
    audience_subject: Option<&'a ResourceAudienceSubjectId>,
    resource_client: &'a EnterpriseClientKey,
    resource: &'a CanonicalResourceId,
    snapshot: &'a EnterpriseIdentitySnapshotKey,
    oidc_digest: Sha256Digest,
    id_jag_digest: Sha256Digest,
    binding_digest: Sha256Digest,
    expires_at: SystemTime,
}
impl<'a> ResolvedEnterpriseSubject<'a> {
    #[must_use]
    pub const fn local_subject(&self) -> &'a LocalEnterpriseSubjectId { self.local_subject }
    #[must_use]
    pub const fn client_subject(&self) -> &ClientSessionSubjectKey<'a> { &self.client_subject }
    #[must_use]
    pub const fn enterprise_subject(&self) -> &EnterpriseSubjectKey<'a> { &self.enterprise_subject }
    #[must_use]
    pub const fn audience_subject(&self) -> Option<&'a ResourceAudienceSubjectId> { self.audience_subject }
    #[must_use]
    pub const fn resource_client(&self) -> &'a EnterpriseClientKey { self.resource_client }
    #[must_use]
    pub const fn resource(&self) -> &'a CanonicalResourceId { self.resource }
    #[must_use]
    pub const fn snapshot(&self) -> &'a EnterpriseIdentitySnapshotKey { self.snapshot }
    #[must_use]
    pub const fn oidc_digest(&self) -> Sha256Digest { self.oidc_digest }
    #[must_use]
    pub const fn id_jag_digest(&self) -> Sha256Digest { self.id_jag_digest }
    #[must_use]
    pub const fn binding_digest(&self) -> Sha256Digest { self.binding_digest }
    #[must_use]
    pub const fn expires_at(&self) -> SystemTime { self.expires_at }
}

fn namespace(
    registration: &EnterpriseOidcRelyingPartyConfiguration,
) -> Result<OidcSubjectNamespace, EnterpriseIdentityError> {
    OidcSubjectNamespace::from_preregistered_redirects(
        &registration.issuer, registration.subject_type,
        registration.registration_generation, &registration.redirect_uris,
    )
}

fn admit_mappings(
    mappings: Vec<PreexistingEnterpriseSubjectMapping>,
    audience_required: bool,
) -> Result<BTreeMap<String, MappingRecord>, EnterpriseIdentityError> {
    if mappings.len() > MAX_ENTERPRISE_SUBJECT_MAPPINGS {
        return Err(EnterpriseIdentityError::CapacityExceeded);
    }
    let mut records = BTreeMap::new();
    let mut resource_subjects = BTreeSet::new();
    let mut audience_subjects = BTreeSet::new();
    for mapping in mappings {
        if !valid_oidc_subject(&mapping.client_subject)
            || !valid_oidc_subject(&mapping.resource_subject)
            || admit_text(&mapping.local_subject, MAX_IDENTIFIER_BYTES).is_err()
            || mapping.resource_audience_subject.is_some() != audience_required
            || mapping.resource_audience_subject.as_ref().is_some_and(|subject| {
                admit_text(subject, MAX_IDENTIFIER_BYTES).is_err()
            })
        {
            return Err(EnterpriseIdentityError::InvalidMapping);
        }
        if records.contains_key(&mapping.client_subject)
            || !resource_subjects.insert(mapping.resource_subject.clone())
            || mapping.resource_audience_subject.as_ref()
                .is_some_and(|subject| !audience_subjects.insert(subject.clone()))
        {
            return Err(EnterpriseIdentityError::DuplicateMapping);
        }
        records.insert(mapping.client_subject, MappingRecord {
            resource_subject: mapping.resource_subject,
            audience_subject: mapping.resource_audience_subject,
            local_subject: LocalEnterpriseSubjectId(mapping.local_subject),
        });
    }
    Ok(records)
}

fn admit_inventory(
    model: &EnterpriseClientIdModel,
    profile: &EnterpriseProfile,
    tenant: &ConfiguredResourceAsTenantId,
) -> Result<BTreeMap<String, (String, u64)>, EnterpriseIdentityError> {
    let mut inventory = BTreeMap::new();
    if let EnterpriseClientIdModel::Global { registrations } = model {
        if registrations.is_empty() || registrations.len() > MAX_ENTERPRISE_SUBJECT_MAPPINGS {
            return Err(EnterpriseIdentityError::CapacityExceeded);
        }
        for registration in registrations {
            admit_client_id(&registration.client_id)?;
            admit_text(&registration.resource_as_tenant, MAX_TENANT_BYTES)?;
            if registration.registration_generation == 0 {
                return Err(EnterpriseIdentityError::InvalidConfiguration);
            }
            if inventory.insert(registration.client_id.clone(), (
                registration.resource_as_tenant.clone(), registration.registration_generation,
            )).is_some() {
                return Err(EnterpriseIdentityError::DuplicateMapping);
            }
        }
        let selected = inventory.get(profile.resource_as_client_id())
            .ok_or(EnterpriseIdentityError::RegistrationMismatch)?;
        if selected.0 != tenant.as_str()
            || selected.1 != profile.resource_as_registration_generation()
        {
            return Err(EnterpriseIdentityError::RegistrationMismatch);
        }
    }
    Ok(inventory)
}

fn admit_text(value: &str, limit: usize) -> Result<(), EnterpriseIdentityError> {
    if value.is_empty() || value.len() > limit || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(EnterpriseIdentityError::InvalidConfiguration)
    } else {
        Ok(())
    }
}

fn admit_client_id(value: &str) -> Result<(), EnterpriseIdentityError> {
    admit_text(value, MAX_IDENTIFIER_BYTES)?;
    if !value.is_ascii() || value.contains("://")
        || fastmcp_core::AbsoluteUri::parse(value).is_ok()
    {
        return Err(EnterpriseIdentityError::RegistrationMismatch);
    }
    Ok(())
}

fn admit_issuer(value: &str) -> Result<(), EnterpriseIdentityError> {
    admit_text(value, MAX_URL_BYTES)?;
    let url = CanonicalHttpUrl::parse(value)
        .map_err(|_| EnterpriseIdentityError::InvalidNamespace)?;
    if url.scheme() != "https" || url.has_syntax_violation() || url.has_userinfo()
        || url.query().is_some() || url.fragment().is_some()
    {
        return Err(EnterpriseIdentityError::InvalidNamespace);
    }
    Ok(())
}

fn admit_redirect(value: &str) -> Result<CanonicalHttpUrl, EnterpriseIdentityError> {
    let url = CanonicalHttpUrl::parse_with_max_bytes(value, MAX_URL_BYTES)
        .map_err(|_| EnterpriseIdentityError::InvalidNamespace)?;
    if url.scheme() != "https" || url.as_str() != value || url.has_syntax_violation()
        || url.has_userinfo() || url.query().is_some() || url.fragment().is_some()
    {
        return Err(EnterpriseIdentityError::InvalidNamespace);
    }
    Ok(url)
}

fn valid_oidc_subject(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_SUBJECT_BYTES && value.is_ascii()
        && !value.chars().any(char::is_control)
}

fn admit_review(
    review: &EnterpriseIdentitySnapshotConfiguration,
    now: SystemTime,
) -> Result<(), EnterpriseIdentityError> {
    admit_text(&review.id, MAX_TENANT_BYTES)
        .map_err(|_| EnterpriseIdentityError::InvalidSnapshot)?;
    let duration = review.review_expires_at.duration_since(review.reviewed_at)
        .map_err(|_| EnterpriseIdentityError::InvalidSnapshot)?;
    if review.generation == 0 || duration.is_zero()
        || duration > MAX_ENTERPRISE_IDENTITY_REVIEW_LIFETIME
        || finite_time(review.reviewed_at).is_err()
        || finite_time(review.review_expires_at).is_err()
    {
        return Err(EnterpriseIdentityError::InvalidSnapshot);
    }
    if now < review.reviewed_at || now >= review.review_expires_at {
        return Err(EnterpriseIdentityError::ExpiredSnapshot);
    }
    Ok(())
}

fn finite_time(value: SystemTime) -> Result<Duration, EnterpriseIdentityError> {
    value.duration_since(UNIX_EPOCH).ok()
        .filter(|value| value.as_secs() <= MAX_UNIX_SECONDS)
        .ok_or(EnterpriseIdentityError::InvalidSnapshot)
}

// Every field is length-framed, with explicit enum tags and option presence.
// Sorted inventories/rows/redirect sets make semantically identical input order
// deterministic. No serde serializer or platform-width integer enters a digest.
struct IdentityEncoding(Vec<u8>);
impl IdentityEncoding {
    fn new(domain: &[u8]) -> Self { Self(domain.to_vec()) }
    fn field(&mut self, value: &[u8]) -> Result<(), EnterpriseIdentityError> {
        let total = self.0.len().checked_add(8).and_then(|n| n.checked_add(value.len()))
            .ok_or(EnterpriseIdentityError::CapacityExceeded)?;
        if total > MAX_CONFIGURATION_BYTES {
            return Err(EnterpriseIdentityError::CapacityExceeded);
        }
        let length = u64::try_from(value.len())
            .map_err(|_| EnterpriseIdentityError::CapacityExceeded)?;
        self.0.extend_from_slice(&length.to_be_bytes());
        self.0.extend_from_slice(value);
        Ok(())
    }
    fn text(&mut self, value: &str) -> Result<(), EnterpriseIdentityError> {
        self.field(value.as_bytes())
    }
    fn number(&mut self, value: u64) -> Result<(), EnterpriseIdentityError> {
        self.field(&value.to_be_bytes())
    }
    fn optional(&mut self, value: Option<&str>) -> Result<(), EnterpriseIdentityError> {
        self.field(&[u8::from(value.is_some())])?;
        if let Some(value) = value { self.text(value)?; }
        Ok(())
    }
    fn time(&mut self, value: SystemTime) -> Result<(), EnterpriseIdentityError> {
        let value = finite_time(value)?;
        self.number(value.as_secs())?;
        self.number(u64::from(value.subsec_nanos()))
    }
    fn finish(self) -> Result<Sha256Digest, EnterpriseIdentityError> {
        sha256_bounded(&self.0, MAX_CONFIGURATION_BYTES)
            .map_err(|_| EnterpriseIdentityError::CapacityExceeded)
    }
}

fn profile_names(profile: &EnterpriseProfile) -> [&str; 12] {
    [profile.idp_issuer(), profile.idp_token_endpoint(),
        profile.idp_authorization_endpoint(), profile.idp_client_id(),
        profile.idp_authentication().as_str(), profile.oidc_jwks_uri(),
        profile.id_jag_jwks_uri(), profile.resource_as_issuer(),
        profile.resource_as_token_endpoint(), profile.resource_as_client_id(),
        profile.resource_as_authentication().as_str(), profile.resource().as_str()]
}

fn profile_generations(profile: &EnterpriseProfile) -> [u64; 9] {
    [profile.oidc_key_generation(), profile.id_jag_key_generation(),
        profile.id_jag_policy_generation(), profile.policy_generation(),
        profile.idp_metadata_generation(), profile.resource_as_metadata_generation(),
        profile.idp_registration_generation(), profile.resource_as_registration_generation(),
        profile.aggregate_registration_generation()]
}

fn profile_digest(profile: &EnterpriseProfile) -> Result<Sha256Digest, EnterpriseIdentityError> {
    let mut encoded = IdentityEncoding::new(b"fastmcp-enterprise-identity-profile-v1");
    for value in profile_names(profile) { encoded.text(value)?; }
    for value in profile_generations(profile) { encoded.number(value)?; }
    encoded.field(&[u8::from(profile.permits_oidc_openid())])?;
    encoded.number(profile.requested_scopes().as_slice().len() as u64)?;
    for scope in profile.requested_scopes().as_slice() { encoded.text(scope)?; }
    encoded.finish()
}

fn encode_rp(
    encoded: &mut IdentityEncoding,
    registration: &EnterpriseOidcRelyingPartyConfiguration,
) -> Result<(), EnterpriseIdentityError> {
    encoded.text(&registration.issuer)?;
    encoded.optional(registration.tenant.as_deref())?;
    encoded.text(&registration.client_id)?;
    encoded.number(registration.registration_generation)?;
    encoded.text(match registration.subject_type {
        EnterpriseOidcSubjectType::Public => "public",
        EnterpriseOidcSubjectType::Pairwise => "pairwise",
    })?;
    let redirects: BTreeSet<_> = registration.redirect_uris.iter().collect();
    encoded.number(redirects.len() as u64)?;
    for redirect in redirects { encoded.text(redirect)?; }
    Ok(())
}

fn snapshot_digest(
    configuration: &EnterpriseIdentityConfiguration,
    profile: Sha256Digest,
    inventory: &BTreeMap<String, (String, u64)>,
    records: &BTreeMap<String, MappingRecord>,
) -> Result<Sha256Digest, EnterpriseIdentityError> {
    let mut encoded = IdentityEncoding::new(b"fastmcp-enterprise-identity-snapshot-v1");
    encoded.field(profile.as_bytes())?;
    encoded.text(&configuration.snapshot.id)?;
    encoded.number(configuration.snapshot.generation)?;
    encoded.time(configuration.snapshot.reviewed_at)?;
    encoded.time(configuration.snapshot.review_expires_at)?;
    encoded.number(configuration.profile_policy_generation)?;
    encoded.text(&configuration.trust_domains.client)?;
    encoded.text(&configuration.trust_domains.idp)?;
    encoded.text(&configuration.trust_domains.resource_as)?;
    encoded.text(match &configuration.idp_tenancy {
        EnterpriseIdpTenancyConfiguration::SingleTenant => "single",
        EnterpriseIdpTenancyConfiguration::MultiTenant { .. } => "multi",
    })?;
    encoded.text(match &configuration.resource_as_tenancy {
        EnterpriseResourceAsTenancyConfiguration::SingleTenant { .. } => "single",
        EnterpriseResourceAsTenancyConfiguration::MultiTenant { .. } => "multi",
    })?;
    encoded.text(match &configuration.client_id_model {
        EnterpriseClientIdModel::Global { .. } => "global",
        EnterpriseClientIdModel::TenantScoped => "tenant-scoped",
    })?;
    encode_rp(&mut encoded, &configuration.client_relying_party)?;
    encode_rp(&mut encoded, &configuration.resource_as_relying_party.relying_party)?;
    encoded.text(&configuration.resource_as_relying_party.resource_as_issuer)?;
    encoded.text(&configuration.resource_as_relying_party.resource_as_tenant)?;
    encoded.optional(configuration.tenant_relationship.idp_tenant.as_deref())?;
    encoded.text(&configuration.tenant_relationship.resource_as_tenant)?;
    encoded.number(configuration.tenant_relationship.generation)?;
    encoded.number(configuration.cross_domain_binding_generation)?;
    encoded.number(configuration.subject_continuity_generation)?;
    encoded.number(inventory.len() as u64)?;
    for (client, (tenant, generation)) in inventory {
        encoded.text(client)?;
        encoded.text(tenant)?;
        encoded.number(*generation)?;
    }
    encoded.number(records.len() as u64)?;
    for (client_subject, record) in records {
        encoded.text(client_subject)?;
        encoded.text(&record.resource_subject)?;
        encoded.optional(record.audience_subject.as_deref())?;
        encoded.text(record.local_subject.as_str())?;
    }
    encoded.finish()
}

macro_rules! redacted_debug {
    ($($name:ty),+ $(,)?) => {$ (
        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    )+};
}
redacted_debug!(
    OidcSubjectNamespace, EnterpriseOidcRelyingPartyConfiguration,
    ResourceAsIdpRelyingPartyConfiguration, EnterpriseIdpTenancyConfiguration,
    EnterpriseResourceAsTenancyConfiguration, EnterpriseGlobalClientRegistration,
    EnterpriseClientIdModel, EnterpriseTenantRelationshipConfiguration,
    EnterpriseIdentityTrustDomains, EnterpriseIdentitySnapshotConfiguration,
    EnterpriseIdentityConfiguration, PreexistingEnterpriseSubjectMapping,
    ConfiguredIdpTenantId, ConfiguredResourceAsTenantId, LocalEnterpriseSubjectId,
    ClientIdpRelyingPartyKey, EnterpriseClientKey, ResourceAsIdpRelyingPartyKey,
    EnterpriseIdentitySnapshotKey, EnterpriseSubjectMappingTable,
    ClientSessionSubjectKey<'_>, EnterpriseSubjectKey<'_>, ResolvedEnterpriseSubject<'_>,
);

#[cfg(test)]
mod tests;
