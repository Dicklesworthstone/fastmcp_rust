//! Local semantic verification for the signed OIDC / ID-JAG enterprise subset.
//!
//! The two key owners require separate, explicit trusted imports, even when an
//! operator deliberately authorizes the same public key for both purposes.
//! These imports are not discovery, registration, custody or policy attestation.
//! Verification creates no login, account mapping, replay reservation or EMA
//! activation receipt. The caller still owns browser-flow/nonce provenance,
//! subject continuity, current policy, one-use storage and exchange dispatch.
//!
//! Only bounded three-segment RS256 JWS values are admitted. OIDC permits an
//! absent typ or the PRT-01 JWT media type; ID-JAG requires oauth-id-jag+jwt.
//! Both use a closed local header and claim vocabulary. Optional ID-JAG
//! disclosures require an explicit, current ValidateAndDiscard policy.
//! Returned facts contain no compact assertion, signing input or signature and
//! cannot become an Authorization header. The caller owns and destroys the
//! borrowed input token and, for OIDC at_hash, its temporary access token.

#[cfg(test)]
mod tests;

pub mod disclosure;

use std::collections::BTreeSet;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fastmcp_core::{CanonicalHttpUrl, Sha256Digest, crypto::sha256_bounded};
use serde_json::{Map, Value};

use super::{
    AdmittedRsaJwks, MAX_COMPACT_JWS_BYTES, MAX_JWKS_BYTES, MAX_JWS_HEADER_BYTES,
    decode_base64url, parse_json, split_compact_jws, verify_compact_jws_rs256,
};
use crate::security_admission::{AdmittedCompactJws, CompactJwsProfile, admit_compact_jws};
use disclosure::{IdJagDisclosureFacts, IdJagDisclosurePolicy};

/// Local identifier cap; never permission to use an identifier as a provider key.
pub const MAX_ENTERPRISE_IDENTIFIER_BYTES: usize = 1024;
/// Exact tenant strings preserve Unicode without normalization or trimming.
pub const MAX_ENTERPRISE_TENANT_BYTES: usize = 256;
/// OIDC public/pairwise subject identifiers have at most 255 ASCII characters.
pub const MAX_ENTERPRISE_OIDC_SUBJECT_BYTES: usize = 255;
pub const MAX_ENTERPRISE_SCOPE_COUNT: usize = 64;
pub const MAX_ENTERPRISE_SCOPE_BYTES: usize = 256;
pub const MAX_ENTERPRISE_SCOPE_SET_BYTES: usize = 4096;
/// The local OIDC verifier admits lifetimes no longer than one day.
pub const MAX_ENTERPRISE_TOKEN_LIFETIME: Duration = Duration::from_hours(24);
/// The ID-JAG profile further tightens that bound to fifteen minutes.
pub const MAX_ID_JAG_LIFETIME: Duration = Duration::from_mins(15);
pub const MAX_ENTERPRISE_CLOCK_SKEW: Duration = Duration::from_secs(300);

const MAX_ACCESS_TOKEN_BYTES: usize = 4096;
const MAX_JTI_BYTES: usize = 256;
const MAX_NUMERIC_DATE_LEXEME_BYTES: usize = 32;
const NANOS_PER_SECOND: u128 = 1_000_000_000;
const MAX_NUMERIC_DATE_NANOS: u128 = 253_402_300_799_999_999_999;
const OIDC_CLAIMS: &[&str] = &[
    "iss", "sub", "aud", "exp", "iat", "nbf", "azp", "nonce", "auth_time", "at_hash", "tenant",
];
const ID_JAG_CLAIMS: &[&str] = &[
    "iss", "sub", "aud", "client_id", "jti", "exp", "iat", "resource", "scope", "tenant",
    "aud_tenant", "aud_sub",
];

/// Fixed diagnostics never contain a token, claim value, issuer, subject or key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseVerificationError {
    InvalidConfiguration,
    InvalidKeys,
    InvalidToken,
    InvalidClaims,
    BindingMismatch,
    InvalidTime,
    Expired,
    NotYetValid,
    InvalidNonce,
    InvalidAccessTokenHash,
}

impl fmt::Display for EnterpriseVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid enterprise verification configuration",
            Self::InvalidKeys => "invalid enterprise verification keys",
            Self::InvalidToken => "invalid enterprise signed token",
            Self::InvalidClaims => "enterprise token claims do not satisfy the local profile",
            Self::BindingMismatch => "enterprise token does not match its expected binding",
            Self::InvalidTime => "invalid enterprise token time",
            Self::Expired => "enterprise token has expired",
            Self::NotYetValid => "enterprise token is not yet valid",
            Self::InvalidNonce => "enterprise ID token nonce does not match",
            Self::InvalidAccessTokenHash => "enterprise ID token access-token hash does not match",
        })
    }
}

impl std::error::Error for EnterpriseVerificationError {}

/// One bounded time policy. NumericDates retain exact nanoseconds, including
/// equivalent integer, fraction and exponent spellings. Clock skew is applied
/// only to admission; it never changes the returned signed expiration time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JwtTimePolicy {
    max_lifetime: Duration,
    clock_skew: Duration,
}

impl JwtTimePolicy {
    pub fn new(
        max_lifetime: Duration,
        clock_skew: Duration,
    ) -> Result<Self, EnterpriseVerificationError> {
        if max_lifetime.is_zero()
            || max_lifetime > MAX_ENTERPRISE_TOKEN_LIFETIME
            || clock_skew > MAX_ENTERPRISE_CLOCK_SKEW
        {
            return Err(EnterpriseVerificationError::InvalidConfiguration);
        }
        Ok(Self { max_lifetime, clock_skew })
    }

    /// One-hour OIDC lifetime and sixty seconds of skew.
    #[must_use]
    pub const fn oidc_default() -> Self {
        Self {
            max_lifetime: Duration::from_secs(3600),
            clock_skew: Duration::from_secs(60),
        }
    }

    /// Five-minute ID-JAG lifetime and sixty seconds of skew.
    #[must_use]
    pub const fn id_jag_default() -> Self {
        Self {
            max_lifetime: Duration::from_secs(300),
            clock_skew: Duration::from_secs(60),
        }
    }

    #[must_use]
    pub const fn max_lifetime(self) -> Duration {
        self.max_lifetime
    }

    #[must_use]
    pub const fn clock_skew(self) -> Duration {
        self.clock_skew
    }
}

impl Default for JwtTimePolicy {
    fn default() -> Self {
        Self::oidc_default()
    }
}

struct PurposeKeys {
    issuer: String,
    generation: u64,
    keys: AdmittedRsaJwks,
    document_digest: Sha256Digest,
}

impl PurposeKeys {
    fn from_trusted_jwks(
        issuer: impl Into<String>,
        generation: u64,
        jwks: &[u8],
    ) -> Result<Self, EnterpriseVerificationError> {
        let issuer = issuer.into();
        validate_issuer(&issuer)?;
        if generation == 0 {
            return Err(EnterpriseVerificationError::InvalidConfiguration);
        }
        let keys = AdmittedRsaJwks::from_json(jwks)
            .map_err(|_| EnterpriseVerificationError::InvalidKeys)?;
        let document_digest = sha256_bounded(jwks, MAX_JWKS_BYTES)
            .map_err(|_| EnterpriseVerificationError::InvalidKeys)?;
        Ok(Self { issuer, generation, keys, document_digest })
    }
}

/// Public keys explicitly authorized by the operator for this OIDC issuer.
/// Importing them does not prove remote registration or a browser-flow receipt.
pub struct OidcVerificationKeys(PurposeKeys);

impl OidcVerificationKeys {
    pub fn from_trusted_jwks(
        issuer: impl Into<String>,
        generation: u64,
        jwks: &[u8],
    ) -> Result<Self, EnterpriseVerificationError> {
        PurposeKeys::from_trusted_jwks(issuer, generation, jwks).map(Self)
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.0.issuer
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.0.generation
    }

    /// SHA-256 of the exact imported JWKS document, not a deployment attestation.
    #[must_use]
    pub const fn document_digest(&self) -> Sha256Digest {
        self.0.document_digest
    }
}

/// A distinct import granting ID-JAG verification for this exact IdP issuer.
/// There is deliberately no conversion from OidcVerificationKeys. The owning
/// layer must bind this grant to its resource-AS trust relationship and policy.
pub struct IdJagVerificationKeys(PurposeKeys);

impl IdJagVerificationKeys {
    pub fn from_trusted_jwks(
        issuer: impl Into<String>,
        generation: u64,
        jwks: &[u8],
    ) -> Result<Self, EnterpriseVerificationError> {
        PurposeKeys::from_trusted_jwks(issuer, generation, jwks).map(Self)
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.0.issuer
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.0.generation
    }

    #[must_use]
    pub const fn document_digest(&self) -> Sha256Digest {
        self.0.document_digest
    }
}

/// Trusted IdP tenancy chosen before token acquisition. A token cannot select
/// the mode or the expected tenant; SingleTenant rejects even a null tenant.
#[derive(Clone, Copy)]
pub enum TenantExpectation<'a> {
    SingleTenant,
    Exact(&'a str),
}

/// Resource-AS tenancy is independent of IdP tenancy. Exact requires both the
/// expected aud_tenant and a bounded opaque aud_sub. It does not establish an
/// account mapping or any relationship between the two tenant namespaces.
#[derive(Clone, Copy)]
pub enum ResourceTenantExpectation<'a> {
    SingleTenant,
    Exact(&'a str),
}

/// Exact caller-owned expectations for one OIDC authorization-code flow.
/// nonce provenance and access-token destruction remain the caller's duties.
pub struct OidcIdTokenExpectations<'a> {
    pub client_id: &'a str,
    pub nonce: &'a str,
    pub access_token: Option<&'a str>,
    pub tenant: TenantExpectation<'a>,
    pub max_authentication_age: Option<Duration>,
    pub time: JwtTimePolicy,
}

/// Exact bindings from the independently configured resource-AS registration.
/// require_resource=false is only a primitive for an already-admitted explicit
/// single-resource mapping; this value does not establish such a mapping.
pub struct IdJagExpectations<'a> {
    pub audience: &'a str,
    pub client_id: &'a str,
    pub resource: &'a str,
    pub require_resource: bool,
    pub idp_tenant: TenantExpectation<'a>,
    pub resource_tenant: ResourceTenantExpectation<'a>,
    pub time: JwtTimePolicy,
}

macro_rules! identity_type {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(PartialEq, Eq)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    };
}

identity_type!(ClientFacingSubjectId, "An OIDC subject in the client RP's namespace.");
identity_type!(ResourceFacingSubjectId, "An ID-JAG subject in the resource AS RP's namespace.");
identity_type!(IdpTenantId, "An exact tenant identifier in the configured IdP namespace.");
identity_type!(ResourceAsTenantId, "An exact tenant identifier in the resource-AS namespace.");
identity_type!(ResourceAudienceSubjectId, "An opaque aud_sub; never interchangeable with an OIDC sub.");

/// Verified identity facts only. No bearer, nonce, access token, optional
/// disclosure claim or serialization capability is retained.
pub struct VerifiedOidcIdToken {
    issuer: String,
    client_id: String,
    subject: ClientFacingSubjectId,
    tenant: Option<IdpTenantId>,
    issued_at: SystemTime,
    expires_at: SystemTime,
    authentication_time: Option<SystemTime>,
    key_id: String,
    generation: u64,
    compact_digest: Sha256Digest,
}

impl VerifiedOidcIdToken {
    #[must_use]
    pub fn issuer(&self) -> &str { &self.issuer }
    #[must_use]
    pub fn client_id(&self) -> &str { &self.client_id }
    #[must_use]
    pub const fn subject(&self) -> &ClientFacingSubjectId { &self.subject }
    #[must_use]
    pub const fn tenant(&self) -> Option<&IdpTenantId> { self.tenant.as_ref() }
    #[must_use]
    pub const fn issued_at(&self) -> SystemTime { self.issued_at }
    #[must_use]
    pub const fn expires_at(&self) -> SystemTime { self.expires_at }
    #[must_use]
    pub const fn authentication_time(&self) -> Option<SystemTime> { self.authentication_time }
    #[must_use]
    pub fn key_id(&self) -> &str { &self.key_id }
    #[must_use]
    pub const fn generation(&self) -> u64 { self.generation }
    #[must_use]
    pub const fn compact_digest(&self) -> Sha256Digest { self.compact_digest }
}

impl fmt::Debug for VerifiedOidcIdToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("VerifiedOidcIdToken").finish_non_exhaustive()
    }
}

/// Verified grant facts, not a replay reservation, subject-mapping receipt or
/// authorization decision. A scope value still requires the owning exchange's
/// request/response/signed-claim intersection before it can grant anything.
pub struct VerifiedIdJag {
    issuer: String,
    audience: String,
    client_id: String,
    subject: ResourceFacingSubjectId,
    idp_tenant: Option<IdpTenantId>,
    resource_tenant: Option<ResourceAsTenantId>,
    audience_subject: Option<ResourceAudienceSubjectId>,
    resource: Option<String>,
    scope: Option<String>,
    jti: String,
    issued_at: SystemTime,
    expires_at: SystemTime,
    key_id: String,
    generation: u64,
    compact_digest: Sha256Digest,
    disclosure: Option<IdJagDisclosureFacts>,
}

impl VerifiedIdJag {
    #[must_use]
    pub fn issuer(&self) -> &str { &self.issuer }
    #[must_use]
    pub fn audience(&self) -> &str { &self.audience }
    #[must_use]
    pub fn client_id(&self) -> &str { &self.client_id }
    #[must_use]
    pub const fn subject(&self) -> &ResourceFacingSubjectId { &self.subject }
    #[must_use]
    pub const fn idp_tenant(&self) -> Option<&IdpTenantId> { self.idp_tenant.as_ref() }
    #[must_use]
    pub const fn resource_tenant(&self) -> Option<&ResourceAsTenantId> { self.resource_tenant.as_ref() }
    #[must_use]
    pub const fn audience_subject(&self) -> Option<&ResourceAudienceSubjectId> { self.audience_subject.as_ref() }
    #[must_use]
    pub fn resource(&self) -> Option<&str> { self.resource.as_deref() }
    #[must_use]
    pub fn scope(&self) -> Option<&str> { self.scope.as_deref() }
    #[must_use]
    pub fn jti(&self) -> &str { &self.jti }
    #[must_use]
    pub const fn issued_at(&self) -> SystemTime { self.issued_at }
    #[must_use]
    pub const fn expires_at(&self) -> SystemTime { self.expires_at }
    #[must_use]
    pub fn key_id(&self) -> &str { &self.key_id }
    #[must_use]
    pub const fn generation(&self) -> u64 { self.generation }
    #[must_use]
    pub const fn compact_digest(&self) -> Sha256Digest { self.compact_digest }
    /// Names and policy identity only; optional claim values are discarded.
    #[must_use]
    pub const fn disclosure(&self) -> Option<&IdJagDisclosureFacts> { self.disclosure.as_ref() }
}

impl fmt::Debug for VerifiedIdJag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("VerifiedIdJag").finish_non_exhaustive()
    }
}

/// Verifies one exact OIDC compact assertion against independent trusted
/// expectations. now is one caller-sampled wall-clock instant. No network,
/// key discovery, nonce consumption or fallback occurs.
pub fn verify_oidc_id_token(
    compact: &str,
    keys: &OidcVerificationKeys,
    expected: &OidcIdTokenExpectations<'_>,
    now: SystemTime,
) -> Result<VerifiedOidcIdToken, EnterpriseVerificationError> {
    validate_identifier(expected.client_id)?;
    validate_identifier(expected.nonce)?;
    validate_tenant_expectation(expected.tenant)?;
    if expected.max_authentication_age.is_some_and(|age| age > MAX_ENTERPRISE_TOKEN_LIFETIME)
        || expected.access_token.is_some_and(|token| !valid_access_token(token))
    {
        return Err(EnterpriseVerificationError::InvalidConfiguration);
    }
    let admitted = verify_profile(compact, &keys.0, CompactJwsProfile::OidcIdToken)?;
    let claims = admitted.claims();
    closed_claims(claims, OIDC_CLAIMS)?;
    exact_string(claims, "iss", keys.issuer())?;
    exact_singleton(claims.get("aud"), expected.client_id)?;
    if claims.contains_key("azp") {
        exact_string(claims, "azp", expected.client_id)?;
    }
    let nonce = claim_string(claims, "nonce")?;
    if !constant_time_equal(nonce.as_bytes(), expected.nonce.as_bytes()) {
        return Err(EnterpriseVerificationError::InvalidNonce);
    }
    let subject = oidc_subject(claims)?;
    let tenant = idp_tenant(claims, expected.tenant)?;
    let times = validate_times(claims, expected.time, now)?;
    let authentication_time = claims.get("auth_time").map(numeric_date).transpose()?;
    if let Some(auth_time) = authentication_time {
        if auth_time > times.issued {
            return Err(EnterpriseVerificationError::InvalidTime);
        }
        if let Some(max_age) = expected.max_authentication_age {
            let acceptable_until = auth_time
                .as_nanos()
                .checked_add(max_age.as_nanos())
                .and_then(|value| value.checked_add(expected.time.clock_skew.as_nanos()))
                .ok_or(EnterpriseVerificationError::InvalidTime)?;
            if times.now.as_nanos() > acceptable_until {
                return Err(EnterpriseVerificationError::Expired);
            }
        }
    } else if expected.max_authentication_age.is_some() {
        return Err(EnterpriseVerificationError::InvalidClaims);
    }
    if let Some(hash) = claims.get("at_hash") {
        let hash = hash.as_str().ok_or(EnterpriseVerificationError::InvalidAccessTokenHash)?;
        let access_token = expected.access_token
            .ok_or(EnterpriseVerificationError::InvalidAccessTokenHash)?;
        if hash.len() != 22 {
            return Err(EnterpriseVerificationError::InvalidAccessTokenHash);
        }
        let decoded = URL_SAFE_NO_PAD.decode(hash)
            .map_err(|_| EnterpriseVerificationError::InvalidAccessTokenHash)?;
        let digest = sha256_bounded(access_token.as_bytes(), MAX_ACCESS_TOKEN_BYTES)
            .map_err(|_| EnterpriseVerificationError::InvalidAccessTokenHash)?;
        if decoded.len() != 16
            || !constant_time_equal(&decoded, &digest.as_bytes()[..16])
        {
            return Err(EnterpriseVerificationError::InvalidAccessTokenHash);
        }
    }
    Ok(VerifiedOidcIdToken {
        issuer: keys.issuer().to_owned(),
        client_id: expected.client_id.to_owned(),
        subject: ClientFacingSubjectId(subject.to_owned()),
        tenant,
        issued_at: system_time(times.issued)?,
        expires_at: system_time(times.expires)?,
        authentication_time: authentication_time.map(system_time).transpose()?,
        key_id: admitted.header().key_id()
            .ok_or(EnterpriseVerificationError::InvalidToken)?.to_owned(),
        generation: keys.generation(),
        compact_digest: token_digest(compact)?,
    })
}

/// Verifies the ID-JAG purpose and its exact issuer/resource-AS/client/resource
/// bindings. The default closed claim set admits no email, actor, RAR, display
/// name, cnf, key-location or other optional identity claims.
pub fn verify_id_jag(
    compact: &str,
    keys: &IdJagVerificationKeys,
    expected: &IdJagExpectations<'_>,
    now: SystemTime,
) -> Result<VerifiedIdJag, EnterpriseVerificationError> {
    verify_id_jag_with_policy(compact, keys, expected, None, now)
}

/// Verifies an ID-JAG with a separately reviewed optional-disclosure policy.
/// The signature covers every optional value before its bounded schema is
/// admitted. Those values are discarded; only policy identity and claim names
/// are retained. This cannot enable actor, RAR, aliases, cnf or key-location
/// claims, and does not alter any core issuer/client/resource/subject checks.
pub fn verify_id_jag_with_disclosure(
    compact: &str,
    keys: &IdJagVerificationKeys,
    expected: &IdJagExpectations<'_>,
    disclosure: &IdJagDisclosurePolicy,
    now: SystemTime,
) -> Result<VerifiedIdJag, EnterpriseVerificationError> {
    verify_id_jag_with_policy(compact, keys, expected, Some(disclosure), now)
}

fn verify_id_jag_with_policy(
    compact: &str,
    keys: &IdJagVerificationKeys,
    expected: &IdJagExpectations<'_>,
    disclosure: Option<&IdJagDisclosurePolicy>,
    now: SystemTime,
) -> Result<VerifiedIdJag, EnterpriseVerificationError> {
    validate_issuer(expected.audience)?;
    validate_identifier(expected.client_id)?;
    validate_resource(expected.resource)?;
    validate_tenant_expectation(expected.idp_tenant)?;
    if let ResourceTenantExpectation::Exact(tenant) = expected.resource_tenant {
        validate_tenant(tenant)
            .map_err(|_| EnterpriseVerificationError::InvalidConfiguration)?;
    }
    if expected.time.max_lifetime > MAX_ID_JAG_LIFETIME {
        return Err(EnterpriseVerificationError::InvalidConfiguration);
    }
    if let Some(policy) = disclosure {
        policy.admit_context(keys.issuer(), expected.audience, now)?;
    }
    let admitted = verify_profile(
        compact,
        &keys.0,
        CompactJwsProfile::IdentityAssertionJwtAuthorizationGrant,
    )?;
    let claims = admitted.claims();
    let disclosure = match disclosure {
        Some(policy) => Some(policy.admit_claims(claims)?),
        None => {
            closed_claims(claims, ID_JAG_CLAIMS)?;
            None
        }
    };
    exact_string(claims, "iss", keys.issuer())?;
    exact_singleton(claims.get("aud"), expected.audience)?;
    exact_string(claims, "client_id", expected.client_id)?;
    let resource = match claims.get("resource") {
        Some(value) => {
            exact_singleton(Some(value), expected.resource)?;
            Some(expected.resource.to_owned())
        }
        None if expected.require_resource => {
            return Err(EnterpriseVerificationError::BindingMismatch);
        }
        None => None,
    };
    let subject = oidc_subject(claims)?;
    let idp_tenant = idp_tenant(claims, expected.idp_tenant)?;
    let (resource_tenant, audience_subject) = match expected.resource_tenant {
        ResourceTenantExpectation::SingleTenant => {
            if claims.contains_key("aud_tenant") || claims.contains_key("aud_sub") {
                return Err(EnterpriseVerificationError::BindingMismatch);
            }
            (None, None)
        }
        ResourceTenantExpectation::Exact(tenant) => {
            exact_string(claims, "aud_tenant", tenant)?;
            let audience_subject = claim_string(claims, "aud_sub")?;
            if !valid_bounded_text(audience_subject, MAX_ENTERPRISE_IDENTIFIER_BYTES) {
                return Err(EnterpriseVerificationError::InvalidClaims);
            }
            (
                Some(ResourceAsTenantId(tenant.to_owned())),
                Some(ResourceAudienceSubjectId(audience_subject.to_owned())),
            )
        }
    };
    let jti = claim_string(claims, "jti")?;
    if !valid_bounded_text(jti, MAX_JTI_BYTES) {
        return Err(EnterpriseVerificationError::InvalidClaims);
    }
    let scope = scope_claim(claims)?;
    let times = validate_times(claims, expected.time, now)?;
    Ok(VerifiedIdJag {
        issuer: keys.issuer().to_owned(),
        audience: expected.audience.to_owned(),
        client_id: expected.client_id.to_owned(),
        subject: ResourceFacingSubjectId(subject.to_owned()),
        idp_tenant,
        resource_tenant,
        audience_subject,
        resource,
        scope,
        jti: jti.to_owned(),
        issued_at: system_time(times.issued)?,
        expires_at: system_time(times.expires)?,
        key_id: admitted.header().key_id()
            .ok_or(EnterpriseVerificationError::InvalidToken)?.to_owned(),
        generation: keys.generation(),
        compact_digest: token_digest(compact)?,
        disclosure,
    })
}

fn verify_profile(
    compact: &str,
    keys: &PurposeKeys,
    profile: CompactJwsProfile,
) -> Result<AdmittedCompactJws, EnterpriseVerificationError> {
    if compact.len() > MAX_COMPACT_JWS_BYTES {
        return Err(EnterpriseVerificationError::InvalidToken);
    }
    let admitted = admit_compact_jws(profile, compact)
        .map_err(|_| EnterpriseVerificationError::InvalidToken)?;
    // The generic profile admission owns duplicate, type, JSON and base64
    // rules. This local profile also closes header extensions, including cty,
    // so a nested/encrypted token or alternate key source cannot be smuggled.
    let (header, _, _, _) = split_compact_jws(compact)
        .map_err(|_| EnterpriseVerificationError::InvalidToken)?;
    let header = decode_base64url(header, MAX_JWS_HEADER_BYTES, "header")
        .map_err(|_| EnterpriseVerificationError::InvalidToken)?;
    let header = parse_json(&header, "header")
        .map_err(|_| EnterpriseVerificationError::InvalidToken)?;
    let header = header.as_object().ok_or(EnterpriseVerificationError::InvalidToken)?;
    if header.keys().any(|key| !matches!(key.as_str(), "alg" | "kid" | "typ")) {
        return Err(EnterpriseVerificationError::InvalidToken);
    }
    // Use the existing local verifier unchanged. Its key admission and
    // signature checks are independent of the new semantic policy.
    verify_compact_jws_rs256(compact, &keys.keys)
        .map_err(|_| EnterpriseVerificationError::InvalidToken)?;
    Ok(admitted)
}

fn token_digest(compact: &str) -> Result<Sha256Digest, EnterpriseVerificationError> {
    sha256_bounded(compact.as_bytes(), MAX_COMPACT_JWS_BYTES)
        .map_err(|_| EnterpriseVerificationError::InvalidToken)
}

fn validate_identifier(value: &str) -> Result<(), EnterpriseVerificationError> {
    if valid_bounded_text(value, MAX_ENTERPRISE_IDENTIFIER_BYTES) {
        Ok(())
    } else {
        Err(EnterpriseVerificationError::InvalidConfiguration)
    }
}

fn validate_issuer(value: &str) -> Result<(), EnterpriseVerificationError> {
    validate_identifier(value)?;
    let url = CanonicalHttpUrl::parse(value)
        .map_err(|_| EnterpriseVerificationError::InvalidConfiguration)?;
    if !url.as_str().starts_with("https://")
        || url.has_syntax_violation()
        || url.has_userinfo()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(EnterpriseVerificationError::InvalidConfiguration);
    }
    // Keep the trusted spelling for exact issuer/audience comparison.
    Ok(())
}

fn validate_resource(value: &str) -> Result<(), EnterpriseVerificationError> {
    validate_identifier(value)?;
    let url = CanonicalHttpUrl::parse(value)
        .map_err(|_| EnterpriseVerificationError::InvalidConfiguration)?;
    if !url.as_str().starts_with("https://")
        || url.as_str() != value
        || url.has_syntax_violation()
        || url.has_userinfo()
        || url.fragment().is_some()
    {
        return Err(EnterpriseVerificationError::InvalidConfiguration);
    }
    Ok(())
}

fn valid_bounded_text(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn validate_tenant(value: &str) -> Result<(), EnterpriseVerificationError> {
    if valid_bounded_text(value, MAX_ENTERPRISE_TENANT_BYTES) {
        Ok(())
    } else {
        Err(EnterpriseVerificationError::InvalidClaims)
    }
}

fn validate_tenant_expectation(
    expected: TenantExpectation<'_>,
) -> Result<(), EnterpriseVerificationError> {
    if let TenantExpectation::Exact(tenant) = expected {
        validate_tenant(tenant)
            .map_err(|_| EnterpriseVerificationError::InvalidConfiguration)?;
    }
    Ok(())
}

fn idp_tenant(
    claims: &Map<String, Value>,
    expected: TenantExpectation<'_>,
) -> Result<Option<IdpTenantId>, EnterpriseVerificationError> {
    match expected {
        TenantExpectation::SingleTenant => {
            if claims.contains_key("tenant") {
                return Err(EnterpriseVerificationError::BindingMismatch);
            }
            Ok(None)
        }
        TenantExpectation::Exact(tenant) => {
            exact_string(claims, "tenant", tenant)?;
            Ok(Some(IdpTenantId(tenant.to_owned())))
        }
    }
}

fn closed_claims(
    claims: &Map<String, Value>,
    names: &[&str],
) -> Result<(), EnterpriseVerificationError> {
    if claims.keys().any(|key| !names.contains(&key.as_str())) {
        return Err(EnterpriseVerificationError::InvalidClaims);
    }
    Ok(())
}

fn claim_string<'a>(
    claims: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a str, EnterpriseVerificationError> {
    claims.get(name).and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(EnterpriseVerificationError::InvalidClaims)
}

fn exact_string(
    claims: &Map<String, Value>,
    name: &str,
    expected: &str,
) -> Result<(), EnterpriseVerificationError> {
    if claim_string(claims, name)? != expected {
        return Err(EnterpriseVerificationError::BindingMismatch);
    }
    Ok(())
}

fn exact_singleton(
    value: Option<&Value>,
    expected: &str,
) -> Result<(), EnterpriseVerificationError> {
    let actual = match value {
        Some(Value::String(value)) => value,
        Some(Value::Array(values)) if values.len() == 1 => {
            values[0].as_str().ok_or(EnterpriseVerificationError::BindingMismatch)?
        }
        _ => return Err(EnterpriseVerificationError::BindingMismatch),
    };
    if actual != expected {
        return Err(EnterpriseVerificationError::BindingMismatch);
    }
    Ok(())
}

fn oidc_subject(claims: &Map<String, Value>) -> Result<&str, EnterpriseVerificationError> {
    let subject = claim_string(claims, "sub")?;
    if subject.len() > MAX_ENTERPRISE_OIDC_SUBJECT_BYTES
        || !subject.is_ascii()
        || subject.chars().any(char::is_control)
    {
        return Err(EnterpriseVerificationError::InvalidClaims);
    }
    Ok(subject)
}

fn scope_claim(
    claims: &Map<String, Value>,
) -> Result<Option<String>, EnterpriseVerificationError> {
    let Some(scope) = claims.get("scope") else {
        return Ok(None);
    };
    let scope = scope.as_str().ok_or(EnterpriseVerificationError::InvalidClaims)?;
    if scope.is_empty() || scope.len() > MAX_ENTERPRISE_SCOPE_SET_BYTES {
        return Err(EnterpriseVerificationError::InvalidClaims);
    }
    let mut unique = BTreeSet::new();
    for token in scope.split(' ') {
        if token.is_empty()
            || token.len() > MAX_ENTERPRISE_SCOPE_BYTES
            || !token.bytes().all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
            || unique.len() >= MAX_ENTERPRISE_SCOPE_COUNT
            || !unique.insert(token)
        {
            return Err(EnterpriseVerificationError::InvalidClaims);
        }
    }
    Ok(Some(scope.to_owned()))
}

fn valid_access_token(token: &str) -> bool {
    if token.is_empty() || token.len() > MAX_ACCESS_TOKEN_BYTES {
        return false;
    }
    let body = token.trim_end_matches('=');
    !body.is_empty()
        && body.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
}

// Keep comparison on the pinned ring 0.17 compatibility primitive instead of
// introducing a handwritten or early-exit byte loop. Upstream deprecates this
// API and makes no external side-channel guarantee; this use is not timing
// qualification evidence for an enterprise deployment.
#[allow(deprecated)]
fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    ring::constant_time::verify_slices_are_equal(left, right).is_ok()
}

struct TimeFacts {
    issued: Duration,
    expires: Duration,
    now: Duration,
}

fn validate_times(
    claims: &Map<String, Value>,
    policy: JwtTimePolicy,
    now: SystemTime,
) -> Result<TimeFacts, EnterpriseVerificationError> {
    let now = now.duration_since(UNIX_EPOCH)
        .map_err(|_| EnterpriseVerificationError::InvalidTime)?;
    if now.as_nanos() > MAX_NUMERIC_DATE_NANOS {
        return Err(EnterpriseVerificationError::InvalidTime);
    }
    let issued = numeric_date(claims.get("iat").ok_or(EnterpriseVerificationError::InvalidTime)?)?;
    let expires = numeric_date(claims.get("exp").ok_or(EnterpriseVerificationError::InvalidTime)?)?;
    if expires <= issued || expires - issued > policy.max_lifetime {
        return Err(EnterpriseVerificationError::InvalidTime);
    }
    let latest = now.as_nanos().checked_add(policy.clock_skew.as_nanos())
        .ok_or(EnterpriseVerificationError::InvalidTime)?;
    if issued.as_nanos() > latest {
        return Err(EnterpriseVerificationError::NotYetValid);
    }
    if let Some(not_before) = claims.get("nbf") {
        let not_before = numeric_date(not_before)?;
        if not_before > expires {
            return Err(EnterpriseVerificationError::InvalidTime);
        }
        if not_before.as_nanos() > latest {
            return Err(EnterpriseVerificationError::NotYetValid);
        }
    }
    if expires.as_nanos() <= now.as_nanos().saturating_sub(policy.clock_skew.as_nanos()) {
        return Err(EnterpriseVerificationError::Expired);
    }
    Ok(TimeFacts { issued, expires, now })
}

fn system_time(value: Duration) -> Result<SystemTime, EnterpriseVerificationError> {
    UNIX_EPOCH.checked_add(value).ok_or(EnterpriseVerificationError::InvalidTime)
}

/// Parses the preserved number lexeme without floats or an unbounded decimal.
/// After removing trailing zeroes, a nonzero value must have <=9 fractional
/// digits. Even negative zero is rejected. The finite range ends in year 9999.
fn numeric_date(value: &Value) -> Result<Duration, EnterpriseVerificationError> {
    let Value::Number(number) = value else {
        return Err(EnterpriseVerificationError::InvalidTime);
    };
    let lexeme = number.as_str();
    if lexeme.is_empty()
        || lexeme.len() > MAX_NUMERIC_DATE_LEXEME_BYTES
        || lexeme.starts_with('-')
    {
        return Err(EnterpriseVerificationError::InvalidTime);
    }
    let (mantissa, exponent) = if let Some(index) = lexeme.find(['e', 'E']) {
        let exponent = lexeme[index + 1..].parse::<i32>()
            .map_err(|_| EnterpriseVerificationError::InvalidTime)?;
        if !(-9999..=9999).contains(&exponent) {
            return Err(EnterpriseVerificationError::InvalidTime);
        }
        (&lexeme[..index], exponent)
    } else {
        (lexeme, 0)
    };
    let mut digits = [0_u8; MAX_NUMERIC_DATE_LEXEME_BYTES];
    let mut length = 0_usize;
    let mut fraction = 0_i32;
    let mut after_dot = false;
    for byte in mantissa.bytes() {
        if byte == b'.' && !after_dot {
            after_dot = true;
        } else if byte.is_ascii_digit() {
            digits[length] = byte - b'0';
            length += 1;
            if after_dot {
                fraction += 1;
            }
        } else {
            return Err(EnterpriseVerificationError::InvalidTime);
        }
    }
    let Some(start) = digits[..length].iter().position(|digit| *digit != 0) else {
        return Ok(Duration::ZERO);
    };
    let mut end = length;
    let mut scale = exponent - fraction;
    while digits[end - 1] == 0 {
        end -= 1;
        scale += 1;
    }
    let power = scale + 9;
    if !(0..=20).contains(&power) || end - start + power as usize > 21 {
        return Err(EnterpriseVerificationError::InvalidTime);
    }
    let mut coefficient = 0_u128;
    for digit in &digits[start..end] {
        coefficient = coefficient.checked_mul(10)
            .and_then(|value| value.checked_add(u128::from(*digit)))
            .ok_or(EnterpriseVerificationError::InvalidTime)?;
    }
    let nanoseconds = coefficient.checked_mul(10_u128.pow(power as u32))
        .filter(|value| *value <= MAX_NUMERIC_DATE_NANOS)
        .ok_or(EnterpriseVerificationError::InvalidTime)?;
    Ok(Duration::new(
        (nanoseconds / NANOS_PER_SECOND) as u64,
        (nanoseconds % NANOS_PER_SECOND) as u32,
    ))
}
