//! Composed admission of OIDC, ID-JAG and final enterprise token responses.
//!
//! Bounded response admission and an explicit guarded HTTPS exchange driver.
//!
//! The driver binds each protected grant to its original profile before
//! serialization, requires durable identity-assertion reservation before ID-JAG
//! exchange, keeps the three grant forms distinct, and consumes inputs on every
//! outcome. It does not activate EMA or issue browser-flow, credential-custody,
//! subject-mapping or deployment receipts. Those trust boundaries are
//! additional requirements for the complete enterprise profile. Embeddings run
//! synchronous signature admission on their caller-owned bounded CPU lane.

#[cfg(test)]
mod tests;
mod wire;

use std::fmt;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::http::h1::Request as H1Request;
use asupersync::security::SecretString;
use asupersync::time::Sleep;
use asupersync::types::Time;
use fastmcp_core::runtime::CallerContextFuture;
use fastmcp_core::{AccessToken, CanonicalHttpUrl};
use fastmcp_transport::{
    GuardedHttpFetchError, GuardedHttpFetchResponse, GuardedHttpFetcher, GuardedHttpPeerProvenance,
    GuardedHttpRequest, GuardedHttpsUrl,
};

use super::oidc::{OidcCodeFlowError, OidcCodeGrant};
use super::policy::{
    EnterpriseClientAuthentication, EnterpriseProfile, ID_JAG_TOKEN_TYPE, IdJagGrantedScopeSet,
    JWT_BEARER_GRANT, TOKEN_EXCHANGE_GRANT,
};
use super::replay::{
    IdentityAssertionExchangeGuard, IdentityAssertionReplayError, ReservedIdentityAssertion,
};
use super::verification::disclosure::{IdJagDisclosureFacts, IdJagDisclosurePolicy};
use super::verification::{
    IdJagExpectations, IdJagVerificationKeys, JwtTimePolicy, OidcIdTokenExpectations,
    OidcVerificationKeys, ResourceTenantExpectation, TenantExpectation, VerifiedIdJag,
    VerifiedOidcIdToken, verify_id_jag, verify_id_jag_with_disclosure, verify_oidc_id_token,
};
use crate::http_auth::BoundBearerCredential;

/// Fixed diagnostics retain no tokens, claims, scopes, issuer text or peer body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseResponseError {
    InvalidPolicy,
    InvalidResponse,
    InvalidHeaders,
    InvalidCachePolicy,
    UnexpectedStatus,
    PolicyBindingMismatch,
    AssertionRejected,
    ScopeRejected,
    InvalidLifetime,
}

impl fmt::Display for EnterpriseResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid enterprise response policy",
            Self::InvalidResponse => "enterprise token response rejected",
            Self::InvalidHeaders => "enterprise token response headers rejected",
            Self::InvalidCachePolicy => "enterprise token response cache policy rejected",
            Self::UnexpectedStatus => "enterprise token response status does not match its body",
            Self::PolicyBindingMismatch => {
                "enterprise assertion key authority differs from the selected profile"
            }
            Self::AssertionRejected => "enterprise signed assertion rejected",
            Self::ScopeRejected => "enterprise scope grants are inconsistent",
            Self::InvalidLifetime => "enterprise token lifetime rejected",
        })
    }
}
impl std::error::Error for EnterpriseResponseError {}

/// A borrowed response from its already-selected trusted token endpoint.
///
/// This value does not establish endpoint or transport provenance. An exchange
/// driver must separately bind the response to its actual dispatch receipt.
/// Refusals retain no body or header, and this type has no Debug implementation.
pub struct EnterpriseTokenResponse<'a> {
    pub status: u16,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EnterpriseTokenResponseStage {
    OidcCode,
    IdJag,
    AccessToken,
}

/// Redacted peer diagnostics. Cache bypass is mandatory independently of these
/// flags; missing no-store or Pragma alone does not invalidate a response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnterpriseCacheDiagnostics {
    missing_no_store: bool,
    missing_pragma_no_cache: bool,
}
impl EnterpriseCacheDiagnostics {
    pub const fn missing_no_store(self) -> bool {
        self.missing_no_store
    }

    /// Pragma is optional for the OIDC code response; that stage does not report
    /// its absence as peer nonconformance.
    pub const fn missing_pragma_no_cache(self) -> bool {
        self.missing_pragma_no_cache
    }
}

/// An unknown bounded OAuth error is discarded into Extension. Peer text cannot
/// select a retry, fallback, browser launch or local policy action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseOAuthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    InvalidTarget,
    AccessDenied,
    InteractionRequired,
    Extension,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnterpriseOAuthDenial {
    code: EnterpriseOAuthErrorCode,
    status: u16,
    basic_challenge: bool,
}
impl EnterpriseOAuthDenial {
    pub const fn code(self) -> EnterpriseOAuthErrorCode {
        self.code
    }
    pub const fn status(self) -> u16 {
        self.status
    }
    /// Distinguishes the matching Basic/401 rule from the OIDC/400 variant.
    pub const fn matched_basic_challenge(self) -> bool {
        self.basic_challenge
    }
}

/// This indication never restarts a flow. A caller must explicitly begin a new
/// authorization with fresh assertion custody and a new operation budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnterpriseStepUpRequired {
    maximum_authentication_age: Option<Duration>,
}
impl EnterpriseStepUpRequired {
    pub const fn maximum_authentication_age(self) -> Option<Duration> {
        self.maximum_authentication_age
    }
}

/// A stage-specific success, typed denial or first-stage step-up. Success owners
/// need not implement Clone or Debug and never expose their compact tokens.
pub enum EnterpriseResponseOutcome<T> {
    Success {
        value: T,
        cache: EnterpriseCacheDiagnostics,
    },
    Denied {
        denial: EnterpriseOAuthDenial,
        cache: EnterpriseCacheDiagnostics,
    },
    StepUpRequired {
        requirement: EnterpriseStepUpRequired,
        cache: EnterpriseCacheDiagnostics,
    },
}

/// Immutable finite bounds for local response validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnterpriseResponsePolicy {
    id_token_lifetime: Duration,
    id_jag_lifetime: Duration,
    access_token_lifetime: Duration,
    clock_skew: Duration,
    maximum_step_up_age: Duration,
}
impl Default for EnterpriseResponsePolicy {
    fn default() -> Self {
        Self {
            id_token_lifetime: Duration::from_secs(3600),
            id_jag_lifetime: Duration::from_secs(300),
            access_token_lifetime: Duration::from_secs(3600),
            clock_skew: Duration::from_secs(60),
            maximum_step_up_age: Duration::from_hours(24),
        }
    }
}
impl EnterpriseResponsePolicy {
    pub fn new(
        id_token_lifetime: Duration,
        id_jag_lifetime: Duration,
        access_token_lifetime: Duration,
        clock_skew: Duration,
        maximum_step_up_age: Duration,
    ) -> Result<Self, EnterpriseResponseError> {
        if id_token_lifetime.is_zero()
            || id_token_lifetime > Duration::from_hours(24)
            || id_jag_lifetime.is_zero()
            || id_jag_lifetime > Duration::from_mins(15)
            || access_token_lifetime.is_zero()
            || access_token_lifetime > Duration::from_hours(24)
            || clock_skew > Duration::from_secs(300)
            || maximum_step_up_age > Duration::from_hours(24)
            || maximum_step_up_age.subsec_nanos() != 0
        {
            return Err(EnterpriseResponseError::InvalidPolicy);
        }
        JwtTimePolicy::new(id_token_lifetime, clock_skew)
            .map_err(|_| EnterpriseResponseError::InvalidPolicy)?;
        JwtTimePolicy::new(id_jag_lifetime, clock_skew)
            .map_err(|_| EnterpriseResponseError::InvalidPolicy)?;
        Ok(Self {
            id_token_lifetime,
            id_jag_lifetime,
            access_token_lifetime,
            clock_skew,
            maximum_step_up_age,
        })
    }
}

/// Locally verified identity facts and exclusive zeroizing assertion custody.
/// This is not the sealed authorization-code-flow receipt needed for exchange
/// activation; there is no compact-token getter or credential conversion.
pub struct EnterpriseIdentityAssertion {
    compact_assertion: SecretString,
    identity: VerifiedOidcIdToken,
    profile: EnterpriseProfile,
    policy: EnterpriseResponsePolicy,
    received_at: SystemTime,
}
impl EnterpriseIdentityAssertion {
    pub fn identity(&self) -> &VerifiedOidcIdToken {
        &self.identity
    }
}

/// The signed ID-JAG, original request, IdP scope grant and earliest effective
/// expiry stay coupled. Local ownership is not resource-AS replay prevention.
pub struct EnterpriseIdJagResponse {
    compact_assertion: SecretString,
    assertion: VerifiedIdJag,
    profile: EnterpriseProfile,
    requested_scopes: Vec<String>,
    granted_scopes: IdJagGrantedScopeSet,
    resource: String,
    received_at: SystemTime,
    effective_expires_at: SystemTime,
    policy: EnterpriseResponsePolicy,
    used_basic: bool,
}
impl EnterpriseIdJagResponse {
    pub fn assertion(&self) -> &VerifiedIdJag {
        &self.assertion
    }
    pub fn requested_scopes(&self) -> &[String] {
        &self.requested_scopes
    }
    pub fn granted_scopes(&self) -> &[String] {
        self.granted_scopes.as_slice()
    }
    pub fn effective_expires_at(&self) -> SystemTime {
        self.effective_expires_at
    }

    /// Consumes this local owner while admitting one final token response.
    ///
    /// The required scalar resource and explicit scope are compared with the
    /// original profile and signed IdP grant. A denial or malformed response
    /// consumes this owner too. No assertion retry or token header is produced.
    /// JWT access-token verification, network receipts and issuer-side replay
    /// protection remain distinct from this response overlay.
    pub fn admit_access_token_response(
        self,
        response: EnterpriseTokenResponse<'_>,
        received_at: SystemTime,
    ) -> Result<EnterpriseResponseOutcome<EnterpriseAccessTokenResponse>, EnterpriseResponseError>
    {
        if received_at < self.received_at || received_at >= self.effective_expires_at {
            return Err(EnterpriseResponseError::InvalidLifetime);
        }
        let (body, cache) = wire::admit(
            &response,
            EnterpriseTokenResponseStage::AccessToken,
            self.used_basic,
            self.policy.maximum_step_up_age.as_secs(),
        )?;
        let wire::AdmittedBody::Success(body) = body else {
            return terminal(body, cache);
        };
        if body.resource.as_deref() != Some(self.resource.as_str()) {
            return Err(EnterpriseResponseError::PolicyBindingMismatch);
        }
        let granted_scopes = self
            .granted_scopes
            .admit_access_grant(body.scope.as_deref())
            .map_err(|_| EnterpriseResponseError::ScopeRejected)?;
        let mut expires_at = bounded_expiry(
            received_at,
            body.expires_in,
            86_400,
            self.policy.access_token_lifetime,
            None,
        )?;
        let id_jag_disclosure = self.assertion.disclosure().cloned();
        if let Some(disclosure) = &id_jag_disclosure {
            expires_at = expires_at.min(disclosure.review_expires_at());
        }
        let token = body
            .access_token
            .ok_or(EnterpriseResponseError::InvalidResponse)?;
        if !AccessToken::is_valid_token68(token.as_str()) {
            return Err(EnterpriseResponseError::InvalidResponse);
        }
        Ok(EnterpriseResponseOutcome::Success {
            value: EnterpriseAccessTokenResponse {
                access_token: token,
                resource: self.resource,
                requested_scopes: self.requested_scopes,
                idp_granted_scopes: self.granted_scopes.as_slice().to_vec(),
                granted_scopes,
                expires_at,
                id_jag_disclosure,
            },
            cache,
        })
    }
}

/// The exact final response grant, with exclusive protected token custody.
///
/// This admits the response overlay, not the full exchange evidence or a JWT
/// access token's signature. There is no bearer conversion or MCP installation
/// method. The original request, signed IdP grant and final grant remain three
/// separate values so absence or narrowing cannot recreate authority.
pub struct EnterpriseAccessTokenResponse {
    access_token: SecretString,
    resource: String,
    requested_scopes: Vec<String>,
    idp_granted_scopes: Vec<String>,
    granted_scopes: Vec<String>,
    expires_at: SystemTime,
    id_jag_disclosure: Option<IdJagDisclosureFacts>,
}
impl EnterpriseAccessTokenResponse {
    pub fn resource(&self) -> &str {
        &self.resource
    }
    pub fn requested_scopes(&self) -> &[String] {
        &self.requested_scopes
    }
    pub fn idp_granted_scopes(&self) -> &[String] {
        &self.idp_granted_scopes
    }
    pub fn granted_scopes(&self) -> &[String] {
        &self.granted_scopes
    }
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
    /// Reviewed policy and admitted optional claim names, never claim values.
    pub fn id_jag_disclosure(&self) -> Option<&IdJagDisclosureFacts> {
        self.id_jag_disclosure.as_ref()
    }
}

impl EnterpriseProfile {
    /// Verifies the distinct OIDC code-token response. Its temporary access
    /// token is destroyed after optional at_hash validation, including when
    /// this branch legitimately omits expires_in. No access credential results.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_oidc_code_response(
        &self,
        response: EnterpriseTokenResponse<'_>,
        keys: &OidcVerificationKeys,
        nonce: &str,
        tenant: TenantExpectation<'_>,
        maximum_authentication_age: Option<Duration>,
        policy: EnterpriseResponsePolicy,
        received_at: SystemTime,
    ) -> Result<EnterpriseResponseOutcome<EnterpriseIdentityAssertion>, EnterpriseResponseError>
    {
        if keys.issuer() != self.idp_issuer() || keys.generation() != self.oidc_key_generation() {
            return Err(EnterpriseResponseError::PolicyBindingMismatch);
        }
        let (body, cache) = wire::admit(
            &response,
            EnterpriseTokenResponseStage::OidcCode,
            self.idp_authentication() == EnterpriseClientAuthentication::ClientSecretBasic,
            policy.maximum_step_up_age.as_secs(),
        )?;
        let wire::AdmittedBody::Success(body) = body else {
            return terminal(body, cache);
        };
        if body.scope.as_deref().is_some_and(|scope| scope != "openid")
            || body.expires_in.is_some_and(|seconds| seconds > 86_400)
        {
            return Err(EnterpriseResponseError::InvalidResponse);
        }
        let access = body
            .access_token
            .ok_or(EnterpriseResponseError::InvalidResponse)?;
        if !AccessToken::is_valid_token68(access.as_str()) {
            return Err(EnterpriseResponseError::InvalidResponse);
        }
        let assertion = body
            .id_token
            .ok_or(EnterpriseResponseError::InvalidResponse)?;
        let expected = OidcIdTokenExpectations {
            client_id: self.idp_client_id(),
            nonce,
            access_token: Some(access.as_str()),
            tenant,
            max_authentication_age: maximum_authentication_age,
            time: JwtTimePolicy::new(policy.id_token_lifetime, policy.clock_skew)
                .map_err(|_| EnterpriseResponseError::InvalidPolicy)?,
        };
        let identity = verify_oidc_id_token(assertion.as_str(), keys, &expected, received_at)
            .map_err(|_| EnterpriseResponseError::AssertionRejected)?;
        if identity.expires_at() <= received_at {
            return Err(EnterpriseResponseError::InvalidLifetime);
        }
        // This temporary token never enters a bearer, refresh, cache or result owner.
        drop(access);
        Ok(EnterpriseResponseOutcome::Success {
            value: EnterpriseIdentityAssertion {
                compact_assertion: assertion,
                identity,
                profile: self.clone(),
                policy,
                received_at,
            },
            cache,
        })
    }

    /// Verifies the first token exchange under independently configured ID-JAG
    /// keys. This native subset requires the exact resource claim; it infers no
    /// single-resource mapping. JWT, expires_in and local-cap checks share one
    /// caller-sampled response-admission time.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_id_jag_response(
        &self,
        response: EnterpriseTokenResponse<'_>,
        keys: &IdJagVerificationKeys,
        idp_tenant: TenantExpectation<'_>,
        resource_tenant: ResourceTenantExpectation<'_>,
        policy: EnterpriseResponsePolicy,
        received_at: SystemTime,
    ) -> Result<EnterpriseResponseOutcome<EnterpriseIdJagResponse>, EnterpriseResponseError> {
        self.admit_id_jag_response_inner(
            response,
            keys,
            idp_tenant,
            resource_tenant,
            policy,
            None,
            received_at,
        )
    }

    /// Admits reviewed optional disclosures through the same signed grant and
    /// scope checks. Claim values are discarded. The review expiry bounds both
    /// this owner and any locally admitted final token; an expired policy cannot
    /// survive into a later stage. This does not establish policy attestation.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_id_jag_response_with_disclosure(
        &self,
        response: EnterpriseTokenResponse<'_>,
        keys: &IdJagVerificationKeys,
        idp_tenant: TenantExpectation<'_>,
        resource_tenant: ResourceTenantExpectation<'_>,
        policy: EnterpriseResponsePolicy,
        disclosure: &IdJagDisclosurePolicy,
        received_at: SystemTime,
    ) -> Result<EnterpriseResponseOutcome<EnterpriseIdJagResponse>, EnterpriseResponseError> {
        self.admit_id_jag_response_inner(
            response,
            keys,
            idp_tenant,
            resource_tenant,
            policy,
            Some(disclosure),
            received_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_id_jag_response_inner(
        &self,
        response: EnterpriseTokenResponse<'_>,
        keys: &IdJagVerificationKeys,
        idp_tenant: TenantExpectation<'_>,
        resource_tenant: ResourceTenantExpectation<'_>,
        policy: EnterpriseResponsePolicy,
        disclosure: Option<&IdJagDisclosurePolicy>,
        received_at: SystemTime,
    ) -> Result<EnterpriseResponseOutcome<EnterpriseIdJagResponse>, EnterpriseResponseError> {
        if keys.issuer() != self.idp_issuer() || keys.generation() != self.id_jag_key_generation() {
            return Err(EnterpriseResponseError::PolicyBindingMismatch);
        }
        let (body, cache) = wire::admit(
            &response,
            EnterpriseTokenResponseStage::IdJag,
            self.idp_authentication() == EnterpriseClientAuthentication::ClientSecretBasic,
            policy.maximum_step_up_age.as_secs(),
        )?;
        let wire::AdmittedBody::Success(body) = body else {
            return terminal(body, cache);
        };
        let compact = body
            .access_token
            .ok_or(EnterpriseResponseError::InvalidResponse)?;
        let expected = IdJagExpectations {
            audience: self.resource_as_issuer(),
            client_id: self.resource_as_client_id(),
            resource: self.resource().as_str(),
            require_resource: true,
            idp_tenant,
            resource_tenant,
            time: JwtTimePolicy::new(policy.id_jag_lifetime, policy.clock_skew)
                .map_err(|_| EnterpriseResponseError::InvalidPolicy)?,
        };
        let assertion = match disclosure {
            Some(disclosure) => verify_id_jag_with_disclosure(
                compact.as_str(),
                keys,
                &expected,
                disclosure,
                received_at,
            ),
            None => verify_id_jag(compact.as_str(), keys, &expected, received_at),
        }
        .map_err(|_| EnterpriseResponseError::AssertionRejected)?;
        let granted_scopes = self
            .requested_scopes()
            .admit_id_jag_grant(body.scope.as_deref(), assertion.scope())
            .map_err(|_| EnterpriseResponseError::ScopeRejected)?;
        let mut effective_expires_at = bounded_expiry(
            received_at,
            body.expires_in,
            900,
            policy.id_jag_lifetime,
            Some(assertion.expires_at()),
        )?;
        if let Some(disclosure) = assertion.disclosure() {
            effective_expires_at = effective_expires_at.min(disclosure.review_expires_at());
        }
        Ok(EnterpriseResponseOutcome::Success {
            value: EnterpriseIdJagResponse {
                compact_assertion: compact,
                assertion,
                profile: self.clone(),
                requested_scopes: self.requested_scopes().as_slice().to_vec(),
                granted_scopes,
                resource: self.resource().as_str().to_owned(),
                received_at,
                effective_expires_at,
                policy,
                used_basic: self.resource_as_authentication()
                    == EnterpriseClientAuthentication::ClientSecretBasic,
            },
            cache,
        })
    }
}

fn terminal<T>(
    body: wire::AdmittedBody,
    cache: EnterpriseCacheDiagnostics,
) -> Result<EnterpriseResponseOutcome<T>, EnterpriseResponseError> {
    match body {
        wire::AdmittedBody::Denied(denial) => {
            Ok(EnterpriseResponseOutcome::Denied { denial, cache })
        }
        wire::AdmittedBody::StepUp(seconds) => Ok(EnterpriseResponseOutcome::StepUpRequired {
            requirement: EnterpriseStepUpRequired {
                maximum_authentication_age: seconds.map(Duration::from_secs),
            },
            cache,
        }),
        wire::AdmittedBody::Success(_) => Err(EnterpriseResponseError::InvalidResponse),
    }
}

fn bounded_expiry(
    received_at: SystemTime,
    response_seconds: Option<u64>,
    maximum_seconds: u64,
    local_cap: Duration,
    signed_expiry: Option<SystemTime>,
) -> Result<SystemTime, EnterpriseResponseError> {
    if response_seconds.is_some_and(|seconds| seconds == 0 || seconds > maximum_seconds) {
        return Err(EnterpriseResponseError::InvalidLifetime);
    }
    let mut expires_at = received_at
        .checked_add(local_cap)
        .ok_or(EnterpriseResponseError::InvalidLifetime)?;
    if let Some(seconds) = response_seconds {
        expires_at = expires_at.min(
            received_at
                .checked_add(Duration::from_secs(seconds))
                .ok_or(EnterpriseResponseError::InvalidLifetime)?,
        );
    }
    if let Some(signed) = signed_expiry {
        expires_at = expires_at.min(signed);
    }
    if expires_at <= received_at {
        return Err(EnterpriseResponseError::InvalidLifetime);
    }
    Ok(expires_at)
}

// ============================================================================
// Sealed RFC 8693 + RFC 7523 Guarded HTTPS Exchange Driver (AUTHX-01..03)
// ============================================================================

const SUBJECT_TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
const MAX_ENTERPRISE_CLIENT_SECRET_BYTES: usize = 4_096;
const MAX_ENTERPRISE_EXCHANGE_FORM_BYTES: usize = 32 * 1_024;
const MAX_ENTERPRISE_EXCHANGE_RESPONSE_BYTES: usize = 64 * 1_024;

/// Bounded confidential client secret for one enterprise role (IdP or Resource AS).
///
/// Never echoes secret bytes in `Debug` or `Display` and zeroizes on drop.
pub struct EnterpriseClientSecret {
    value: SecretString,
}

impl EnterpriseClientSecret {
    /// Validates and wraps a bounded non-empty confidential client secret.
    pub fn try_new(value: impl Into<String>) -> Result<Self, EnterpriseExchangeError> {
        let value = SecretString::from_string(value.into());
        if value.is_empty()
            || value.len() > MAX_ENTERPRISE_CLIENT_SECRET_BYTES
            || value.as_bytes().iter().any(|b| *b < 0x20 || *b == 0x7f)
        {
            return Err(EnterpriseExchangeError::InvalidConfiguration);
        }
        Ok(Self { value })
    }

    fn as_str(&self) -> &str {
        self.value.as_str()
    }
}

impl fmt::Debug for EnterpriseClientSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnterpriseClientSecret([redacted])")
    }
}

/// Redacted failure surface for guarded enterprise token exchanges.
///
/// Never carries tokens, secrets, headers, endpoints, or peer response bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseExchangeError {
    InvalidConfiguration,
    InvalidEndpoint,
    InvalidPolicy,
    RuntimeUnavailable,
    ExchangeInProgress,
    Cancelled,
    TimedOut,
    TransportFailed,
    RedirectRefused,
    EvidenceMismatch,
    ReservationRejected,
    EncodingFailed,
    CodeFlowRejected(OidcCodeFlowError),
    ResponseRejected(EnterpriseResponseError),
    CredentialBindingFailed,
}

impl fmt::Display for EnterpriseExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => {
                formatter.write_str("invalid enterprise exchange configuration")
            }
            Self::InvalidEndpoint => formatter.write_str("invalid enterprise token endpoint"),
            Self::InvalidPolicy => formatter.write_str("invalid enterprise exchange fetch policy"),
            Self::RuntimeUnavailable => formatter.write_str(
                "enterprise token exchange requires caller I/O, time, spawn and timer authority",
            ),
            Self::ExchangeInProgress => {
                formatter.write_str("enterprise token exchange is already in progress")
            }
            Self::Cancelled => formatter.write_str("enterprise token exchange was cancelled"),
            Self::TimedOut => {
                formatter.write_str("enterprise token exchange exceeded its deadline")
            }
            Self::TransportFailed => {
                formatter.write_str("enterprise guarded HTTPS token exchange failed")
            }
            Self::RedirectRefused => {
                formatter.write_str("enterprise token exchange refused HTTP redirect")
            }
            Self::EvidenceMismatch => {
                formatter.write_str("enterprise token exchange peer provenance did not match")
            }
            Self::ReservationRejected => {
                formatter.write_str("enterprise assertion reservation is no longer usable")
            }
            Self::EncodingFailed => {
                formatter.write_str("enterprise token exchange form encoding failed")
            }
            Self::CodeFlowRejected(error) => error.fmt(formatter),
            Self::ResponseRejected(error) => error.fmt(formatter),
            Self::CredentialBindingFailed => {
                formatter.write_str("enterprise access token could not be bound to HTTPS resource")
            }
        }
    }
}

impl std::error::Error for EnterpriseExchangeError {}

/// Transport provenance recorded for one enterprise token-endpoint POST.
pub struct EnterpriseExchangeObservation {
    endpoint: String,
    provenance: GuardedHttpPeerProvenance,
}

impl EnterpriseExchangeObservation {
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    #[must_use]
    pub fn provenance(&self) -> &GuardedHttpPeerProvenance {
        &self.provenance
    }
}

impl fmt::Debug for EnterpriseExchangeObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnterpriseExchangeObservation")
            .finish_non_exhaustive()
    }
}

/// Exclusive ID-JAG returned by the guarded first-stage exchange after durable
/// identity-assertion reservation. A locally parsed response cannot construct
/// this owner. It has no Clone, raw-token getter, retry or unwrapping method.
/// Dropping it never releases the identity assertion's durable replay aliases.
pub struct EnterpriseExchangedIdJag {
    response: EnterpriseIdJagResponse,
    reservation: IdentityAssertionExchangeGuard,
    expires_at_monotonic: Instant,
}

impl EnterpriseExchangedIdJag {
    /// Borrows signed facts and admitted grant metadata without extracting the
    /// protected assertion or bypassing second-stage ownership.
    pub fn response(&self) -> &EnterpriseIdJagResponse {
        &self.response
    }

    pub fn granted_scopes(&self) -> &[String] {
        self.response.granted_scopes()
    }

    pub fn effective_expires_at(&self) -> SystemTime {
        self.response.effective_expires_at()
    }
}

/// Admitted final enterprise access-token grant paired with its sealed
/// resource-bound bearer conversion.
pub struct EnterpriseBoundAccessToken {
    response: EnterpriseAccessTokenResponse,
    reservation: IdentityAssertionExchangeGuard,
    received_at: SystemTime,
    expires_at_monotonic: Instant,
}

impl EnterpriseBoundAccessToken {
    /// Inspects the admitted scope/resource/expiry metadata without exposing token bytes.
    #[must_use]
    pub fn response(&self) -> &EnterpriseAccessTokenResponse {
        &self.response
    }

    /// Consumes this grant and binds it strictly to its exact HTTPS MCP resource
    /// with a monotonic deadline no later than the original response's deadline.
    /// A stale wall-clock sample cannot extend the grant or reset its lifetime.
    pub fn into_bound_bearer_credential(
        self,
        now_monotonic: Instant,
        received_at_wall: SystemTime,
    ) -> Result<BoundBearerCredential, EnterpriseExchangeError> {
        self.reservation.check().map_err(map_reservation_error)?;
        if received_at_wall < self.received_at || Instant::now() >= self.expires_at_monotonic {
            return Err(EnterpriseExchangeError::CredentialBindingFailed);
        }
        let ttl = self
            .response
            .expires_at
            .duration_since(received_at_wall)
            .map_err(|_| EnterpriseExchangeError::CredentialBindingFailed)?;
        if ttl.is_zero() {
            return Err(EnterpriseExchangeError::CredentialBindingFailed);
        }
        let deadline = now_monotonic
            .checked_add(ttl)
            .ok_or(EnterpriseExchangeError::CredentialBindingFailed)?
            .min(self.expires_at_monotonic);
        let resource = CanonicalHttpUrl::parse(self.response.resource())
            .map_err(|_| EnterpriseExchangeError::CredentialBindingFailed)?;
        BoundBearerCredential::bind_with_expiry(
            resource,
            self.response.access_token.as_str(),
            deadline,
        )
        .map_err(|_| EnterpriseExchangeError::CredentialBindingFailed)
    }
}

impl fmt::Debug for EnterpriseBoundAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnterpriseBoundAccessToken")
            .field("resource", &self.response.resource())
            .field("granted_scopes", &self.response.granted_scopes())
            .finish_non_exhaustive()
    }
}

struct ExchangeDriverInner {
    profile: EnterpriseProfile,
    idp_token_url: GuardedHttpsUrl,
    resource_as_token_url: GuardedHttpsUrl,
    fetcher: GuardedHttpFetcher,
    response_policy: EnterpriseResponsePolicy,
    busy: Arc<AtomicBool>,
    #[cfg(test)]
    test_post: Option<Arc<dyn tests::ExchangePoster>>,
}

/// Sealed guarded-HTTPS driver redeeming an OIDC code grant and executing the
/// two-stage Enterprise-Managed Authorization token exchange:
///
/// 1. OIDC authorization-code redemption consumes [`OidcCodeGrant`] and produces
///    a nonce-bound, signature-verified [`EnterpriseIdentityAssertion`]. The
///    caller must reserve that assertion through the separate replay boundary
///    before it can enter the two-stage exchange.
/// 2. RFC 8693 (`token-exchange`) at the IdP token endpoint consumes
///    `ReservedIdentityAssertion` and produces `EnterpriseExchangedIdJag`.
/// 3. RFC 7523 (`jwt-bearer`) at the Resource AS token endpoint consumes
///    `EnterpriseExchangedIdJag` and produces `EnterpriseBoundAccessToken`.
///
/// Enforces single-flight execution, bounded deadlines, zero HTTP redirects,
/// strict peer provenance verification, exact per-role client authentication
/// (`client_secret_basic` vs `client_secret_post`), real RS256 ID-JAG signature
/// verification, and scope/resource/expiry clamping without exposing compact
/// assertions externally.
///
/// This is a low-level transport component, not complete EMA activation. Raw
/// secrets supplied here do not attest a confidential credential provider, and
/// the required reservation's local flow identifiers do not attest browser
/// acquisition. Store durability, credential custody, browser custody and
/// deployment qualification remain independent trust boundaries.
#[derive(Clone)]
pub struct EnterpriseExchangeDriver {
    inner: Arc<ExchangeDriverInner>,
}

impl EnterpriseExchangeDriver {
    /// Freezes one admitted [`EnterpriseProfile`], [`GuardedHttpFetcher`], and
    /// [`EnterpriseResponsePolicy`]. Performs no network I/O.
    pub fn new(
        profile: EnterpriseProfile,
        fetcher: GuardedHttpFetcher,
        response_policy: EnterpriseResponsePolicy,
    ) -> Result<Self, EnterpriseExchangeError> {
        if fetcher.policy().response_body_bytes() > MAX_ENTERPRISE_EXCHANGE_RESPONSE_BYTES
            || fetcher.policy().deadline() > Duration::from_secs(30)
        {
            return Err(EnterpriseExchangeError::InvalidPolicy);
        }
        let idp_token_url = GuardedHttpsUrl::parse(profile.idp_token_endpoint())
            .map_err(|_| EnterpriseExchangeError::InvalidEndpoint)?;
        let resource_as_token_url = GuardedHttpsUrl::parse(profile.resource_as_token_endpoint())
            .map_err(|_| EnterpriseExchangeError::InvalidEndpoint)?;
        Ok(Self {
            inner: Arc::new(ExchangeDriverInner {
                profile,
                idp_token_url,
                resource_as_token_url,
                fetcher,
                response_policy,
                busy: Arc::new(AtomicBool::new(false)),
                #[cfg(test)]
                test_post: None,
            }),
        })
    }

    #[must_use]
    pub fn profile(&self) -> &EnterpriseProfile {
        &self.inner.profile
    }

    /// Redeems one locally admitted OIDC authorization code at its exact IdP
    /// endpoint without exposing the code, verifier, nonce or temporary token.
    ///
    /// The grant retains its original issuer, client registration, redirect,
    /// response policy, tenancy and nonce. Those bindings and the OIDC key
    /// issuer/generation are checked before serialization. The closed form
    /// carries only grant, code, redirect, verifier and the registered client
    /// authentication; it never carries MCP scope, resource or audience.
    ///
    /// `received_at` is the embedding's trusted wall-clock sample at call entry;
    /// monotonic elapsed time advances it through dispatch and signed-response
    /// admission. The request shares this driver's single-flight slot and is
    /// bounded by the grant expiry, caller budget and guarded fetch deadline.
    /// Every outcome consumes the code grant. There is no redirect or retry.
    ///
    /// This low-level operation does not attest browser launch or durable
    /// pending-flow custody, activate EMA, or reserve identity-assertion replay
    /// aliases. A successful identity must still pass that separate reservation
    /// before [`Self::exchange_identity_for_id_jag`] can consume it.
    pub async fn exchange_oidc_code_for_identity(
        &self,
        cx: &Cx,
        grant: OidcCodeGrant,
        idp_client_secret: &EnterpriseClientSecret,
        oidc_keys: &OidcVerificationKeys,
        received_at: SystemTime,
    ) -> Result<
        (
            EnterpriseResponseOutcome<EnterpriseIdentityAssertion>,
            EnterpriseExchangeObservation,
        ),
        EnterpriseExchangeError,
    > {
        let clock = ExchangeClock::new(received_at);
        let admitted = crate::http_auth::caller::with_caller(cx, admit_exchange_caller)?;
        let expires_at = grant.expires_at();
        let (request, response_admission) = grant.into_token_request(
            &self.inner.profile,
            self.inner.response_policy,
            idp_client_secret.as_str(),
            oidc_keys,
            clock.wall_now()?,
        )?;
        let input_deadline = clock.deadline(expires_at)?;
        let permit = Arc::new(ExchangePermit::acquire(Arc::clone(&self.inner.busy))?);
        let response = self
            .dispatch_post(
                &admitted,
                &self.inner.idp_token_url,
                &request,
                input_deadline,
                Arc::clone(&permit),
                // No identity assertion exists until this response is verified.
                // Replay reservation is mandatory in the subsequent stage.
                || Ok(()),
            )
            .await?;
        let observation = EnterpriseExchangeObservation {
            endpoint: self.inner.profile.idp_token_endpoint().to_owned(),
            provenance: response.provenance,
        };
        let outcome = response_admission
            .admit_token_response(
                EnterpriseTokenResponse {
                    status: response.status,
                    headers: &response.headers,
                    body: &response.body,
                },
                oidc_keys,
                clock.wall_now()?,
            )
            .map_err(EnterpriseExchangeError::CodeFlowRejected)?;
        // Signature validation is bounded synchronous work. A caller cancellation
        // or deadline reached during that work must still prevent identity release.
        crate::http_auth::caller::with_caller(&admitted, admit_exchange_caller)?;
        if Instant::now() >= input_deadline
            || clock.monotonic.elapsed() >= self.inner.fetcher.policy().deadline()
        {
            return Err(EnterpriseExchangeError::TimedOut);
        }
        if let EnterpriseResponseOutcome::Success {
            value: assertion, ..
        } = &outcome
            && assertion.identity().expires_at() <= clock.wall_now()?
        {
            return Err(EnterpriseExchangeError::TimedOut);
        }
        Ok((outcome, observation))
    }

    /// Stage 1 (RFC 8693): consumes a durably reserved OIDC identity assertion
    /// at the IdP token endpoint for an exclusively owned signed ID-JAG.
    ///
    /// `received_at` is the trusted wall-clock sample at call entry. Elapsed
    /// monotonic time advances it before response admission. The exact original
    /// profile, verification keys, tenancy and live input lifetime are checked
    /// before a confidential form is constructed or posted. No outcome releases
    /// the durable replay reservation, including a local refusal or a denial.
    #[allow(clippy::too_many_arguments)]
    pub async fn exchange_identity_for_id_jag(
        &self,
        cx: &Cx,
        reserved: ReservedIdentityAssertion,
        idp_client_secret: &EnterpriseClientSecret,
        id_jag_keys: &IdJagVerificationKeys,
        idp_tenant: TenantExpectation<'_>,
        resource_tenant: ResourceTenantExpectation<'_>,
        received_at: SystemTime,
    ) -> Result<
        (
            EnterpriseResponseOutcome<EnterpriseExchangedIdJag>,
            EnterpriseExchangeObservation,
        ),
        EnterpriseExchangeError,
    > {
        let clock = ExchangeClock::new(received_at);
        let admitted = crate::http_auth::caller::with_caller(cx, admit_exchange_caller)?;
        let profile = &self.inner.profile;
        let (assertion, reservation) = reserved
            .into_exchange(profile)
            .map_err(map_reservation_error)?;
        if assertion.profile != *profile
            || assertion.policy != self.inner.response_policy
            || id_jag_keys.issuer() != profile.idp_issuer()
            || id_jag_keys.generation() != profile.id_jag_key_generation()
            || !matches_tenant(
                assertion.identity.tenant().map(|tenant| tenant.as_str()),
                idp_tenant,
            )
        {
            return Err(EnterpriseExchangeError::ResponseRejected(
                EnterpriseResponseError::PolicyBindingMismatch,
            ));
        }
        let input_deadline = clock
            .input_deadline(assertion.received_at, assertion.identity.expires_at())?
            .min(reservation.identity_deadline());
        if Instant::now() >= input_deadline {
            return Err(EnterpriseExchangeError::TimedOut);
        }
        let permit = Arc::new(ExchangePermit::acquire(Arc::clone(&self.inner.busy))?);
        let scope_wire = profile.requested_scopes().as_wire_value();
        let mut fields: Vec<(&str, &str)> = vec![
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("requested_token_type", ID_JAG_TOKEN_TYPE),
            ("audience", profile.resource_as_issuer()),
            ("resource", profile.resource().as_str()),
            ("subject_token", assertion.compact_assertion.as_str()),
            ("subject_token_type", SUBJECT_TOKEN_TYPE_ID_TOKEN),
        ];
        if let Some(scope) = scope_wire.as_deref() {
            fields.push(("scope", scope));
        }
        let request = build_confidential_token_request(
            profile.idp_authentication(),
            profile.idp_client_id(),
            idp_client_secret.as_str(),
            &mut fields,
        )?;
        let response = self
            .dispatch_post(
                &admitted,
                &self.inner.idp_token_url,
                &request,
                input_deadline,
                Arc::clone(&permit),
                || reservation.check().map_err(map_reservation_error),
            )
            .await?;
        let observation = EnterpriseExchangeObservation {
            endpoint: profile.idp_token_endpoint().to_owned(),
            provenance: response.provenance,
        };
        let outcome = profile
            .admit_id_jag_response(
                EnterpriseTokenResponse {
                    status: response.status,
                    headers: &response.headers,
                    body: &response.body,
                },
                id_jag_keys,
                idp_tenant,
                resource_tenant,
                self.inner.response_policy,
                clock.wall_now()?,
            )
            .map_err(EnterpriseExchangeError::ResponseRejected)?;
        reservation.check().map_err(map_reservation_error)?;
        let outcome = match outcome {
            EnterpriseResponseOutcome::Success { value, cache } => {
                let expires_at_monotonic = clock.deadline(value.effective_expires_at)?;
                if Instant::now() >= expires_at_monotonic {
                    return Err(EnterpriseExchangeError::TimedOut);
                }
                EnterpriseResponseOutcome::Success {
                    value: EnterpriseExchangedIdJag {
                        response: value,
                        reservation,
                        expires_at_monotonic,
                    },
                    cache,
                }
            }
            EnterpriseResponseOutcome::Denied { denial, cache } => {
                EnterpriseResponseOutcome::Denied { denial, cache }
            }
            EnterpriseResponseOutcome::StepUpRequired { requirement, cache } => {
                EnterpriseResponseOutcome::StepUpRequired { requirement, cache }
            }
        };
        Ok((outcome, observation))
    }

    /// Stage 2 (RFC 7523): consumes the first-stage exchange's sealed ID-JAG
    /// owner at the Resource AS for a resource-bound final MCP access token.
    ///
    /// The closed JWT-bearer form carries only grant_type, assertion and the
    /// registered authentication representation. Its scope/resource authority
    /// remains in the signed assertion and response checks, never extra form
    /// fields. `received_at` is sampled at entry and advanced by elapsed time.
    pub async fn exchange_id_jag_for_access_token(
        &self,
        cx: &Cx,
        exchanged: EnterpriseExchangedIdJag,
        resource_as_client_secret: &EnterpriseClientSecret,
        received_at: SystemTime,
    ) -> Result<
        (
            EnterpriseResponseOutcome<EnterpriseBoundAccessToken>,
            EnterpriseExchangeObservation,
        ),
        EnterpriseExchangeError,
    > {
        let clock = ExchangeClock::new(received_at);
        let admitted = crate::http_auth::caller::with_caller(cx, admit_exchange_caller)?;
        let profile = &self.inner.profile;
        let EnterpriseExchangedIdJag {
            response: id_jag,
            reservation,
            expires_at_monotonic,
        } = exchanged;
        reservation.check().map_err(map_reservation_error)?;
        if id_jag.profile != *profile || id_jag.policy != self.inner.response_policy {
            return Err(EnterpriseExchangeError::ResponseRejected(
                EnterpriseResponseError::PolicyBindingMismatch,
            ));
        }
        let input_deadline = clock
            .input_deadline(id_jag.received_at, id_jag.effective_expires_at)?
            .min(expires_at_monotonic);
        if Instant::now() >= input_deadline {
            return Err(EnterpriseExchangeError::TimedOut);
        }
        let permit = Arc::new(ExchangePermit::acquire(Arc::clone(&self.inner.busy))?);
        let mut fields: Vec<(&str, &str)> = vec![
            ("grant_type", JWT_BEARER_GRANT),
            ("assertion", id_jag.compact_assertion.as_str()),
        ];
        let request = build_confidential_token_request(
            profile.resource_as_authentication(),
            profile.resource_as_client_id(),
            resource_as_client_secret.as_str(),
            &mut fields,
        )?;
        let response = self
            .dispatch_post(
                &admitted,
                &self.inner.resource_as_token_url,
                &request,
                input_deadline,
                Arc::clone(&permit),
                || reservation.check().map_err(map_reservation_error),
            )
            .await?;
        let observation = EnterpriseExchangeObservation {
            endpoint: profile.resource_as_token_endpoint().to_owned(),
            provenance: response.provenance,
        };
        let received_at = clock.wall_now()?;
        let outcome = id_jag
            .admit_access_token_response(
                EnterpriseTokenResponse {
                    status: response.status,
                    headers: &response.headers,
                    body: &response.body,
                },
                received_at,
            )
            .map_err(EnterpriseExchangeError::ResponseRejected)?;
        reservation.check().map_err(map_reservation_error)?;
        let mapped = match outcome {
            EnterpriseResponseOutcome::Success { value, cache } => {
                let expires_at_monotonic = clock.deadline(value.expires_at)?;
                if Instant::now() >= expires_at_monotonic {
                    return Err(EnterpriseExchangeError::TimedOut);
                }
                EnterpriseResponseOutcome::Success {
                    value: EnterpriseBoundAccessToken {
                        response: value,
                        reservation,
                        received_at: clock.wall,
                        expires_at_monotonic,
                    },
                    cache,
                }
            }
            EnterpriseResponseOutcome::Denied { denial, cache } => {
                EnterpriseResponseOutcome::Denied { denial, cache }
            }
            EnterpriseResponseOutcome::StepUpRequired { requirement, cache } => {
                EnterpriseResponseOutcome::StepUpRequired { requirement, cache }
            }
        };
        Ok((mapped, observation))
    }

    async fn dispatch_post(
        &self,
        cx: &Cx,
        url: &GuardedHttpsUrl,
        request: &GuardedHttpRequest,
        input_deadline: Instant,
        permit: Arc<ExchangePermit>,
        check_reservation: impl Fn() -> Result<(), EnterpriseExchangeError>,
    ) -> Result<GuardedHttpFetchResponse, EnterpriseExchangeError> {
        let admitted = crate::http_auth::caller::with_caller(cx, admit_exchange_caller)?;
        let response = CallerContextFuture::new(&admitted, async {
            let started = Instant::now();
            let remaining = input_deadline
                .checked_duration_since(started)
                .filter(|remaining| !remaining.is_zero())
                .ok_or(EnterpriseExchangeError::TimedOut)?;
            let timeout = self.inner.fetcher.policy().deadline().min(remaining);
            let nanos = u64::try_from(timeout.as_nanos())
                .map_err(|_| EnterpriseExchangeError::InvalidPolicy)?;
            let deadline = admitted.now().saturating_add_nanos(nanos);
            let deadline = admitted
                .budget()
                .deadline
                .map_or(deadline, |limit| limit.min(deadline));
            let mut timer = std::pin::pin!(Sleep::new(deadline));
            let (_sender, mut receiver) = oneshot::channel::<()>();
            let mut cancelled = std::pin::pin!(receiver.recv(&admitted));
            let mut call = std::pin::pin!(async {
                self.send_post(&admitted, url, request, permit.clone())
                    .await
            });
            poll_fn(|task| {
                check_reservation()?;
                exchange_checkpoint(&admitted, deadline, started, timeout)?;
                if cancelled.as_mut().poll(task).is_ready() {
                    return Poll::Ready(Err(EnterpriseExchangeError::Cancelled));
                }
                if timer.as_mut().poll(task).is_ready() {
                    exchange_checkpoint(&admitted, deadline, started, timeout)?;
                    return Poll::Ready(Err(EnterpriseExchangeError::TimedOut));
                }
                let res = call.as_mut().poll(task);
                check_reservation()?;
                exchange_checkpoint(&admitted, deadline, started, timeout)?;
                res
            })
            .await
        })
        .await?;

        if response.redirect.is_some() {
            return Err(EnterpriseExchangeError::RedirectRefused);
        }
        if response.body.len() > self.inner.fetcher.policy().response_body_bytes()
            || response.body.len() > MAX_ENTERPRISE_EXCHANGE_RESPONSE_BYTES
        {
            return Err(EnterpriseExchangeError::ResponseRejected(
                EnterpriseResponseError::InvalidResponse,
            ));
        }
        verify_exchange_provenance(&response.provenance, url, &self.inner.fetcher)?;
        Ok(response)
    }

    async fn send_post(
        &self,
        cx: &Cx,
        url: &GuardedHttpsUrl,
        request: &GuardedHttpRequest,
        lifetime: Arc<dyn Send + Sync>,
    ) -> Result<GuardedHttpFetchResponse, EnterpriseExchangeError> {
        #[cfg(test)]
        if let Some(poster) = &self.inner.test_post {
            return poster
                .post(cx, url, request, lifetime)
                .await
                .map_err(map_exchange_fetch_error);
        }
        Box::pin(
            self.inner
                .fetcher
                .post_with_lifetime(cx, url, request, lifetime),
        )
        .await
        .map_err(map_exchange_fetch_error)
    }
}

/// One trusted wall sample advances with monotonic elapsed time. Caller time
/// selects admission; it cannot freeze a signed lifetime across slow I/O or
/// restart the final bearer lifetime when the credential is later installed.
struct ExchangeClock {
    wall: SystemTime,
    monotonic: Instant,
}

impl ExchangeClock {
    fn new(wall: SystemTime) -> Self {
        Self {
            wall,
            monotonic: Instant::now(),
        }
    }

    fn wall_now(&self) -> Result<SystemTime, EnterpriseExchangeError> {
        self.wall.checked_add(self.monotonic.elapsed()).ok_or(
            EnterpriseExchangeError::ResponseRejected(EnterpriseResponseError::InvalidLifetime),
        )
    }

    fn deadline(&self, expires_at: SystemTime) -> Result<Instant, EnterpriseExchangeError> {
        let remaining = expires_at.duration_since(self.wall).map_err(|_| {
            EnterpriseExchangeError::ResponseRejected(EnterpriseResponseError::InvalidLifetime)
        })?;
        self.monotonic
            .checked_add(remaining)
            .ok_or(EnterpriseExchangeError::ResponseRejected(
                EnterpriseResponseError::InvalidLifetime,
            ))
    }

    fn input_deadline(
        &self,
        admitted_at: SystemTime,
        expires_at: SystemTime,
    ) -> Result<Instant, EnterpriseExchangeError> {
        if self.wall < admitted_at || self.wall >= expires_at {
            return Err(EnterpriseExchangeError::ResponseRejected(
                EnterpriseResponseError::InvalidLifetime,
            ));
        }
        self.deadline(expires_at)
    }
}

fn matches_tenant(tenant: Option<&str>, expected: TenantExpectation<'_>) -> bool {
    match expected {
        TenantExpectation::SingleTenant => tenant.is_none(),
        TenantExpectation::Exact(expected) => tenant == Some(expected),
    }
}

impl fmt::Debug for EnterpriseExchangeDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnterpriseExchangeDriver")
            .finish_non_exhaustive()
    }
}

struct ExchangePermit(Arc<AtomicBool>);

impl ExchangePermit {
    fn acquire(busy: Arc<AtomicBool>) -> Result<Self, EnterpriseExchangeError> {
        busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| EnterpriseExchangeError::ExchangeInProgress)?;
        Ok(Self(busy))
    }
}

impl Drop for ExchangePermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn admit_exchange_caller() -> Result<Cx, EnterpriseExchangeError> {
    let current = Cx::current().ok_or(EnterpriseExchangeError::RuntimeUnavailable)?;
    if current.checkpoint().is_err() {
        return Err(EnterpriseExchangeError::Cancelled);
    }
    let caps = current.capabilities();
    if !caps.io || !caps.time || !caps.spawn || current.timer_driver().is_none() {
        return Err(EnterpriseExchangeError::RuntimeUnavailable);
    }
    if current
        .budget()
        .deadline
        .is_some_and(|limit| current.now() >= limit)
    {
        return Err(EnterpriseExchangeError::TimedOut);
    }
    Ok(current)
}

fn exchange_checkpoint(
    admitted: &Cx,
    deadline: Time,
    started: Instant,
    timeout: Duration,
) -> Result<(), EnterpriseExchangeError> {
    let current = admit_exchange_caller()?;
    let held = admitted.capabilities();
    let active = current.capabilities();
    if (held.entropy && !active.entropy) || (held.remote && !active.remote) {
        return Err(EnterpriseExchangeError::RuntimeUnavailable);
    }
    if current.now() >= deadline || started.elapsed() >= timeout {
        return Err(EnterpriseExchangeError::TimedOut);
    }
    Ok(())
}

fn map_exchange_fetch_error(error: GuardedHttpFetchError) -> EnterpriseExchangeError {
    match error {
        GuardedHttpFetchError::Cancelled => EnterpriseExchangeError::Cancelled,
        GuardedHttpFetchError::DeadlineExceeded => EnterpriseExchangeError::TimedOut,
        _ => EnterpriseExchangeError::TransportFailed,
    }
}

fn map_reservation_error(error: IdentityAssertionReplayError) -> EnterpriseExchangeError {
    match error {
        IdentityAssertionReplayError::InvalidAssertion => {
            EnterpriseExchangeError::ResponseRejected(
                EnterpriseResponseError::PolicyBindingMismatch,
            )
        }
        _ => EnterpriseExchangeError::ReservationRejected,
    }
}

fn verify_exchange_provenance(
    peer: &GuardedHttpPeerProvenance,
    url: &GuardedHttpsUrl,
    fetcher: &GuardedHttpFetcher,
) -> Result<(), EnterpriseExchangeError> {
    if peer.host != url.host()
        || peer.selected_address.port() != url.port()
        || peer.root_policy_revision != fetcher.root_identity()
        || peer.alpn.as_deref().is_some_and(|alpn| alpn != b"http/1.1")
        || peer.tls_protocol.as_deref().is_some_and(|protocol| {
            protocol.is_empty()
                || protocol.len() > 64
                || !protocol.is_ascii()
                || protocol.chars().any(char::is_control)
        })
    {
        return Err(EnterpriseExchangeError::EvidenceMismatch);
    }
    Ok(())
}

fn encode_form_component(value: &str) -> SecretString {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    // Pre-size for worst-case percent-encoding so secret bytes never leave
    // unzeroized copies in an abandoned heap buffer after a reallocation.
    let mut encoded = String::with_capacity(value.len().saturating_mul(3));
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            b' ' => encoded.push('+'),
            _ => {
                encoded.push('%');
                encoded.push(char::from(HEX[usize::from(byte >> 4)]));
                encoded.push(char::from(HEX[usize::from(byte & 15)]));
            }
        }
    }
    SecretString::from_string(encoded)
}

pub(super) fn build_confidential_token_request<'a>(
    auth: EnterpriseClientAuthentication,
    client_id: &'a str,
    client_secret: &'a str,
    fields: &mut Vec<(&str, &'a str)>,
) -> Result<GuardedHttpRequest, EnterpriseExchangeError> {
    let basic_header = match auth {
        EnterpriseClientAuthentication::ClientSecretBasic => {
            let encoded_id = encode_form_component(client_id);
            let encoded_secret = encode_form_component(client_secret);
            let header = H1Request::post("/")
                .basic_auth(encoded_id.as_str(), Some(encoded_secret.as_str()))
                .build()
                .headers
                .into_iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .map(|(_, value)| value)
                .ok_or(EnterpriseExchangeError::EncodingFailed)?;
            Some(SecretString::from_string(header))
        }
        EnterpriseClientAuthentication::ClientSecretPost => {
            fields.push(("client_id", client_id));
            fields.push(("client_secret", client_secret));
            None
        }
    };

    let mut encoded_fields = Vec::with_capacity(fields.len());
    let mut total_len = 0usize;
    for (index, (name, value)) in fields.iter().enumerate() {
        let encoded_name = encode_form_component(name);
        let encoded_value = encode_form_component(value);
        let sep = usize::from(index != 0);
        total_len = total_len
            .saturating_add(sep)
            .saturating_add(encoded_name.as_str().len())
            .saturating_add(1)
            .saturating_add(encoded_value.as_str().len());
        if total_len > MAX_ENTERPRISE_EXCHANGE_FORM_BYTES {
            return Err(EnterpriseExchangeError::EncodingFailed);
        }
        encoded_fields.push((encoded_name, encoded_value));
    }
    // Exact capacity prevents reallocating secret-bearing form bytes.
    let mut body_text = String::with_capacity(total_len);
    for (index, (encoded_name, encoded_value)) in encoded_fields.iter().enumerate() {
        if index != 0 {
            body_text.push('&');
        }
        body_text.push_str(encoded_name.as_str());
        body_text.push('=');
        body_text.push_str(encoded_value.as_str());
    }
    let body_secret = SecretString::from_string(body_text);
    let mut request = GuardedHttpRequest::new(
        "application/x-www-form-urlencoded",
        body_secret.as_str().as_bytes().to_vec(),
    )
    .map_err(|_| EnterpriseExchangeError::EncodingFailed)?;
    if let Some(header) = basic_header {
        request = request
            .with_authorization(header.as_str())
            .map_err(|_| EnterpriseExchangeError::EncodingFailed)?;
    }
    Ok(request)
}
