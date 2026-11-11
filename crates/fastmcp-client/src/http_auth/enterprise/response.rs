//! Composed admission of OIDC, ID-JAG and final enterprise token responses.
//!
//! These bounded synchronous operations validate already-received responses.
//! They do not fetch keys, send credentials, activate EMA or issue flow, custody,
//! subject-mapping or replay receipts. Embeddings run signature verification on
//! their caller-owned bounded CPU lane. Callers must erase confidential transport
//! buffers; admitted compact tokens have private zeroizing custody.

mod wire;
#[cfg(test)]
mod tests;

use std::fmt;
use std::time::{Duration, SystemTime};

use asupersync::security::SecretString;
use fastmcp_core::AccessToken;

use super::policy::{EnterpriseClientAuthentication, EnterpriseProfile, IdJagGrantedScopeSet};
use super::verification::{
    IdJagExpectations, IdJagVerificationKeys, JwtTimePolicy, OidcIdTokenExpectations,
    OidcVerificationKeys, ResourceTenantExpectation, TenantExpectation,
    VerifiedIdJag, VerifiedOidcIdToken, verify_id_jag, verify_id_jag_with_disclosure,
    verify_oidc_id_token,
};
use super::verification::disclosure::{IdJagDisclosureFacts, IdJagDisclosurePolicy};

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
            Self::PolicyBindingMismatch => "enterprise assertion key authority differs from the selected profile",
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
    pub const fn code(self) -> EnterpriseOAuthErrorCode { self.code }
    pub const fn status(self) -> u16 { self.status }
    /// Distinguishes the matching Basic/401 rule from the OIDC/400 variant.
    pub const fn matched_basic_challenge(self) -> bool { self.basic_challenge }
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
    Success { value: T, cache: EnterpriseCacheDiagnostics },
    Denied { denial: EnterpriseOAuthDenial, cache: EnterpriseCacheDiagnostics },
    StepUpRequired { requirement: EnterpriseStepUpRequired, cache: EnterpriseCacheDiagnostics },
}

/// Immutable finite bounds for local response validation.
#[derive(Clone, Copy, Debug)]
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
        if id_token_lifetime.is_zero() || id_token_lifetime > Duration::from_hours(24)
            || id_jag_lifetime.is_zero() || id_jag_lifetime > Duration::from_mins(15)
            || access_token_lifetime.is_zero() || access_token_lifetime > Duration::from_hours(24)
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
            id_token_lifetime, id_jag_lifetime, access_token_lifetime,
            clock_skew, maximum_step_up_age,
        })
    }
}

/// Locally verified identity facts and exclusive zeroizing assertion custody.
/// This is not the sealed authorization-code-flow receipt needed for exchange
/// activation; there is no compact-token getter or credential conversion.
pub struct EnterpriseIdentityAssertion {
    _assertion: SecretString,
    identity: VerifiedOidcIdToken,
}
impl EnterpriseIdentityAssertion {
    pub fn identity(&self) -> &VerifiedOidcIdToken { &self.identity }
}

/// The signed ID-JAG, original request, IdP scope grant and earliest effective
/// expiry stay coupled. Local ownership is not resource-AS replay prevention.
pub struct EnterpriseIdJagResponse {
    _assertion: SecretString,
    assertion: VerifiedIdJag,
    requested_scopes: Vec<String>,
    granted_scopes: IdJagGrantedScopeSet,
    resource: String,
    received_at: SystemTime,
    effective_expires_at: SystemTime,
    policy: EnterpriseResponsePolicy,
    used_basic: bool,
}
impl EnterpriseIdJagResponse {
    pub fn assertion(&self) -> &VerifiedIdJag { &self.assertion }
    pub fn requested_scopes(&self) -> &[String] { &self.requested_scopes }
    pub fn granted_scopes(&self) -> &[String] { self.granted_scopes.as_slice() }
    pub fn effective_expires_at(&self) -> SystemTime { self.effective_expires_at }

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
    ) -> Result<EnterpriseResponseOutcome<EnterpriseAccessTokenResponse>, EnterpriseResponseError> {
        if received_at < self.received_at || received_at >= self.effective_expires_at {
            return Err(EnterpriseResponseError::InvalidLifetime);
        }
        let (body, cache) = wire::admit(
            &response, EnterpriseTokenResponseStage::AccessToken,
            self.used_basic, self.policy.maximum_step_up_age.as_secs(),
        )?;
        let wire::AdmittedBody::Success(body) = body else {
            return terminal(body, cache);
        };
        if body.resource.as_deref() != Some(self.resource.as_str()) {
            return Err(EnterpriseResponseError::PolicyBindingMismatch);
        }
        let granted_scopes = self.granted_scopes.admit_access_grant(body.scope.as_deref())
            .map_err(|_| EnterpriseResponseError::ScopeRejected)?;
        let mut expires_at = bounded_expiry(
            received_at, body.expires_in, 86_400, self.policy.access_token_lifetime, None,
        )?;
        let id_jag_disclosure = self.assertion.disclosure().cloned();
        if let Some(disclosure) = &id_jag_disclosure {
            expires_at = expires_at.min(disclosure.review_expires_at());
        }
        let token = body.access_token.ok_or(EnterpriseResponseError::InvalidResponse)?;
        if !AccessToken::is_valid_token68(token.as_str()) {
            return Err(EnterpriseResponseError::InvalidResponse);
        }
        Ok(EnterpriseResponseOutcome::Success {
            value: EnterpriseAccessTokenResponse {
                _access_token: token, resource: self.resource,
                requested_scopes: self.requested_scopes,
                idp_granted_scopes: self.granted_scopes.as_slice().to_vec(),
                granted_scopes, expires_at, id_jag_disclosure,
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
    _access_token: SecretString,
    resource: String,
    requested_scopes: Vec<String>,
    idp_granted_scopes: Vec<String>,
    granted_scopes: Vec<String>,
    expires_at: SystemTime,
    id_jag_disclosure: Option<IdJagDisclosureFacts>,
}
impl EnterpriseAccessTokenResponse {
    pub fn resource(&self) -> &str { &self.resource }
    pub fn requested_scopes(&self) -> &[String] { &self.requested_scopes }
    pub fn idp_granted_scopes(&self) -> &[String] { &self.idp_granted_scopes }
    pub fn granted_scopes(&self) -> &[String] { &self.granted_scopes }
    pub fn expires_at(&self) -> SystemTime { self.expires_at }
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
    ) -> Result<EnterpriseResponseOutcome<EnterpriseIdentityAssertion>, EnterpriseResponseError> {
        if keys.issuer() != self.idp_issuer() || keys.generation() != self.oidc_key_generation() {
            return Err(EnterpriseResponseError::PolicyBindingMismatch);
        }
        let (body, cache) = wire::admit(
            &response, EnterpriseTokenResponseStage::OidcCode,
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
        let access = body.access_token.ok_or(EnterpriseResponseError::InvalidResponse)?;
        if !AccessToken::is_valid_token68(access.as_str()) {
            return Err(EnterpriseResponseError::InvalidResponse);
        }
        let assertion = body.id_token.ok_or(EnterpriseResponseError::InvalidResponse)?;
        let expected = OidcIdTokenExpectations {
            client_id: self.idp_client_id(), nonce, access_token: Some(access.as_str()), tenant,
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
            value: EnterpriseIdentityAssertion { _assertion: assertion, identity }, cache,
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
            response, keys, idp_tenant, resource_tenant, policy, None, received_at,
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
            response, keys, idp_tenant, resource_tenant, policy, Some(disclosure), received_at,
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
            &response, EnterpriseTokenResponseStage::IdJag,
            self.idp_authentication() == EnterpriseClientAuthentication::ClientSecretBasic,
            policy.maximum_step_up_age.as_secs(),
        )?;
        let wire::AdmittedBody::Success(body) = body else {
            return terminal(body, cache);
        };
        let compact = body.access_token.ok_or(EnterpriseResponseError::InvalidResponse)?;
        let expected = IdJagExpectations {
            audience: self.resource_as_issuer(), client_id: self.resource_as_client_id(),
            resource: self.resource().as_str(), require_resource: true, idp_tenant, resource_tenant,
            time: JwtTimePolicy::new(policy.id_jag_lifetime, policy.clock_skew)
                .map_err(|_| EnterpriseResponseError::InvalidPolicy)?,
        };
        let assertion = match disclosure {
            Some(disclosure) => verify_id_jag_with_disclosure(
                compact.as_str(), keys, &expected, disclosure, received_at,
            ),
            None => verify_id_jag(compact.as_str(), keys, &expected, received_at),
        }.map_err(|_| EnterpriseResponseError::AssertionRejected)?;
        let granted_scopes = self.requested_scopes()
            .admit_id_jag_grant(body.scope.as_deref(), assertion.scope())
            .map_err(|_| EnterpriseResponseError::ScopeRejected)?;
        let mut effective_expires_at = bounded_expiry(
            received_at, body.expires_in, 900, policy.id_jag_lifetime, Some(assertion.expires_at()),
        )?;
        if let Some(disclosure) = assertion.disclosure() {
            effective_expires_at = effective_expires_at.min(disclosure.review_expires_at());
        }
        Ok(EnterpriseResponseOutcome::Success {
            value: EnterpriseIdJagResponse {
                _assertion: compact, assertion,
                requested_scopes: self.requested_scopes().as_slice().to_vec(),
                granted_scopes, resource: self.resource().as_str().to_owned(), received_at,
                effective_expires_at, policy,
                used_basic: self.resource_as_authentication() == EnterpriseClientAuthentication::ClientSecretBasic,
            },
            cache,
        })
    }
}

fn terminal<T>(
    body: wire::AdmittedBody, cache: EnterpriseCacheDiagnostics,
) -> Result<EnterpriseResponseOutcome<T>, EnterpriseResponseError> {
    match body {
        wire::AdmittedBody::Denied(denial) => Ok(EnterpriseResponseOutcome::Denied { denial, cache }),
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
    let mut expires_at = received_at.checked_add(local_cap)
        .ok_or(EnterpriseResponseError::InvalidLifetime)?;
    if let Some(seconds) = response_seconds {
        expires_at = expires_at.min(received_at.checked_add(Duration::from_secs(seconds))
            .ok_or(EnterpriseResponseError::InvalidLifetime)?);
    }
    if let Some(signed) = signed_expiry { expires_at = expires_at.min(signed); }
    if expires_at <= received_at { return Err(EnterpriseResponseError::InvalidLifetime); }
    Ok(expires_at)
}
