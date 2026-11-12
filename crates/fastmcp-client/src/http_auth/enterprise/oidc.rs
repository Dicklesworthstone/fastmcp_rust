//! Local, single-owner OIDC code-flow request and callback codecs.
//!
//! This module joins preregistered OIDC discovery, independent state/nonce/PKCE
//! generation, an exact authorization GET, callback admission, confidential
//! code-form serialization, and the signed token-response validator. It does
//! not launch a browser, perform HTTP, or create deployment/dispatch receipts.
//! Its in-memory owners are not the durable pending-flow store required for
//! enterprise activation. An embedding must separately provide the attested
//! browser, persistent custody, replay and identity authorities before using
//! these codecs in an operational enterprise authorization flow.
//! HTTPS checks here admit URL syntax only. Public-address/DNS/SSRF and origin
//! authorization still belong to the independently guarded adapter and transport.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Write;
use std::time::{Duration, SystemTime};

use asupersync::Cx;
use asupersync::security::SecretString;
use fastmcp_core::{AbsoluteUri, CanonicalHttpUrl};
use fastmcp_core::crypto::{draw_security_identifier, sha256_bounded};
use fastmcp_protocol::security_admission::{SecurityDocumentKind, admit_security_document};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use super::identity::{
    EnterpriseOidcRelyingPartyConfiguration, EnterpriseOidcSubjectType,
    OidcSectorDocumentReview, OidcSectorRegistrationRole, OidcSubjectNamespace,
};
use super::policy::{EnterpriseProfile, RequestedEnterpriseScopeSet, TOKEN_EXCHANGE_GRANT};
use super::response::{
    EnterpriseIdentityAssertion, EnterpriseResponseOutcome, EnterpriseResponsePolicy,
    EnterpriseTokenResponse,
};
use super::verification::{OidcVerificationKeys, TenantExpectation};

#[cfg(test)]
mod tests;

const MAX_URL_BYTES: usize = 4096;
const MAX_LAUNCH_BYTES: usize = 32 * 1024;
const MAX_CALLBACK_BYTES: usize = 16 * 1024;
const MAX_CALLBACK_FIELDS: usize = 32;
const MAX_FIELD_BYTES: usize = 4096;
const MAX_CODE_FORM_BYTES: usize = 32 * 1024;
const MAX_FLOW_LIFETIME: Duration = Duration::from_mins(15);

/// Fixed errors retain no callback, authorization URL, code, nonce or peer text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcCodeFlowError {
    InvalidConfiguration,
    InvalidMetadata,
    InvalidRegistration,
    UnsupportedSubjectNamespace,
    CapabilityUnavailable,
    Cancelled,
    RandomSourceUnavailable,
    InvalidLifetime,
    CallbackRejected,
    IssuerMismatch,
    EncodingFailed,
    TokenResponseRejected,
}

impl fmt::Display for OidcCodeFlowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid enterprise OIDC code-flow configuration",
            Self::InvalidMetadata => "enterprise OIDC metadata does not admit this code flow",
            Self::InvalidRegistration => "enterprise OIDC preregistration does not admit this code flow",
            Self::UnsupportedSubjectNamespace => "enterprise OIDC subject namespace is unsupported",
            Self::CapabilityUnavailable => "enterprise OIDC requires caller time and entropy authority",
            Self::Cancelled => "enterprise OIDC code flow was cancelled",
            Self::RandomSourceUnavailable => "enterprise OIDC security randomness is unavailable",
            Self::InvalidLifetime => "enterprise OIDC code flow is expired or has an invalid lifetime",
            Self::CallbackRejected => "enterprise OIDC callback was refused",
            Self::IssuerMismatch => "enterprise OIDC callback issuer does not match its registration",
            Self::EncodingFailed => "enterprise OIDC confidential form serialization failed",
            Self::TokenResponseRejected => "enterprise OIDC signed token response was refused",
        })
    }
}

impl std::error::Error for OidcCodeFlowError {}

#[derive(Clone)]
enum ConfiguredTenant {
    SingleTenant,
    Exact(String),
}

impl ConfiguredTenant {
    fn expectation(&self) -> TenantExpectation<'_> {
        match self {
            Self::SingleTenant => TenantExpectation::SingleTenant,
            Self::Exact(value) => TenantExpectation::Exact(value),
        }
    }
}

/// Immutable local code-flow policy. It contains no credential or pending flow.
///
/// Metadata and preregistration are trusted inputs, not fetched provenance.
/// Public and redirect-host pairwise subject namespaces use local admission.
/// An explicit sector_identifier_uri requires the separately completed guarded
/// review supplied to Self::from_documents_with_sector_review. The resulting
/// namespace retains that exact review digest without refetching its document.
#[derive(Clone)]
pub struct OidcCodeFlowConfiguration {
    profile: EnterpriseProfile,
    authorization_endpoint: CanonicalHttpUrl,
    redirect_uri: String,
    subject_namespace: OidcSubjectNamespace,
    tenant: ConfiguredTenant,
    require_callback_issuer: bool,
    metadata_digest: [u8; 32],
    registration_digest: [u8; 32],
    response_policy: EnterpriseResponsePolicy,
    maximum_authentication_age: Option<Duration>,
}

impl OidcCodeFlowConfiguration {
    /// Admits the exact OIDC code-flow intersection independently of the later
    /// MCP scope request. All required metadata arrays are explicit, including
    /// openid, query, S256, authorization-code and the selected secret method.
    /// The preregistration is one web/code client with one exact HTTPS callback.
    /// Tenancy is selected here, before any generated request or assertion.
    pub fn from_documents(
        profile: EnterpriseProfile,
        redirect_uri: &str,
        subject_type: EnterpriseOidcSubjectType,
        tenant: TenantExpectation<'_>,
        idp_metadata: &[u8],
        idp_registration: &[u8],
    ) -> Result<Self, OidcCodeFlowError> {
        Self::admit_documents(
            profile, redirect_uri, subject_type, tenant,
            idp_metadata, idp_registration, None,
        )
    }

    /// Admits a pairwise code flow against an already fetched sector review.
    ///
    /// The selected callback must be one of the complete preregistered redirect
    /// set frozen in the review. Additional entries in the remote document do
    /// not authorize callbacks. Issuer, client, tenant, Client role, generation
    /// and exact sector URL must match; this constructor performs no network I/O.
    pub fn from_documents_with_sector_review(
        profile: EnterpriseProfile,
        redirect_uri: &str,
        tenant: TenantExpectation<'_>,
        idp_metadata: &[u8],
        idp_registration: &[u8],
        sector_review: &OidcSectorDocumentReview,
    ) -> Result<Self, OidcCodeFlowError> {
        Self::admit_documents(
            profile, redirect_uri, EnterpriseOidcSubjectType::Pairwise, tenant,
            idp_metadata, idp_registration, Some(sector_review),
        )
    }

    fn admit_documents(
        profile: EnterpriseProfile,
        redirect_uri: &str,
        subject_type: EnterpriseOidcSubjectType,
        tenant: TenantExpectation<'_>,
        idp_metadata: &[u8],
        idp_registration: &[u8],
        sector_review: Option<&OidcSectorDocumentReview>,
    ) -> Result<Self, OidcCodeFlowError> {
        let metadata = document(SecurityDocumentKind::OidcProviderMetadata, idp_metadata)?;
        let registration = document(SecurityDocumentKind::ClientRegistration, idp_registration)?;
        let authorization_endpoint = https_url(profile.idp_authorization_endpoint(), true)?;
        https_url(profile.idp_token_endpoint(), true)?;
        https_url(profile.oidc_jwks_uri(), false)?;
        https_url(redirect_uri, true)?;

        for (name, expected) in [
            ("issuer", profile.idp_issuer()),
            ("authorization_endpoint", profile.idp_authorization_endpoint()),
            ("token_endpoint", profile.idp_token_endpoint()),
            ("jwks_uri", profile.oidc_jwks_uri()),
        ] {
            if string(&metadata, name)? != expected {
                return Err(OidcCodeFlowError::InvalidMetadata);
            }
        }
        let subject_name = match subject_type {
            EnterpriseOidcSubjectType::Public => "public",
            EnterpriseOidcSubjectType::Pairwise => "pairwise",
        };
        for (name, required) in [
            ("response_types_supported", "code"),
            ("response_modes_supported", "query"),
            ("code_challenge_methods_supported", "S256"),
            ("scopes_supported", "openid"),
            ("subject_types_supported", subject_name),
            ("id_token_signing_alg_values_supported", "RS256"),
            ("token_endpoint_auth_methods_supported", profile.idp_authentication().as_str()),
        ] {
            if !array(&metadata, name)?.contains(&required) {
                return Err(OidcCodeFlowError::InvalidMetadata);
            }
        }
        let grants = array(&metadata, "grant_types_supported")?;
        if !grants.contains(&"authorization_code") || !grants.contains(&TOKEN_EXCHANGE_GRANT) {
            return Err(OidcCodeFlowError::InvalidMetadata);
        }
        if !profile.permits_oidc_openid() {
            return Err(OidcCodeFlowError::InvalidConfiguration);
        }
        let require_callback_issuer = match metadata.get("authorization_response_iss_parameter_supported") {
            None => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => return Err(OidcCodeFlowError::InvalidMetadata),
        };
        for (name, expected) in [
            ("issuer", profile.idp_issuer()),
            ("token_endpoint", profile.idp_token_endpoint()),
            ("client_id", profile.idp_client_id()),
            ("application_type", "web"),
            ("subject_type", subject_name),
            ("token_endpoint_auth_method", profile.idp_authentication().as_str()),
        ] {
            if string(&registration, name)? != expected {
                return Err(OidcCodeFlowError::InvalidRegistration);
            }
        }
        let registered_redirects = array(&registration, "redirect_uris")?;
        if array(&registration, "response_types")? != ["code"]
            || if sector_review.is_some() {
                !registered_redirects.contains(&redirect_uri)
            } else {
                registered_redirects != [redirect_uri]
            }
        {
            return Err(OidcCodeFlowError::InvalidRegistration);
        }
        let mut grants = array(&registration, "grant_types")?;
        grants.sort_unstable();
        let mut required_grants = ["authorization_code", TOKEN_EXCHANGE_GRANT];
        required_grants.sort_unstable();
        if grants != required_grants
            || registration.contains_key("id_token_encrypted_response_alg")
            || registration.contains_key("id_token_encrypted_response_enc")
            || registration.get("id_token_signed_response_alg")
                .is_some_and(|value| value.as_str() != Some("RS256"))
        {
            return Err(OidcCodeFlowError::InvalidRegistration);
        }
        if let Some(scope) = registration.get("scope") {
            let scope = scope.as_str().ok_or(OidcCodeFlowError::InvalidRegistration)?;
            let admitted = RequestedEnterpriseScopeSet::from_literals(scope.split(' ').map(str::to_owned))
                .map_err(|_| OidcCodeFlowError::InvalidRegistration)?;
            if !admitted.as_slice().iter().any(|scope| scope == "openid") {
                return Err(OidcCodeFlowError::InvalidRegistration);
            }
        }
        let tenant = match tenant {
            TenantExpectation::SingleTenant => ConfiguredTenant::SingleTenant,
            TenantExpectation::Exact(value) => {
                if value.is_empty() || value.len() > 256 || value.trim() != value
                    || value.chars().any(char::is_control)
                {
                    return Err(OidcCodeFlowError::InvalidConfiguration);
                }
                ConfiguredTenant::Exact(value.to_owned())
            }
        };
        let subject_namespace = if let Some(review) = sector_review {
            if string(&registration, "sector_identifier_uri")? != review.sector_identifier_uri() {
                return Err(OidcCodeFlowError::UnsupportedSubjectNamespace);
            }
            let relying_party = EnterpriseOidcRelyingPartyConfiguration {
                issuer: profile.idp_issuer().to_owned(),
                tenant: match &tenant {
                    ConfiguredTenant::SingleTenant => None,
                    ConfiguredTenant::Exact(value) => Some(value.clone()),
                },
                client_id: profile.idp_client_id().to_owned(),
                registration_generation: profile.idp_registration_generation(),
                subject_type,
                redirect_uris: registered_redirects.into_iter().map(str::to_owned).collect(),
            };
            OidcSubjectNamespace::from_reviewed_sector(
                &relying_party, OidcSectorRegistrationRole::Client, review,
            ).map_err(|_| OidcCodeFlowError::UnsupportedSubjectNamespace)?
        } else {
            if registration.contains_key("sector_identifier_uri") {
                return Err(OidcCodeFlowError::UnsupportedSubjectNamespace);
            }
            OidcSubjectNamespace::from_preregistered_redirects(
                profile.idp_issuer(), subject_type, profile.idp_registration_generation(),
                &[redirect_uri.to_owned()],
            ).map_err(|_| OidcCodeFlowError::UnsupportedSubjectNamespace)?
        };
        Ok(Self {
            profile, authorization_endpoint, redirect_uri: redirect_uri.to_owned(),
            subject_namespace, tenant, require_callback_issuer,
            metadata_digest: digest(idp_metadata, SecurityDocumentKind::OidcProviderMetadata.byte_limit())?,
            registration_digest: digest(idp_registration, SecurityDocumentKind::ClientRegistration.byte_limit())?,
            response_policy: EnterpriseResponsePolicy::default(),
            maximum_authentication_age: None,
        })
    }

    /// Fixes response bounds before request generation. This does not append
    /// max_age, prompt, tenant or any other authorization-request parameter.
    pub fn with_response_policy(
        mut self,
        policy: EnterpriseResponsePolicy,
        maximum_authentication_age: Option<Duration>,
    ) -> Result<Self, OidcCodeFlowError> {
        if maximum_authentication_age.is_some_and(|age| {
            age > Duration::from_hours(24) || age.subsec_nanos() != 0
        }) {
            return Err(OidcCodeFlowError::InvalidConfiguration);
        }
        self.response_policy = policy;
        self.maximum_authentication_age = maximum_authentication_age;
        Ok(self)
    }

    pub fn subject_namespace(&self) -> &OidcSubjectNamespace { &self.subject_namespace }
    pub fn metadata_digest(&self) -> &[u8; 32] { &self.metadata_digest }
    pub fn registration_digest(&self) -> &[u8; 32] { &self.registration_digest }
    pub fn requires_callback_issuer(&self) -> bool { self.require_callback_issuer }

    /// Generates three independent 256-bit OS draws under the caller's effect
    /// ceiling. Lifetime is finite and additionally bounded by its Cx budget.
    /// The supplied now is the embedding's trusted wall-clock sample. The Cx
    /// clock is sampled for its remaining deadline; no runtime is created here.
    pub fn prepare(
        &self,
        cx: &Cx,
        now: SystemTime,
        lifetime: Duration,
    ) -> Result<PreparedOidcAuthorization, OidcCodeFlowError> {
        crate::http_auth::caller::with_caller(cx, || {
            let active = Cx::current().ok_or(OidcCodeFlowError::CapabilityUnavailable)?;
            if active.checkpoint().is_err() { return Err(OidcCodeFlowError::Cancelled); }
            if !active.capabilities().entropy || !active.capabilities().time {
                return Err(OidcCodeFlowError::CapabilityUnavailable);
            }
            if lifetime.is_zero() || lifetime > MAX_FLOW_LIFETIME {
                return Err(OidcCodeFlowError::InvalidLifetime);
            }
            let lifetime = if let Some(deadline) = active.budget().deadline {
                let remaining = deadline.as_nanos().checked_sub(active.now().as_nanos())
                    .filter(|remaining| *remaining != 0)
                    .ok_or(OidcCodeFlowError::InvalidLifetime)?;
                lifetime.min(Duration::from_nanos(remaining))
            } else { lifetime };
            let expires_at = now.checked_add(lifetime).ok_or(OidcCodeFlowError::InvalidLifetime)?;
            let state = draw_security_identifier().map_err(|_| OidcCodeFlowError::RandomSourceUnavailable)?;
            let nonce = draw_security_identifier().map_err(|_| OidcCodeFlowError::RandomSourceUnavailable)?;
            let verifier = draw_security_identifier().map_err(|_| OidcCodeFlowError::RandomSourceUnavailable)?;
            let prepared = self.prepare_from_draws(
                state.as_bytes(), nonce.as_bytes(), verifier.as_bytes(), now, expires_at,
            )?;
            if active.checkpoint().is_err() { return Err(OidcCodeFlowError::Cancelled); }
            if active.budget().deadline.is_some_and(|deadline| active.now() >= deadline) {
                return Err(OidcCodeFlowError::InvalidLifetime);
            }
            Ok(prepared)
        })
    }

    fn prepare_from_draws(
        &self,
        state: &[u8; 32],
        nonce: &[u8; 32],
        verifier: &[u8; 32],
        created_at: SystemTime,
        expires_at: SystemTime,
    ) -> Result<PreparedOidcAuthorization, OidcCodeFlowError> {
        let state = base64url32(state);
        let nonce = base64url32(nonce);
        let verifier = base64url32(verifier);
        let challenge = base64url32(&digest(verifier.as_bytes(), 43)?);
        let query = form(&[
            ("response_type", "code"),
            ("client_id", self.profile.idp_client_id()),
            ("redirect_uri", &self.redirect_uri),
            ("scope", "openid"),
            ("state", state.as_str()),
            ("nonce", nonce.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ], MAX_LAUNCH_BYTES)?;
        if self.authorization_endpoint.as_str().len().checked_add(1)
            .and_then(|length| length.checked_add(query.len()))
            .is_none_or(|length| length > MAX_LAUNCH_BYTES)
        {
            return Err(OidcCodeFlowError::EncodingFailed);
        }
        let mut url = ProtectedBuffer::with_capacity(MAX_LAUNCH_BYTES);
        url.push_str(self.authorization_endpoint.as_str());
        url.push('?');
        url.push_str(query.as_str());
        if url.len() > MAX_LAUNCH_BYTES { return Err(OidcCodeFlowError::EncodingFailed); }
        let url = url.finish();
        let mut target = ProtectedBuffer::with_capacity(MAX_LAUNCH_BYTES);
        target.push_str(self.authorization_endpoint.path());
        target.push('?');
        target.push_str(query.as_str());
        let target = target.finish();
        let url_digest = digest(url.as_bytes(), MAX_LAUNCH_BYTES)?;
        let target_digest = digest(target.as_bytes(), MAX_LAUNCH_BYTES)?;
        Ok(PreparedOidcAuthorization {
            configuration: self.clone(), url, target, url_digest, target_digest,
            state, nonce, verifier, created_at, expires_at,
        })
    }
}

/// Exact immutable GET bytes and one private local pending challenge.
///
/// No Clone, Debug or serialization surface exists. Reading these bytes does
/// not prove a browser launch. A durable owner must attach independently
/// verified launch evidence before authorizing an operational callback.
pub struct PreparedOidcAuthorization {
    configuration: OidcCodeFlowConfiguration,
    url: SecretString,
    target: SecretString,
    url_digest: [u8; 32],
    target_digest: [u8; 32],
    state: SecretString,
    nonce: SecretString,
    verifier: SecretString,
    created_at: SystemTime,
    expires_at: SystemTime,
}

impl PreparedOidcAuthorization {
    pub const fn method(&self) -> &'static str { "GET" }
    /// Contains state and nonce. The adapter must not log or persist these bytes.
    pub fn authorization_url(&self) -> &str { self.url.as_str() }
    /// Exact origin-form target derived from that same URL, without re-encoding.
    pub fn request_target(&self) -> &str { self.target.as_str() }
    pub fn authorization_url_digest(&self) -> &[u8; 32] { &self.url_digest }
    pub fn request_target_digest(&self) -> &[u8; 32] { &self.target_digest }
    pub fn expires_at(&self) -> SystemTime { self.expires_at }

    /// Consumes local challenge custody on success, denial and every malformed
    /// callback. The callback URI is the exact registered absolute route followed
    /// by its raw query. No URL normalization can rescue a different route.
    /// This verifies bytes, not callback origin, browser or durable one-use proof.
    pub fn admit_callback(
        self,
        callback_uri: &str,
        received_at: SystemTime,
    ) -> Result<OidcCallbackOutcome, OidcCodeFlowError> {
        live(self.created_at, self.expires_at, received_at)?;
        if callback_uri.len() > MAX_CALLBACK_BYTES
            || callback_uri.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
            || callback_uri.contains('#')
        {
            return Err(OidcCodeFlowError::CallbackRejected);
        }
        let (route, query) = callback_uri.split_once('?').ok_or(OidcCodeFlowError::CallbackRejected)?;
        if route != self.configuration.redirect_uri { return Err(OidcCodeFlowError::CallbackRejected); }
        let mut fields = callback_fields(query)?;
        // An unsolicited iss is still authoritative for mix-up refusal. Check
        // it before interpreting the success or error arm, never only on code.
        match fields.get("iss") {
            Some(issuer) if issuer.as_str() == self.configuration.profile.idp_issuer() => {}
            None if !self.configuration.require_callback_issuer => {}
            _ => return Err(OidcCodeFlowError::IssuerMismatch),
        }
        if fields.get("state") != Some(&self.state) {
            return Err(OidcCodeFlowError::CallbackRejected);
        }
        for name in ["id_token", "access_token", "refresh_token", "token_type", "expires_in", "response_mode", "response_type"] {
            if fields.contains_key(name) { return Err(OidcCodeFlowError::CallbackRejected); }
        }
        match (fields.remove("code"), fields.remove("error")) {
            (Some(code), None) => {
                if !vschar(code.as_str(), MAX_FIELD_BYTES)
                    || fields.contains_key("error_description") || fields.contains_key("error_uri")
                {
                    return Err(OidcCodeFlowError::CallbackRejected);
                }
                Ok(OidcCallbackOutcome::Code(OidcCodeGrant {
                    configuration: self.configuration, code, verifier: self.verifier,
                    nonce: self.nonce, launch_url_digest: self.url_digest,
                    callback_digest: digest(callback_uri.as_bytes(), MAX_CALLBACK_BYTES)?,
                    created_at: received_at, expires_at: self.expires_at,
                }))
            }
            (None, Some(error)) => {
                if !error_text(error.as_str(), 256, true)
                    || fields.get("error_description").is_some_and(|value| !error_text(value.as_str(), 2048, true))
                    || fields.get("error_uri").is_some_and(|value| !error_uri(value.as_str()))
                {
                    return Err(OidcCodeFlowError::CallbackRejected);
                }
                Ok(OidcCallbackOutcome::Denied(authorization_error(error.as_str())))
            }
            _ => Err(OidcCodeFlowError::CallbackRejected),
        }
    }
}

/// Redacted terminal authorization errors. None is a retry or fallback command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcAuthorizationError {
    InvalidRequest, UnauthorizedClient, AccessDenied, UnsupportedResponseType,
    InvalidScope, ServerError, TemporarilyUnavailable, InteractionRequired,
    LoginRequired, AccountSelectionRequired, ConsentRequired, InvalidRequestUri,
    InvalidRequestObject, RequestNotSupported, RequestUriNotSupported,
    RegistrationNotSupported, Extension,
}

#[allow(clippy::large_enum_variant)]
pub enum OidcCallbackOutcome {
    Code(OidcCodeGrant),
    Denied(OidcAuthorizationError),
}

/// Protected code and verifier admitted from one exact local callback.
/// Serialization consumes this owner even when the sink fails partway through.
pub struct OidcCodeGrant {
    configuration: OidcCodeFlowConfiguration,
    code: SecretString,
    verifier: SecretString,
    nonce: SecretString,
    launch_url_digest: [u8; 32],
    callback_digest: [u8; 32],
    created_at: SystemTime,
    expires_at: SystemTime,
}

impl OidcCodeGrant {
    pub fn token_endpoint(&self) -> &str { self.configuration.profile.idp_token_endpoint() }
    pub fn expires_at(&self) -> SystemTime { self.expires_at }

    /// Serializes the closed unauthenticated code form to a confidential sink.
    ///
    /// Emits only grant_type, code, redirect_uri and code_verifier. The caller's
    /// separately admitted confidential-client serializer must add its exact
    /// selected authentication representation. No scope or resource is emitted.
    /// This is a local codec, not a custody-qualified dispatcher: the sink can
    /// observe the code/verifier and must erase its storage on every outcome.
    /// A complete write returns the private nonce-bound response admission owner;
    /// a partial/error write destroys it and cannot restore this code grant.
    pub fn write_token_form(
        self,
        writer: &mut dyn Write,
        now: SystemTime,
    ) -> Result<OidcCodeResponseAdmission, OidcCodeFlowError> {
        live(self.created_at, self.expires_at, now)?;
        let body = form(&[
            ("grant_type", "authorization_code"),
            ("code", self.code.as_str()),
            ("redirect_uri", &self.configuration.redirect_uri),
            ("code_verifier", self.verifier.as_str()),
        ], MAX_CODE_FORM_BYTES)?;
        writer.write_all(body.as_bytes()).map_err(|_| OidcCodeFlowError::EncodingFailed)?;
        Ok(OidcCodeResponseAdmission {
            configuration: self.configuration, nonce: self.nonce,
            launch_url_digest: self.launch_url_digest, callback_digest: self.callback_digest,
            request_digest: digest(body.as_bytes(), MAX_CODE_FORM_BYTES)?,
            created_at: now, expires_at: self.expires_at,
        })
    }
}

/// One consuming response validator bound to the generated nonce and profile.
/// Digests record local byte correspondence, not transport/launch provenance.
pub struct OidcCodeResponseAdmission {
    configuration: OidcCodeFlowConfiguration,
    nonce: SecretString,
    launch_url_digest: [u8; 32],
    callback_digest: [u8; 32],
    request_digest: [u8; 32],
    created_at: SystemTime,
    expires_at: SystemTime,
}

impl OidcCodeResponseAdmission {
    pub fn launch_url_digest(&self) -> &[u8; 32] { &self.launch_url_digest }
    pub fn callback_digest(&self) -> &[u8; 32] { &self.callback_digest }
    pub fn request_digest(&self) -> &[u8; 32] { &self.request_digest }

    /// Applies the existing distinct OIDC response and real signature checks.
    /// The caller cannot substitute its own nonce, client, issuer or tenant at
    /// this stage. Every response consumes this owner, including OAuth denial.
    pub fn admit_token_response(
        self,
        response: EnterpriseTokenResponse<'_>,
        keys: &OidcVerificationKeys,
        received_at: SystemTime,
    ) -> Result<EnterpriseResponseOutcome<EnterpriseIdentityAssertion>, OidcCodeFlowError> {
        live(self.created_at, self.expires_at, received_at)?;
        self.configuration.profile.admit_oidc_code_response(
            response, keys, self.nonce.as_str(), self.configuration.tenant.expectation(),
            self.configuration.maximum_authentication_age,
            self.configuration.response_policy, received_at,
        ).map_err(|_| OidcCodeFlowError::TokenResponseRejected)
    }
}

fn live(created_at: SystemTime, expires_at: SystemTime, now: SystemTime) -> Result<(), OidcCodeFlowError> {
    if now < created_at || now >= expires_at || expires_at <= created_at {
        Err(OidcCodeFlowError::InvalidLifetime)
    } else {
        Ok(())
    }
}

fn digest(bytes: &[u8], bound: usize) -> Result<[u8; 32], OidcCodeFlowError> {
    sha256_bounded(bytes, bound).map(|hash| hash.into_bytes())
        .map_err(|_| OidcCodeFlowError::EncodingFailed)
}

fn https_url(value: &str, query_free: bool) -> Result<CanonicalHttpUrl, OidcCodeFlowError> {
    if value.is_empty() || value.len() > MAX_URL_BYTES || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(OidcCodeFlowError::InvalidConfiguration);
    }
    let parsed = CanonicalHttpUrl::parse(value).map_err(|_| OidcCodeFlowError::InvalidConfiguration)?;
    if parsed.scheme() != "https" || parsed.has_userinfo() || parsed.has_syntax_violation()
        || parsed.fragment().is_some() || (query_free && parsed.query().is_some())
    {
        return Err(OidcCodeFlowError::InvalidConfiguration);
    }
    Ok(parsed)
}

#[derive(Default)]
struct ForbiddenMember(bool);

impl<'de> Deserialize<'de> for ForbiddenMember {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde::de::IgnoredAny::deserialize(deserializer)?;
        Ok(Self(true))
    }
}

#[derive(Deserialize)]
struct SecretMetadataOverlay {
    #[serde(default)]
    client_secret: ForbiddenMember,
    #[serde(default)]
    registration_access_token: ForbiddenMember,
    #[serde(default)]
    registration_client_uri: ForbiddenMember,
}

fn document(kind: SecurityDocumentKind, bytes: &[u8]) -> Result<Map<String, Value>, OidcCodeFlowError> {
    admit_security_document(kind, bytes).map_err(|_| OidcCodeFlowError::InvalidMetadata)?;
    // Reject credential/DCR fields by presence before allocating a JSON Value
    // tree, including null or wrong-type values in those forbidden fields.
    let overlay: SecretMetadataOverlay =
        serde_json::from_slice(bytes).map_err(|_| OidcCodeFlowError::InvalidMetadata)?;
    if overlay.client_secret.0 || overlay.registration_access_token.0 || overlay.registration_client_uri.0 {
        return Err(OidcCodeFlowError::InvalidRegistration);
    }
    serde_json::from_slice(bytes).map_err(|_| OidcCodeFlowError::InvalidMetadata)
}

fn string<'a>(document: &'a Map<String, Value>, name: &str) -> Result<&'a str, OidcCodeFlowError> {
    let value = document.get(name).and_then(Value::as_str).ok_or(OidcCodeFlowError::InvalidMetadata)?;
    if value.is_empty() || value.len() > MAX_FIELD_BYTES || value.chars().any(char::is_control) {
        return Err(OidcCodeFlowError::InvalidMetadata);
    }
    Ok(value)
}

fn array<'a>(document: &'a Map<String, Value>, name: &str) -> Result<Vec<&'a str>, OidcCodeFlowError> {
    let values = document.get(name).and_then(Value::as_array).ok_or(OidcCodeFlowError::InvalidMetadata)?;
    if values.is_empty() || values.len() > 128 { return Err(OidcCodeFlowError::InvalidMetadata); }
    let mut admitted = Vec::with_capacity(values.len());
    let mut seen = BTreeSet::new();
    for value in values {
        let value = value.as_str().ok_or(OidcCodeFlowError::InvalidMetadata)?;
        if value.is_empty() || value.len() > MAX_FIELD_BYTES || value.chars().any(char::is_control)
            || !seen.insert(value)
        {
            return Err(OidcCodeFlowError::InvalidMetadata);
        }
        admitted.push(value);
    }
    Ok(admitted)
}

// The builder is protected on early return as well as success. Moving its
// allocation into SecretString avoids a second unprotected serialized copy.
// Call sites pre-size the bounded result so secret-bearing buffers do not grow.
struct ProtectedBuffer(String);

impl ProtectedBuffer {
    fn with_capacity(capacity: usize) -> Self { Self(String::with_capacity(capacity)) }
    fn push(&mut self, value: char) { self.0.push(value); }
    fn push_str(&mut self, value: &str) { self.0.push_str(value); }
    fn len(&self) -> usize { self.0.len() }
    fn finish(mut self) -> SecretString { SecretString::from_string(std::mem::take(&mut self.0)) }
}

impl Drop for ProtectedBuffer {
    fn drop(&mut self) {
        drop(SecretString::from_string(std::mem::take(&mut self.0)));
    }
}

fn base64url32(bytes: &[u8; 32]) -> SecretString {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = ProtectedBuffer::with_capacity(43);
    let mut accumulator = 0_u32;
    let mut bits = 0;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            output.push(char::from(ALPHABET[((accumulator >> bits) & 63) as usize]));
        }
        accumulator &= (1 << bits) - 1;
    }
    if bits != 0 {
        output.push(char::from(ALPHABET[((accumulator << (6 - bits)) & 63) as usize]));
    }
    output.finish()
}

fn form_literal(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'*' | b'-' | b'.' | b'_')
}

fn form(fields: &[(&str, &str)], limit: usize) -> Result<SecretString, OidcCodeFlowError> {
    let mut length = fields.len().saturating_sub(1);
    for (name, value) in fields {
        length = length.checked_add(1).ok_or(OidcCodeFlowError::EncodingFailed)?;
        for byte in name.bytes().chain(value.bytes()) {
            length = length.checked_add(if byte == b' ' || form_literal(byte) { 1 } else { 3 })
                .ok_or(OidcCodeFlowError::EncodingFailed)?;
        }
    }
    if length > limit { return Err(OidcCodeFlowError::EncodingFailed); }
    let mut output = ProtectedBuffer::with_capacity(length);
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for (index, (name, value)) in fields.iter().enumerate() {
        if index != 0 { output.push('&'); }
        for (part, text) in [*name, *value].into_iter().enumerate() {
            if part == 1 { output.push('='); }
            for byte in text.bytes() {
                if form_literal(byte) {
                    output.push(char::from(byte));
                } else if byte == b' ' {
                    output.push('+');
                } else {
                    output.push('%');
                    output.push(char::from(HEX[usize::from(byte >> 4)]));
                    output.push(char::from(HEX[usize::from(byte & 15)]));
                }
            }
        }
    }
    Ok(output.finish())
}

fn callback_fields(query: &str) -> Result<BTreeMap<String, SecretString>, OidcCodeFlowError> {
    if query.is_empty() || query.len() > MAX_CALLBACK_BYTES {
        return Err(OidcCodeFlowError::CallbackRejected);
    }
    let mut result = BTreeMap::new();
    for (index, field) in query.split('&').enumerate() {
        if index >= MAX_CALLBACK_FIELDS { return Err(OidcCodeFlowError::CallbackRejected); }
        let (name, value) = field.split_once('=').ok_or(OidcCodeFlowError::CallbackRejected)?;
        let name = decode_component(name, 128)?;
        let value = decode_component(value, MAX_FIELD_BYTES)?;
        if name.is_empty() || result.insert(name.as_str().to_owned(), value).is_some() {
            return Err(OidcCodeFlowError::CallbackRejected);
        }
    }
    Ok(result)
}

// Decode bounded UTF-8 directly into protected String custody. Invalid UTF-8
// never leaves a partially decoded secret in an ordinary Vec error object.
fn decode_component(source: &str, maximum: usize) -> Result<SecretString, OidcCodeFlowError> {
    let mut output = ProtectedBuffer::with_capacity(source.len().min(maximum));
    let mut at = 0;
    while let Some(first) = decoded_octet(source.as_bytes(), &mut at)? {
        let width = match first {
            0..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return Err(OidcCodeFlowError::CallbackRejected),
        };
        let mut scalar = [0_u8; 4];
        scalar[0] = first;
        for byte in scalar.iter_mut().take(width).skip(1) {
            *byte = decoded_octet(source.as_bytes(), &mut at)?
                .ok_or(OidcCodeFlowError::CallbackRejected)?;
        }
        let value = std::str::from_utf8(&scalar[..width]).map_err(|_| OidcCodeFlowError::CallbackRejected)?;
        if value.chars().any(char::is_control) || output.len() + width > maximum {
            return Err(OidcCodeFlowError::CallbackRejected);
        }
        output.push_str(value);
    }
    Ok(output.finish())
}

fn decoded_octet(source: &[u8], at: &mut usize) -> Result<Option<u8>, OidcCodeFlowError> {
    let Some(byte) = source.get(*at).copied() else { return Ok(None); };
    *at += 1;
    match byte {
        b'+' => Ok(Some(b' ')),
        b'%' => {
            let high = source.get(*at).copied().and_then(hex_digit).ok_or(OidcCodeFlowError::CallbackRejected)?;
            let low = source.get(*at + 1).copied().and_then(hex_digit).ok_or(OidcCodeFlowError::CallbackRejected)?;
            *at += 2;
            Ok(Some((high << 4) | low))
        }
        0x21..=0x7e => Ok(Some(byte)),
        _ => Err(OidcCodeFlowError::CallbackRejected),
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn vschar(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn error_text(value: &str, maximum: usize, spaces: bool) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| {
        (spaces && byte == 0x20) || byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
    })
}

// A discarded diagnostic URI-reference: validate RFC3986 syntax without
// resolving it against an issuer or treating any scheme as fetch authority.
// The relative-ref and URI hier-part productions differ in the first
// path-noscheme segment, where ':' is forbidden. Adding a fixed scheme after
// that check lets the existing byte-preserving parser validate every component.
fn error_uri(value: &str) -> bool {
    if !error_text(value, 2048, false) { return false; }
    if AbsoluteUri::parse_with_max_bytes(value, 2048).is_ok() { return true; }
    let first_segment = value.split(['/', '?', '#']).next().unwrap_or("");
    if first_segment.contains(':') { return false; }
    let with_scheme = format!("oidc-diagnostic:{value}");
    AbsoluteUri::parse_with_max_bytes(&with_scheme, 2048 + 16).is_ok()
}

fn authorization_error(value: &str) -> OidcAuthorizationError {
    match value {
        "invalid_request" => OidcAuthorizationError::InvalidRequest,
        "unauthorized_client" => OidcAuthorizationError::UnauthorizedClient,
        "access_denied" => OidcAuthorizationError::AccessDenied,
        "unsupported_response_type" => OidcAuthorizationError::UnsupportedResponseType,
        "invalid_scope" => OidcAuthorizationError::InvalidScope,
        "server_error" => OidcAuthorizationError::ServerError,
        "temporarily_unavailable" => OidcAuthorizationError::TemporarilyUnavailable,
        "interaction_required" => OidcAuthorizationError::InteractionRequired,
        "login_required" => OidcAuthorizationError::LoginRequired,
        "account_selection_required" => OidcAuthorizationError::AccountSelectionRequired,
        "consent_required" => OidcAuthorizationError::ConsentRequired,
        "invalid_request_uri" => OidcAuthorizationError::InvalidRequestUri,
        "invalid_request_object" => OidcAuthorizationError::InvalidRequestObject,
        "request_not_supported" => OidcAuthorizationError::RequestNotSupported,
        "request_uri_not_supported" => OidcAuthorizationError::RequestUriNotSupported,
        "registration_not_supported" => OidcAuthorizationError::RegistrationNotSupported,
        _ => OidcAuthorizationError::Extension,
    }
}
