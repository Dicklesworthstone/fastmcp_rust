//! OpenID Connect (OIDC) Provider for MCP.
//!
//! This module extends the OAuth 2.0/2.1 server with OpenID Connect identity
//! layer features:
//!
//! - **ID Token Issuance**: fail-closed until an FND-09 external signer is admitted
//! - **UserInfo Endpoint**: Standard endpoint for retrieving user claims
//! - **Discovery Document**: `.well-known/openid-configuration` metadata
//! - **Standard Claims**: OpenID Connect standard claim types
//!
//! This source inventory is not a promoted production OIDC profile. AUTH and
//! MCP 2026-07-28 conformance gates remain outstanding; the public protocol
//! constant is still `2024-11-05`.
//!
//! # Architecture
//!
//! The OIDC provider builds on top of [`OAuthServer`] by:
//!
//! 1. Adding the `openid` scope to enable OIDC flows
//! 2. Reserving ID-token issuance for an FND-09 externally custodied signer
//! 3. Providing standard endpoints for identity operations
//!
//! # Example
//!
//! ```ignore
//! use std::sync::Arc;
//!
//! use fastmcp_rust::oidc::{OidcProvider, OidcProviderConfig, UserClaims};
//! use fastmcp_rust::oauth::{OAuthServer, OAuthServerConfig};
//!
//! // Create OAuth server first
//! let oauth = Arc::new(OAuthServer::new(OAuthServerConfig::default()));
//!
//! // Create OIDC provider on top
//! let oidc = OidcProvider::new(oauth, OidcProviderConfig::default())
//!     .expect("oidc provider");
//!
//! // Set up user claims provider
//! oidc.set_claims_fn(|subject| {
//!     Some(UserClaims::new(subject)
//!         .with_name("John Doe")
//!         .with_email("john@example.com"))
//! });
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
#[cfg(feature = "builtin-auth-server")]
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "builtin-auth-server")]
use fastmcp_core::Cx;
#[cfg(feature = "builtin-auth-server")]
use fastmcp_protocol::jose::{
    AdmittedRsaJwks, BoundedJwsClaims, CanonicalRs256PublicJwks, ExternalRs256Signer,
    ExternalRs256SigningDeadline, JwsSigningError, JwsSigningProfile, Rs256SigningBinding,
    verify_compact_jws_rs256,
};
#[cfg(feature = "builtin-auth-server")]
use url::Url;

use crate::oauth::{OAuthError, OAuthServer, OAuthServerConfig, OAuthToken, validate_oauth_issuer};

#[cfg(feature = "builtin-auth-server")]
const MAX_OIDC_NONCE_BYTES: usize = 1_024;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the OIDC provider.
#[derive(Debug, Clone)]
pub struct OidcProviderConfig {
    /// Issuer identifier (URL) - must match OAuth server issuer.
    pub issuer: String,
    /// Supported claims.
    pub supported_claims: Vec<String>,
    /// Supported scopes beyond `openid`.
    pub supported_scopes: Vec<String>,
}

impl Default for OidcProviderConfig {
    fn default() -> Self {
        Self {
            issuer: OAuthServerConfig::default().issuer,
            supported_claims: vec![
                "sub".to_string(),
                "name".to_string(),
                "email".to_string(),
                "email_verified".to_string(),
                "preferred_username".to_string(),
                "picture".to_string(),
                "updated_at".to_string(),
            ],
            supported_scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
        }
    }
}

// =============================================================================
// User Claims
// =============================================================================

/// Standard OpenID Connect user claims.
///
/// These claims describe the authenticated user and are included in
/// ID tokens and returned from the userinfo endpoint.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UserClaims {
    /// Subject identifier (required, unique user ID).
    pub sub: String,

    // Profile scope claims
    /// User's full name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// User's given/first name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// User's family/last name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// User's middle name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    /// User's nickname/username.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    /// User's preferred username.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// URL of user's profile page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// URL of user's profile picture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// URL of user's website.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// User's gender.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,
    /// User's birthday (ISO 8601 date).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,
    /// User's timezone (IANA timezone string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,
    /// User's locale (BCP47 language tag).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Time the user's info was last updated (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,

    // Email scope claims
    /// User's email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether the email has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    // Phone scope claims
    /// User's phone number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    /// Whether the phone number has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,

    // Address scope claims
    /// User's address (JSON object).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<AddressClaim>,

    /// Additional custom claims.
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

impl std::fmt::Debug for UserClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let profile_claim_count = [
            self.name.is_some(),
            self.given_name.is_some(),
            self.family_name.is_some(),
            self.middle_name.is_some(),
            self.nickname.is_some(),
            self.preferred_username.is_some(),
            self.profile.is_some(),
            self.picture.is_some(),
            self.website.is_some(),
            self.gender.is_some(),
            self.birthdate.is_some(),
            self.zoneinfo.is_some(),
            self.locale.is_some(),
            self.updated_at.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();

        f.debug_struct("UserClaims")
            .field("subject_len", &self.sub.len())
            .field("profile_claim_count", &profile_claim_count)
            .field("email_present", &self.email.is_some())
            .field("email_verified_present", &self.email_verified.is_some())
            .field("phone_number_present", &self.phone_number.is_some())
            .field(
                "phone_number_verified_present",
                &self.phone_number_verified.is_some(),
            )
            .field("address_present", &self.address.is_some())
            .field("custom_claim_count", &self.custom.len())
            .finish()
    }
}

impl UserClaims {
    /// Creates new user claims with the given subject.
    #[must_use]
    pub fn new(sub: impl Into<String>) -> Self {
        Self {
            sub: sub.into(),
            ..Default::default()
        }
    }

    /// Sets the user's full name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the user's email.
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Sets whether the email is verified.
    #[must_use]
    pub fn with_email_verified(mut self, verified: bool) -> Self {
        self.email_verified = Some(verified);
        self
    }

    /// Sets the user's preferred username.
    #[must_use]
    pub fn with_preferred_username(mut self, username: impl Into<String>) -> Self {
        self.preferred_username = Some(username.into());
        self
    }

    /// Sets the user's profile picture URL.
    #[must_use]
    pub fn with_picture(mut self, url: impl Into<String>) -> Self {
        self.picture = Some(url.into());
        self
    }

    /// Sets the user's given name.
    #[must_use]
    pub fn with_given_name(mut self, name: impl Into<String>) -> Self {
        self.given_name = Some(name.into());
        self
    }

    /// Sets the user's family name.
    #[must_use]
    pub fn with_family_name(mut self, name: impl Into<String>) -> Self {
        self.family_name = Some(name.into());
        self
    }

    /// Sets the user's phone number.
    #[must_use]
    pub fn with_phone_number(mut self, phone: impl Into<String>) -> Self {
        self.phone_number = Some(phone.into());
        self
    }

    /// Sets the updated_at timestamp.
    #[must_use]
    pub fn with_updated_at(mut self, timestamp: i64) -> Self {
        self.updated_at = Some(timestamp);
        self
    }

    /// Adds a custom claim.
    #[must_use]
    pub fn with_custom(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.custom.insert(key.into(), value);
        self
    }

    /// Filters claims based on requested scopes.
    ///
    /// Only returns claims that are allowed by the given scopes.
    #[must_use]
    #[allow(clippy::assigning_clones)]
    pub fn filter_by_scopes(&self, scopes: &[String]) -> UserClaims {
        let mut filtered = UserClaims::new(&self.sub);

        // Profile scope claims
        if scopes.iter().any(|s| s == "profile") {
            filtered.name = self.name.clone();
            filtered.given_name = self.given_name.clone();
            filtered.family_name = self.family_name.clone();
            filtered.middle_name = self.middle_name.clone();
            filtered.nickname = self.nickname.clone();
            filtered.preferred_username = self.preferred_username.clone();
            filtered.profile = self.profile.clone();
            filtered.picture = self.picture.clone();
            filtered.website = self.website.clone();
            filtered.gender = self.gender.clone();
            filtered.birthdate = self.birthdate.clone();
            filtered.zoneinfo = self.zoneinfo.clone();
            filtered.locale = self.locale.clone();
            filtered.updated_at = self.updated_at;
        }

        // Email scope claims
        if scopes.iter().any(|s| s == "email") {
            filtered.email = self.email.clone();
            filtered.email_verified = self.email_verified;
        }

        // Phone scope claims
        if scopes.iter().any(|s| s == "phone") {
            filtered.phone_number = self.phone_number.clone();
            filtered.phone_number_verified = self.phone_number_verified;
        }

        // Address scope claims
        if scopes.iter().any(|s| s == "address") {
            filtered.address = self.address.clone();
        }

        filtered
    }
}

/// Address claim structure per OpenID Connect spec.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AddressClaim {
    /// Full formatted address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    /// Street address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    /// City/locality.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    /// State/region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Postal/zip code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    /// Country.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

impl std::fmt::Debug for AddressClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let populated_field_count = [
            self.formatted.is_some(),
            self.street_address.is_some(),
            self.locality.is_some(),
            self.region.is_some(),
            self.postal_code.is_some(),
            self.country.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();

        f.debug_struct("AddressClaim")
            .field("populated_field_count", &populated_field_count)
            .finish()
    }
}

// =============================================================================
// ID Token
// =============================================================================

/// ID Token claims (JWT payload).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct IdTokenClaims {
    /// Issuer identifier.
    pub iss: String,
    /// Subject identifier.
    pub sub: String,
    /// Audience (client ID).
    pub aud: String,
    /// Expiration time (Unix timestamp).
    pub exp: i64,
    /// Issued at time (Unix timestamp).
    pub iat: i64,
    /// Authentication time (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// Nonce from authorization request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Authentication Context Class Reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Authentication Methods References.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    /// Authorized party (client ID that was issued the token).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    /// Access token hash (for hybrid flows).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    /// Code hash (for hybrid flows).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_hash: Option<String>,
    /// Additional user claims.
    #[serde(flatten)]
    pub user_claims: UserClaims,
}

impl std::fmt::Debug for IdTokenClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdTokenClaims")
            .field("issuer_len", &self.iss.len())
            .field("subject_len", &self.sub.len())
            .field("audience_len", &self.aud.len())
            .field("auth_time_present", &self.auth_time.is_some())
            .field("nonce_present", &self.nonce.is_some())
            .field("acr_present", &self.acr.is_some())
            .field("amr_count", &self.amr.as_ref().map_or(0, Vec::len))
            .field("authorized_party_present", &self.azp.is_some())
            .field("access_token_hash_present", &self.at_hash.is_some())
            .field("code_hash_present", &self.c_hash.is_some())
            .field("user_claims", &self.user_claims)
            .finish_non_exhaustive()
    }
}

/// A signed ID token.
#[derive(Clone)]
pub struct IdToken {
    /// The raw JWT string.
    pub raw: String,
    /// The parsed claims.
    pub claims: IdTokenClaims,
}

impl std::fmt::Debug for IdToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdToken")
            .field("raw_len", &self.raw.len())
            .field("claims", &self.claims)
            .finish()
    }
}

// =============================================================================
// Discovery Document
// =============================================================================

/// OpenID Connect Discovery Document.
///
/// This is served at `/.well-known/openid-configuration`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiscoveryDocument {
    /// Issuer identifier URL.
    pub issuer: String,
    /// Authorization endpoint URL.
    pub authorization_endpoint: String,
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// UserInfo endpoint URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    /// JWKs URI for public key retrieval.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// Registration endpoint URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// Revocation endpoint URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    /// Supported scopes.
    pub scopes_supported: Vec<String>,
    /// Supported response types.
    pub response_types_supported: Vec<String>,
    /// Supported response modes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_modes_supported: Option<Vec<String>>,
    /// Supported grant types.
    pub grant_types_supported: Vec<String>,
    /// Supported subject types.
    pub subject_types_supported: Vec<String>,
    /// Supported ID token signing algorithms.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Supported token endpoint auth methods.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Supported claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,
    /// Supported code challenge methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

impl DiscoveryDocument {
    /// Creates a new discovery document with the given issuer and base URL.
    #[must_use]
    pub fn new(issuer: impl Into<String>, base_url: impl Into<String>) -> Self {
        let issuer = issuer.into();
        let base = base_url.into();

        Self {
            issuer: issuer.clone(),
            authorization_endpoint: format!("{}/authorize", base),
            token_endpoint: format!("{}/token", base),
            userinfo_endpoint: Some(format!("{}/userinfo", base)),
            jwks_uri: None,
            registration_endpoint: None,
            revocation_endpoint: Some(format!("{}/revoke", base)),
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            response_types_supported: vec!["code".to_string()],
            response_modes_supported: Some(vec!["query".to_string()]),
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: Vec::new(),
            token_endpoint_auth_methods_supported: vec![
                "client_secret_post".to_string(),
                "client_secret_basic".to_string(),
            ],
            claims_supported: Some(vec![
                "sub".to_string(),
                "iss".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
                "name".to_string(),
                "email".to_string(),
                "email_verified".to_string(),
                "preferred_username".to_string(),
                "picture".to_string(),
            ]),
            code_challenge_methods_supported: Some(vec!["S256".to_string()]),
        }
    }
}

// =============================================================================
// Claims Provider
// =============================================================================

/// Trait for providing user claims.
pub trait ClaimsProvider: Send + Sync {
    /// Retrieves claims for a user by subject identifier.
    ///
    /// Returns `None` if the user is not found.
    fn get_claims(&self, subject: &str) -> Option<UserClaims>;
}

/// Simple in-memory claims provider.
#[derive(Default)]
pub struct InMemoryClaimsProvider {
    claims: RwLock<HashMap<String, UserClaims>>,
}

impl std::fmt::Debug for InMemoryClaimsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let claim_count = self.claims.try_read().ok().map(|claims| claims.len());
        f.debug_struct("InMemoryClaimsProvider")
            .field("claim_count", &claim_count)
            .finish()
    }
}

impl InMemoryClaimsProvider {
    /// Creates a new empty claims provider.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or updates claims for a user.
    pub fn set_claims(&self, claims: UserClaims) {
        if let Ok(mut guard) = self.claims.write() {
            guard.insert(claims.sub.clone(), claims);
        }
    }

    /// Removes claims for a user.
    pub fn remove_claims(&self, subject: &str) {
        if let Ok(mut guard) = self.claims.write() {
            guard.remove(subject);
        }
    }
}

impl ClaimsProvider for InMemoryClaimsProvider {
    fn get_claims(&self, subject: &str) -> Option<UserClaims> {
        self.claims
            .read()
            .ok()
            .and_then(|guard| guard.get(subject).cloned())
    }
}

/// Function-based claims provider.
pub struct FnClaimsProvider<F>
where
    F: Fn(&str) -> Option<UserClaims> + Send + Sync,
{
    func: F,
}

impl<F> FnClaimsProvider<F>
where
    F: Fn(&str) -> Option<UserClaims> + Send + Sync,
{
    /// Creates a new function-based claims provider.
    #[must_use]
    pub fn new(func: F) -> Self {
        Self { func }
    }
}

impl<F> ClaimsProvider for FnClaimsProvider<F>
where
    F: Fn(&str) -> Option<UserClaims> + Send + Sync,
{
    fn get_claims(&self, subject: &str) -> Option<UserClaims> {
        (self.func)(subject)
    }
}

impl ClaimsProvider for Arc<dyn ClaimsProvider> {
    fn get_claims(&self, subject: &str) -> Option<UserClaims> {
        (**self).get_claims(subject)
    }
}

// =============================================================================
// OIDC Errors
// =============================================================================

/// OIDC-specific errors.
pub enum OidcError {
    /// Underlying OAuth error.
    OAuth(OAuthError),
    /// Missing openid scope.
    MissingOpenIdScope,
    /// User claims not found.
    ClaimsNotFound(String),
    /// Claims provider returned an identity other than the requested subject.
    ClaimsSubjectMismatch,
    /// Token signing failed.
    SigningError(String),
    /// An external signer outcome, including its dispatch knowledge.
    #[cfg(feature = "builtin-auth-server")]
    ExternalSigning(JwsSigningError),
    /// Invalid ID token.
    InvalidIdToken(String),
}

impl std::fmt::Debug for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OAuth(error) => f.debug_tuple("OAuth").field(error).finish(),
            Self::MissingOpenIdScope => f.write_str("MissingOpenIdScope"),
            Self::ClaimsNotFound(subject) => f
                .debug_struct("ClaimsNotFound")
                .field("subject_len", &subject.len())
                .finish(),
            Self::ClaimsSubjectMismatch => f.write_str("ClaimsSubjectMismatch"),
            Self::SigningError(description) => f
                .debug_struct("SigningError")
                .field("description_len", &description.len())
                .finish(),
            #[cfg(feature = "builtin-auth-server")]
            Self::ExternalSigning(error) => f.debug_tuple("ExternalSigning").field(error).finish(),
            Self::InvalidIdToken(description) => f
                .debug_struct("InvalidIdToken")
                .field("description_len", &description.len())
                .finish(),
        }
    }
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OAuth(e) => write!(f, "OAuth error: {}", e),
            Self::MissingOpenIdScope => write!(f, "missing 'openid' scope"),
            Self::ClaimsNotFound(_) => f.write_str("claims not found for requested subject"),
            Self::ClaimsSubjectMismatch => {
                write!(f, "claims provider returned a mismatched subject")
            }
            Self::SigningError(_) => f.write_str("ID token signing failed"),
            #[cfg(feature = "builtin-auth-server")]
            Self::ExternalSigning(error) => write!(f, "external ID token signing failed: {error}"),
            Self::InvalidIdToken(_) => f.write_str("invalid ID token"),
        }
    }
}

impl std::error::Error for OidcError {}

impl From<OAuthError> for OidcError {
    fn from(err: OAuthError) -> Self {
        Self::OAuth(err)
    }
}

// =============================================================================
// OIDC Provider
// =============================================================================

/// OpenID Connect Provider.
///
/// This extends the OAuth server with OIDC identity features.
pub struct OidcProvider {
    /// Underlying OAuth server.
    oauth: Arc<OAuthServer>,
    /// OIDC configuration.
    config: OidcProviderConfig,
    /// Claims provider.
    claims_provider: RwLock<Option<Arc<dyn ClaimsProvider>>>,
    /// A non-forgeable external-signer activation. It remains absent until a
    /// caller supplies an exact publication/read-back of the selected public
    /// JWKS under the same immutable signer binding.
    #[cfg(feature = "builtin-auth-server")]
    signing_activation: RwLock<Option<OidcIdTokenSigningActivation>>,
}

/// A server-held activation for one externally custodied ID-token signer.
///
/// Its fields are private and it has no public constructor. It can only be
/// created after the selected signer's canonical public JWKS exactly matches
/// both the bytes supplied for publication and the separately read-back bytes.
/// This type neither publishes an endpoint nor implements a KMS/HSM adapter.
#[cfg(feature = "builtin-auth-server")]
pub struct OidcIdTokenSigningActivation {
    signer: Arc<ExternalRs256Signer>,
    binding: Rs256SigningBinding,
    issuer: String,
    advertised_jwks_uri: String,
    advertised_jwks_origin: String,
    published_jwks: Vec<u8>,
    read_back_keys: AdmittedRsaJwks,
}

#[cfg(feature = "builtin-auth-server")]
impl std::fmt::Debug for OidcIdTokenSigningActivation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OidcIdTokenSigningActivation")
            .field("binding", &self.binding)
            .field("issuer_bytes", &self.issuer.len())
            .field("advertised_jwks_uri_bytes", &self.advertised_jwks_uri.len())
            .field(
                "advertised_jwks_origin_bytes",
                &self.advertised_jwks_origin.len(),
            )
            .field("published_jwks_bytes", &self.published_jwks.len())
            .field("read_back_key_count", &self.read_back_keys.len())
            .finish()
    }
}

fn validate_oidc_config(config: &OidcProviderConfig) -> Result<(), OidcError> {
    // Reuse the OAuth issuer admission policy so OIDC discovery cannot publish
    // a non-HTTPS, non-canonical, or otherwise unsafe issuer spelling.
    validate_oauth_issuer(&config.issuer).map_err(OidcError::from)
}

impl OidcProvider {
    /// Creates a new OIDC provider with the given OAuth server.
    ///
    /// # Errors
    ///
    /// Returns an error when the OIDC issuer is unsafe or does not exactly
    /// match the underlying OAuth server issuer.
    pub fn new(oauth: Arc<OAuthServer>, config: OidcProviderConfig) -> Result<Self, OidcError> {
        validate_oidc_config(&config)?;
        if config.issuer != oauth.config().issuer {
            return Err(OidcError::OAuth(OAuthError::ServerError(
                "OIDC issuer must exactly match the OAuth server issuer".to_string(),
            )));
        }
        Ok(Self {
            oauth,
            config,
            claims_provider: RwLock::new(None),
            #[cfg(feature = "builtin-auth-server")]
            signing_activation: RwLock::new(None),
        })
    }

    /// Creates a new OIDC provider with default configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying OAuth server has an unsafe issuer.
    pub fn with_defaults(oauth: Arc<OAuthServer>) -> Result<Self, OidcError> {
        let config = OidcProviderConfig {
            issuer: oauth.config().issuer.clone(),
            ..OidcProviderConfig::default()
        };
        Self::new(oauth, config)
    }

    /// Returns the OIDC configuration.
    #[must_use]
    pub fn config(&self) -> &OidcProviderConfig {
        &self.config
    }

    /// Returns a reference to the underlying OAuth server.
    #[must_use]
    pub fn oauth(&self) -> &Arc<OAuthServer> {
        &self.oauth
    }

    /// Sets the claims provider.
    pub fn set_claims_provider<P: ClaimsProvider + 'static>(&self, provider: P) {
        if let Ok(mut guard) = self.claims_provider.write() {
            *guard = Some(Arc::new(provider));
        }
    }

    /// Sets a function-based claims provider.
    pub fn set_claims_fn<F>(&self, func: F)
    where
        F: Fn(&str) -> Option<UserClaims> + Send + Sync + 'static,
    {
        self.set_claims_provider(FnClaimsProvider::new(func));
    }

    /// Creates a sealed activation for an externally custodied RS256 signer.
    ///
    /// The caller must first publish `published_jwks` at `advertised_jwks_uri`,
    /// then supply bytes read back from that exact HTTPS issuer-origin endpoint.
    /// This crate does not manufacture a publisher, perform HTTP reads, or
    /// treat a configuration flag as publication evidence.
    #[cfg(feature = "builtin-auth-server")]
    pub fn create_id_token_signing_activation(
        &self,
        signer: Arc<ExternalRs256Signer>,
        published_jwks: CanonicalRs256PublicJwks,
        advertised_jwks_uri: &str,
        read_back_jwks: &[u8],
    ) -> Result<OidcIdTokenSigningActivation, OidcError> {
        let (advertised_jwks_uri, advertised_jwks_origin) =
            validate_advertised_jwks_uri(&self.config.issuer, advertised_jwks_uri)?;
        let expected_jwks = signer.canonical_public_jwks().map_err(|_| {
            OidcError::SigningError("unable to canonicalize signing JWKS".to_string())
        })?;
        if published_jwks.binding() != signer.binding()
            || expected_jwks.binding() != signer.binding()
            || published_jwks.as_bytes() != expected_jwks.as_bytes()
            || read_back_jwks != expected_jwks.as_bytes()
        {
            return Err(OidcError::SigningError(
                "OIDC signing JWKS publication/read-back does not match the selected signer"
                    .to_string(),
            ));
        }
        let read_back_keys = AdmittedRsaJwks::from_json(read_back_jwks).map_err(|_| {
            OidcError::SigningError("OIDC signing JWKS read-back is not admitted".to_string())
        })?;

        Ok(OidcIdTokenSigningActivation {
            binding: signer.binding(),
            signer,
            issuer: self.config.issuer.clone(),
            advertised_jwks_uri,
            advertised_jwks_origin,
            published_jwks: read_back_jwks.to_vec(),
            read_back_keys,
        })
    }

    /// Installs one sealed signer activation for this exact OIDC issuer.
    ///
    /// The activation is consumed. Replacing an active signer requires a
    /// separate rotation/retirement path, so this narrow initial integration
    /// refuses replacement rather than silently changing a live key.
    #[cfg(feature = "builtin-auth-server")]
    pub fn install_id_token_signing_activation(
        &self,
        activation: OidcIdTokenSigningActivation,
    ) -> Result<(), OidcError> {
        let endpoint_is_bound =
            validate_advertised_jwks_uri(&activation.issuer, &activation.advertised_jwks_uri)
                .is_ok_and(|(uri, origin)| {
                    uri == activation.advertised_jwks_uri
                        && origin == activation.advertised_jwks_origin
                });
        if activation.issuer != self.config.issuer
            || activation.binding != activation.signer.binding()
            || !endpoint_is_bound
        {
            return Err(OidcError::SigningError(
                "OIDC signing activation does not match this issuer or signer binding".to_string(),
            ));
        }
        let mut slot = self.signing_activation.write().map_err(|_| {
            OidcError::SigningError("OIDC signing activation state is unavailable".to_string())
        })?;
        if slot.is_some() {
            return Err(OidcError::SigningError(
                "OIDC signing activation is already installed".to_string(),
            ));
        }
        *slot = Some(activation);
        Ok(())
    }

    /// Returns exact public JWKS bytes only after their matching activation is
    /// installed. An HTTP server may serve these bytes at its advertised JWKS
    /// endpoint; this method does not bind, publish, or fetch HTTP itself.
    #[cfg(feature = "builtin-auth-server")]
    pub fn activated_jwks_document(&self) -> Result<Vec<u8>, OidcError> {
        let slot = self.signing_activation.read().map_err(|_| {
            OidcError::SigningError("OIDC signing activation state is unavailable".to_string())
        })?;
        let activation = slot.as_ref().ok_or_else(|| {
            OidcError::SigningError("OIDC signing activation is required".to_string())
        })?;
        Ok(activation.published_jwks.clone())
    }

    /// Generates the discovery document.
    #[must_use]
    pub fn discovery_document(&self, base_url: impl Into<String>) -> DiscoveryDocument {
        let base_url = base_url.into();
        let mut doc = DiscoveryDocument::new(&self.config.issuer, base_url);
        doc.scopes_supported = self.config.supported_scopes.clone();
        doc.claims_supported = Some(self.config.supported_claims.clone());
        #[cfg(feature = "builtin-auth-server")]
        if let Ok(slot) = self.signing_activation.read() {
            if let Some(activation) = slot.as_ref() {
                doc.id_token_signing_alg_values_supported = vec!["RS256".to_string()];
                doc.jwks_uri = Some(activation.advertised_jwks_uri.clone());
            }
        }
        doc
    }

    // -------------------------------------------------------------------------
    // ID Token Issuance
    // -------------------------------------------------------------------------

    /// Issues one OIDC ID-token candidate through the active external RS256
    /// signer. The returned compact JWS is self-verified by the signer facade
    /// and then verified again against the exact JWKS publication read-back.
    ///
    /// This is intentionally asynchronous and accepts the caller's [`Cx`];
    /// it never creates a runtime or substitutes an in-process signing key.
    #[cfg(feature = "builtin-auth-server")]
    pub async fn issue_id_token(
        &self,
        cx: &Cx,
        access_token: &str,
        nonce: Option<&str>,
        deadline: ExternalRs256SigningDeadline,
    ) -> Result<IdToken, OidcError> {
        let access_token_credential = access_token;
        let access_token = self.validated_oidc_access_token(access_token)?;
        let subject = access_token
            .subject
            .as_deref()
            .ok_or_else(|| OidcError::ClaimsNotFound("no subject in access token".to_string()))?;
        validate_oidc_nonce(nonce)?;
        let user_claims = self.get_user_claims(subject, &access_token.scopes)?;
        let now = oidc_unix_timestamp()?;
        let expires_in = access_token
            .expires_at
            .saturating_duration_since(Instant::now())
            .as_secs();
        let expires_in = i64::try_from(expires_in).map_err(|_| {
            OidcError::InvalidIdToken("access-token lifetime exceeds ID-token range".to_string())
        })?;
        let exp = now.checked_add(expires_in).ok_or_else(|| {
            OidcError::InvalidIdToken("ID-token expiry exceeds timestamp range".to_string())
        })?;
        if exp <= now {
            return Err(OidcError::InvalidIdToken(
                "access token is expired before ID-token issuance".to_string(),
            ));
        }
        let claims = IdTokenClaims {
            iss: self.config.issuer.clone(),
            sub: subject.to_string(),
            aud: access_token.client_id.clone(),
            exp,
            iat: now,
            auth_time: None,
            nonce: nonce.map(str::to_string),
            acr: None,
            amr: None,
            azp: None,
            at_hash: None,
            c_hash: None,
            user_claims,
        };
        let signing_claims = id_token_signing_claims(&claims)?;
        let (signer, binding, read_back_keys) = {
            let slot = self.signing_activation.read().map_err(|_| {
                OidcError::SigningError("OIDC signing activation state is unavailable".to_string())
            })?;
            let activation = slot.as_ref().ok_or_else(|| {
                OidcError::SigningError("OIDC signing activation is required".to_string())
            })?;
            if activation.issuer != self.config.issuer
                || activation.binding != activation.signer.binding()
            {
                return Err(OidcError::SigningError(
                    "OIDC signing activation no longer matches the selected signer".to_string(),
                ));
            }
            (
                Arc::clone(&activation.signer),
                activation.binding,
                activation.read_back_keys.clone(),
            )
        };
        let signed = signer
            .sign(cx, JwsSigningProfile::OidcIdToken, signing_claims, deadline)
            .await
            .map_err(OidcError::ExternalSigning)?;
        if signed.binding() != binding {
            return Err(OidcError::SigningError(
                "external ID-token signing binding changed before exposure".to_string(),
            ));
        }
        cx.checkpoint().map_err(|_| {
            OidcError::SigningError("OIDC request cancelled after external signing".to_string())
        })?;
        let revalidated = self.validated_oidc_access_token(access_token_credential)?;
        if !same_id_token_authorization(&access_token, &revalidated) {
            return Err(OidcError::SigningError(
                "OIDC access-token authorization changed during external signing".to_string(),
            ));
        }
        let raw = signed.into_compact_jws();
        verify_compact_jws_rs256(&raw, &read_back_keys).map_err(|_| {
            OidcError::SigningError("ID-token failed published-JWKS verification".to_string())
        })?;
        Ok(IdToken { raw, claims })
    }

    // -------------------------------------------------------------------------
    // UserInfo Endpoint
    // -------------------------------------------------------------------------

    /// Handles a userinfo request.
    ///
    /// Returns the user's claims filtered by the access token's scopes.
    pub fn userinfo(&self, access_token: &str) -> Result<UserClaims, OidcError> {
        let validated = self.validated_oidc_access_token(access_token)?;

        let subject = validated
            .subject
            .as_ref()
            .ok_or_else(|| OidcError::ClaimsNotFound("no subject in access token".to_string()))?;

        self.get_user_claims(subject, &validated.scopes)
    }

    fn validated_oidc_access_token(&self, access_token: &str) -> Result<OAuthToken, OidcError> {
        let validated = self
            .oauth
            .validate_access_token(access_token)
            .ok_or_else(|| {
                OidcError::OAuth(OAuthError::InvalidGrant(
                    "invalid, revoked, or expired OAuth access token".to_string(),
                ))
            })?;
        if validated.is_refresh_token || validated.is_expired() {
            return Err(OidcError::OAuth(OAuthError::InvalidGrant(
                "invalid, revoked, or expired OAuth access token".to_string(),
            )));
        }
        if !validated.scopes.iter().any(|scope| scope == "openid") {
            return Err(OidcError::MissingOpenIdScope);
        }
        Ok(validated)
    }

    // -------------------------------------------------------------------------
    // Helper Methods
    // -------------------------------------------------------------------------

    fn get_user_claims(&self, subject: &str, scopes: &[String]) -> Result<UserClaims, OidcError> {
        let provider = self
            .claims_provider
            .read()
            .ok()
            .and_then(|guard| guard.clone());

        let claims = match provider {
            Some(p) => p
                .get_claims(subject)
                .ok_or_else(|| OidcError::ClaimsNotFound(subject.to_string()))?,
            None => {
                // Default: just return subject
                UserClaims::new(subject)
            }
        };

        // The validated access token is the authority for user identity. A
        // custom provider must never be able to substitute another subject's
        // claims, even when it was queried with the correct key.
        if claims.sub != subject {
            return Err(OidcError::ClaimsSubjectMismatch);
        }

        Ok(claims.filter_by_scopes(scopes))
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

#[cfg(feature = "builtin-auth-server")]
fn validate_advertised_jwks_uri(
    issuer: &str,
    advertised_jwks_uri: &str,
) -> Result<(String, String), OidcError> {
    let issuer = Url::parse(issuer).map_err(|_| {
        OidcError::SigningError("OIDC issuer cannot bind an advertised JWKS endpoint".to_string())
    })?;
    let endpoint = Url::parse(advertised_jwks_uri).map_err(|_| {
        OidcError::SigningError("advertised JWKS endpoint is not an absolute HTTPS URL".to_string())
    })?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(OidcError::SigningError(
            "advertised JWKS endpoint is not a canonical HTTPS origin path".to_string(),
        ));
    }
    let issuer_origin = issuer.origin().ascii_serialization();
    let endpoint_origin = endpoint.origin().ascii_serialization();
    if endpoint_origin != issuer_origin {
        return Err(OidcError::SigningError(
            "advertised JWKS endpoint origin does not match the OIDC issuer".to_string(),
        ));
    }
    Ok((endpoint.to_string(), endpoint_origin))
}

#[cfg(feature = "builtin-auth-server")]
fn same_id_token_authorization(left: &OAuthToken, right: &OAuthToken) -> bool {
    left.client_id == right.client_id
        && left.scopes == right.scopes
        && left.resource == right.resource
        && left.issued_at == right.issued_at
        && left.expires_at == right.expires_at
        && left.subject == right.subject
        && left.token_type == right.token_type
        && !left.is_refresh_token
        && !right.is_refresh_token
}

#[cfg(feature = "builtin-auth-server")]
fn validate_oidc_nonce(nonce: Option<&str>) -> Result<(), OidcError> {
    if nonce.is_some_and(|nonce| {
        nonce.is_empty()
            || nonce.len() > MAX_OIDC_NONCE_BYTES
            || nonce.bytes().any(|byte| byte.is_ascii_control())
    }) {
        return Err(OidcError::InvalidIdToken(
            "OIDC nonce is outside admitted bounds".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "builtin-auth-server")]
fn oidc_unix_timestamp() -> Result<i64, OidcError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OidcError::InvalidIdToken("system clock predates Unix epoch".to_string()))?
        .as_secs();
    i64::try_from(seconds)
        .map_err(|_| OidcError::InvalidIdToken("system clock exceeds ID-token range".to_string()))
}

#[cfg(feature = "builtin-auth-server")]
fn id_token_signing_claims(claims: &IdTokenClaims) -> Result<BoundedJwsClaims, OidcError> {
    let mut value = serde_json::to_value(&claims.user_claims)
        .map_err(|_| OidcError::InvalidIdToken("user claims cannot be serialized".to_string()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        OidcError::InvalidIdToken("user claims must serialize as an object".to_string())
    })?;
    // A claims provider may supply arbitrary public profile claims, but it
    // cannot overwrite the identity and lifetime facts that this server owns.
    for name in [
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "auth_time",
        "nonce",
        "acr",
        "amr",
        "azp",
        "at_hash",
        "c_hash",
    ] {
        object.remove(name);
    }
    object.insert(
        "iss".to_string(),
        serde_json::Value::String(claims.iss.clone()),
    );
    object.insert(
        "sub".to_string(),
        serde_json::Value::String(claims.sub.clone()),
    );
    object.insert(
        "aud".to_string(),
        serde_json::Value::String(claims.aud.clone()),
    );
    object.insert("exp".to_string(), serde_json::Value::from(claims.exp));
    object.insert("iat".to_string(), serde_json::Value::from(claims.iat));
    if let Some(auth_time) = claims.auth_time {
        object.insert("auth_time".to_string(), serde_json::Value::from(auth_time));
    }
    if let Some(nonce) = &claims.nonce {
        object.insert(
            "nonce".to_string(),
            serde_json::Value::String(nonce.clone()),
        );
    }
    if let Some(acr) = &claims.acr {
        object.insert("acr".to_string(), serde_json::Value::String(acr.clone()));
    }
    if let Some(amr) = &claims.amr {
        object.insert(
            "amr".to_string(),
            serde_json::to_value(amr).map_err(|_| {
                OidcError::InvalidIdToken("authentication methods cannot be serialized".to_string())
            })?,
        );
    }
    if let Some(azp) = &claims.azp {
        object.insert("azp".to_string(), serde_json::Value::String(azp.clone()));
    }
    if let Some(at_hash) = &claims.at_hash {
        object.insert(
            "at_hash".to_string(),
            serde_json::Value::String(at_hash.clone()),
        );
    }
    if let Some(c_hash) = &claims.c_hash {
        object.insert(
            "c_hash".to_string(),
            serde_json::Value::String(c_hash.clone()),
        );
    }
    BoundedJwsClaims::from_value(&value)
        .map_err(|_| OidcError::InvalidIdToken("ID-token claims exceed signing bounds".to_string()))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod non_signing_tests {
    use super::*;

    #[test]
    fn default_oidc_and_oauth_issuers_match() {
        assert_eq!(
            OidcProviderConfig::default().issuer,
            OAuthServerConfig::default().issuer
        );
    }

    #[test]
    fn provider_requires_exact_safe_oauth_issuer_and_defaults_follow_custom_oauth() {
        let oauth = Arc::new(
            OAuthServer::try_new(OAuthServerConfig {
                issuer: "https://issuer.example/tenant".to_string(),
                ..OAuthServerConfig::default()
            })
            .unwrap(),
        );
        let provider = OidcProvider::with_defaults(Arc::clone(&oauth)).unwrap();
        assert_eq!(provider.config().issuer, oauth.config().issuer);
        assert_eq!(
            provider.discovery_document("https://issuer.example").issuer,
            oauth.config().issuer
        );

        assert!(matches!(
            OidcProvider::new(Arc::clone(&oauth), OidcProviderConfig::default()),
            Err(OidcError::OAuth(OAuthError::ServerError(_)))
        ));

        let unsafe_config = OidcProviderConfig {
            issuer: "http://issuer.example".to_string(),
            ..OidcProviderConfig::default()
        };
        assert!(matches!(
            OidcProvider::new(oauth, unsafe_config),
            Err(OidcError::OAuth(OAuthError::ServerError(_)))
        ));
    }

    #[test]
    fn discovery_does_not_advertise_signing() {
        let doc = DiscoveryDocument::new("https://issuer.example", "https://issuer.example");
        assert!(doc.id_token_signing_alg_values_supported.is_empty());
        assert!(doc.jwks_uri.is_none());
        assert_eq!(
            doc.code_challenge_methods_supported,
            Some(vec!["S256".to_string()])
        );
    }

    #[test]
    fn user_claims_filter_by_scope() {
        let claims = UserClaims::new("subject")
            .with_name("Alice")
            .with_email("alice@example.test")
            .with_email_verified(true);
        let filtered = claims.filter_by_scopes(&["openid".to_string()]);
        assert_eq!(filtered.sub, "subject");
        assert!(filtered.name.is_none());
        assert!(filtered.email.is_none());
    }

    #[test]
    fn claims_provider_cannot_substitute_a_different_subject() {
        let oauth = Arc::new(OAuthServer::new(OAuthServerConfig::default()));
        let provider = OidcProvider::with_defaults(oauth).expect("default provider");
        provider.set_claims_fn(|requested_subject| {
            assert_eq!(requested_subject, "authenticated-subject");
            Some(UserClaims::new("different-subject").with_email("different-subject@example.test"))
        });

        let error = provider
            .get_user_claims(
                "authenticated-subject",
                &["openid".to_string(), "email".to_string()],
            )
            .expect_err("a claims provider must not substitute another identity");

        assert!(matches!(error, OidcError::ClaimsSubjectMismatch));
        assert!(!error.to_string().contains("authenticated-subject"));
        assert!(!error.to_string().contains("different-subject"));
    }

    #[test]
    fn oidc_debug_surfaces_redact_token_and_pii_canaries_without_changing_wire_data() {
        const CANARY: &str = "oidc-debug-token-pii-canary";
        let address = AddressClaim {
            formatted: Some(CANARY.to_owned()),
            street_address: Some(CANARY.to_owned()),
            locality: Some(CANARY.to_owned()),
            region: Some(CANARY.to_owned()),
            postal_code: Some(CANARY.to_owned()),
            country: Some(CANARY.to_owned()),
        };
        let mut user_claims = UserClaims::new(CANARY)
            .with_name(CANARY)
            .with_email(CANARY)
            .with_email_verified(true)
            .with_phone_number(CANARY)
            .with_custom(CANARY, serde_json::json!(CANARY));
        user_claims.preferred_username = Some(CANARY.to_owned());
        user_claims.address = Some(address.clone());
        let id_token_claims = IdTokenClaims {
            iss: CANARY.to_owned(),
            sub: CANARY.to_owned(),
            aud: CANARY.to_owned(),
            exp: 2,
            iat: 1,
            auth_time: Some(1),
            nonce: Some(CANARY.to_owned()),
            acr: Some(CANARY.to_owned()),
            amr: Some(vec![CANARY.to_owned()]),
            azp: Some(CANARY.to_owned()),
            at_hash: Some(CANARY.to_owned()),
            c_hash: Some(CANARY.to_owned()),
            user_claims: user_claims.clone(),
        };

        let wire = serde_json::to_value(&id_token_claims).unwrap();
        assert_eq!(wire["nonce"], CANARY);
        assert_eq!(wire["email"], CANARY);
        assert_eq!(wire["phone_number"], CANARY);
        assert_eq!(wire["address"]["formatted"], CANARY);
        assert_eq!(wire[CANARY], CANARY);

        let id_token = IdToken {
            raw: CANARY.to_owned(),
            claims: id_token_claims.clone(),
        };
        let provider = InMemoryClaimsProvider::new();
        provider.set_claims(user_claims.clone());
        let errors = [
            OidcError::ClaimsNotFound(CANARY.to_owned()),
            OidcError::SigningError(CANARY.to_owned()),
            OidcError::InvalidIdToken(CANARY.to_owned()),
        ];
        let debug_outputs = [
            format!("{address:?}"),
            format!("{user_claims:?}"),
            format!("{id_token_claims:?}"),
            format!("{id_token:?}"),
            format!("{provider:?}"),
            format!("{:?}", errors[0]),
            format!("{:?}", errors[1]),
            format!("{:?}", errors[2]),
        ];

        for debug in debug_outputs {
            assert!(
                !debug.contains(CANARY),
                "sensitive canary leaked through Debug: {debug}"
            );
            assert!(
                debug.contains("_len") || debug.contains("_count") || debug.contains("_present"),
                "Debug output lacked safe structural metadata: {debug}"
            );
        }

        for display in errors.map(|error| error.to_string()) {
            assert!(
                !display.contains(CANARY),
                "sensitive canary leaked through Display: {display}"
            );
        }
    }
}

#[cfg(all(test, feature = "builtin-auth-server"))]
mod signer_activation_tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use base64::Engine as _;
    use fastmcp_protocol::jose::{
        AttestedRs256PublicKey, ExternalRs256OperationReceipt, ExternalRs256SignDisposition,
        ExternalRs256SignerBackend, ExternalRs256SigningRequest, RawRs256Signature,
        RedactedSignerProvenance,
    };

    use super::*;
    use crate::oauth::{AuthorizationRequest, CodeChallengeMethod, OAuthClient, TokenRequest};

    const TEST_CLIENT_ID: &str = "oidc-signing-test-client";
    const TEST_REDIRECT_URI: &str = "http://127.0.0.1/oidc-callback";
    const TEST_CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const TEST_CODE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    // This is a retained public RS256 verification vector; no private key is
    // present here. Negative tests never ask their backend to produce a JWS.
    const TEST_PUBLIC_MODULUS: &str = "jlHZ9nzuIuM4aiAQSAgEJMBaYS7qm7Z_3mtGYDdzReIkzxPHHr21oeXQyUJI89eQG13fsUdyoodcuh5kmndPCrODJekfr_zgor6sNspcB88iQEqEc9yf9YAf5v-cNH1Evh82KABuWb26LMaNAzZFR3BMhMEQ1FD6fLFGAbX76Drd5_UZ-1xcU07IXEc_9zvQvOwXckhO7P5Yil1fVzLTrHye_6zTbGWvdqi45095bKPnSqjrLBCTVrUW8o02Gi6mt7Ls9pZeWx2DXV8SqV06DdlqiovtKWRooQ1zV-v7BGsLsVk6T6d-8mNMGNrh0fpNb_5kdaHphAt_Ji6eE1wQPw";

    struct UnexpectedBackend {
        calls: Arc<AtomicUsize>,
    }

    impl ExternalRs256SignerBackend for UnexpectedBackend {
        fn sign<'a>(
            &'a self,
            _: &'a Cx,
            _: ExternalRs256SigningRequest,
        ) -> Pin<Box<dyn Future<Output = ExternalRs256SignDisposition> + Send + 'a>> {
            let calls = Arc::clone(&self.calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::AcqRel);
                panic!("a rejected OIDC issuance must not dispatch external signing")
            })
        }
    }

    struct CancellationAfterDispatchBackend {
        calls: Arc<AtomicUsize>,
    }

    impl ExternalRs256SignerBackend for CancellationAfterDispatchBackend {
        fn sign<'a>(
            &'a self,
            cx: &'a Cx,
            request: ExternalRs256SigningRequest,
        ) -> Pin<Box<dyn Future<Output = ExternalRs256SignDisposition> + Send + 'a>> {
            let calls = Arc::clone(&self.calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::AcqRel);
                cx.set_cancel_requested(true);
                let receipt = ExternalRs256OperationReceipt::new(
                    request.binding(),
                    1,
                    RedactedSignerProvenance::new("oidc-cancellation-test")
                        .expect("bounded redacted test provenance"),
                )
                .expect("valid dispatched-operation receipt");
                // This is intentionally not a signature: cancellation must
                // consume the dispatched attempt before any JWS can exist.
                ExternalRs256SignDisposition::Dispatched(
                    RawRs256Signature::from_bytes(vec![0_u8; 256])
                        .expect("bounded cancellation-path bytes"),
                    receipt,
                )
            })
        }
    }

    fn test_signer(backend: Arc<dyn ExternalRs256SignerBackend>) -> Arc<ExternalRs256Signer> {
        let binding =
            Rs256SigningBinding::new(11, 12, 13, 14).expect("nonzero external signer generations");
        let modulus = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(TEST_PUBLIC_MODULUS)
            .expect("retained public verification modulus");
        let key = AttestedRs256PublicKey::admit(
            "fixed-rs256",
            modulus,
            binding,
            RedactedSignerProvenance::new("oidc-test-adapter")
                .expect("bounded redacted test provenance"),
        )
        .expect("retained public verification key admits");
        Arc::new(ExternalRs256Signer::new(backend, key))
    }

    fn issue_access_token(scopes: &[&str]) -> (Arc<OAuthServer>, crate::oauth::TokenResponse) {
        let oauth = Arc::new(OAuthServer::with_defaults());
        oauth
            .register_client(
                OAuthClient::builder(TEST_CLIENT_ID)
                    .redirect_uri(TEST_REDIRECT_URI)
                    .scopes(scopes.iter().copied())
                    .build()
                    .expect("valid test client"),
            )
            .expect("register test client");
        let (code, _) = oauth
            .authorize(&AuthorizationRequest {
                response_type: "code".to_string(),
                client_id: TEST_CLIENT_ID.to_string(),
                redirect_uri: TEST_REDIRECT_URI.to_string(),
                scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
                resource: None,
                state: Some("oidc-test-state".to_string()),
                code_challenge: TEST_CODE_CHALLENGE.to_string(),
                code_challenge_method: CodeChallengeMethod::S256,
            })
            .expect("authorize test access token");
        let response = oauth
            .token(&TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some(code),
                redirect_uri: Some(TEST_REDIRECT_URI.to_string()),
                client_id: TEST_CLIENT_ID.to_string(),
                client_secret: None,
                code_verifier: Some(TEST_CODE_VERIFIER.to_string()),
                refresh_token: None,
                scopes: None,
                resource: None,
            })
            .expect("exchange test access token");
        (oauth, response)
    }

    fn activated_provider(
        oauth: Arc<OAuthServer>,
        signer: Arc<ExternalRs256Signer>,
    ) -> OidcProvider {
        let provider = OidcProvider::with_defaults(oauth).expect("OIDC provider");
        let canonical = signer
            .canonical_public_jwks()
            .expect("canonical external public JWKS");
        let read_back = canonical.as_bytes().to_vec();
        let activation = provider
            .create_id_token_signing_activation(
                signer,
                canonical,
                "https://fastmcp.invalid/oidc/jwks",
                &read_back,
            )
            .expect("exact publication/read-back activation");
        provider
            .install_id_token_signing_activation(activation)
            .expect("install activation");
        provider
    }

    fn signing_deadline() -> ExternalRs256SigningDeadline {
        ExternalRs256SigningDeadline::new(std::time::Duration::from_secs(1))
            .expect("bounded test deadline")
    }

    #[test]
    fn forged_revoked_refresh_and_non_openid_credentials_never_dispatch_signing() {
        let calls = Arc::new(AtomicUsize::new(0));
        let signer = test_signer(Arc::new(UnexpectedBackend {
            calls: Arc::clone(&calls),
        }));
        let (oauth, issued) = issue_access_token(&["openid"]);
        let refresh = issued
            .refresh_token
            .as_deref()
            .expect("refresh credential")
            .to_string();
        let provider = activated_provider(Arc::clone(&oauth), signer);
        let cx = Cx::for_testing();
        let refresh_result = fastmcp_core::block_on(provider.issue_id_token(
            &cx,
            &refresh,
            None,
            signing_deadline(),
        ))
        .0;
        assert!(matches!(
            refresh_result,
            Err(OidcError::OAuth(OAuthError::InvalidGrant(_)))
        ));
        oauth
            .revoke(&issued.access_token, TEST_CLIENT_ID, None)
            .expect("revoke owned access credential");

        for credential in ["forged-opaque-credential".to_string(), issued.access_token] {
            let cx = Cx::for_testing();
            let result = fastmcp_core::block_on(provider.issue_id_token(
                &cx,
                &credential,
                None,
                signing_deadline(),
            ))
            .0;
            assert!(matches!(
                result,
                Err(OidcError::OAuth(OAuthError::InvalidGrant(_)))
            ));
        }
        assert_eq!(calls.load(Ordering::Acquire), 0);

        let calls = Arc::new(AtomicUsize::new(0));
        let signer = test_signer(Arc::new(UnexpectedBackend {
            calls: Arc::clone(&calls),
        }));
        let (oauth, issued) = issue_access_token(&[]);
        let provider = activated_provider(oauth, signer);
        let cx = Cx::for_testing();
        let result = fastmcp_core::block_on(provider.issue_id_token(
            &cx,
            &issued.access_token,
            None,
            signing_deadline(),
        ))
        .0;
        assert!(matches!(result, Err(OidcError::MissingOpenIdScope)));
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn mismatched_read_back_cannot_construct_activation_or_dispatch_signing() {
        let calls = Arc::new(AtomicUsize::new(0));
        let signer = test_signer(Arc::new(UnexpectedBackend {
            calls: Arc::clone(&calls),
        }));
        let oauth = Arc::new(OAuthServer::with_defaults());
        let provider = OidcProvider::with_defaults(oauth).expect("OIDC provider");
        let canonical = signer
            .canonical_public_jwks()
            .expect("canonical external public JWKS");
        let mut mismatched_read_back = canonical.as_bytes().to_vec();
        let final_byte = mismatched_read_back
            .last_mut()
            .expect("canonical JWKS is nonempty");
        *final_byte ^= 1;

        assert!(matches!(
            provider.create_id_token_signing_activation(
                signer,
                canonical,
                "https://fastmcp.invalid/oidc/jwks",
                &mismatched_read_back,
            ),
            Err(OidcError::SigningError(_))
        ));
        assert!(provider.activated_jwks_document().is_err());
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn cancellation_after_dispatch_exposes_no_id_token() {
        let calls = Arc::new(AtomicUsize::new(0));
        let signer = test_signer(Arc::new(CancellationAfterDispatchBackend {
            calls: Arc::clone(&calls),
        }));
        let (oauth, issued) = issue_access_token(&["openid"]);
        let provider = activated_provider(oauth, signer);
        let cx = Cx::for_testing();

        let result = fastmcp_core::block_on(provider.issue_id_token(
            &cx,
            &issued.access_token,
            None,
            signing_deadline(),
        ))
        .0;
        assert!(matches!(
            result,
            Err(OidcError::ExternalSigning(
                JwsSigningError::CancelledAfterDispatch(_)
            ))
        ));
        assert!(cx.is_cancel_requested());
        assert_eq!(calls.load(Ordering::Acquire), 1);
    }
}
