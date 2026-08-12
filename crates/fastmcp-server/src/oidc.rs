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

use crate::oauth::{OAuthError, OAuthServer, OAuthServerConfig, OAuthToken, validate_oauth_issuer};

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
#[derive(Clone)]
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

    /// Generates the discovery document.
    #[must_use]
    pub fn discovery_document(&self, base_url: impl Into<String>) -> DiscoveryDocument {
        let base_url = base_url.into();
        let mut doc = DiscoveryDocument::new(&self.config.issuer, base_url.clone());
        doc.scopes_supported = self.config.supported_scopes.clone();
        doc.claims_supported = Some(self.config.supported_claims.clone());
        // Do not advertise an algorithm or JWKS while FND-09 external signer
        // custody is unavailable.
        doc.id_token_signing_alg_values_supported = Vec::new();
        doc.jwks_uri = None;
        doc
    }

    // -------------------------------------------------------------------------
    // ID Token Issuance
    // -------------------------------------------------------------------------

    /// ID-token issuance is intentionally unavailable until FND-09 admits an
    /// externally custodied signer. No local JWT is constructed or cached.
    pub fn issue_id_token(
        &self,
        _access_token: &OAuthToken,
        _nonce: Option<&str>,
    ) -> Result<IdToken, OidcError> {
        Err(OidcError::SigningError(
            "OIDC ID-token issuance is unavailable until the FND-09 external signer/provider is admitted"
                .to_string(),
        ))
    }

    // -------------------------------------------------------------------------
    // UserInfo Endpoint
    // -------------------------------------------------------------------------

    /// Handles a userinfo request.
    ///
    /// Returns the user's claims filtered by the access token's scopes.
    pub fn userinfo(&self, access_token: &str) -> Result<UserClaims, OidcError> {
        // Validate access token
        let validated = self
            .oauth
            .validate_access_token(access_token)
            .ok_or_else(|| {
                OidcError::OAuth(OAuthError::InvalidGrant(
                    "invalid or expired access token".to_string(),
                ))
            })?;

        // Verify openid scope
        if !validated.scopes.iter().any(|s| s == "openid") {
            return Err(OidcError::MissingOpenIdScope);
        }

        let subject = validated
            .subject
            .as_ref()
            .ok_or_else(|| OidcError::ClaimsNotFound("no subject in access token".to_string()))?;

        self.get_user_claims(subject, &validated.scopes)
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
    fn issuance_fails_closed_without_external_signer() {
        let oauth = Arc::new(OAuthServer::new(crate::oauth::OAuthServerConfig::default()));
        let provider = OidcProvider::with_defaults(oauth).expect("default provider");
        let token = OAuthToken {
            token: "opaque".to_string(),
            token_type: crate::oauth::TokenType::Bearer,
            client_id: "client".to_string(),
            scopes: vec!["openid".to_string()],
            resource: None,
            issued_at: std::time::Instant::now(),
            expires_at: std::time::Instant::now(),
            subject: Some("subject".to_string()),
            is_refresh_token: false,
        };
        assert!(matches!(
            provider.issue_id_token(&token, None),
            Err(OidcError::SigningError(_))
        ));
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
