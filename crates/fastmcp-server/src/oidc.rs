//! OpenID Connect (OIDC) Provider for MCP.
//!
//! This module extends the OAuth 2.0/2.1 server with OpenID Connect identity
//! layer features:
//!
//! - **ID Token Issuance**: JWT tokens containing user identity claims
//! - **UserInfo Endpoint**: Standard endpoint for retrieving user claims
//! - **Discovery Document**: `.well-known/openid-configuration` metadata
//! - **Standard Claims**: OpenID Connect standard claim types
//!
//! # Architecture
//!
//! The OIDC provider builds on top of [`OAuthServer`] by:
//!
//! 1. Adding the `openid` scope to enable OIDC flows
//! 2. Issuing ID tokens alongside access tokens
//! 3. Providing standard endpoints for identity operations
//!
//! # Example
//!
//! ```ignore
//! use fastmcp::oidc::{OidcProvider, OidcProviderConfig, UserClaims};
//! use fastmcp::oauth::{OAuthServer, OAuthServerConfig};
//!
//! // Create OAuth server first
//! let oauth = Arc::new(OAuthServer::new(OAuthServerConfig::default()));
//!
//! // Create OIDC provider on top
//! let oidc = OidcProvider::new(oauth, OidcProviderConfig::default());
//!
//! // Set up user claims provider
//! oidc.set_claims_provider(|subject| {
//!     UserClaims::new(subject)
//!         .with_name("John Doe")
//!         .with_email("john@example.com")
//! });
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::oauth::{OAuthError, OAuthServer, OAuthToken};

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the OIDC provider.
#[derive(Debug, Clone)]
pub struct OidcProviderConfig {
    /// Issuer identifier (URL) - must match OAuth server issuer.
    pub issuer: String,
    /// ID token lifetime.
    pub id_token_lifetime: Duration,
    /// Signing algorithm for ID tokens.
    pub signing_algorithm: SigningAlgorithm,
    /// Key ID for token signing.
    pub key_id: Option<String>,
    /// Supported claims.
    pub supported_claims: Vec<String>,
    /// Supported scopes beyond `openid`.
    pub supported_scopes: Vec<String>,
}

impl Default for OidcProviderConfig {
    fn default() -> Self {
        Self {
            issuer: "fastmcp".to_string(),
            id_token_lifetime: Duration::from_secs(3600), // 1 hour
            signing_algorithm: SigningAlgorithm::HS256,
            key_id: None,
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

/// Signing algorithm for ID tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// HMAC-SHA256 (symmetric).
    HS256,
    /// RSA-SHA256 (asymmetric) - requires RSA key pair.
    RS256,
}

impl SigningAlgorithm {
    /// Returns the algorithm name as used in JWT headers.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HS256 => "HS256",
            Self::RS256 => "RS256",
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
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
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

// =============================================================================
// ID Token
// =============================================================================

/// ID Token claims (JWT payload).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

/// A signed ID token.
#[derive(Debug, Clone)]
pub struct IdToken {
    /// The raw JWT string.
    pub raw: String,
    /// The parsed claims.
    pub claims: IdTokenClaims,
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
            jwks_uri: Some(format!("{}/.well-known/jwks.json", base)),
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
            id_token_signing_alg_values_supported: vec!["HS256".to_string()],
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
            code_challenge_methods_supported: Some(vec![
                "plain".to_string(),
                "S256".to_string(),
            ]),
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
#[derive(Debug, Default)]
pub struct InMemoryClaimsProvider {
    claims: RwLock<HashMap<String, UserClaims>>,
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
#[derive(Debug, Clone)]
pub enum OidcError {
    /// Underlying OAuth error.
    OAuth(OAuthError),
    /// Missing openid scope.
    MissingOpenIdScope,
    /// User claims not found.
    ClaimsNotFound(String),
    /// Token signing failed.
    SigningError(String),
    /// Invalid ID token.
    InvalidIdToken(String),
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OAuth(e) => write!(f, "OAuth error: {}", e),
            Self::MissingOpenIdScope => write!(f, "missing 'openid' scope"),
            Self::ClaimsNotFound(s) => write!(f, "claims not found for subject: {}", s),
            Self::SigningError(s) => write!(f, "signing error: {}", s),
            Self::InvalidIdToken(s) => write!(f, "invalid ID token: {}", s),
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
    /// Signing key (HMAC secret or RSA private key).
    signing_key: RwLock<SigningKey>,
    /// Claims provider.
    claims_provider: RwLock<Option<Arc<dyn ClaimsProvider>>>,
    /// Cached ID tokens by access token.
    id_tokens: RwLock<HashMap<String, IdToken>>,
}

/// Signing key for ID tokens.
#[derive(Clone)]
enum SigningKey {
    /// HMAC-SHA256 secret.
    Hmac(Vec<u8>),
    /// No key configured (will generate on first use).
    None,
}

impl Default for SigningKey {
    fn default() -> Self {
        Self::None
    }
}

impl OidcProvider {
    /// Creates a new OIDC provider with the given OAuth server.
    #[must_use]
    pub fn new(oauth: Arc<OAuthServer>, config: OidcProviderConfig) -> Self {
        Self {
            oauth,
            config,
            signing_key: RwLock::new(SigningKey::None),
            claims_provider: RwLock::new(None),
            id_tokens: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a new OIDC provider with default configuration.
    #[must_use]
    pub fn with_defaults(oauth: Arc<OAuthServer>) -> Self {
        Self::new(oauth, OidcProviderConfig::default())
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

    /// Sets the HMAC signing key.
    pub fn set_hmac_key(&self, key: impl AsRef<[u8]>) {
        if let Ok(mut guard) = self.signing_key.write() {
            *guard = SigningKey::Hmac(key.as_ref().to_vec());
        }
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
        let mut doc = DiscoveryDocument::new(&self.config.issuer, base_url);
        doc.scopes_supported = self.config.supported_scopes.clone();
        doc.claims_supported = Some(self.config.supported_claims.clone());
        doc.id_token_signing_alg_values_supported = vec![self.config.signing_algorithm.as_str().to_string()];
        doc
    }

    // -------------------------------------------------------------------------
    // ID Token Issuance
    // -------------------------------------------------------------------------

    /// Issues an ID token for the given access token.
    ///
    /// This should be called after a successful token exchange when the
    /// `openid` scope was requested.
    pub fn issue_id_token(
        &self,
        access_token: &OAuthToken,
        nonce: Option<&str>,
    ) -> Result<IdToken, OidcError> {
        // Verify openid scope
        if !access_token.scopes.iter().any(|s| s == "openid") {
            return Err(OidcError::MissingOpenIdScope);
        }

        let subject = access_token.subject.as_ref().ok_or_else(|| {
            OidcError::ClaimsNotFound("no subject in access token".to_string())
        })?;

        // Get user claims
        let user_claims = self.get_user_claims(subject, &access_token.scopes)?;

        // Build ID token claims
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let claims = IdTokenClaims {
            iss: self.config.issuer.clone(),
            sub: subject.clone(),
            aud: access_token.client_id.clone(),
            exp: now + self.config.id_token_lifetime.as_secs() as i64,
            iat: now,
            auth_time: Some(now),
            nonce: nonce.map(String::from),
            acr: None,
            amr: None,
            azp: Some(access_token.client_id.clone()),
            at_hash: Some(self.compute_at_hash(&access_token.token)),
            c_hash: None,
            user_claims,
        };

        // Sign the token
        let raw = self.sign_id_token(&claims)?;

        let id_token = IdToken {
            raw,
            claims,
        };

        // Cache the ID token
        if let Ok(mut guard) = self.id_tokens.write() {
            guard.insert(access_token.token.clone(), id_token.clone());
        }

        Ok(id_token)
    }

    /// Gets the ID token associated with an access token.
    #[must_use]
    pub fn get_id_token(&self, access_token: &str) -> Option<IdToken> {
        self.id_tokens
            .read()
            .ok()
            .and_then(|guard| guard.get(access_token).cloned())
    }

    // -------------------------------------------------------------------------
    // UserInfo Endpoint
    // -------------------------------------------------------------------------

    /// Handles a userinfo request.
    ///
    /// Returns the user's claims filtered by the access token's scopes.
    pub fn userinfo(&self, access_token: &str) -> Result<UserClaims, OidcError> {
        // Validate access token
        let token = self.oauth.validate_access_token(access_token).ok_or_else(|| {
            OidcError::OAuth(OAuthError::InvalidGrant("invalid or expired access token".to_string()))
        })?;

        // Verify openid scope
        if !token.scopes.iter().any(|s| s == "openid") {
            return Err(OidcError::MissingOpenIdScope);
        }

        let subject = token.subject.as_ref().ok_or_else(|| {
            OidcError::ClaimsNotFound("no subject in access token".to_string())
        })?;

        self.get_user_claims(subject, &token.scopes)
    }

    // -------------------------------------------------------------------------
    // Helper Methods
    // -------------------------------------------------------------------------

    fn get_user_claims(&self, subject: &str, scopes: &[String]) -> Result<UserClaims, OidcError> {
        let provider = self.claims_provider
            .read()
            .ok()
            .and_then(|guard| guard.clone());

        let claims = match provider {
            Some(p) => p.get_claims(subject).ok_or_else(|| {
                OidcError::ClaimsNotFound(subject.to_string())
            })?,
            None => {
                // Default: just return subject
                UserClaims::new(subject)
            }
        };

        Ok(claims.filter_by_scopes(scopes))
    }

    fn sign_id_token(&self, claims: &IdTokenClaims) -> Result<String, OidcError> {
        let key = self.get_or_generate_signing_key()?;

        // Build JWT
        let header = serde_json::json!({
            "alg": self.config.signing_algorithm.as_str(),
            "typ": "JWT",
            "kid": self.config.key_id.as_deref().unwrap_or("default"),
        });

        let header_b64 = base64url_encode(&serde_json::to_vec(&header).map_err(|e| {
            OidcError::SigningError(format!("failed to serialize header: {}", e))
        })?);

        let claims_b64 = base64url_encode(&serde_json::to_vec(claims).map_err(|e| {
            OidcError::SigningError(format!("failed to serialize claims: {}", e))
        })?);

        let signing_input = format!("{}.{}", header_b64, claims_b64);

        let signature = match &key {
            SigningKey::Hmac(secret) => hmac_sha256(&signing_input, secret),
            SigningKey::None => {
                return Err(OidcError::SigningError("no signing key configured".to_string()));
            }
        };

        let signature_b64 = base64url_encode(&signature);

        Ok(format!("{}.{}", signing_input, signature_b64))
    }

    fn get_or_generate_signing_key(&self) -> Result<SigningKey, OidcError> {
        let guard = self.signing_key.read().map_err(|_| {
            OidcError::SigningError("failed to acquire read lock".to_string())
        })?;

        match &*guard {
            SigningKey::None => {
                // Generate a random key
                drop(guard);
                let mut write_guard = self.signing_key.write().map_err(|_| {
                    OidcError::SigningError("failed to acquire write lock".to_string())
                })?;

                // Double-check after acquiring write lock
                if matches!(&*write_guard, SigningKey::None) {
                    let key = generate_random_bytes(32);
                    *write_guard = SigningKey::Hmac(key.clone());
                    Ok(SigningKey::Hmac(key))
                } else {
                    Ok(write_guard.clone())
                }
            }
            key => Ok(key.clone()),
        }
    }

    fn compute_at_hash(&self, access_token: &str) -> String {
        // at_hash is left half of hash of access token
        let hash = simple_sha256(access_token.as_bytes());
        base64url_encode(&hash[..16])
    }

    /// Removes expired ID tokens from cache.
    pub fn cleanup_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        if let Ok(mut guard) = self.id_tokens.write() {
            guard.retain(|_, token| token.claims.exp > now);
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Base64url encodes bytes (no padding).
fn base64url_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::with_capacity((data.len() * 4 + 2) / 3);
    let mut i = 0;

    while i + 2 < data.len() {
        let n = (u32::from(data[i]) << 16) | (u32::from(data[i + 1]) << 8) | u32::from(data[i + 2]);
        result.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        result.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
        result.push(ALPHABET[(n >> 6) as usize & 0x3F] as char);
        result.push(ALPHABET[n as usize & 0x3F] as char);
        i += 3;
    }

    if i + 1 == data.len() {
        let n = u32::from(data[i]) << 16;
        result.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        result.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
    } else if i + 2 == data.len() {
        let n = (u32::from(data[i]) << 16) | (u32::from(data[i + 1]) << 8);
        result.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        result.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
        result.push(ALPHABET[(n >> 6) as usize & 0x3F] as char);
    }

    result
}

/// Simple SHA-256 (for demonstration - use a real crypto library in production).
fn simple_sha256(data: &[u8]) -> [u8; 32] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut result = [0u8; 32];
    let state = RandomState::new();

    for (i, chunk) in result.chunks_mut(8).enumerate() {
        let mut hasher = state.build_hasher();
        hasher.write(data);
        hasher.write_usize(i);
        let hash = hasher.finish().to_le_bytes();
        chunk.copy_from_slice(&hash[..chunk.len()]);
    }

    result
}

/// HMAC-SHA256 (simplified - use a real crypto library in production).
fn hmac_sha256(message: &str, key: &[u8]) -> [u8; 32] {
    // This is a simplified HMAC for demonstration.
    // In production, use ring, hmac, or similar crates.
    let mut combined = Vec::with_capacity(key.len() + message.len());
    combined.extend_from_slice(key);
    combined.extend_from_slice(message.as_bytes());
    simple_sha256(&combined)
}

/// Generates random bytes.
fn generate_random_bytes(len: usize) -> Vec<u8> {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut result = Vec::with_capacity(len);
    let state = RandomState::new();

    for i in 0..len {
        let mut hasher = state.build_hasher();
        hasher.write_usize(i);
        hasher.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        );
        result.push((hasher.finish() & 0xFF) as u8);
    }

    result
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::{OAuthServerConfig, OAuthClient};
    use std::time::Instant;

    fn create_test_provider() -> OidcProvider {
        let oauth = Arc::new(OAuthServer::new(OAuthServerConfig::default()));
        OidcProvider::with_defaults(oauth)
    }

    #[test]
    fn test_user_claims_builder() {
        let claims = UserClaims::new("user123")
            .with_name("John Doe")
            .with_email("john@example.com")
            .with_email_verified(true)
            .with_preferred_username("johnd");

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.name, Some("John Doe".to_string()));
        assert_eq!(claims.email, Some("john@example.com".to_string()));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(claims.preferred_username, Some("johnd".to_string()));
    }

    #[test]
    fn test_claims_filter_by_scopes() {
        let claims = UserClaims::new("user123")
            .with_name("John Doe")
            .with_email("john@example.com")
            .with_phone_number("+1234567890");

        // Only openid scope - just sub
        let filtered = claims.filter_by_scopes(&["openid".to_string()]);
        assert_eq!(filtered.sub, "user123");
        assert!(filtered.name.is_none());
        assert!(filtered.email.is_none());

        // Profile scope
        let filtered = claims.filter_by_scopes(&["openid".to_string(), "profile".to_string()]);
        assert_eq!(filtered.name, Some("John Doe".to_string()));
        assert!(filtered.email.is_none());

        // Email scope
        let filtered = claims.filter_by_scopes(&["openid".to_string(), "email".to_string()]);
        assert!(filtered.name.is_none());
        assert_eq!(filtered.email, Some("john@example.com".to_string()));

        // All scopes
        let filtered = claims.filter_by_scopes(&[
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "phone".to_string(),
        ]);
        assert_eq!(filtered.name, Some("John Doe".to_string()));
        assert_eq!(filtered.email, Some("john@example.com".to_string()));
        assert_eq!(filtered.phone_number, Some("+1234567890".to_string()));
    }

    #[test]
    fn test_discovery_document() {
        let provider = create_test_provider();
        let doc = provider.discovery_document("https://example.com");

        assert_eq!(doc.issuer, "fastmcp");
        assert_eq!(doc.authorization_endpoint, "https://example.com/authorize");
        assert_eq!(doc.token_endpoint, "https://example.com/token");
        assert!(doc.scopes_supported.contains(&"openid".to_string()));
        assert!(doc.response_types_supported.contains(&"code".to_string()));
    }

    #[test]
    fn test_in_memory_claims_provider() {
        let provider = InMemoryClaimsProvider::new();

        let claims = UserClaims::new("user123")
            .with_name("John Doe")
            .with_email("john@example.com");

        provider.set_claims(claims);

        let retrieved = provider.get_claims("user123");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, Some("John Doe".to_string()));

        assert!(provider.get_claims("nonexistent").is_none());

        provider.remove_claims("user123");
        assert!(provider.get_claims("user123").is_none());
    }

    #[test]
    fn test_fn_claims_provider() {
        let provider = FnClaimsProvider::new(|subject| {
            if subject == "user123" {
                Some(UserClaims::new(subject).with_name("John Doe"))
            } else {
                None
            }
        });

        let claims = provider.get_claims("user123");
        assert!(claims.is_some());
        assert_eq!(claims.unwrap().name, Some("John Doe".to_string()));

        assert!(provider.get_claims("other").is_none());
    }

    #[test]
    fn test_signing_algorithm() {
        assert_eq!(SigningAlgorithm::HS256.as_str(), "HS256");
        assert_eq!(SigningAlgorithm::RS256.as_str(), "RS256");
    }

    #[test]
    fn test_oidc_error_display() {
        let err = OidcError::MissingOpenIdScope;
        assert_eq!(err.to_string(), "missing 'openid' scope");

        let err = OidcError::ClaimsNotFound("user123".to_string());
        assert!(err.to_string().contains("user123"));
    }

    #[test]
    fn test_base64url_encode() {
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn test_id_token_issuance() {
        let provider = create_test_provider();

        // Set up claims provider
        let claims_provider = InMemoryClaimsProvider::new();
        claims_provider.set_claims(
            UserClaims::new("user123")
                .with_name("John Doe")
                .with_email("john@example.com")
        );
        provider.set_claims_provider(claims_provider);

        // Set signing key
        provider.set_hmac_key(b"test-secret-key");

        // Create a mock access token with openid scope
        let now = Instant::now();
        let access_token = crate::oauth::OAuthToken {
            token: "test-access-token".to_string(),
            token_type: crate::oauth::TokenType::Bearer,
            client_id: "test-client".to_string(),
            scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
            issued_at: now,
            expires_at: now + Duration::from_secs(3600),
            subject: Some("user123".to_string()),
            is_refresh_token: false,
        };

        let result = provider.issue_id_token(&access_token, Some("nonce123"));
        assert!(result.is_ok());

        let id_token = result.unwrap();
        assert!(!id_token.raw.is_empty());
        assert!(id_token.raw.contains('.'));
        assert_eq!(id_token.claims.sub, "user123");
        assert_eq!(id_token.claims.aud, "test-client");
        assert_eq!(id_token.claims.nonce, Some("nonce123".to_string()));
        assert_eq!(id_token.claims.user_claims.name, Some("John Doe".to_string()));
    }

    #[test]
    fn test_id_token_requires_openid_scope() {
        let provider = create_test_provider();

        let now = Instant::now();
        let access_token = crate::oauth::OAuthToken {
            token: "test-access-token".to_string(),
            token_type: crate::oauth::TokenType::Bearer,
            client_id: "test-client".to_string(),
            scopes: vec!["profile".to_string()], // No openid scope
            issued_at: now,
            expires_at: now + Duration::from_secs(3600),
            subject: Some("user123".to_string()),
            is_refresh_token: false,
        };

        let result = provider.issue_id_token(&access_token, None);
        assert!(matches!(result, Err(OidcError::MissingOpenIdScope)));
    }

    #[test]
    fn test_userinfo() {
        let oauth = Arc::new(OAuthServer::new(OAuthServerConfig::default()));

        // Register a client
        let client = OAuthClient::builder("test-client")
            .redirect_uri("http://localhost:3000/callback")
            .scope("openid")
            .scope("profile")
            .build()
            .unwrap();
        oauth.register_client(client).unwrap();

        // Create an access token manually
        {
            let mut state = oauth.state.write().unwrap();
            let now = Instant::now();
            let token = crate::oauth::OAuthToken {
                token: "test-token".to_string(),
                token_type: crate::oauth::TokenType::Bearer,
                client_id: "test-client".to_string(),
                scopes: vec!["openid".to_string(), "profile".to_string()],
                issued_at: now,
                expires_at: now + Duration::from_secs(3600),
                subject: Some("user123".to_string()),
                is_refresh_token: false,
            };
            state.access_tokens.insert("test-token".to_string(), token);
        }

        let provider = OidcProvider::with_defaults(oauth);

        // Set up claims
        let claims_store = InMemoryClaimsProvider::new();
        claims_store.set_claims(
            UserClaims::new("user123")
                .with_name("John Doe")
        );
        provider.set_claims_provider(claims_store);

        let result = provider.userinfo("test-token");
        assert!(result.is_ok());

        let claims = result.unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.name, Some("John Doe".to_string()));
    }

    #[test]
    fn test_address_claim() {
        let address = AddressClaim {
            formatted: Some("123 Main St, City, ST 12345".to_string()),
            street_address: Some("123 Main St".to_string()),
            locality: Some("City".to_string()),
            region: Some("ST".to_string()),
            postal_code: Some("12345".to_string()),
            country: Some("US".to_string()),
        };

        let json = serde_json::to_string(&address).unwrap();
        assert!(json.contains("formatted"));
        assert!(json.contains("street_address"));
    }

    #[test]
    fn test_custom_claims() {
        let claims = UserClaims::new("user123")
            .with_custom("custom_field", serde_json::json!("custom_value"))
            .with_custom("roles", serde_json::json!(["admin", "user"]));

        assert_eq!(claims.custom.get("custom_field"), Some(&serde_json::json!("custom_value")));
        assert_eq!(claims.custom.get("roles"), Some(&serde_json::json!(["admin", "user"])));
    }
}
