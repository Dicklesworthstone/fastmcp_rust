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
    /// RS256 signing key (PEM-encoded private key).
    ///
    /// Required when `signing_algorithm = RS256`.
    pub rsa_private_key_pem: Option<Vec<u8>>,
    /// JSON Web Key Set (JWKS) served at `/.well-known/jwks.json`.
    ///
    /// Required when `signing_algorithm = RS256`.
    pub jwks: Option<serde_json::Value>,
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
            rsa_private_key_pem: None,
            jwks: None,
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
            code_challenge_methods_supported: Some(vec!["plain".to_string(), "S256".to_string()]),
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
    /// Signing key (HMAC secret).
    signing_key: RwLock<SigningKey>,
    /// Claims provider.
    claims_provider: RwLock<Option<Arc<dyn ClaimsProvider>>>,
    /// Cached ID tokens by access token.
    id_tokens: RwLock<HashMap<String, IdToken>>,
}

/// Signing key for ID tokens.
#[derive(Clone, Default)]
enum SigningKey {
    /// HMAC-SHA256 secret.
    Hmac(Vec<u8>),
    /// No key configured (will generate on first use).
    #[default]
    None,
}

fn validate_oidc_config(config: &OidcProviderConfig) -> Result<(), OidcError> {
    match config.signing_algorithm {
        SigningAlgorithm::HS256 => Ok(()),
        SigningAlgorithm::RS256 => {
            #[cfg(feature = "jwt")]
            {
                let kid = config.key_id.as_deref().ok_or_else(|| {
                    OidcError::SigningError("RS256 requires `key_id` to be set".to_string())
                })?;

                let pem = config.rsa_private_key_pem.as_ref().ok_or_else(|| {
                    OidcError::SigningError("RS256 requires `rsa_private_key_pem`".to_string())
                })?;
                // Fail fast: reject invalid PEM so we never advertise RS256 with a broken signer.
                jsonwebtoken::EncodingKey::from_rsa_pem(pem).map_err(|e| {
                    OidcError::SigningError(format!("invalid RSA private key PEM: {e}"))
                })?;

                let jwks = config.jwks.as_ref().ok_or_else(|| {
                    OidcError::SigningError("RS256 requires `jwks` (JWKS JSON)".to_string())
                })?;

                // Validate JWKS shape and that it includes a plausible RSA key with the configured kid.
                let keys = jwks.get("keys").and_then(|v| v.as_array()).ok_or_else(|| {
                    OidcError::SigningError(
                        "JWKS must be an object with a `keys` array".to_string(),
                    )
                })?;

                let mut found = false;
                for key in keys {
                    let Some(obj) = key.as_object() else { continue };
                    let key_kid = obj.get("kid").and_then(|v| v.as_str());
                    if key_kid != Some(kid) {
                        continue;
                    }
                    let kty = obj.get("kty").and_then(|v| v.as_str());
                    if kty != Some("RSA") {
                        continue;
                    }
                    // Require the minimal RSA public key components so the JWKS is usable.
                    if obj.get("n").and_then(|v| v.as_str()).is_none()
                        || obj.get("e").and_then(|v| v.as_str()).is_none()
                    {
                        return Err(OidcError::SigningError(format!(
                            "JWKS key kid={kid} is missing RSA components `n`/`e`"
                        )));
                    }
                    found = true;
                    break;
                }

                if !found {
                    return Err(OidcError::SigningError(format!(
                        "JWKS does not contain an RSA key with kid={kid}"
                    )));
                }

                Ok(())
            }
            #[cfg(not(feature = "jwt"))]
            {
                Err(OidcError::SigningError(
                    "RS256 requires the `fastmcp-server/jwt` feature".to_string(),
                ))
            }
        }
    }
}

impl OidcProvider {
    /// Creates a new OIDC provider with the given OAuth server.
    pub fn new(oauth: Arc<OAuthServer>, config: OidcProviderConfig) -> Result<Self, OidcError> {
        validate_oidc_config(&config)?;
        Ok(Self {
            oauth,
            config,
            signing_key: RwLock::new(SigningKey::None),
            claims_provider: RwLock::new(None),
            id_tokens: RwLock::new(HashMap::new()),
        })
    }

    /// Creates a new OIDC provider with default configuration.
    pub fn with_defaults(oauth: Arc<OAuthServer>) -> Result<Self, OidcError> {
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
        let base_url = base_url.into();
        let mut doc = DiscoveryDocument::new(&self.config.issuer, base_url.clone());
        doc.scopes_supported = self.config.supported_scopes.clone();
        doc.claims_supported = Some(self.config.supported_claims.clone());
        doc.id_token_signing_alg_values_supported =
            vec![self.config.signing_algorithm.as_str().to_string()];
        doc.jwks_uri = match self.config.signing_algorithm {
            SigningAlgorithm::HS256 => None,
            SigningAlgorithm::RS256 => Some(format!("{}/.well-known/jwks.json", base_url)),
        };
        doc
    }

    /// Returns the configured JSON Web Key Set (JWKS), if any.
    ///
    /// For HS256 this is typically `None`. For RS256 it is required and should be served at
    /// `/.well-known/jwks.json` alongside the discovery document.
    #[must_use]
    pub fn jwks(&self) -> Option<serde_json::Value> {
        self.config.jwks.clone()
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

        let subject = access_token
            .subject
            .as_ref()
            .ok_or_else(|| OidcError::ClaimsNotFound("no subject in access token".to_string()))?;

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

        let issued = IdToken { raw, claims };

        // Cache the ID token
        if let Ok(mut guard) = self.id_tokens.write() {
            guard.insert(access_token.token.clone(), issued.clone());
        }

        Ok(issued)
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

        Ok(claims.filter_by_scopes(scopes))
    }

    fn sign_id_token(&self, claims: &IdTokenClaims) -> Result<String, OidcError> {
        match self.config.signing_algorithm {
            SigningAlgorithm::HS256 => {
                let key = self.get_or_generate_signing_key()?;

                // Build JWT (manual, minimal dependencies)
                let header = serde_json::json!({
                    "alg": "HS256",
                    "typ": "JWT",
                    "kid": self.config.key_id.as_deref().unwrap_or("default"),
                });

                let header_b64 = base64url_encode(&serde_json::to_vec(&header).map_err(|e| {
                    OidcError::SigningError(format!("failed to serialize header: {e}"))
                })?);

                let claims_b64 = base64url_encode(&serde_json::to_vec(claims).map_err(|e| {
                    OidcError::SigningError(format!("failed to serialize claims: {e}"))
                })?);

                let signing_input = format!("{header_b64}.{claims_b64}");

                let signature = match &key {
                    SigningKey::Hmac(secret) => hmac_sha256(&signing_input, secret)?,
                    SigningKey::None => {
                        return Err(OidcError::SigningError(
                            "no signing key configured".to_string(),
                        ));
                    }
                };

                let signature_b64 = base64url_encode(&signature);
                Ok(format!("{signing_input}.{signature_b64}"))
            }
            SigningAlgorithm::RS256 => {
                #[cfg(feature = "jwt")]
                {
                    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

                    let pem = self.config.rsa_private_key_pem.as_ref().ok_or_else(|| {
                        OidcError::SigningError("RS256 requires `rsa_private_key_pem`".to_string())
                    })?;

                    let kid = self.config.key_id.as_deref().ok_or_else(|| {
                        OidcError::SigningError("RS256 requires `key_id` to be set".to_string())
                    })?;

                    let mut header = Header::new(Algorithm::RS256);
                    header.typ = Some("JWT".to_string());
                    header.kid = Some(kid.to_string());

                    let key = EncodingKey::from_rsa_pem(pem).map_err(|e| {
                        OidcError::SigningError(format!("failed to parse RSA private key PEM: {e}"))
                    })?;

                    encode(&header, claims, &key)
                        .map_err(|e| OidcError::SigningError(format!("RS256 signing failed: {e}")))
                }
                #[cfg(not(feature = "jwt"))]
                {
                    Err(OidcError::SigningError(
                        "RS256 requires the `fastmcp-server/jwt` feature".to_string(),
                    ))
                }
            }
        }
    }

    fn get_or_generate_signing_key(&self) -> Result<SigningKey, OidcError> {
        let guard = self
            .signing_key
            .read()
            .map_err(|_| OidcError::SigningError("failed to acquire read lock".to_string()))?;

        match &*guard {
            SigningKey::None => {
                // Generate a random key
                drop(guard);
                let mut write_guard = self.signing_key.write().map_err(|_| {
                    OidcError::SigningError("failed to acquire write lock".to_string())
                })?;

                // Double-check after acquiring write lock
                if matches!(&*write_guard, SigningKey::None) {
                    let key = generate_random_bytes(32)?;
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
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    URL_SAFE_NO_PAD.encode(data)
}

fn simple_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hmac_sha256(message: &str, key: &[u8]) -> Result<[u8; 32], OidcError> {
    use hmac::Mac;
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| OidcError::SigningError(format!("invalid HMAC key: {e}")))?;
    mac.update(message.as_bytes());

    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Generates random bytes.
fn generate_random_bytes(len: usize) -> Result<Vec<u8>, OidcError> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf)
        .map_err(|e| OidcError::SigningError(format!("secure random generation failed: {e}")))?;
    Ok(buf)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::{
        AuthorizationRequest, CodeChallengeMethod, OAuthClient, OAuthServerConfig, TokenRequest,
    };

    const TEST_CLIENT_ID: &str = "test-client";
    const TEST_REDIRECT_URI: &str = "http://localhost:3000/callback";
    const TEST_CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn create_test_provider() -> OidcProvider {
        let oauth = Arc::new(OAuthServer::new(OAuthServerConfig::default()));
        OidcProvider::with_defaults(oauth).expect("create provider")
    }

    fn issue_token_via_auth_code(oauth: &OAuthServer, scopes: &[&str], subject: &str) -> String {
        let mut client_builder =
            OAuthClient::builder(TEST_CLIENT_ID).redirect_uri(TEST_REDIRECT_URI);
        for scope in scopes {
            client_builder = client_builder.scope(*scope);
        }
        let client = client_builder.build().expect("build client");
        oauth.register_client(client).expect("register client");

        let auth_request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: TEST_CLIENT_ID.to_string(),
            redirect_uri: TEST_REDIRECT_URI.to_string(),
            scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
            state: Some("state-123".to_string()),
            code_challenge: TEST_CODE_VERIFIER.to_string(),
            code_challenge_method: CodeChallengeMethod::Plain,
        };

        let (code, _redirect) = oauth
            .authorize(&auth_request, Some(subject.to_string()))
            .expect("authorize");
        oauth
            .token(&TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some(code),
                redirect_uri: Some(TEST_REDIRECT_URI.to_string()),
                client_id: TEST_CLIENT_ID.to_string(),
                client_secret: None,
                code_verifier: Some(TEST_CODE_VERIFIER.to_string()),
                refresh_token: None,
                scopes: None,
            })
            .expect("exchange token")
            .access_token
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
        assert!(doc.jwks_uri.is_none(), "HS256 must not publish jwks_uri");
        assert!(doc.scopes_supported.contains(&"openid".to_string()));
        assert!(doc.response_types_supported.contains(&"code".to_string()));
    }

    #[test]
    #[cfg(not(feature = "jwt"))]
    fn test_rs256_requires_jwt_feature() {
        let oauth = Arc::new(OAuthServer::new(OAuthServerConfig::default()));
        let mut config = OidcProviderConfig::default();
        config.signing_algorithm = SigningAlgorithm::RS256;
        config.key_id = Some("test-kid".to_string());
        config.rsa_private_key_pem = Some(b"dummy".to_vec());
        config.jwks = Some(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": "test-kid",
                "n": "x",
                "e": "AQAB"
            }]
        }));

        let res = OidcProvider::new(oauth, config);
        assert!(
            res.is_err(),
            "expected RS256 to be rejected without jwt feature"
        );
    }

    #[test]
    #[cfg(feature = "jwt")]
    fn test_rs256_rejects_invalid_pem() {
        let oauth = Arc::new(OAuthServer::new(OAuthServerConfig::default()));
        let mut config = OidcProviderConfig::default();
        config.signing_algorithm = SigningAlgorithm::RS256;
        config.key_id = Some("test-kid".to_string());
        config.rsa_private_key_pem = Some(b"not a pem".to_vec());
        config.jwks = Some(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": "test-kid",
                "n": "x",
                "e": "AQAB"
            }]
        }));

        let res = OidcProvider::new(oauth, config);
        assert!(res.is_err(), "expected invalid PEM to be rejected");
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
                .with_email("john@example.com"),
        );
        provider.set_claims_provider(claims_provider);

        // Set signing key
        provider.set_hmac_key(b"test-secret-key");

        let oauth_at = provider
            .oauth()
            .validate_access_token(&issue_token_via_auth_code(
                provider.oauth().as_ref(),
                &["openid", "profile", "email"],
                "user123",
            ))
            .expect("valid access token");

        let result = provider.issue_id_token(&oauth_at, Some("nonce123"));
        let issued = result.expect("issue id token");
        assert!(!issued.raw.is_empty());
        assert!(issued.raw.contains('.'));
        assert_eq!(issued.claims.sub, "user123");
        assert_eq!(issued.claims.aud, TEST_CLIENT_ID);
        assert_eq!(issued.claims.nonce, Some("nonce123".to_string()));
        assert_eq!(issued.claims.user_claims.name, Some("John Doe".to_string()));
    }

    #[test]
    fn test_id_token_requires_openid_scope() {
        let provider = create_test_provider();
        let oauth_at = provider
            .oauth()
            .validate_access_token(&issue_token_via_auth_code(
                provider.oauth().as_ref(),
                &["profile"],
                "user123",
            ))
            .expect("valid access token");

        let result = provider.issue_id_token(&oauth_at, None);
        assert!(matches!(result, Err(OidcError::MissingOpenIdScope)));
    }

    #[test]
    fn test_userinfo() {
        let oauth = Arc::new(OAuthServer::new(OAuthServerConfig::default()));

        let provider = OidcProvider::with_defaults(oauth).expect("create provider");

        // Set up claims
        let claims_store = InMemoryClaimsProvider::new();
        claims_store.set_claims(UserClaims::new("user123").with_name("John Doe"));
        provider.set_claims_provider(claims_store);

        let result = provider.userinfo(&issue_token_via_auth_code(
            provider.oauth().as_ref(),
            &["openid", "profile"],
            "user123",
        ));
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

        assert_eq!(
            claims.custom.get("custom_field"),
            Some(&serde_json::json!("custom_value"))
        );
        assert_eq!(
            claims.custom.get("roles"),
            Some(&serde_json::json!(["admin", "user"]))
        );
    }

    // ── OidcProviderConfig ─────────────────────────────────────────

    #[test]
    fn config_default_values() {
        let cfg = OidcProviderConfig::default();
        assert_eq!(cfg.issuer, "fastmcp");
        assert_eq!(cfg.id_token_lifetime, Duration::from_secs(3600));
        assert_eq!(cfg.signing_algorithm, SigningAlgorithm::HS256);
        assert!(cfg.key_id.is_none());
        assert!(cfg.rsa_private_key_pem.is_none());
        assert!(cfg.jwks.is_none());
        assert!(cfg.supported_claims.contains(&"sub".to_string()));
        assert!(cfg.supported_claims.contains(&"email".to_string()));
        assert!(cfg.supported_scopes.contains(&"openid".to_string()));
        assert!(cfg.supported_scopes.contains(&"profile".to_string()));
    }

    #[test]
    fn config_debug() {
        let cfg = OidcProviderConfig::default();
        let debug = format!("{:?}", cfg);
        assert!(debug.contains("fastmcp"));
        assert!(debug.contains("HS256"));
    }

    #[test]
    fn config_clone() {
        let cfg = OidcProviderConfig::default();
        let cloned = cfg.clone();
        assert_eq!(cloned.issuer, cfg.issuer);
        assert_eq!(cloned.signing_algorithm, cfg.signing_algorithm);
    }

    // ── SigningAlgorithm ───────────────────────────────────────────

    #[test]
    fn signing_algorithm_copy() {
        let alg = SigningAlgorithm::HS256;
        let copied = alg;
        assert_eq!(alg, copied);
    }

    #[test]
    fn signing_algorithm_eq() {
        assert_eq!(SigningAlgorithm::HS256, SigningAlgorithm::HS256);
        assert_eq!(SigningAlgorithm::RS256, SigningAlgorithm::RS256);
        assert_ne!(SigningAlgorithm::HS256, SigningAlgorithm::RS256);
    }

    #[test]
    fn signing_algorithm_debug() {
        let debug = format!("{:?}", SigningAlgorithm::RS256);
        assert!(debug.contains("RS256"));
    }

    #[test]
    fn signing_algorithm_clone() {
        let alg = SigningAlgorithm::RS256;
        let cloned = alg.clone();
        assert_eq!(alg, cloned);
    }

    // ── UserClaims additional builders ─────────────────────────────

    #[test]
    fn user_claims_with_given_name() {
        let claims = UserClaims::new("u").with_given_name("Jane");
        assert_eq!(claims.given_name, Some("Jane".to_string()));
    }

    #[test]
    fn user_claims_with_family_name() {
        let claims = UserClaims::new("u").with_family_name("Smith");
        assert_eq!(claims.family_name, Some("Smith".to_string()));
    }

    #[test]
    fn user_claims_with_phone_number() {
        let claims = UserClaims::new("u").with_phone_number("+15551234567");
        assert_eq!(claims.phone_number, Some("+15551234567".to_string()));
    }

    #[test]
    fn user_claims_with_updated_at() {
        let claims = UserClaims::new("u").with_updated_at(1700000000);
        assert_eq!(claims.updated_at, Some(1700000000));
    }

    #[test]
    fn user_claims_with_picture() {
        let claims = UserClaims::new("u").with_picture("https://example.com/pic.jpg");
        assert_eq!(
            claims.picture,
            Some("https://example.com/pic.jpg".to_string())
        );
    }

    #[test]
    fn user_claims_debug() {
        let claims = UserClaims::new("dbg-user");
        let debug = format!("{:?}", claims);
        assert!(debug.contains("dbg-user"));
    }

    #[test]
    fn user_claims_clone() {
        let claims = UserClaims::new("u1").with_name("Alice");
        let cloned = claims.clone();
        assert_eq!(cloned.sub, "u1");
        assert_eq!(cloned.name, Some("Alice".to_string()));
    }

    #[test]
    fn user_claims_default() {
        let claims = UserClaims::default();
        assert_eq!(claims.sub, "");
        assert!(claims.name.is_none());
        assert!(claims.email.is_none());
        assert!(claims.custom.is_empty());
    }

    #[test]
    fn user_claims_serde_roundtrip() {
        let claims = UserClaims::new("serde-user")
            .with_name("Test")
            .with_email("test@example.com")
            .with_email_verified(true)
            .with_given_name("T")
            .with_family_name("Est")
            .with_phone_number("+1")
            .with_updated_at(123)
            .with_picture("http://pic")
            .with_preferred_username("tester")
            .with_custom("role", serde_json::json!("admin"));

        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: UserClaims = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.sub, "serde-user");
        assert_eq!(deserialized.name, Some("Test".to_string()));
        assert_eq!(deserialized.email, Some("test@example.com".to_string()));
        assert_eq!(deserialized.email_verified, Some(true));
        assert_eq!(deserialized.given_name, Some("T".to_string()));
        assert_eq!(deserialized.family_name, Some("Est".to_string()));
        assert_eq!(deserialized.phone_number, Some("+1".to_string()));
        assert_eq!(deserialized.updated_at, Some(123));
        assert_eq!(deserialized.picture, Some("http://pic".to_string()));
        assert_eq!(deserialized.preferred_username, Some("tester".to_string()));
        assert_eq!(
            deserialized.custom.get("role"),
            Some(&serde_json::json!("admin"))
        );
    }

    #[test]
    fn user_claims_serde_skip_nones() {
        let claims = UserClaims::new("minimal");
        let json = serde_json::to_string(&claims).unwrap();
        // None fields should be skipped
        assert!(!json.contains("name"));
        assert!(!json.contains("email"));
        assert!(!json.contains("phone_number"));
        assert!(json.contains("sub"));
    }

    #[test]
    fn filter_by_scopes_address() {
        let address = AddressClaim {
            formatted: Some("123 Main St".to_string()),
            ..Default::default()
        };
        let claims = UserClaims {
            sub: "u1".to_string(),
            address: Some(address),
            name: Some("Name".to_string()),
            ..Default::default()
        };

        // Only address scope
        let filtered = claims.filter_by_scopes(&["address".to_string()]);
        assert!(filtered.address.is_some());
        assert!(filtered.name.is_none());

        // Without address scope
        let filtered = claims.filter_by_scopes(&["profile".to_string()]);
        assert!(filtered.address.is_none());
        assert!(filtered.name.is_some());
    }

    #[test]
    fn filter_by_scopes_phone_verified() {
        let claims = UserClaims {
            sub: "u1".to_string(),
            phone_number: Some("+1".to_string()),
            phone_number_verified: Some(true),
            ..Default::default()
        };

        let filtered = claims.filter_by_scopes(&["phone".to_string()]);
        assert_eq!(filtered.phone_number, Some("+1".to_string()));
        assert_eq!(filtered.phone_number_verified, Some(true));

        let filtered = claims.filter_by_scopes(&["email".to_string()]);
        assert!(filtered.phone_number.is_none());
        assert!(filtered.phone_number_verified.is_none());
    }

    // ── AddressClaim ───────────────────────────────────────────────

    #[test]
    fn address_claim_default() {
        let addr = AddressClaim::default();
        assert!(addr.formatted.is_none());
        assert!(addr.street_address.is_none());
        assert!(addr.locality.is_none());
        assert!(addr.region.is_none());
        assert!(addr.postal_code.is_none());
        assert!(addr.country.is_none());
    }

    #[test]
    fn address_claim_debug() {
        let addr = AddressClaim {
            country: Some("US".to_string()),
            ..Default::default()
        };
        let debug = format!("{:?}", addr);
        assert!(debug.contains("US"));
    }

    #[test]
    fn address_claim_clone() {
        let addr = AddressClaim {
            locality: Some("NYC".to_string()),
            ..Default::default()
        };
        let cloned = addr.clone();
        assert_eq!(cloned.locality, Some("NYC".to_string()));
    }

    #[test]
    fn address_claim_serde_roundtrip() {
        let addr = AddressClaim {
            formatted: Some("123 Main St, City, ST 12345, US".to_string()),
            street_address: Some("123 Main St".to_string()),
            locality: Some("City".to_string()),
            region: Some("ST".to_string()),
            postal_code: Some("12345".to_string()),
            country: Some("US".to_string()),
        };

        let json = serde_json::to_string(&addr).unwrap();
        let deserialized: AddressClaim = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.formatted, addr.formatted);
        assert_eq!(deserialized.country, addr.country);
    }

    #[test]
    fn address_claim_serde_skip_nones() {
        let addr = AddressClaim {
            country: Some("US".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&addr).unwrap();
        assert!(json.contains("country"));
        assert!(!json.contains("formatted"));
        assert!(!json.contains("street_address"));
    }

    // ── IdTokenClaims ──────────────────────────────────────────────

    #[test]
    fn id_token_claims_debug() {
        let claims = IdTokenClaims {
            iss: "iss".to_string(),
            sub: "sub".to_string(),
            aud: "aud".to_string(),
            exp: 999,
            iat: 100,
            auth_time: None,
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            at_hash: None,
            c_hash: None,
            user_claims: UserClaims::new("sub"),
        };
        let debug = format!("{:?}", claims);
        assert!(debug.contains("iss"));
        assert!(debug.contains("sub"));
    }

    #[test]
    fn id_token_claims_clone() {
        let claims = IdTokenClaims {
            iss: "issuer".to_string(),
            sub: "subject".to_string(),
            aud: "audience".to_string(),
            exp: 999,
            iat: 100,
            auth_time: Some(100),
            nonce: Some("n".to_string()),
            acr: Some("1".to_string()),
            amr: Some(vec!["pwd".to_string()]),
            azp: Some("azp".to_string()),
            at_hash: Some("hash".to_string()),
            c_hash: Some("chash".to_string()),
            user_claims: UserClaims::new("subject"),
        };
        let cloned = claims.clone();
        assert_eq!(cloned.iss, "issuer");
        assert_eq!(cloned.nonce, Some("n".to_string()));
        assert_eq!(cloned.amr, Some(vec!["pwd".to_string()]));
    }

    #[test]
    fn id_token_claims_serialization() {
        // Note: IdTokenClaims.sub and user_claims.sub overlap due to
        // #[serde(flatten)], so we test serialization output rather than
        // a full roundtrip.
        let claims = IdTokenClaims {
            iss: "fastmcp".to_string(),
            sub: "user1".to_string(),
            aud: "client1".to_string(),
            exp: 1700001000,
            iat: 1700000000,
            auth_time: Some(1700000000),
            nonce: Some("abc".to_string()),
            acr: None,
            amr: None,
            azp: Some("client1".to_string()),
            at_hash: Some("h".to_string()),
            c_hash: None,
            user_claims: UserClaims::new("user1").with_name("Test"),
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"iss\":\"fastmcp\""));
        assert!(json.contains("\"aud\":\"client1\""));
        assert!(json.contains("\"exp\":1700001000"));
        assert!(json.contains("\"nonce\":\"abc\""));
        assert!(json.contains("\"name\":\"Test\""));
    }

    #[test]
    fn id_token_claims_serde_skip_nones() {
        let claims = IdTokenClaims {
            iss: "i".to_string(),
            sub: "s".to_string(),
            aud: "a".to_string(),
            exp: 1,
            iat: 0,
            auth_time: None,
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            at_hash: None,
            c_hash: None,
            user_claims: UserClaims::new("s"),
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("nonce"));
        assert!(!json.contains("auth_time"));
        assert!(!json.contains("acr"));
    }

    // ── IdToken ────────────────────────────────────────────────────

    #[test]
    fn id_token_debug() {
        let claims = IdTokenClaims {
            iss: "i".to_string(),
            sub: "s".to_string(),
            aud: "a".to_string(),
            exp: 1,
            iat: 0,
            auth_time: None,
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            at_hash: None,
            c_hash: None,
            user_claims: UserClaims::new("s"),
        };
        let token = IdToken {
            raw: "header.payload.sig".to_string(),
            claims,
        };
        let debug = format!("{:?}", token);
        assert!(debug.contains("header.payload.sig"));
    }

    #[test]
    fn id_token_clone() {
        let claims = IdTokenClaims {
            iss: "i".to_string(),
            sub: "s".to_string(),
            aud: "a".to_string(),
            exp: 1,
            iat: 0,
            auth_time: None,
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            at_hash: None,
            c_hash: None,
            user_claims: UserClaims::new("s"),
        };
        let token = IdToken {
            raw: "jwt-token".to_string(),
            claims,
        };
        let cloned = token.clone();
        assert_eq!(cloned.raw, "jwt-token");
        assert_eq!(cloned.claims.sub, "s");
    }

    // ── DiscoveryDocument ──────────────────────────────────────────

    #[test]
    fn discovery_document_new_defaults() {
        let doc = DiscoveryDocument::new("https://issuer.example", "https://api.example");
        assert_eq!(doc.issuer, "https://issuer.example");
        assert_eq!(doc.authorization_endpoint, "https://api.example/authorize");
        assert_eq!(doc.token_endpoint, "https://api.example/token");
        assert_eq!(
            doc.userinfo_endpoint,
            Some("https://api.example/userinfo".to_string())
        );
        assert_eq!(
            doc.revocation_endpoint,
            Some("https://api.example/revoke".to_string())
        );
        assert!(doc.jwks_uri.is_none());
        assert!(doc.registration_endpoint.is_none());
        assert!(doc.scopes_supported.contains(&"openid".to_string()));
        assert_eq!(doc.response_types_supported, vec!["code"]);
        assert_eq!(
            doc.response_modes_supported,
            Some(vec!["query".to_string()])
        );
        assert!(
            doc.grant_types_supported
                .contains(&"authorization_code".to_string())
        );
        assert!(
            doc.grant_types_supported
                .contains(&"refresh_token".to_string())
        );
        assert_eq!(doc.subject_types_supported, vec!["public"]);
        assert_eq!(doc.id_token_signing_alg_values_supported, vec!["HS256"]);
        assert!(
            doc.token_endpoint_auth_methods_supported
                .contains(&"client_secret_post".to_string())
        );
        assert!(doc.claims_supported.is_some());
        assert!(
            doc.code_challenge_methods_supported
                .as_ref()
                .unwrap()
                .contains(&"S256".to_string())
        );
    }

    #[test]
    fn discovery_document_debug() {
        let doc = DiscoveryDocument::new("iss", "http://base");
        let debug = format!("{:?}", doc);
        assert!(debug.contains("iss"));
    }

    #[test]
    fn discovery_document_clone() {
        let doc = DiscoveryDocument::new("iss", "http://base");
        let cloned = doc.clone();
        assert_eq!(cloned.issuer, "iss");
        assert_eq!(cloned.token_endpoint, doc.token_endpoint);
    }

    #[test]
    fn discovery_document_serde_roundtrip() {
        let doc = DiscoveryDocument::new("iss", "http://base");
        let json = serde_json::to_string(&doc).unwrap();
        let deserialized: DiscoveryDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.issuer, "iss");
        assert_eq!(deserialized.token_endpoint, "http://base/token");
        assert_eq!(
            deserialized.userinfo_endpoint,
            Some("http://base/userinfo".to_string())
        );
    }

    // ── OidcError ──────────────────────────────────────────────────

    #[test]
    fn oidc_error_oauth_display() {
        let inner = OAuthError::InvalidClient("bad".to_string());
        let err = OidcError::OAuth(inner);
        let msg = err.to_string();
        assert!(msg.contains("OAuth error"));
        assert!(msg.contains("bad"));
    }

    #[test]
    fn oidc_error_signing_error_display() {
        let err = OidcError::SigningError("key problem".to_string());
        assert!(err.to_string().contains("signing error"));
        assert!(err.to_string().contains("key problem"));
    }

    #[test]
    fn oidc_error_invalid_id_token_display() {
        let err = OidcError::InvalidIdToken("malformed".to_string());
        assert!(err.to_string().contains("invalid ID token"));
        assert!(err.to_string().contains("malformed"));
    }

    #[test]
    fn oidc_error_debug() {
        let err = OidcError::MissingOpenIdScope;
        let debug = format!("{:?}", err);
        assert!(debug.contains("MissingOpenIdScope"));
    }

    #[test]
    fn oidc_error_clone() {
        let err = OidcError::ClaimsNotFound("u".to_string());
        let cloned = err.clone();
        assert!(cloned.to_string().contains('u'));
    }

    #[test]
    fn oidc_error_std_error() {
        let err = OidcError::SigningError("x".to_string());
        let std_err: &dyn std::error::Error = &err;
        assert!(std_err.to_string().contains('x'));
    }

    #[test]
    fn oidc_error_from_oauth_error() {
        let oauth_err = OAuthError::InvalidGrant("expired".to_string());
        let oidc_err: OidcError = oauth_err.into();
        match &oidc_err {
            OidcError::OAuth(inner) => {
                assert!(inner.to_string().contains("expired"));
            }
            _ => panic!("expected OAuth variant"),
        }
    }

    // ── OidcProvider ───────────────────────────────────────────────

    #[test]
    fn provider_config_accessor() {
        let provider = create_test_provider();
        let cfg = provider.config();
        assert_eq!(cfg.issuer, "fastmcp");
        assert_eq!(cfg.signing_algorithm, SigningAlgorithm::HS256);
    }

    #[test]
    fn provider_oauth_accessor() {
        let provider = create_test_provider();
        let _oauth = provider.oauth();
        // Just check it returns without panic
    }

    #[test]
    fn provider_set_hmac_key() {
        let provider = create_test_provider();
        provider.set_hmac_key(b"my-secret");
        // Verify it works by issuing a token (the key gets used during signing)
        let claims_store = InMemoryClaimsProvider::new();
        claims_store.set_claims(UserClaims::new("user1"));
        provider.set_claims_provider(claims_store);

        let at = issue_token_via_auth_code(provider.oauth().as_ref(), &["openid"], "user1");
        let oauth_token = provider.oauth().validate_access_token(&at).unwrap();
        let result = provider.issue_id_token(&oauth_token, None);
        assert!(result.is_ok());
    }

    #[test]
    fn provider_set_claims_fn() {
        let provider = create_test_provider();
        provider.set_claims_fn(|sub| Some(UserClaims::new(sub).with_name("FnUser")));
        provider.set_hmac_key(b"secret");

        let at =
            issue_token_via_auth_code(provider.oauth().as_ref(), &["openid", "profile"], "fn-user");
        let oauth_token = provider.oauth().validate_access_token(&at).unwrap();
        let id_token = provider.issue_id_token(&oauth_token, None).unwrap();
        assert_eq!(id_token.claims.user_claims.name, Some("FnUser".to_string()));
    }

    #[test]
    fn provider_jwks_hs256_returns_none() {
        let provider = create_test_provider();
        assert!(provider.jwks().is_none());
    }

    #[test]
    fn provider_get_id_token_nonexistent() {
        let provider = create_test_provider();
        assert!(provider.get_id_token("nonexistent-token").is_none());
    }

    #[test]
    fn provider_get_id_token_after_issue() {
        let provider = create_test_provider();
        provider.set_hmac_key(b"key123");
        let claims_store = InMemoryClaimsProvider::new();
        claims_store.set_claims(UserClaims::new("cached-user"));
        provider.set_claims_provider(claims_store);

        let at = issue_token_via_auth_code(provider.oauth().as_ref(), &["openid"], "cached-user");
        let oauth_token = provider.oauth().validate_access_token(&at).unwrap();
        provider
            .issue_id_token(&oauth_token, Some("nonce1"))
            .unwrap();

        // Should be retrievable via get_id_token
        let retrieved = provider.get_id_token(&at);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().claims.sub, "cached-user");
    }

    #[test]
    fn provider_cleanup_expired() {
        let provider = create_test_provider();
        // cleanup_expired should run without panic even with empty cache
        provider.cleanup_expired();
    }

    #[test]
    fn provider_issue_id_token_no_claims_provider() {
        // Without a claims provider, should use default UserClaims (just sub)
        let provider = create_test_provider();
        provider.set_hmac_key(b"key");

        let at = issue_token_via_auth_code(provider.oauth().as_ref(), &["openid"], "default-user");
        let oauth_token = provider.oauth().validate_access_token(&at).unwrap();
        let id_token = provider.issue_id_token(&oauth_token, None).unwrap();
        assert_eq!(id_token.claims.sub, "default-user");
        // No claims provider → default claims (no name, email, etc.)
        assert!(id_token.claims.user_claims.name.is_none());
    }

    #[test]
    fn provider_issue_id_token_claims_not_found() {
        let provider = create_test_provider();
        provider.set_hmac_key(b"key");
        // Set claims provider that has no user "missing-user"
        let claims_store = InMemoryClaimsProvider::new();
        claims_store.set_claims(UserClaims::new("other-user"));
        provider.set_claims_provider(claims_store);

        let at = issue_token_via_auth_code(provider.oauth().as_ref(), &["openid"], "missing-user");
        let oauth_token = provider.oauth().validate_access_token(&at).unwrap();
        let result = provider.issue_id_token(&oauth_token, None);
        assert!(matches!(result, Err(OidcError::ClaimsNotFound(_))));
    }

    #[test]
    fn provider_discovery_document_overrides_scopes_and_claims() {
        let mut config = OidcProviderConfig::default();
        config.supported_scopes = vec!["openid".to_string(), "custom".to_string()];
        config.supported_claims = vec!["sub".to_string(), "custom_field".to_string()];

        let oauth = Arc::new(OAuthServer::new(OAuthServerConfig::default()));
        let provider = OidcProvider::new(oauth, config).unwrap();
        let doc = provider.discovery_document("https://api");

        assert!(doc.scopes_supported.contains(&"custom".to_string()));
        assert!(!doc.scopes_supported.contains(&"profile".to_string()));
        assert!(
            doc.claims_supported
                .as_ref()
                .unwrap()
                .contains(&"custom_field".to_string())
        );
    }

    #[test]
    fn provider_issue_id_token_jwt_structure() {
        let provider = create_test_provider();
        provider.set_hmac_key(b"secret");

        let at = issue_token_via_auth_code(provider.oauth().as_ref(), &["openid"], "jwt-user");
        let oauth_token = provider.oauth().validate_access_token(&at).unwrap();
        let id_token = provider.issue_id_token(&oauth_token, None).unwrap();

        // JWT must have 3 parts
        let parts: Vec<&str> = id_token.raw.split('.').collect();
        assert_eq!(parts.len(), 3);
        // Each part is non-empty
        assert!(!parts[0].is_empty());
        assert!(!parts[1].is_empty());
        assert!(!parts[2].is_empty());
    }

    #[test]
    fn provider_issue_id_token_auto_generates_key() {
        // Without set_hmac_key, should auto-generate a key
        let provider = create_test_provider();

        let at = issue_token_via_auth_code(provider.oauth().as_ref(), &["openid"], "auto-key-user");
        let oauth_token = provider.oauth().validate_access_token(&at).unwrap();
        let result = provider.issue_id_token(&oauth_token, None);
        assert!(result.is_ok());
    }

    #[test]
    fn provider_userinfo_invalid_token() {
        let provider = create_test_provider();
        let result = provider.userinfo("invalid-access-token");
        assert!(matches!(result, Err(OidcError::OAuth(_))));
    }

    #[test]
    fn provider_userinfo_without_openid_scope() {
        let provider = create_test_provider();
        let at = issue_token_via_auth_code(provider.oauth().as_ref(), &["profile"], "no-openid");
        let result = provider.userinfo(&at);
        assert!(matches!(result, Err(OidcError::MissingOpenIdScope)));
    }

    // ── Arc<dyn ClaimsProvider> delegation ──────────────────────────

    #[test]
    fn arc_claims_provider_delegation() {
        let inner = InMemoryClaimsProvider::new();
        inner.set_claims(UserClaims::new("arc-user").with_name("ArcUser"));
        let arc_provider: Arc<dyn ClaimsProvider> = Arc::new(inner);

        // Arc<dyn ClaimsProvider> should delegate
        let claims = arc_provider.get_claims("arc-user");
        assert!(claims.is_some());
        assert_eq!(claims.unwrap().name, Some("ArcUser".to_string()));

        assert!(arc_provider.get_claims("missing").is_none());
    }

    // ── InMemoryClaimsProvider ──────────────────────────────────────

    #[test]
    fn in_memory_claims_provider_debug() {
        let provider = InMemoryClaimsProvider::new();
        let debug = format!("{:?}", provider);
        assert!(debug.contains("InMemoryClaimsProvider"));
    }

    #[test]
    fn in_memory_claims_provider_default() {
        let provider = InMemoryClaimsProvider::default();
        assert!(provider.get_claims("any").is_none());
    }

    #[test]
    fn in_memory_claims_provider_overwrite() {
        let provider = InMemoryClaimsProvider::new();
        provider.set_claims(UserClaims::new("u1").with_name("First"));
        provider.set_claims(UserClaims::new("u1").with_name("Second"));
        let claims = provider.get_claims("u1").unwrap();
        assert_eq!(claims.name, Some("Second".to_string()));
    }

    // ── Helper functions ────────────────────────────────────────────

    #[test]
    fn simple_sha256_deterministic() {
        let hash1 = simple_sha256(b"hello world");
        let hash2 = simple_sha256(b"hello world");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);

        // Different input → different hash
        let hash3 = simple_sha256(b"different");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn hmac_sha256_deterministic() {
        let sig1 = hmac_sha256("message", b"key").unwrap();
        let sig2 = hmac_sha256("message", b"key").unwrap();
        assert_eq!(sig1, sig2);
        assert_eq!(sig1.len(), 32);
    }

    #[test]
    fn hmac_sha256_different_keys() {
        let sig1 = hmac_sha256("msg", b"key1").unwrap();
        let sig2 = hmac_sha256("msg", b"key2").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn hmac_sha256_different_messages() {
        let sig1 = hmac_sha256("msg1", b"key").unwrap();
        let sig2 = hmac_sha256("msg2", b"key").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn generate_random_bytes_length() {
        let bytes = generate_random_bytes(16).unwrap();
        assert_eq!(bytes.len(), 16);

        let bytes = generate_random_bytes(64).unwrap();
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn generate_random_bytes_unique() {
        let a = generate_random_bytes(32).unwrap();
        let b = generate_random_bytes(32).unwrap();
        // Probabilistically, two random 32-byte sequences should differ
        assert_ne!(a, b);
    }

    // ── validate_oidc_config ───────────────────────────────────────

    #[test]
    fn validate_config_hs256_always_ok() {
        let config = OidcProviderConfig::default();
        assert!(validate_oidc_config(&config).is_ok());
    }

    #[test]
    #[cfg(not(feature = "jwt"))]
    fn validate_config_rs256_without_jwt_feature() {
        let mut config = OidcProviderConfig::default();
        config.signing_algorithm = SigningAlgorithm::RS256;
        let result = validate_oidc_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("jwt"));
    }

    // ── SigningKey ──────────────────────────────────────────────────

    #[test]
    fn signing_key_default_is_none() {
        let key = SigningKey::default();
        assert!(matches!(key, SigningKey::None));
    }

    #[test]
    fn signing_key_clone() {
        let key = SigningKey::Hmac(vec![1, 2, 3]);
        let cloned = key.clone();
        match cloned {
            SigningKey::Hmac(bytes) => assert_eq!(bytes, vec![1, 2, 3]),
            SigningKey::None => panic!("expected Hmac"),
        }
    }

    #[test]
    fn userinfo_claims_not_found() {
        let provider = create_test_provider();
        // Set a claims provider that only knows about "other-user"
        let store = InMemoryClaimsProvider::new();
        store.set_claims(UserClaims::new("other-user"));
        provider.set_claims_provider(store);

        let at = issue_token_via_auth_code(
            provider.oauth().as_ref(),
            &["openid", "profile"],
            "missing-user",
        );
        let result = provider.userinfo(&at);
        assert!(matches!(result, Err(OidcError::ClaimsNotFound(_))));
    }

    #[test]
    fn filter_by_scopes_profile_all_fields() {
        let claims = UserClaims {
            sub: "u".to_string(),
            name: Some("N".to_string()),
            given_name: Some("G".to_string()),
            family_name: Some("F".to_string()),
            middle_name: Some("M".to_string()),
            nickname: Some("Nick".to_string()),
            preferred_username: Some("Pref".to_string()),
            profile: Some("http://profile".to_string()),
            picture: Some("http://pic".to_string()),
            website: Some("http://web".to_string()),
            gender: Some("other".to_string()),
            birthdate: Some("2000-01-01".to_string()),
            zoneinfo: Some("UTC".to_string()),
            locale: Some("en-US".to_string()),
            updated_at: Some(12345),
            ..Default::default()
        };

        let filtered = claims.filter_by_scopes(&["profile".to_string()]);
        assert_eq!(filtered.name, Some("N".to_string()));
        assert_eq!(filtered.given_name, Some("G".to_string()));
        assert_eq!(filtered.family_name, Some("F".to_string()));
        assert_eq!(filtered.middle_name, Some("M".to_string()));
        assert_eq!(filtered.nickname, Some("Nick".to_string()));
        assert_eq!(filtered.preferred_username, Some("Pref".to_string()));
        assert_eq!(filtered.profile, Some("http://profile".to_string()));
        assert_eq!(filtered.picture, Some("http://pic".to_string()));
        assert_eq!(filtered.website, Some("http://web".to_string()));
        assert_eq!(filtered.gender, Some("other".to_string()));
        assert_eq!(filtered.birthdate, Some("2000-01-01".to_string()));
        assert_eq!(filtered.zoneinfo, Some("UTC".to_string()));
        assert_eq!(filtered.locale, Some("en-US".to_string()));
        assert_eq!(filtered.updated_at, Some(12345));
    }

    #[test]
    fn filter_by_scopes_does_not_include_custom_claims() {
        let claims = UserClaims::new("u")
            .with_name("Name")
            .with_custom("role", serde_json::json!("admin"));

        let filtered = claims.filter_by_scopes(&["profile".to_string()]);
        assert_eq!(filtered.name, Some("Name".to_string()));
        assert!(
            filtered.custom.is_empty(),
            "custom claims should not pass through scope filtering"
        );
    }

    #[test]
    fn issue_id_token_fields_populated() {
        let provider = create_test_provider();
        provider.set_hmac_key(b"key");

        let at = issue_token_via_auth_code(provider.oauth().as_ref(), &["openid"], "field-user");
        let oauth_token = provider.oauth().validate_access_token(&at).unwrap();
        let id_token = provider.issue_id_token(&oauth_token, None).unwrap();

        assert_eq!(id_token.claims.iss, "fastmcp");
        assert_eq!(id_token.claims.aud, TEST_CLIENT_ID);
        assert_eq!(id_token.claims.azp, Some(TEST_CLIENT_ID.to_string()));
        assert!(id_token.claims.at_hash.is_some());
        assert!(id_token.claims.auth_time.is_some());
        assert!(id_token.claims.nonce.is_none());
        assert!(id_token.claims.exp > id_token.claims.iat);
    }

    #[test]
    fn base64url_encode_url_safe_characters() {
        // Bytes 0xFB, 0xFF, 0xFE produce +//+ in standard base64,
        // but base64url should use - and _ instead.
        let encoded = base64url_encode(&[0xFB, 0xFF, 0xFE]);
        assert!(
            !encoded.contains('+') && !encoded.contains('/'),
            "base64url must not contain + or /: {encoded}"
        );
        assert!(
            encoded.contains('-') || encoded.contains('_'),
            "base64url should use URL-safe chars: {encoded}"
        );
    }

    #[test]
    fn discovery_document_serde_skip_nones() {
        let mut doc = DiscoveryDocument::new("iss", "http://base");
        doc.jwks_uri = None;
        doc.registration_endpoint = None;
        let json = serde_json::to_string(&doc).unwrap();
        assert!(!json.contains("jwks_uri"));
        assert!(!json.contains("registration_endpoint"));
        // Present optional fields should be in the JSON
        assert!(json.contains("userinfo_endpoint"));
        assert!(json.contains("revocation_endpoint"));
    }

    #[test]
    fn issue_id_token_with_nonce_round_trips() {
        let provider = create_test_provider();
        provider.set_hmac_key(b"key");

        let at = issue_token_via_auth_code(provider.oauth().as_ref(), &["openid"], "nonce-rt-user");
        let oauth_token = provider.oauth().validate_access_token(&at).unwrap();

        // With nonce
        let with = provider
            .issue_id_token(&oauth_token, Some("my-nonce"))
            .unwrap();
        assert_eq!(with.claims.nonce, Some("my-nonce".to_string()));

        // Verify the nonce appears in the raw JWT payload
        let parts: Vec<&str> = with.raw.split('.').collect();
        use base64::Engine;
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["nonce"], "my-nonce");
    }
}
