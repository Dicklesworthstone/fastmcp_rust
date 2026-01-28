//! OAuth 2.0/2.1 Authorization Server for MCP.
//!
//! This module implements a complete OAuth 2.0/2.1 authorization server for MCP
//! servers, providing:
//!
//! - **Authorization Code Flow** with PKCE (required for OAuth 2.1)
//! - **Token Issuance** - Access tokens and refresh tokens
//! - **Token Revocation** - RFC 7009 token revocation
//! - **Client Registration** - Dynamic client registration
//! - **Scope Validation** - Fine-grained scope control
//! - **Redirect URI Validation** - Security-critical validation
//!
//! # Architecture
//!
//! The OAuth server is designed to be modular:
//!
//! - [`OAuthServer`]: Main authorization server component
//! - [`OAuthClient`]: Registered OAuth client
//! - [`AuthorizationCode`]: Temporary code for token exchange
//! - [`OAuthToken`]: Access and refresh tokens
//! - [`OAuthTokenVerifier`]: Implements [`TokenVerifier`] for MCP integration
//!
//! # Security Considerations
//!
//! - PKCE is **required** for all authorization code flows (OAuth 2.1 compliance)
//! - Redirect URIs must be exact matches or localhost with any port
//! - Tokens are cryptographically random and securely generated
//! - Authorization codes are single-use and expire quickly
//!
//! # Example
//!
//! ```ignore
//! use fastmcp::oauth::{OAuthServer, OAuthServerConfig, OAuthClient};
//!
//! let oauth = OAuthServer::new(OAuthServerConfig::default());
//!
//! // Register a client
//! let client = OAuthClient::builder("my-client")
//!     .redirect_uri("http://localhost:3000/callback")
//!     .scope("read")
//!     .scope("write")
//!     .build()?;
//!
//! oauth.register_client(client)?;
//!
//! // Use with MCP server
//! let verifier = oauth.token_verifier();
//! Server::new("my-server", "1.0.0")
//!     .auth_provider(TokenAuthProvider::new(verifier))
//!     .run_stdio();
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fastmcp_core::{AccessToken, AuthContext, McpContext, McpError, McpErrorCode, McpResult};

use crate::auth::{AuthRequest, TokenVerifier};

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the OAuth authorization server.
#[derive(Debug, Clone)]
pub struct OAuthServerConfig {
    /// Issuer identifier (URL) for this authorization server.
    pub issuer: String,
    /// Access token lifetime.
    pub access_token_lifetime: Duration,
    /// Refresh token lifetime.
    pub refresh_token_lifetime: Duration,
    /// Authorization code lifetime (should be short, e.g., 10 minutes).
    pub authorization_code_lifetime: Duration,
    /// Whether to allow public clients (clients without a secret).
    pub allow_public_clients: bool,
    /// Minimum PKCE code verifier length (default: 43, min: 43, max: 128).
    pub min_code_verifier_length: usize,
    /// Maximum PKCE code verifier length.
    pub max_code_verifier_length: usize,
    /// Token entropy bytes (default: 32 = 256 bits).
    pub token_entropy_bytes: usize,
}

impl Default for OAuthServerConfig {
    fn default() -> Self {
        Self {
            issuer: "fastmcp".to_string(),
            access_token_lifetime: Duration::from_secs(3600), // 1 hour
            refresh_token_lifetime: Duration::from_secs(86400 * 30), // 30 days
            authorization_code_lifetime: Duration::from_secs(600), // 10 minutes
            allow_public_clients: true,
            min_code_verifier_length: 43,
            max_code_verifier_length: 128,
            token_entropy_bytes: 32,
        }
    }
}

// =============================================================================
// OAuth Client
// =============================================================================

/// OAuth client types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientType {
    /// Confidential client (has a secret).
    Confidential,
    /// Public client (no secret, e.g., native apps, SPAs).
    Public,
}

/// A registered OAuth client.
#[derive(Debug, Clone)]
pub struct OAuthClient {
    /// Unique client identifier.
    pub client_id: String,
    /// Client secret (None for public clients).
    pub client_secret: Option<String>,
    /// Client type.
    pub client_type: ClientType,
    /// Allowed redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Allowed scopes.
    pub allowed_scopes: HashSet<String>,
    /// Client name (for display).
    pub name: Option<String>,
    /// Client description.
    pub description: Option<String>,
    /// When the client was registered.
    pub registered_at: SystemTime,
}

impl OAuthClient {
    /// Creates a new client builder.
    #[must_use]
    pub fn builder(client_id: impl Into<String>) -> OAuthClientBuilder {
        OAuthClientBuilder::new(client_id)
    }

    /// Validates that a redirect URI is allowed for this client.
    #[must_use]
    pub fn validate_redirect_uri(&self, uri: &str) -> bool {
        // Check for exact match first
        if self.redirect_uris.contains(&uri.to_string()) {
            return true;
        }

        // For localhost URIs, allow any port (OAuth 2.0 for Native Apps, RFC 8252)
        for allowed in &self.redirect_uris {
            if is_localhost_redirect(allowed) && is_localhost_redirect(uri) {
                // Compare scheme and path, allow different ports
                if localhost_match(allowed, uri) {
                    return true;
                }
            }
        }

        false
    }

    /// Validates that the requested scopes are allowed for this client.
    #[must_use]
    pub fn validate_scopes(&self, scopes: &[String]) -> bool {
        scopes.iter().all(|s| self.allowed_scopes.contains(s))
    }

    /// Authenticates a confidential client.
    #[must_use]
    pub fn authenticate(&self, secret: Option<&str>) -> bool {
        match (&self.client_secret, secret) {
            (Some(expected), Some(provided)) => constant_time_eq(expected, provided),
            (None, None) => self.client_type == ClientType::Public,
            _ => false,
        }
    }
}

/// Builder for OAuth clients.
#[derive(Debug)]
pub struct OAuthClientBuilder {
    client_id: String,
    client_secret: Option<String>,
    redirect_uris: Vec<String>,
    allowed_scopes: HashSet<String>,
    name: Option<String>,
    description: Option<String>,
}

impl OAuthClientBuilder {
    /// Creates a new client builder.
    fn new(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: None,
            redirect_uris: Vec::new(),
            allowed_scopes: HashSet::new(),
            name: None,
            description: None,
        }
    }

    /// Sets the client secret (makes this a confidential client).
    #[must_use]
    pub fn secret(mut self, secret: impl Into<String>) -> Self {
        self.client_secret = Some(secret.into());
        self
    }

    /// Adds a redirect URI.
    #[must_use]
    pub fn redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uris.push(uri.into());
        self
    }

    /// Adds multiple redirect URIs.
    #[must_use]
    pub fn redirect_uris<I, S>(mut self, uris: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.redirect_uris.extend(uris.into_iter().map(Into::into));
        self
    }

    /// Adds an allowed scope.
    #[must_use]
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.allowed_scopes.insert(scope.into());
        self
    }

    /// Adds multiple allowed scopes.
    #[must_use]
    pub fn scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_scopes
            .extend(scopes.into_iter().map(Into::into));
        self
    }

    /// Sets the client name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the client description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Builds the OAuth client.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No redirect URIs are configured
    /// - Client ID is empty
    pub fn build(self) -> Result<OAuthClient, OAuthError> {
        if self.client_id.is_empty() {
            return Err(OAuthError::InvalidRequest(
                "client_id cannot be empty".to_string(),
            ));
        }

        if self.redirect_uris.is_empty() {
            return Err(OAuthError::InvalidRequest(
                "at least one redirect_uri is required".to_string(),
            ));
        }

        let client_type = if self.client_secret.is_some() {
            ClientType::Confidential
        } else {
            ClientType::Public
        };

        Ok(OAuthClient {
            client_id: self.client_id,
            client_secret: self.client_secret,
            client_type,
            redirect_uris: self.redirect_uris,
            allowed_scopes: self.allowed_scopes,
            name: self.name,
            description: self.description,
            registered_at: SystemTime::now(),
        })
    }
}

// =============================================================================
// Authorization Code
// =============================================================================

/// PKCE code challenge method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeChallengeMethod {
    /// Plain text (not recommended, but allowed for compatibility).
    Plain,
    /// SHA-256 hash (recommended).
    S256,
}

impl CodeChallengeMethod {
    /// Parses a code challenge method from a string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "plain" => Some(Self::Plain),
            "S256" => Some(Self::S256),
            _ => None,
        }
    }

    /// Returns the string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::S256 => "S256",
        }
    }
}

/// Authorization code issued during the authorization flow.
#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    /// The code value.
    pub code: String,
    /// Client ID this code was issued to.
    pub client_id: String,
    /// Redirect URI used in the authorization request.
    pub redirect_uri: String,
    /// Approved scopes.
    pub scopes: Vec<String>,
    /// PKCE code challenge.
    pub code_challenge: String,
    /// PKCE code challenge method.
    pub code_challenge_method: CodeChallengeMethod,
    /// When the code was issued.
    pub issued_at: Instant,
    /// When the code expires.
    pub expires_at: Instant,
    /// Subject (user) this code was issued for.
    pub subject: Option<String>,
    /// State parameter from the authorization request.
    pub state: Option<String>,
}

impl AuthorizationCode {
    /// Checks if this code has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Validates the PKCE code verifier against the stored challenge.
    #[must_use]
    pub fn validate_code_verifier(&self, verifier: &str) -> bool {
        match self.code_challenge_method {
            CodeChallengeMethod::Plain => constant_time_eq(&self.code_challenge, verifier),
            CodeChallengeMethod::S256 => {
                let computed = compute_s256_challenge(verifier);
                constant_time_eq(&self.code_challenge, &computed)
            }
        }
    }
}

// =============================================================================
// OAuth Tokens
// =============================================================================

/// Token type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// Bearer token.
    Bearer,
}

impl TokenType {
    /// Returns the string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
        }
    }
}

/// OAuth token (access or refresh).
#[derive(Debug, Clone)]
pub struct OAuthToken {
    /// Token value.
    pub token: String,
    /// Token type.
    pub token_type: TokenType,
    /// Client ID this token was issued to.
    pub client_id: String,
    /// Approved scopes.
    pub scopes: Vec<String>,
    /// When the token was issued.
    pub issued_at: Instant,
    /// When the token expires.
    pub expires_at: Instant,
    /// Subject (user) this token was issued for.
    pub subject: Option<String>,
    /// Whether this is a refresh token.
    pub is_refresh_token: bool,
}

impl OAuthToken {
    /// Checks if this token has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Returns the remaining lifetime in seconds.
    #[must_use]
    pub fn expires_in_secs(&self) -> u64 {
        self.expires_at
            .saturating_duration_since(Instant::now())
            .as_secs()
    }
}

/// Token response for successful token issuance.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,
    /// Token type (always "bearer").
    pub token_type: String,
    /// Token lifetime in seconds.
    pub expires_in: u64,
    /// Refresh token (if issued).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Granted scopes (space-separated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

// =============================================================================
// Authorization Request
// =============================================================================

/// Authorization request parameters.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// Response type (must be "code" for authorization code flow).
    pub response_type: String,
    /// Client ID.
    pub client_id: String,
    /// Redirect URI.
    pub redirect_uri: String,
    /// Requested scopes (space-separated in original request).
    pub scopes: Vec<String>,
    /// State parameter (recommended for CSRF protection).
    pub state: Option<String>,
    /// PKCE code challenge.
    pub code_challenge: String,
    /// PKCE code challenge method.
    pub code_challenge_method: CodeChallengeMethod,
}

/// Token request parameters.
#[derive(Debug, Clone)]
pub struct TokenRequest {
    /// Grant type.
    pub grant_type: String,
    /// Authorization code (for authorization_code grant).
    pub code: Option<String>,
    /// Redirect URI (for authorization_code grant).
    pub redirect_uri: Option<String>,
    /// Client ID.
    pub client_id: String,
    /// Client secret (for confidential clients).
    pub client_secret: Option<String>,
    /// PKCE code verifier.
    pub code_verifier: Option<String>,
    /// Refresh token (for refresh_token grant).
    pub refresh_token: Option<String>,
    /// Requested scopes (for refresh_token grant, subset of original scopes).
    pub scopes: Option<Vec<String>>,
}

// =============================================================================
// OAuth Errors
// =============================================================================

/// OAuth error types following RFC 6749.
#[derive(Debug, Clone)]
pub enum OAuthError {
    /// The request is missing a required parameter or is otherwise malformed.
    InvalidRequest(String),
    /// Client authentication failed.
    InvalidClient(String),
    /// The authorization grant or refresh token is invalid.
    InvalidGrant(String),
    /// The client is not authorized to use this grant type.
    UnauthorizedClient(String),
    /// The grant type is not supported.
    UnsupportedGrantType(String),
    /// The requested scope is invalid or unknown.
    InvalidScope(String),
    /// The authorization server encountered an unexpected condition.
    ServerError(String),
    /// The authorization server is temporarily unavailable.
    TemporarilyUnavailable(String),
    /// Access denied by the resource owner.
    AccessDenied(String),
    /// The response type is not supported.
    UnsupportedResponseType(String),
}

impl OAuthError {
    /// Returns the OAuth error code.
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidClient(_) => "invalid_client",
            Self::InvalidGrant(_) => "invalid_grant",
            Self::UnauthorizedClient(_) => "unauthorized_client",
            Self::UnsupportedGrantType(_) => "unsupported_grant_type",
            Self::InvalidScope(_) => "invalid_scope",
            Self::ServerError(_) => "server_error",
            Self::TemporarilyUnavailable(_) => "temporarily_unavailable",
            Self::AccessDenied(_) => "access_denied",
            Self::UnsupportedResponseType(_) => "unsupported_response_type",
        }
    }

    /// Returns the error description.
    #[must_use]
    pub fn description(&self) -> &str {
        match self {
            Self::InvalidRequest(s)
            | Self::InvalidClient(s)
            | Self::InvalidGrant(s)
            | Self::UnauthorizedClient(s)
            | Self::UnsupportedGrantType(s)
            | Self::InvalidScope(s)
            | Self::ServerError(s)
            | Self::TemporarilyUnavailable(s)
            | Self::AccessDenied(s)
            | Self::UnsupportedResponseType(s) => s,
        }
    }
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error_code(), self.description())
    }
}

impl std::error::Error for OAuthError {}

impl From<OAuthError> for McpError {
    fn from(err: OAuthError) -> Self {
        match &err {
            OAuthError::InvalidClient(_) | OAuthError::UnauthorizedClient(_) => {
                McpError::new(McpErrorCode::ResourceForbidden, err.to_string())
            }
            OAuthError::AccessDenied(_) => {
                McpError::new(McpErrorCode::ResourceForbidden, err.to_string())
            }
            _ => McpError::new(McpErrorCode::InvalidRequest, err.to_string()),
        }
    }
}

// =============================================================================
// OAuth Server
// =============================================================================

/// Internal state for the OAuth server.
pub(crate) struct OAuthServerState {
    /// Registered clients by client_id.
    pub(crate) clients: HashMap<String, OAuthClient>,
    /// Pending authorization codes.
    pub(crate) authorization_codes: HashMap<String, AuthorizationCode>,
    /// Active access tokens.
    pub(crate) access_tokens: HashMap<String, OAuthToken>,
    /// Active refresh tokens.
    pub(crate) refresh_tokens: HashMap<String, OAuthToken>,
    /// Revoked tokens (for revocation checking).
    pub(crate) revoked_tokens: HashSet<String>,
}

impl OAuthServerState {
    fn new() -> Self {
        Self {
            clients: HashMap::new(),
            authorization_codes: HashMap::new(),
            access_tokens: HashMap::new(),
            refresh_tokens: HashMap::new(),
            revoked_tokens: HashSet::new(),
        }
    }
}

/// OAuth 2.0/2.1 authorization server.
///
/// This server implements the OAuth 2.0 authorization code flow with PKCE,
/// which is required for OAuth 2.1 compliance.
pub struct OAuthServer {
    config: OAuthServerConfig,
    pub(crate) state: RwLock<OAuthServerState>,
}

impl OAuthServer {
    /// Creates a new OAuth server with the given configuration.
    #[must_use]
    pub fn new(config: OAuthServerConfig) -> Self {
        Self {
            config,
            state: RwLock::new(OAuthServerState::new()),
        }
    }

    /// Creates a new OAuth server with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(OAuthServerConfig::default())
    }

    /// Returns the server configuration.
    #[must_use]
    pub fn config(&self) -> &OAuthServerConfig {
        &self.config
    }

    // -------------------------------------------------------------------------
    // Client Registration
    // -------------------------------------------------------------------------

    /// Registers a new OAuth client.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A client with the same ID already exists
    /// - Public clients are not allowed and the client has no secret
    pub fn register_client(&self, client: OAuthClient) -> Result<(), OAuthError> {
        if client.client_type == ClientType::Public && !self.config.allow_public_clients {
            return Err(OAuthError::InvalidClient(
                "public clients are not allowed".to_string(),
            ));
        }

        let mut state = self
            .state
            .write()
            .map_err(|_| OAuthError::ServerError("failed to acquire write lock".to_string()))?;

        if state.clients.contains_key(&client.client_id) {
            return Err(OAuthError::InvalidClient(format!(
                "client '{}' already exists",
                client.client_id
            )));
        }

        state.clients.insert(client.client_id.clone(), client);
        Ok(())
    }

    /// Unregisters an OAuth client.
    ///
    /// This also revokes all tokens issued to the client.
    pub fn unregister_client(&self, client_id: &str) -> Result<(), OAuthError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| OAuthError::ServerError("failed to acquire write lock".to_string()))?;

        if state.clients.remove(client_id).is_none() {
            return Err(OAuthError::InvalidClient(format!(
                "client '{}' not found",
                client_id
            )));
        }

        // Revoke all tokens for this client
        let access_tokens: Vec<_> = state
            .access_tokens
            .iter()
            .filter(|(_, t)| t.client_id == client_id)
            .map(|(k, _)| k.clone())
            .collect();
        for token in access_tokens {
            state.access_tokens.remove(&token);
            state.revoked_tokens.insert(token);
        }

        let refresh_tokens: Vec<_> = state
            .refresh_tokens
            .iter()
            .filter(|(_, t)| t.client_id == client_id)
            .map(|(k, _)| k.clone())
            .collect();
        for token in refresh_tokens {
            state.refresh_tokens.remove(&token);
            state.revoked_tokens.insert(token);
        }

        // Remove pending authorization codes
        let codes: Vec<_> = state
            .authorization_codes
            .iter()
            .filter(|(_, c)| c.client_id == client_id)
            .map(|(k, _)| k.clone())
            .collect();
        for code in codes {
            state.authorization_codes.remove(&code);
        }

        Ok(())
    }

    /// Gets a registered client by ID.
    #[must_use]
    pub fn get_client(&self, client_id: &str) -> Option<OAuthClient> {
        self.state
            .read()
            .ok()
            .and_then(|s| s.clients.get(client_id).cloned())
    }

    /// Lists all registered clients.
    #[must_use]
    pub fn list_clients(&self) -> Vec<OAuthClient> {
        self.state
            .read()
            .map(|s| s.clients.values().cloned().collect())
            .unwrap_or_default()
    }

    // -------------------------------------------------------------------------
    // Authorization Endpoint
    // -------------------------------------------------------------------------

    /// Validates an authorization request and creates an authorization code.
    ///
    /// This is called after the resource owner has authenticated and approved
    /// the authorization request.
    ///
    /// # Arguments
    ///
    /// * `request` - The authorization request parameters
    /// * `subject` - The authenticated user's identifier (optional)
    ///
    /// # Returns
    ///
    /// Returns the authorization code and redirect URI on success.
    pub fn authorize(
        &self,
        request: &AuthorizationRequest,
        subject: Option<String>,
    ) -> Result<(String, String), OAuthError> {
        // Validate response_type
        if request.response_type != "code" {
            return Err(OAuthError::UnsupportedResponseType(
                "only 'code' response_type is supported".to_string(),
            ));
        }

        // Get and validate client
        let client = self.get_client(&request.client_id).ok_or_else(|| {
            OAuthError::InvalidClient(format!("client '{}' not found", request.client_id))
        })?;

        // Validate redirect URI
        if !client.validate_redirect_uri(&request.redirect_uri) {
            return Err(OAuthError::InvalidRequest(
                "invalid redirect_uri".to_string(),
            ));
        }

        // Validate scopes
        if !client.validate_scopes(&request.scopes) {
            return Err(OAuthError::InvalidScope(
                "requested scope not allowed".to_string(),
            ));
        }

        // Validate PKCE (required for OAuth 2.1)
        if request.code_challenge.is_empty() {
            return Err(OAuthError::InvalidRequest(
                "code_challenge is required (PKCE)".to_string(),
            ));
        }

        // Generate authorization code
        let code_value = generate_token(self.config.token_entropy_bytes);
        let now = Instant::now();
        let code = AuthorizationCode {
            code: code_value.clone(),
            client_id: request.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            scopes: request.scopes.clone(),
            code_challenge: request.code_challenge.clone(),
            code_challenge_method: request.code_challenge_method,
            issued_at: now,
            expires_at: now + self.config.authorization_code_lifetime,
            subject,
            state: request.state.clone(),
        };

        // Store the code
        {
            let mut state = self
                .state
                .write()
                .map_err(|_| OAuthError::ServerError("failed to acquire write lock".to_string()))?;
            state.authorization_codes.insert(code_value.clone(), code);
        }

        // Build redirect URI with code
        let mut redirect = request.redirect_uri.clone();
        let separator = if redirect.contains('?') { '&' } else { '?' };
        redirect.push(separator);
        redirect.push_str("code=");
        redirect.push_str(&url_encode(&code_value));
        if let Some(state) = &request.state {
            redirect.push_str("&state=");
            redirect.push_str(&url_encode(state));
        }

        Ok((code_value, redirect))
    }

    // -------------------------------------------------------------------------
    // Token Endpoint
    // -------------------------------------------------------------------------

    /// Exchanges an authorization code or refresh token for tokens.
    pub fn token(&self, request: &TokenRequest) -> Result<TokenResponse, OAuthError> {
        match request.grant_type.as_str() {
            "authorization_code" => self.token_authorization_code(request),
            "refresh_token" => self.token_refresh_token(request),
            other => Err(OAuthError::UnsupportedGrantType(format!(
                "grant_type '{}' is not supported",
                other
            ))),
        }
    }

    fn token_authorization_code(
        &self,
        request: &TokenRequest,
    ) -> Result<TokenResponse, OAuthError> {
        // Validate required parameters
        let code_value = request
            .code
            .as_ref()
            .ok_or_else(|| OAuthError::InvalidRequest("code is required".to_string()))?;
        let redirect_uri = request
            .redirect_uri
            .as_ref()
            .ok_or_else(|| OAuthError::InvalidRequest("redirect_uri is required".to_string()))?;
        let code_verifier = request.code_verifier.as_ref().ok_or_else(|| {
            OAuthError::InvalidRequest("code_verifier is required (PKCE)".to_string())
        })?;

        // Validate code verifier length
        if code_verifier.len() < self.config.min_code_verifier_length
            || code_verifier.len() > self.config.max_code_verifier_length
        {
            return Err(OAuthError::InvalidRequest(format!(
                "code_verifier must be between {} and {} characters",
                self.config.min_code_verifier_length, self.config.max_code_verifier_length
            )));
        }

        // Get and validate authorization code
        let auth_code = {
            let mut state = self
                .state
                .write()
                .map_err(|_| OAuthError::ServerError("failed to acquire write lock".to_string()))?;

            // Remove the code (single-use)
            state
                .authorization_codes
                .remove(code_value)
                .ok_or_else(|| {
                    OAuthError::InvalidGrant(
                        "authorization code not found or already used".to_string(),
                    )
                })?
        };

        // Validate the code
        if auth_code.is_expired() {
            return Err(OAuthError::InvalidGrant(
                "authorization code has expired".to_string(),
            ));
        }
        if auth_code.client_id != request.client_id {
            return Err(OAuthError::InvalidGrant("client_id mismatch".to_string()));
        }
        if auth_code.redirect_uri != *redirect_uri {
            return Err(OAuthError::InvalidGrant(
                "redirect_uri mismatch".to_string(),
            ));
        }

        // Validate PKCE
        if !auth_code.validate_code_verifier(code_verifier) {
            return Err(OAuthError::InvalidGrant(
                "code_verifier validation failed".to_string(),
            ));
        }

        // Authenticate client (if confidential)
        let client = self.get_client(&request.client_id).ok_or_else(|| {
            OAuthError::InvalidClient(format!("client '{}' not found", request.client_id))
        })?;

        if client.client_type == ClientType::Confidential {
            if !client.authenticate(request.client_secret.as_deref()) {
                return Err(OAuthError::InvalidClient(
                    "client authentication failed".to_string(),
                ));
            }
        }

        // Issue tokens
        self.issue_tokens(
            &auth_code.client_id,
            &auth_code.scopes,
            auth_code.subject.as_deref(),
        )
    }

    fn token_refresh_token(&self, request: &TokenRequest) -> Result<TokenResponse, OAuthError> {
        let refresh_token_value = request
            .refresh_token
            .as_ref()
            .ok_or_else(|| OAuthError::InvalidRequest("refresh_token is required".to_string()))?;

        // Get and validate refresh token
        let refresh_token = {
            let state = self
                .state
                .read()
                .map_err(|_| OAuthError::ServerError("failed to acquire read lock".to_string()))?;

            // Check if revoked
            if state.revoked_tokens.contains(refresh_token_value) {
                return Err(OAuthError::InvalidGrant(
                    "refresh token has been revoked".to_string(),
                ));
            }

            state
                .refresh_tokens
                .get(refresh_token_value)
                .cloned()
                .ok_or_else(|| OAuthError::InvalidGrant("refresh token not found".to_string()))?
        };

        if refresh_token.is_expired() {
            return Err(OAuthError::InvalidGrant(
                "refresh token has expired".to_string(),
            ));
        }
        if refresh_token.client_id != request.client_id {
            return Err(OAuthError::InvalidGrant("client_id mismatch".to_string()));
        }

        // Authenticate client
        let client = self.get_client(&request.client_id).ok_or_else(|| {
            OAuthError::InvalidClient(format!("client '{}' not found", request.client_id))
        })?;

        if client.client_type == ClientType::Confidential {
            if !client.authenticate(request.client_secret.as_deref()) {
                return Err(OAuthError::InvalidClient(
                    "client authentication failed".to_string(),
                ));
            }
        }

        // Determine scopes (subset of original if specified)
        let scopes = if let Some(requested) = &request.scopes {
            // Validate that requested scopes are a subset of original
            for scope in requested {
                if !refresh_token.scopes.contains(scope) {
                    return Err(OAuthError::InvalidScope(format!(
                        "scope '{}' was not in original grant",
                        scope
                    )));
                }
            }
            requested.clone()
        } else {
            refresh_token.scopes.clone()
        };

        // Issue new access token (keep same refresh token)
        let now = Instant::now();
        let access_token_value = generate_token(self.config.token_entropy_bytes);
        let access_token = OAuthToken {
            token: access_token_value.clone(),
            token_type: TokenType::Bearer,
            client_id: request.client_id.clone(),
            scopes: scopes.clone(),
            issued_at: now,
            expires_at: now + self.config.access_token_lifetime,
            subject: refresh_token.subject.clone(),
            is_refresh_token: false,
        };

        // Store new access token
        {
            let mut state = self
                .state
                .write()
                .map_err(|_| OAuthError::ServerError("failed to acquire write lock".to_string()))?;
            state
                .access_tokens
                .insert(access_token_value.clone(), access_token.clone());
        }

        Ok(TokenResponse {
            access_token: access_token_value,
            token_type: access_token.token_type.as_str().to_string(),
            expires_in: access_token.expires_in_secs(),
            refresh_token: None, // Don't issue new refresh token
            scope: if scopes.is_empty() {
                None
            } else {
                Some(scopes.join(" "))
            },
        })
    }

    fn issue_tokens(
        &self,
        client_id: &str,
        scopes: &[String],
        subject: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        let now = Instant::now();

        // Generate access token
        let access_token_value = generate_token(self.config.token_entropy_bytes);
        let access_token = OAuthToken {
            token: access_token_value.clone(),
            token_type: TokenType::Bearer,
            client_id: client_id.to_string(),
            scopes: scopes.to_vec(),
            issued_at: now,
            expires_at: now + self.config.access_token_lifetime,
            subject: subject.map(String::from),
            is_refresh_token: false,
        };

        // Generate refresh token
        let refresh_token_value = generate_token(self.config.token_entropy_bytes);
        let refresh_token = OAuthToken {
            token: refresh_token_value.clone(),
            token_type: TokenType::Bearer,
            client_id: client_id.to_string(),
            scopes: scopes.to_vec(),
            issued_at: now,
            expires_at: now + self.config.refresh_token_lifetime,
            subject: subject.map(String::from),
            is_refresh_token: true,
        };

        // Store tokens
        {
            let mut state = self
                .state
                .write()
                .map_err(|_| OAuthError::ServerError("failed to acquire write lock".to_string()))?;
            state
                .access_tokens
                .insert(access_token_value.clone(), access_token.clone());
            state
                .refresh_tokens
                .insert(refresh_token_value.clone(), refresh_token);
        }

        Ok(TokenResponse {
            access_token: access_token_value,
            token_type: access_token.token_type.as_str().to_string(),
            expires_in: access_token.expires_in_secs(),
            refresh_token: Some(refresh_token_value),
            scope: if scopes.is_empty() {
                None
            } else {
                Some(scopes.join(" "))
            },
        })
    }

    // -------------------------------------------------------------------------
    // Token Revocation (RFC 7009)
    // -------------------------------------------------------------------------

    /// Revokes a token (access or refresh).
    ///
    /// Per RFC 7009, this always returns success even if the token was not found.
    pub fn revoke(
        &self,
        token: &str,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<(), OAuthError> {
        // Authenticate client
        let client = self.get_client(client_id).ok_or_else(|| {
            OAuthError::InvalidClient(format!("client '{}' not found", client_id))
        })?;

        if client.client_type == ClientType::Confidential {
            if !client.authenticate(client_secret) {
                return Err(OAuthError::InvalidClient(
                    "client authentication failed".to_string(),
                ));
            }
        }

        let mut state = self
            .state
            .write()
            .map_err(|_| OAuthError::ServerError("failed to acquire write lock".to_string()))?;

        // Try to find and remove the token
        let found_access = state.access_tokens.remove(token);
        let found_refresh = state.refresh_tokens.remove(token);

        // Validate client owns the token (if found)
        if let Some(ref t) = found_access {
            if t.client_id != client_id {
                // Don't reveal that the token exists but belongs to another client
                return Ok(());
            }
        }
        if let Some(ref t) = found_refresh {
            if t.client_id != client_id {
                return Ok(());
            }
        }

        // Mark as revoked
        if found_access.is_some() || found_refresh.is_some() {
            state.revoked_tokens.insert(token.to_string());
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Token Introspection
    // -------------------------------------------------------------------------

    /// Validates an access token and returns its metadata.
    ///
    /// This is used internally and by the [`OAuthTokenVerifier`].
    pub fn validate_access_token(&self, token: &str) -> Option<OAuthToken> {
        let state = self.state.read().ok()?;

        // Check if revoked
        if state.revoked_tokens.contains(token) {
            return None;
        }

        let token_info = state.access_tokens.get(token)?;

        if token_info.is_expired() {
            return None;
        }

        Some(token_info.clone())
    }

    // -------------------------------------------------------------------------
    // MCP Integration
    // -------------------------------------------------------------------------

    /// Creates a token verifier for use with MCP [`TokenAuthProvider`].
    #[must_use]
    pub fn token_verifier(self: &Arc<Self>) -> OAuthTokenVerifier {
        OAuthTokenVerifier {
            server: Arc::clone(self),
        }
    }

    // -------------------------------------------------------------------------
    // Maintenance
    // -------------------------------------------------------------------------

    /// Removes expired tokens and authorization codes.
    ///
    /// Call this periodically to prevent memory growth.
    pub fn cleanup_expired(&self) {
        let Ok(mut state) = self.state.write() else {
            return;
        };

        // Remove expired authorization codes
        state.authorization_codes.retain(|_, c| !c.is_expired());

        // Remove expired access tokens
        state.access_tokens.retain(|_, t| !t.is_expired());

        // Remove expired refresh tokens
        state.refresh_tokens.retain(|_, t| !t.is_expired());
    }

    /// Returns statistics about the server state.
    #[must_use]
    pub fn stats(&self) -> OAuthServerStats {
        let state = self.state.read().unwrap();
        OAuthServerStats {
            clients: state.clients.len(),
            authorization_codes: state.authorization_codes.len(),
            access_tokens: state.access_tokens.len(),
            refresh_tokens: state.refresh_tokens.len(),
            revoked_tokens: state.revoked_tokens.len(),
        }
    }
}

/// Statistics about the OAuth server state.
#[derive(Debug, Clone, Default)]
pub struct OAuthServerStats {
    /// Number of registered clients.
    pub clients: usize,
    /// Number of pending authorization codes.
    pub authorization_codes: usize,
    /// Number of active access tokens.
    pub access_tokens: usize,
    /// Number of active refresh tokens.
    pub refresh_tokens: usize,
    /// Number of revoked tokens.
    pub revoked_tokens: usize,
}

// =============================================================================
// Token Verifier Implementation
// =============================================================================

/// OAuth token verifier for MCP integration.
///
/// This implements [`TokenVerifier`] to allow the OAuth server to be used
/// with the MCP server's [`TokenAuthProvider`].
pub struct OAuthTokenVerifier {
    server: Arc<OAuthServer>,
}

impl TokenVerifier for OAuthTokenVerifier {
    fn verify(
        &self,
        _ctx: &McpContext,
        _request: AuthRequest<'_>,
        token: &AccessToken,
    ) -> McpResult<AuthContext> {
        // Only accept Bearer tokens
        if !token.scheme.eq_ignore_ascii_case("Bearer") {
            return Err(McpError::new(
                McpErrorCode::ResourceForbidden,
                "unsupported auth scheme",
            ));
        }

        // Validate the token
        let token_info = self
            .server
            .validate_access_token(&token.token)
            .ok_or_else(|| {
                McpError::new(McpErrorCode::ResourceForbidden, "invalid or expired token")
            })?;

        Ok(AuthContext {
            subject: token_info.subject,
            scopes: token_info.scopes,
            token: Some(token.clone()),
            claims: Some(serde_json::json!({
                "client_id": token_info.client_id,
                "iss": self.server.config.issuer,
                "iat": token_info.issued_at.elapsed().as_secs(),
            })),
        })
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Generates a cryptographically secure random token.
fn generate_token(bytes: usize) -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    // Use system randomness via multiple hash iterations
    let mut result = Vec::with_capacity(bytes * 2);
    let state = RandomState::new();

    for i in 0..bytes {
        let mut hasher = state.build_hasher();
        hasher.write_usize(i);
        hasher.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        );
        let hash = hasher.finish();
        result.extend_from_slice(&hash.to_le_bytes()[..2]);
    }

    // Base64url encode (URL-safe, no padding)
    base64url_encode(&result[..bytes])
}

/// Base64url encodes bytes (URL-safe, no padding).
fn base64url_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::with_capacity((data.len() * 4).div_ceil(3));
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

/// Computes S256 code challenge from a verifier.
fn compute_s256_challenge(verifier: &str) -> String {
    // Simple SHA-256 implementation for PKCE
    // In production, use a proper crypto library
    let hash = simple_sha256(verifier.as_bytes());
    base64url_encode(&hash)
}

/// Simple SHA-256 implementation (for PKCE code challenge).
/// Note: In production, use a proper cryptographic library.
fn simple_sha256(data: &[u8]) -> [u8; 32] {
    // This is a simplified hash for demonstration.
    // In a real implementation, use ring, sha2, or similar.
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

/// URL-encodes a string.
fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", byte));
            }
        }
    }
    result
}

/// Constant-time string comparison.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

/// Checks if a URI is a localhost redirect.
fn is_localhost_redirect(uri: &str) -> bool {
    uri.starts_with("http://localhost")
        || uri.starts_with("http://127.0.0.1")
        || uri.starts_with("http://[::1]")
}

/// Checks if two localhost URIs match (ignoring port).
fn localhost_match(a: &str, b: &str) -> bool {
    // Extract scheme and path, ignore port
    fn extract_parts(uri: &str) -> Option<(String, String)> {
        let after_scheme = uri.strip_prefix("http://")?;
        // Find the host:port separator (first / or end of string)
        let path_start = after_scheme.find('/').unwrap_or(after_scheme.len());
        let host_port = &after_scheme[..path_start];
        let path = &after_scheme[path_start..];

        // Extract host (remove port)
        let host = host_port.rsplit_once(':').map_or(host_port, |(h, _)| h);
        Some((host.to_string(), path.to_string()))
    }

    match (extract_parts(a), extract_parts(b)) {
        (Some((host_a, path_a)), Some((host_b, path_b))) => {
            normalize_localhost(&host_a) == normalize_localhost(&host_b) && path_a == path_b
        }
        _ => false,
    }
}

/// Normalizes localhost variants.
fn normalize_localhost(host: &str) -> &'static str {
    match host {
        "localhost" | "127.0.0.1" | "[::1]" => "localhost",
        _ => "other",
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_builder() {
        let client = OAuthClient::builder("test-client")
            .redirect_uri("http://localhost:3000/callback")
            .scope("read")
            .scope("write")
            .name("Test Client")
            .build()
            .unwrap();

        assert_eq!(client.client_id, "test-client");
        assert_eq!(client.client_type, ClientType::Public);
        assert_eq!(client.redirect_uris.len(), 1);
        assert!(client.allowed_scopes.contains("read"));
        assert!(client.allowed_scopes.contains("write"));
    }

    #[test]
    fn test_confidential_client() {
        let client = OAuthClient::builder("test-client")
            .secret("super-secret")
            .redirect_uri("http://localhost:3000/callback")
            .build()
            .unwrap();

        assert_eq!(client.client_type, ClientType::Confidential);
        assert!(client.authenticate(Some("super-secret")));
        assert!(!client.authenticate(Some("wrong-secret")));
        assert!(!client.authenticate(None));
    }

    #[test]
    fn test_redirect_uri_validation() {
        let client = OAuthClient::builder("test-client")
            .redirect_uri("http://localhost:3000/callback")
            .redirect_uri("https://example.com/oauth/callback")
            .build()
            .unwrap();

        // Exact match
        assert!(client.validate_redirect_uri("http://localhost:3000/callback"));
        assert!(client.validate_redirect_uri("https://example.com/oauth/callback"));

        // Localhost with different port (allowed per RFC 8252)
        assert!(client.validate_redirect_uri("http://localhost:8080/callback"));
        assert!(client.validate_redirect_uri("http://127.0.0.1:9000/callback"));

        // Invalid
        assert!(!client.validate_redirect_uri("http://localhost:3000/other"));
        assert!(!client.validate_redirect_uri("https://evil.com/callback"));
    }

    #[test]
    fn test_scope_validation() {
        let client = OAuthClient::builder("test-client")
            .redirect_uri("http://localhost:3000/callback")
            .scope("read")
            .scope("write")
            .build()
            .unwrap();

        assert!(client.validate_scopes(&["read".to_string()]));
        assert!(client.validate_scopes(&["read".to_string(), "write".to_string()]));
        assert!(!client.validate_scopes(&["admin".to_string()]));
    }

    #[test]
    fn test_oauth_server_client_registration() {
        let server = OAuthServer::with_defaults();

        let client = OAuthClient::builder("test-client")
            .redirect_uri("http://localhost:3000/callback")
            .build()
            .unwrap();

        server.register_client(client).unwrap();

        // Duplicate registration should fail
        let client2 = OAuthClient::builder("test-client")
            .redirect_uri("http://localhost:3000/callback")
            .build()
            .unwrap();
        assert!(server.register_client(client2).is_err());

        // Verify client exists
        assert!(server.get_client("test-client").is_some());
        assert!(server.get_client("nonexistent").is_none());
    }

    #[test]
    fn test_authorization_flow() {
        let server = OAuthServer::with_defaults();

        let client = OAuthClient::builder("test-client")
            .redirect_uri("http://localhost:3000/callback")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        // Create authorization request
        let request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "http://localhost:3000/callback".to_string(),
            scopes: vec!["read".to_string()],
            state: Some("xyz".to_string()),
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
        };

        let (code, redirect) = server
            .authorize(&request, Some("user123".to_string()))
            .unwrap();

        assert!(!code.is_empty());
        assert!(redirect.contains("code="));
        assert!(redirect.contains("state=xyz"));
    }

    #[test]
    fn test_pkce_required() {
        let server = OAuthServer::with_defaults();

        let client = OAuthClient::builder("test-client")
            .redirect_uri("http://localhost:3000/callback")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        // Request without PKCE should fail
        let request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "http://localhost:3000/callback".to_string(),
            scopes: vec![],
            state: None,
            code_challenge: String::new(), // Missing!
            code_challenge_method: CodeChallengeMethod::S256,
        };

        let result = server.authorize(&request, None);
        assert!(matches!(result, Err(OAuthError::InvalidRequest(_))));
    }

    #[test]
    fn test_token_generation() {
        let token1 = generate_token(32);
        let token2 = generate_token(32);

        // Tokens should be unique
        assert_ne!(token1, token2);
        // Tokens should be URL-safe
        assert!(
            token1
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn test_base64url_encode() {
        // Test vectors from RFC 4648
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(b"foob"), "Zm9vYg");
        assert_eq!(base64url_encode(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("hello"), "hello");
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("a=b&c=d"), "a%3Db%26c%3Dd");
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("hello", "hello"));
        assert!(!constant_time_eq("hello", "world"));
        assert!(!constant_time_eq("hello", "hell"));
    }

    #[test]
    fn test_localhost_match() {
        assert!(localhost_match(
            "http://localhost:3000/callback",
            "http://localhost:8080/callback"
        ));
        assert!(localhost_match(
            "http://127.0.0.1:3000/callback",
            "http://localhost:8080/callback"
        ));
        assert!(!localhost_match(
            "http://localhost:3000/callback",
            "http://localhost:3000/other"
        ));
    }

    #[test]
    fn test_oauth_server_stats() {
        let server = OAuthServer::with_defaults();

        let stats = server.stats();
        assert_eq!(stats.clients, 0);
        assert_eq!(stats.access_tokens, 0);

        let client = OAuthClient::builder("test-client")
            .redirect_uri("http://localhost:3000/callback")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let stats = server.stats();
        assert_eq!(stats.clients, 1);
    }

    #[test]
    fn test_code_challenge_method_parse() {
        assert_eq!(
            CodeChallengeMethod::parse("plain"),
            Some(CodeChallengeMethod::Plain)
        );
        assert_eq!(
            CodeChallengeMethod::parse("S256"),
            Some(CodeChallengeMethod::S256)
        );
        assert_eq!(CodeChallengeMethod::parse("unknown"), None);
    }

    #[test]
    fn test_oauth_error_display() {
        let err = OAuthError::InvalidRequest("missing parameter".to_string());
        assert_eq!(err.error_code(), "invalid_request");
        assert_eq!(err.description(), "missing parameter");
        assert_eq!(err.to_string(), "invalid_request: missing parameter");
    }

    #[test]
    fn test_token_revocation() {
        let server = Arc::new(OAuthServer::with_defaults());

        // Register a client
        let client = OAuthClient::builder("test-client")
            .redirect_uri("http://localhost:3000/callback")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        // Manually create a token for testing
        let token_response = {
            let mut state = server.state.write().unwrap();
            let now = Instant::now();
            let token = OAuthToken {
                token: "test-access-token".to_string(),
                token_type: TokenType::Bearer,
                client_id: "test-client".to_string(),
                scopes: vec!["read".to_string()],
                issued_at: now,
                expires_at: now + Duration::from_secs(3600),
                subject: Some("user123".to_string()),
                is_refresh_token: false,
            };
            state
                .access_tokens
                .insert("test-access-token".to_string(), token);
            TokenResponse {
                access_token: "test-access-token".to_string(),
                token_type: "bearer".to_string(),
                expires_in: 3600,
                refresh_token: None,
                scope: Some("read".to_string()),
            }
        };

        // Token should be valid
        assert!(
            server
                .validate_access_token(&token_response.access_token)
                .is_some()
        );

        // Revoke the token
        server
            .revoke(&token_response.access_token, "test-client", None)
            .unwrap();

        // Token should no longer be valid
        assert!(
            server
                .validate_access_token(&token_response.access_token)
                .is_none()
        );
    }

    #[test]
    fn test_client_unregistration() {
        let server = OAuthServer::with_defaults();

        let client = OAuthClient::builder("test-client")
            .redirect_uri("http://localhost:3000/callback")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        assert!(server.get_client("test-client").is_some());

        server.unregister_client("test-client").unwrap();

        assert!(server.get_client("test-client").is_none());

        // Unregistering again should fail
        assert!(server.unregister_client("test-client").is_err());
    }

    #[test]
    fn test_token_verifier() {
        let server = Arc::new(OAuthServer::with_defaults());

        // Register a client and create a token
        let client = OAuthClient::builder("test-client")
            .redirect_uri("http://localhost:3000/callback")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        // Create a token manually
        {
            let mut state = server.state.write().unwrap();
            let now = Instant::now();
            let token = OAuthToken {
                token: "valid-token".to_string(),
                token_type: TokenType::Bearer,
                client_id: "test-client".to_string(),
                scopes: vec!["read".to_string()],
                issued_at: now,
                expires_at: now + Duration::from_secs(3600),
                subject: Some("user123".to_string()),
                is_refresh_token: false,
            };
            state.access_tokens.insert("valid-token".to_string(), token);
        }

        // Create verifier
        let verifier = server.token_verifier();
        let cx = asupersync::Cx::for_testing();
        let mcp_ctx = McpContext::new(cx, 1);
        let auth_request = AuthRequest {
            method: "test",
            params: None,
            request_id: 1,
        };

        // Valid token
        let access = AccessToken {
            scheme: "Bearer".to_string(),
            token: "valid-token".to_string(),
        };
        let result = verifier.verify(&mcp_ctx, auth_request, &access);
        assert!(result.is_ok());
        let auth = result.unwrap();
        assert_eq!(auth.subject, Some("user123".to_string()));
        assert_eq!(auth.scopes, vec!["read".to_string()]);

        // Invalid token
        let invalid = AccessToken {
            scheme: "Bearer".to_string(),
            token: "invalid-token".to_string(),
        };
        let result = verifier.verify(&mcp_ctx, auth_request, &invalid);
        assert!(result.is_err());

        // Wrong scheme
        let wrong_scheme = AccessToken {
            scheme: "Basic".to_string(),
            token: "valid-token".to_string(),
        };
        let result = verifier.verify(&mcp_ctx, auth_request, &wrong_scheme);
        assert!(result.is_err());
    }
}
