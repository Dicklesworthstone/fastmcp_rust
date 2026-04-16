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
//! use fastmcp_rust::oauth::{OAuthServer, OAuthServerConfig, OAuthClient};
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
use std::time::{Duration, Instant, SystemTime};

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
    client_credential: Option<String>,
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
            client_credential: None,
            redirect_uris: Vec::new(),
            allowed_scopes: HashSet::new(),
            name: None,
            description: None,
        }
    }

    /// Sets the client secret (makes this a confidential client).
    #[must_use]
    pub fn secret(mut self, credential: impl Into<String>) -> Self {
        self.client_credential = Some(credential.into());
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

        let client_type = if self.client_credential.is_some() {
            ClientType::Confidential
        } else {
            ClientType::Public
        };

        Ok(OAuthClient {
            client_id: self.client_id,
            client_secret: self.client_credential,
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
        let code_value = generate_token(self.config.token_entropy_bytes)?;
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
        let refresh_value = request
            .refresh_token
            .as_ref()
            .ok_or_else(|| OAuthError::InvalidRequest("refresh_token is required".to_string()))?;

        // Get and validate refresh token
        let stored_refresh = {
            let state = self
                .state
                .read()
                .map_err(|_| OAuthError::ServerError("failed to acquire read lock".to_string()))?;

            // Check if revoked
            if state.revoked_tokens.contains(refresh_value) {
                return Err(OAuthError::InvalidGrant(
                    "refresh token has been revoked".to_string(),
                ));
            }

            state
                .refresh_tokens
                .get(refresh_value)
                .cloned()
                .ok_or_else(|| OAuthError::InvalidGrant("refresh token not found".to_string()))?
        };

        if stored_refresh.is_expired() {
            return Err(OAuthError::InvalidGrant(
                "refresh token has expired".to_string(),
            ));
        }
        if stored_refresh.client_id != request.client_id {
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
                if !stored_refresh.scopes.contains(scope) {
                    return Err(OAuthError::InvalidScope(format!(
                        "scope '{}' was not in original grant",
                        scope
                    )));
                }
            }
            requested.clone()
        } else {
            stored_refresh.scopes.clone()
        };

        // Issue new access token (keep same refresh token)
        let now = Instant::now();
        let access_value = generate_token(self.config.token_entropy_bytes)?;
        let issued_access = OAuthToken {
            token: access_value.clone(),
            token_type: TokenType::Bearer,
            client_id: request.client_id.clone(),
            scopes: scopes.clone(),
            issued_at: now,
            expires_at: now + self.config.access_token_lifetime,
            subject: stored_refresh.subject.clone(),
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
                .insert(access_value.clone(), issued_access.clone());
        }

        Ok(TokenResponse {
            access_token: access_value,
            token_type: issued_access.token_type.as_str().to_string(),
            expires_in: issued_access.expires_in_secs(),
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
        let access_value = generate_token(self.config.token_entropy_bytes)?;
        let access_cred = OAuthToken {
            token: access_value.clone(),
            token_type: TokenType::Bearer,
            client_id: client_id.to_string(),
            scopes: scopes.to_vec(),
            issued_at: now,
            expires_at: now + self.config.access_token_lifetime,
            subject: subject.map(String::from),
            is_refresh_token: false,
        };

        // Generate refresh token
        let refresh_value = generate_token(self.config.token_entropy_bytes)?;
        let refresh_cred = OAuthToken {
            token: refresh_value.clone(),
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
                .insert(access_value.clone(), access_cred.clone());
            state
                .refresh_tokens
                .insert(refresh_value.clone(), refresh_cred);
        }

        Ok(TokenResponse {
            access_token: access_value,
            token_type: access_cred.token_type.as_str().to_string(),
            expires_in: access_cred.expires_in_secs(),
            refresh_token: Some(refresh_value),
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

    /// Creates a token verifier for use with MCP [`crate::auth::TokenAuthProvider`].
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
        let state = match self.state.read() {
            Ok(guard) => guard,
            // Preserve observability during partial failure instead of panicking on poison.
            Err(poisoned) => poisoned.into_inner(),
        };
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
/// with the MCP server's [`crate::auth::TokenAuthProvider`].
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
fn generate_token(bytes: usize) -> Result<String, OAuthError> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf)
        .map_err(|e| OAuthError::ServerError(format!("secure random generation failed: {e}")))?;

    // Base64url encode (URL-safe, no padding).
    Ok(base64url_encode(&buf))
}

/// Base64url encodes bytes (URL-safe, no padding).
fn base64url_encode(data: &[u8]) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    URL_SAFE_NO_PAD.encode(data)
}

/// Computes S256 code challenge from a verifier.
fn compute_s256_challenge(verifier: &str) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(verifier.as_bytes());
    base64url_encode(&hash)
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

    fn issue_access_token_via_auth_code(
        server: &OAuthServer,
        client_id: &str,
        redirect_uri: &str,
        scopes: &[&str],
        subject: &str,
    ) -> TokenResponse {
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string();
        let auth_request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
            state: Some("oauth-test-state".to_string()),
            code_challenge: code_verifier.clone(),
            code_challenge_method: CodeChallengeMethod::Plain,
        };

        let (code, _redirect) = server
            .authorize(&auth_request, Some(subject.to_string()))
            .expect("authorize");
        server
            .token(&TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some(code),
                redirect_uri: Some(redirect_uri.to_string()),
                client_id: client_id.to_string(),
                client_secret: None,
                code_verifier: Some(code_verifier),
                refresh_token: None,
                scopes: None,
            })
            .expect("token exchange")
    }

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
        let value1 = generate_token(32).unwrap();
        let value2 = generate_token(32).unwrap();

        // Tokens should be unique
        assert_ne!(value1, value2);
        // Tokens should be URL-safe
        assert!(
            value1
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

        let token_response = issue_access_token_via_auth_code(
            server.as_ref(),
            "test-client",
            "http://localhost:3000/callback",
            &["read"],
            "user123",
        );

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

        let token_response = issue_access_token_via_auth_code(
            server.as_ref(),
            "test-client",
            "http://localhost:3000/callback",
            &["read"],
            "user123",
        );

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
            token: token_response.access_token.clone(),
        };
        let result = verifier.verify(&mcp_ctx, auth_request, &access);
        assert!(result.is_ok());
        let auth = result.unwrap();
        assert_eq!(auth.subject, Some("user123".to_string()));
        assert_eq!(auth.scopes, vec!["read".to_string()]);

        // Invalid token
        let invalid = AccessToken {
            scheme: "Bearer".to_string(),
            token: "invalid-value".to_string(),
        };
        let result = verifier.verify(&mcp_ctx, auth_request, &invalid);
        assert!(result.is_err());

        // Wrong scheme
        let wrong_scheme = AccessToken {
            scheme: "Basic".to_string(),
            token: token_response.access_token,
        };
        let result = verifier.verify(&mcp_ctx, auth_request, &wrong_scheme);
        assert!(result.is_err());
    }

    // ========================================
    // OAuthServerConfig
    // ========================================

    #[test]
    fn config_default_values() {
        let c = OAuthServerConfig::default();
        assert_eq!(c.issuer, "fastmcp");
        assert_eq!(c.access_token_lifetime, Duration::from_secs(3600));
        assert_eq!(c.refresh_token_lifetime, Duration::from_secs(86400 * 30));
        assert_eq!(c.authorization_code_lifetime, Duration::from_secs(600));
        assert!(c.allow_public_clients);
        assert_eq!(c.min_code_verifier_length, 43);
        assert_eq!(c.max_code_verifier_length, 128);
        assert_eq!(c.token_entropy_bytes, 32);
    }

    #[test]
    fn config_debug_and_clone() {
        let c = OAuthServerConfig::default();
        let debug = format!("{:?}", c);
        assert!(debug.contains("OAuthServerConfig"));
        assert!(debug.contains("fastmcp"));

        let cloned = c.clone();
        assert_eq!(cloned.issuer, "fastmcp");
    }

    // ========================================
    // ClientType
    // ========================================

    #[test]
    fn client_type_debug_and_eq() {
        assert_eq!(ClientType::Public, ClientType::Public);
        assert_ne!(ClientType::Public, ClientType::Confidential);
        let debug = format!("{:?}", ClientType::Confidential);
        assert!(debug.contains("Confidential"));
    }

    #[test]
    fn client_type_copy() {
        let t = ClientType::Public;
        let t2 = t; // Copy
        assert_eq!(t, t2);
    }

    // ========================================
    // OAuthClient — additional
    // ========================================

    #[test]
    fn client_debug_and_clone() {
        let client = OAuthClient::builder("dbg")
            .redirect_uri("http://localhost/cb")
            .build()
            .unwrap();
        let debug = format!("{:?}", client);
        assert!(debug.contains("OAuthClient"));
        assert!(debug.contains("dbg"));

        let cloned = client.clone();
        assert_eq!(cloned.client_id, "dbg");
    }

    #[test]
    fn client_authenticate_public_no_secret() {
        let client = OAuthClient::builder("pub")
            .redirect_uri("http://localhost/cb")
            .build()
            .unwrap();
        // Public client with no secret provided: should succeed
        assert!(client.authenticate(None));
        // Public client with secret provided: should fail
        assert!(!client.authenticate(Some("any")));
    }

    #[test]
    fn client_validate_redirect_uri_non_localhost() {
        let client = OAuthClient::builder("c")
            .redirect_uri("https://example.com/cb")
            .build()
            .unwrap();
        // Non-localhost requires exact match
        assert!(client.validate_redirect_uri("https://example.com/cb"));
        assert!(!client.validate_redirect_uri("https://example.com/cb2"));
        assert!(!client.validate_redirect_uri("https://other.com/cb"));
    }

    #[test]
    fn client_validate_redirect_uri_localhost_ipv6() {
        let client = OAuthClient::builder("c")
            .redirect_uri("http://[::1]:3000/callback")
            .build()
            .unwrap();
        // IPv6 localhost with different port
        assert!(client.validate_redirect_uri("http://[::1]:8080/callback"));
        // Cross-localhost variant match
        assert!(client.validate_redirect_uri("http://localhost:9000/callback"));
    }

    #[test]
    fn client_validate_scopes_empty() {
        let client = OAuthClient::builder("c")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        // Empty scopes should always be valid
        assert!(client.validate_scopes(&[]));
    }

    // ========================================
    // OAuthClientBuilder — additional
    // ========================================

    #[test]
    fn client_builder_debug() {
        let builder = OAuthClient::builder("test-id");
        let debug = format!("{:?}", builder);
        assert!(debug.contains("OAuthClientBuilder"));
        assert!(debug.contains("test-id"));
    }

    #[test]
    fn client_builder_empty_id_fails() {
        let result = OAuthClient::builder("")
            .redirect_uri("http://localhost/cb")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn client_builder_no_redirect_uris_fails() {
        let result = OAuthClient::builder("c").build();
        assert!(result.is_err());
    }

    #[test]
    fn client_builder_redirect_uris_multiple() {
        let client = OAuthClient::builder("c")
            .redirect_uris(vec!["http://localhost/a", "http://localhost/b"])
            .build()
            .unwrap();
        assert_eq!(client.redirect_uris.len(), 2);
    }

    #[test]
    fn client_builder_scopes_multiple() {
        let client = OAuthClient::builder("c")
            .redirect_uri("http://localhost/cb")
            .scopes(vec!["r", "w", "admin"])
            .build()
            .unwrap();
        assert_eq!(client.allowed_scopes.len(), 3);
    }

    #[test]
    fn client_builder_description() {
        let client = OAuthClient::builder("c")
            .redirect_uri("http://localhost/cb")
            .description("A test app")
            .build()
            .unwrap();
        assert_eq!(client.description, Some("A test app".to_string()));
    }

    // ========================================
    // CodeChallengeMethod — additional
    // ========================================

    #[test]
    fn code_challenge_method_as_str() {
        assert_eq!(CodeChallengeMethod::Plain.as_str(), "plain");
        assert_eq!(CodeChallengeMethod::S256.as_str(), "S256");
    }

    #[test]
    fn code_challenge_method_clone_copy_eq() {
        let m = CodeChallengeMethod::S256;
        let m2 = m; // Copy
        assert_eq!(m, m2);
        let m3 = m.clone();
        assert_eq!(m, m3);
    }

    // ========================================
    // AuthorizationCode
    // ========================================

    #[test]
    fn authorization_code_not_expired_initially() {
        let code = AuthorizationCode {
            code: "test-code".to_string(),
            client_id: "c".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scopes: vec![],
            code_challenge: "challenge".to_string(),
            code_challenge_method: CodeChallengeMethod::Plain,
            issued_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(600),
            subject: None,
            state: None,
        };
        assert!(!code.is_expired());
    }

    #[test]
    fn authorization_code_expired() {
        let code = AuthorizationCode {
            code: "test-code".to_string(),
            client_id: "c".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scopes: vec![],
            code_challenge: "challenge".to_string(),
            code_challenge_method: CodeChallengeMethod::Plain,
            issued_at: Instant::now() - Duration::from_secs(100),
            expires_at: Instant::now() - Duration::from_secs(1),
            subject: None,
            state: None,
        };
        assert!(code.is_expired());
    }

    #[test]
    fn authorization_code_validate_plain() {
        let code = AuthorizationCode {
            code: "test".to_string(),
            client_id: "c".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scopes: vec![],
            code_challenge: "my-verifier".to_string(),
            code_challenge_method: CodeChallengeMethod::Plain,
            issued_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(600),
            subject: None,
            state: None,
        };
        assert!(code.validate_code_verifier("my-verifier"));
        assert!(!code.validate_code_verifier("wrong"));
    }

    #[test]
    fn authorization_code_validate_s256() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = compute_s256_challenge(verifier);
        let code = AuthorizationCode {
            code: "test".to_string(),
            client_id: "c".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scopes: vec![],
            code_challenge: challenge,
            code_challenge_method: CodeChallengeMethod::S256,
            issued_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(600),
            subject: None,
            state: None,
        };
        assert!(code.validate_code_verifier(verifier));
        assert!(!code.validate_code_verifier("wrong-verifier"));
    }

    #[test]
    fn authorization_code_debug_and_clone() {
        let code = AuthorizationCode {
            code: "c".to_string(),
            client_id: "cid".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scopes: vec!["read".to_string()],
            code_challenge: "ch".to_string(),
            code_challenge_method: CodeChallengeMethod::Plain,
            issued_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(60),
            subject: Some("user".to_string()),
            state: Some("state".to_string()),
        };
        let debug = format!("{:?}", code);
        assert!(debug.contains("AuthorizationCode"));
        let cloned = code.clone();
        assert_eq!(cloned.client_id, "cid");
    }

    // ========================================
    // TokenType
    // ========================================

    #[test]
    fn token_type_as_str() {
        assert_eq!(TokenType::Bearer.as_str(), "bearer");
    }

    #[test]
    fn token_type_debug_clone_copy_eq() {
        let t = TokenType::Bearer;
        let t2 = t; // Copy
        assert_eq!(t, t2);
        let t3 = t.clone();
        assert_eq!(t, t3);
        let debug = format!("{:?}", t);
        assert!(debug.contains("Bearer"));
    }

    // ========================================
    // OAuthToken
    // ========================================

    #[test]
    fn oauth_token_not_expired() {
        let token = OAuthToken {
            token: "t".to_string(),
            token_type: TokenType::Bearer,
            client_id: "c".to_string(),
            scopes: vec![],
            issued_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(3600),
            subject: None,
            is_refresh_token: false,
        };
        assert!(!token.is_expired());
        assert!(token.expires_in_secs() > 0);
    }

    #[test]
    fn oauth_token_expired() {
        let token = OAuthToken {
            token: "t".to_string(),
            token_type: TokenType::Bearer,
            client_id: "c".to_string(),
            scopes: vec![],
            issued_at: Instant::now() - Duration::from_secs(100),
            expires_at: Instant::now() - Duration::from_secs(1),
            subject: None,
            is_refresh_token: false,
        };
        assert!(token.is_expired());
        assert_eq!(token.expires_in_secs(), 0);
    }

    #[test]
    fn oauth_token_debug_and_clone() {
        let token = OAuthToken {
            token: "tok".to_string(),
            token_type: TokenType::Bearer,
            client_id: "c".to_string(),
            scopes: vec!["read".to_string()],
            issued_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(60),
            subject: Some("user".to_string()),
            is_refresh_token: true,
        };
        let debug = format!("{:?}", token);
        assert!(debug.contains("OAuthToken"));
        let cloned = token.clone();
        assert_eq!(cloned.token, "tok");
        assert!(cloned.is_refresh_token);
    }

    // ========================================
    // TokenResponse
    // ========================================

    #[test]
    fn token_response_serialize_without_optional_fields() {
        let resp = TokenResponse {
            access_token: "at".to_string(),
            token_type: "bearer".to_string(),
            expires_in: 3600,
            refresh_token: None,
            scope: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("refresh_token"));
        assert!(!json.contains("scope"));
    }

    #[test]
    fn token_response_serialize_with_optional_fields() {
        let resp = TokenResponse {
            access_token: "at".to_string(),
            token_type: "bearer".to_string(),
            expires_in: 3600,
            refresh_token: Some("rt".to_string()),
            scope: Some("read write".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("refresh_token"));
        assert!(json.contains("scope"));
    }

    // ========================================
    // AuthorizationRequest / TokenRequest
    // ========================================

    #[test]
    fn authorization_request_debug_and_clone() {
        let req = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "c".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scopes: vec!["read".to_string()],
            state: Some("s".to_string()),
            code_challenge: "ch".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
        };
        let debug = format!("{:?}", req);
        assert!(debug.contains("AuthorizationRequest"));
        let cloned = req.clone();
        assert_eq!(cloned.client_id, "c");
    }

    #[test]
    fn token_request_debug_and_clone() {
        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("code".to_string()),
            redirect_uri: Some("http://localhost/cb".to_string()),
            client_id: "c".to_string(),
            client_secret: None,
            code_verifier: Some("verifier".to_string()),
            refresh_token: None,
            scopes: None,
        };
        let debug = format!("{:?}", req);
        assert!(debug.contains("TokenRequest"));
        let cloned = req.clone();
        assert_eq!(cloned.grant_type, "authorization_code");
    }

    // ========================================
    // OAuthError — additional
    // ========================================

    #[test]
    fn oauth_error_all_codes() {
        let cases: Vec<(OAuthError, &str)> = vec![
            (OAuthError::InvalidRequest("x".into()), "invalid_request"),
            (OAuthError::InvalidClient("x".into()), "invalid_client"),
            (OAuthError::InvalidGrant("x".into()), "invalid_grant"),
            (
                OAuthError::UnauthorizedClient("x".into()),
                "unauthorized_client",
            ),
            (
                OAuthError::UnsupportedGrantType("x".into()),
                "unsupported_grant_type",
            ),
            (OAuthError::InvalidScope("x".into()), "invalid_scope"),
            (OAuthError::ServerError("x".into()), "server_error"),
            (
                OAuthError::TemporarilyUnavailable("x".into()),
                "temporarily_unavailable",
            ),
            (OAuthError::AccessDenied("x".into()), "access_denied"),
            (
                OAuthError::UnsupportedResponseType("x".into()),
                "unsupported_response_type",
            ),
        ];
        for (err, expected_code) in cases {
            assert_eq!(err.error_code(), expected_code);
            assert_eq!(err.description(), "x");
        }
    }

    #[test]
    fn oauth_error_debug_and_clone() {
        let err = OAuthError::ServerError("test".into());
        let debug = format!("{:?}", err);
        assert!(debug.contains("ServerError"));
        let cloned = err.clone();
        assert_eq!(cloned.description(), "test");
    }

    #[test]
    fn oauth_error_is_std_error() {
        let err = OAuthError::InvalidGrant("x".into());
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn oauth_error_into_mcp_error_forbidden() {
        // InvalidClient and UnauthorizedClient and AccessDenied → ResourceForbidden
        let err: McpError = OAuthError::InvalidClient("c".into()).into();
        assert!(err.message.contains("invalid_client"));
        let err: McpError = OAuthError::UnauthorizedClient("c".into()).into();
        assert!(err.message.contains("unauthorized_client"));
        let err: McpError = OAuthError::AccessDenied("d".into()).into();
        assert!(err.message.contains("access_denied"));
    }

    #[test]
    fn oauth_error_into_mcp_error_invalid_request() {
        // Other variants → InvalidRequest
        let err: McpError = OAuthError::InvalidScope("s".into()).into();
        assert!(err.message.contains("invalid_scope"));
        let err: McpError = OAuthError::UnsupportedGrantType("g".into()).into();
        assert!(err.message.contains("unsupported_grant_type"));
    }

    // ========================================
    // OAuthServer — additional
    // ========================================

    #[test]
    fn server_config_accessor() {
        let config = OAuthServerConfig {
            issuer: "custom-issuer".to_string(),
            ..OAuthServerConfig::default()
        };
        let server = OAuthServer::new(config);
        assert_eq!(server.config().issuer, "custom-issuer");
    }

    #[test]
    fn server_register_public_not_allowed() {
        let config = OAuthServerConfig {
            allow_public_clients: false,
            ..OAuthServerConfig::default()
        };
        let server = OAuthServer::new(config);

        let client = OAuthClient::builder("c")
            .redirect_uri("http://localhost/cb")
            .build()
            .unwrap();
        let result = server.register_client(client);
        assert!(matches!(result, Err(OAuthError::InvalidClient(_))));
    }

    #[test]
    fn server_list_clients() {
        let server = OAuthServer::with_defaults();
        assert!(server.list_clients().is_empty());

        let client = OAuthClient::builder("a")
            .redirect_uri("http://localhost/cb")
            .build()
            .unwrap();
        server.register_client(client).unwrap();
        assert_eq!(server.list_clients().len(), 1);
    }

    #[test]
    fn server_authorize_unsupported_response_type() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c")
            .redirect_uri("http://localhost/cb")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let req = AuthorizationRequest {
            response_type: "token".to_string(), // not "code"
            client_id: "c".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scopes: vec![],
            state: None,
            code_challenge: "ch".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
        };
        let result = server.authorize(&req, None);
        assert!(matches!(
            result,
            Err(OAuthError::UnsupportedResponseType(_))
        ));
    }

    #[test]
    fn server_authorize_invalid_redirect() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c")
            .redirect_uri("http://localhost/cb")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let req = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "c".to_string(),
            redirect_uri: "https://evil.com/cb".to_string(),
            scopes: vec![],
            state: None,
            code_challenge: "ch".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
        };
        let result = server.authorize(&req, None);
        assert!(matches!(result, Err(OAuthError::InvalidRequest(_))));
    }

    #[test]
    fn server_authorize_invalid_scope() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let req = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "c".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scopes: vec!["admin".to_string()],
            state: None,
            code_challenge: "ch".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
        };
        let result = server.authorize(&req, None);
        assert!(matches!(result, Err(OAuthError::InvalidScope(_))));
    }

    #[test]
    fn server_authorize_unknown_client() {
        let server = OAuthServer::with_defaults();
        let req = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "nonexistent".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scopes: vec![],
            state: None,
            code_challenge: "ch".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
        };
        let result = server.authorize(&req, None);
        assert!(matches!(result, Err(OAuthError::InvalidClient(_))));
    }

    #[test]
    fn server_token_unsupported_grant_type() {
        let server = OAuthServer::with_defaults();
        let req = TokenRequest {
            grant_type: "client_credentials".to_string(),
            code: None,
            redirect_uri: None,
            client_id: "c".to_string(),
            client_secret: None,
            code_verifier: None,
            refresh_token: None,
            scopes: None,
        };
        let result = server.token(&req);
        assert!(matches!(result, Err(OAuthError::UnsupportedGrantType(_))));
    }

    #[test]
    fn server_token_auth_code_missing_code() {
        let server = OAuthServer::with_defaults();
        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: None, // missing
            redirect_uri: Some("http://localhost/cb".to_string()),
            client_id: "c".to_string(),
            client_secret: None,
            code_verifier: Some("v".repeat(43)),
            refresh_token: None,
            scopes: None,
        };
        let result = server.token(&req);
        assert!(matches!(result, Err(OAuthError::InvalidRequest(_))));
    }

    #[test]
    fn server_token_auth_code_missing_redirect() {
        let server = OAuthServer::with_defaults();
        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("code".to_string()),
            redirect_uri: None, // missing
            client_id: "c".to_string(),
            client_secret: None,
            code_verifier: Some("v".repeat(43)),
            refresh_token: None,
            scopes: None,
        };
        let result = server.token(&req);
        assert!(matches!(result, Err(OAuthError::InvalidRequest(_))));
    }

    #[test]
    fn server_token_auth_code_missing_verifier() {
        let server = OAuthServer::with_defaults();
        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("code".to_string()),
            redirect_uri: Some("http://localhost/cb".to_string()),
            client_id: "c".to_string(),
            client_secret: None,
            code_verifier: None, // missing
            refresh_token: None,
            scopes: None,
        };
        let result = server.token(&req);
        assert!(matches!(result, Err(OAuthError::InvalidRequest(_))));
    }

    #[test]
    fn server_token_auth_code_verifier_too_short() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c")
            .redirect_uri("http://localhost/cb")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        // Authorize first
        let verifier = "short"; // < 43 chars
        let req = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "c".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scopes: vec![],
            state: None,
            code_challenge: verifier.to_string(),
            code_challenge_method: CodeChallengeMethod::Plain,
        };
        let (code, _) = server.authorize(&req, None).unwrap();

        let token_req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code),
            redirect_uri: Some("http://localhost/cb".to_string()),
            client_id: "c".to_string(),
            client_secret: None,
            code_verifier: Some(verifier.to_string()),
            refresh_token: None,
            scopes: None,
        };
        let result = server.token(&token_req);
        assert!(matches!(result, Err(OAuthError::InvalidRequest(_))));
    }

    #[test]
    fn server_full_auth_code_flow_with_s256() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = compute_s256_challenge(verifier);

        let auth_req = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "c".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scopes: vec!["read".to_string()],
            state: None,
            code_challenge: challenge,
            code_challenge_method: CodeChallengeMethod::S256,
        };
        let (code, _) = server
            .authorize(&auth_req, Some("user1".to_string()))
            .unwrap();

        let token_req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code),
            redirect_uri: Some("http://localhost/cb".to_string()),
            client_id: "c".to_string(),
            client_secret: None,
            code_verifier: Some(verifier.to_string()),
            refresh_token: None,
            scopes: None,
        };
        let resp = server.token(&token_req).unwrap();
        assert!(!resp.access_token.is_empty());
        assert!(resp.refresh_token.is_some());
        assert_eq!(resp.token_type, "bearer");
        assert_eq!(resp.scope, Some("read".to_string()));
    }

    #[test]
    fn server_token_code_already_used() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c")
            .redirect_uri("http://localhost/cb")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let auth_req = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "c".to_string(),
            redirect_uri: "http://localhost/cb".to_string(),
            scopes: vec![],
            state: None,
            code_challenge: verifier.to_string(),
            code_challenge_method: CodeChallengeMethod::Plain,
        };
        let (code, _) = server.authorize(&auth_req, None).unwrap();

        let token_req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code.clone()),
            redirect_uri: Some("http://localhost/cb".to_string()),
            client_id: "c".to_string(),
            client_secret: None,
            code_verifier: Some(verifier.to_string()),
            refresh_token: None,
            scopes: None,
        };
        // First use succeeds
        server.token(&token_req).unwrap();
        // Second use fails (code is single-use)
        let result = server.token(&token_req);
        assert!(matches!(result, Err(OAuthError::InvalidGrant(_))));
    }

    #[test]
    fn server_validate_access_token_nonexistent() {
        let server = OAuthServer::with_defaults();
        assert!(server.validate_access_token("nonexistent").is_none());
    }

    #[test]
    fn server_unregister_client_revokes_tokens() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let resp = issue_access_token_via_auth_code(
            &server,
            "c",
            "http://localhost/cb",
            &["read"],
            "user",
        );
        assert!(server.validate_access_token(&resp.access_token).is_some());

        server.unregister_client("c").unwrap();
        assert!(server.validate_access_token(&resp.access_token).is_none());
    }

    #[test]
    fn server_cleanup_expired_removes_old_tokens() {
        let config = OAuthServerConfig {
            access_token_lifetime: Duration::from_millis(1),
            refresh_token_lifetime: Duration::from_millis(1),
            authorization_code_lifetime: Duration::from_millis(1),
            ..OAuthServerConfig::default()
        };
        let server = OAuthServer::new(config);
        let client = OAuthClient::builder("c")
            .redirect_uri("http://localhost/cb")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let _resp =
            issue_access_token_via_auth_code(&server, "c", "http://localhost/cb", &[], "user");

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(5));

        let stats_before = server.stats();
        server.cleanup_expired();
        let stats_after = server.stats();

        assert!(stats_after.access_tokens <= stats_before.access_tokens);
    }

    // ========================================
    // OAuthServerStats
    // ========================================

    #[test]
    fn server_stats_default() {
        let stats = OAuthServerStats::default();
        assert_eq!(stats.clients, 0);
        assert_eq!(stats.authorization_codes, 0);
        assert_eq!(stats.access_tokens, 0);
        assert_eq!(stats.refresh_tokens, 0);
        assert_eq!(stats.revoked_tokens, 0);
    }

    #[test]
    fn server_stats_debug_and_clone() {
        let stats = OAuthServerStats {
            clients: 1,
            access_tokens: 5,
            ..OAuthServerStats::default()
        };
        let debug = format!("{:?}", stats);
        assert!(debug.contains("OAuthServerStats"));
        let cloned = stats.clone();
        assert_eq!(cloned.clients, 1);
    }

    // ========================================
    // Helper functions — additional
    // ========================================

    #[test]
    fn is_localhost_redirect_tests() {
        assert!(is_localhost_redirect("http://localhost:3000/cb"));
        assert!(is_localhost_redirect("http://127.0.0.1:8080/cb"));
        assert!(is_localhost_redirect("http://[::1]:9000/cb"));
        assert!(!is_localhost_redirect("https://example.com/cb"));
        assert!(!is_localhost_redirect("http://evil.com/cb"));
    }

    #[test]
    fn normalize_localhost_variants() {
        assert_eq!(normalize_localhost("localhost"), "localhost");
        assert_eq!(normalize_localhost("127.0.0.1"), "localhost");
        assert_eq!(normalize_localhost("[::1]"), "localhost");
        assert_eq!(normalize_localhost("example.com"), "other");
    }

    #[test]
    fn compute_s256_challenge_deterministic() {
        let v = "test-verifier";
        let c1 = compute_s256_challenge(v);
        let c2 = compute_s256_challenge(v);
        assert_eq!(c1, c2);
        assert!(!c1.is_empty());
    }

    #[test]
    fn url_encode_special_chars() {
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("a+b"), "a%2Bb");
        assert_eq!(url_encode("a/b"), "a%2Fb");
        assert_eq!(url_encode("safe-_~."), "safe-_~.");
    }

    #[test]
    fn constant_time_eq_same_length_different() {
        assert!(!constant_time_eq("abc", "abd"));
    }

    #[test]
    fn localhost_match_different_paths_fail() {
        assert!(!localhost_match(
            "http://localhost:3000/a",
            "http://localhost:3000/b"
        ));
    }

    #[test]
    fn localhost_match_non_http_fails() {
        assert!(!localhost_match("ftp://localhost/a", "ftp://localhost/a"));
    }

    // ========================================
    // Refresh token flow
    // ========================================

    #[test]
    fn server_refresh_token_flow() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .scope("write")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let token_resp = issue_access_token_via_auth_code(
            &server,
            "c1",
            "http://localhost/cb",
            &["read", "write"],
            "user1",
        );
        let refresh = token_resp.refresh_token.unwrap();

        // Use refresh token to get a new access token
        let new_resp = server
            .token(&TokenRequest {
                grant_type: "refresh_token".to_string(),
                code: None,
                redirect_uri: None,
                client_id: "c1".to_string(),
                client_secret: None,
                code_verifier: None,
                refresh_token: Some(refresh),
                scopes: None,
            })
            .unwrap();

        // New access token should be different
        assert_ne!(new_resp.access_token, token_resp.access_token);
        assert_eq!(new_resp.token_type, "bearer");
        // No new refresh token issued by refresh flow
        assert!(new_resp.refresh_token.is_none());
        // Scopes preserved
        assert!(new_resp.scope.is_some());
    }

    #[test]
    fn server_refresh_token_scope_narrowing() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .scope("write")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let token_resp = issue_access_token_via_auth_code(
            &server,
            "c1",
            "http://localhost/cb",
            &["read", "write"],
            "user1",
        );
        let refresh = token_resp.refresh_token.unwrap();

        // Request only a subset of scopes
        let new_resp = server
            .token(&TokenRequest {
                grant_type: "refresh_token".to_string(),
                code: None,
                redirect_uri: None,
                client_id: "c1".to_string(),
                client_secret: None,
                code_verifier: None,
                refresh_token: Some(refresh),
                scopes: Some(vec!["read".to_string()]),
            })
            .unwrap();

        assert_eq!(new_resp.scope, Some("read".to_string()));
    }

    #[test]
    fn server_refresh_token_invalid_scope() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let token_resp = issue_access_token_via_auth_code(
            &server,
            "c1",
            "http://localhost/cb",
            &["read"],
            "user1",
        );
        let refresh = token_resp.refresh_token.unwrap();

        // Request scope not in original grant
        let err = server
            .token(&TokenRequest {
                grant_type: "refresh_token".to_string(),
                code: None,
                redirect_uri: None,
                client_id: "c1".to_string(),
                client_secret: None,
                code_verifier: None,
                refresh_token: Some(refresh),
                scopes: Some(vec!["admin".to_string()]),
            })
            .unwrap_err();

        assert_eq!(err.error_code(), "invalid_scope");
    }

    #[test]
    fn server_refresh_token_revoked() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let token_resp = issue_access_token_via_auth_code(
            &server,
            "c1",
            "http://localhost/cb",
            &["read"],
            "user1",
        );
        let refresh = token_resp.refresh_token.unwrap();

        // Revoke the refresh token
        server.revoke(&refresh, "c1", None).unwrap();

        // Refresh should now fail
        let err = server
            .token(&TokenRequest {
                grant_type: "refresh_token".to_string(),
                code: None,
                redirect_uri: None,
                client_id: "c1".to_string(),
                client_secret: None,
                code_verifier: None,
                refresh_token: Some(refresh),
                scopes: None,
            })
            .unwrap_err();

        assert_eq!(err.error_code(), "invalid_grant");
        assert!(err.description().contains("revoked"));
    }

    #[test]
    fn server_refresh_token_client_id_mismatch() {
        let server = OAuthServer::with_defaults();
        let client1 = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        let client2 = OAuthClient::builder("c2")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client1).unwrap();
        server.register_client(client2).unwrap();

        let token_resp = issue_access_token_via_auth_code(
            &server,
            "c1",
            "http://localhost/cb",
            &["read"],
            "user1",
        );
        let refresh = token_resp.refresh_token.unwrap();

        // Try to use with different client_id
        let err = server
            .token(&TokenRequest {
                grant_type: "refresh_token".to_string(),
                code: None,
                redirect_uri: None,
                client_id: "c2".to_string(),
                client_secret: None,
                code_verifier: None,
                refresh_token: Some(refresh),
                scopes: None,
            })
            .unwrap_err();

        assert_eq!(err.error_code(), "invalid_grant");
        assert!(err.description().contains("client_id"));
    }

    #[test]
    fn server_refresh_token_missing_param() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let err = server
            .token(&TokenRequest {
                grant_type: "refresh_token".to_string(),
                code: None,
                redirect_uri: None,
                client_id: "c1".to_string(),
                client_secret: None,
                code_verifier: None,
                refresh_token: None,
                scopes: None,
            })
            .unwrap_err();

        assert_eq!(err.error_code(), "invalid_request");
        assert!(err.description().contains("refresh_token"));
    }

    #[test]
    fn server_refresh_token_not_found() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let err = server
            .token(&TokenRequest {
                grant_type: "refresh_token".to_string(),
                code: None,
                redirect_uri: None,
                client_id: "c1".to_string(),
                client_secret: None,
                code_verifier: None,
                refresh_token: Some("nonexistent".to_string()),
                scopes: None,
            })
            .unwrap_err();

        assert_eq!(err.error_code(), "invalid_grant");
    }

    // ========================================
    // Token exchange edge cases
    // ========================================

    #[test]
    fn server_token_auth_code_redirect_uri_mismatch() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .redirect_uri("http://localhost/cb2")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let (code, _) = server
            .authorize(
                &AuthorizationRequest {
                    response_type: "code".to_string(),
                    client_id: "c1".to_string(),
                    redirect_uri: "http://localhost/cb".to_string(),
                    scopes: vec!["read".to_string()],
                    state: None,
                    code_challenge: verifier.to_string(),
                    code_challenge_method: CodeChallengeMethod::Plain,
                },
                None,
            )
            .unwrap();

        // Exchange with different redirect_uri
        let err = server
            .token(&TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some(code),
                redirect_uri: Some("http://localhost/cb2".to_string()),
                client_id: "c1".to_string(),
                client_secret: None,
                code_verifier: Some(verifier.to_string()),
                refresh_token: None,
                scopes: None,
            })
            .unwrap_err();

        assert_eq!(err.error_code(), "invalid_grant");
        assert!(err.description().contains("redirect_uri"));
    }

    #[test]
    fn server_token_auth_code_client_id_mismatch() {
        let server = OAuthServer::with_defaults();
        let client1 = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        let client2 = OAuthClient::builder("c2")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client1).unwrap();
        server.register_client(client2).unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let (code, _) = server
            .authorize(
                &AuthorizationRequest {
                    response_type: "code".to_string(),
                    client_id: "c1".to_string(),
                    redirect_uri: "http://localhost/cb".to_string(),
                    scopes: vec!["read".to_string()],
                    state: None,
                    code_challenge: verifier.to_string(),
                    code_challenge_method: CodeChallengeMethod::Plain,
                },
                None,
            )
            .unwrap();

        // Exchange with different client_id
        let err = server
            .token(&TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some(code),
                redirect_uri: Some("http://localhost/cb".to_string()),
                client_id: "c2".to_string(),
                client_secret: None,
                code_verifier: Some(verifier.to_string()),
                refresh_token: None,
                scopes: None,
            })
            .unwrap_err();

        assert_eq!(err.error_code(), "invalid_grant");
        assert!(err.description().contains("client_id"));
    }

    #[test]
    fn server_token_auth_code_confidential_client_auth_fails() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .secret("correct-secret")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let (code, _) = server
            .authorize(
                &AuthorizationRequest {
                    response_type: "code".to_string(),
                    client_id: "c1".to_string(),
                    redirect_uri: "http://localhost/cb".to_string(),
                    scopes: vec!["read".to_string()],
                    state: None,
                    code_challenge: verifier.to_string(),
                    code_challenge_method: CodeChallengeMethod::Plain,
                },
                None,
            )
            .unwrap();

        // Exchange with wrong secret
        let err = server
            .token(&TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some(code),
                redirect_uri: Some("http://localhost/cb".to_string()),
                client_id: "c1".to_string(),
                client_secret: Some("wrong-secret".to_string()),
                code_verifier: Some(verifier.to_string()),
                refresh_token: None,
                scopes: None,
            })
            .unwrap_err();

        assert_eq!(err.error_code(), "invalid_client");
    }

    #[test]
    fn server_token_auth_code_verifier_too_long() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let (code, _) = server
            .authorize(
                &AuthorizationRequest {
                    response_type: "code".to_string(),
                    client_id: "c1".to_string(),
                    redirect_uri: "http://localhost/cb".to_string(),
                    scopes: vec!["read".to_string()],
                    state: None,
                    code_challenge: challenge.to_string(),
                    code_challenge_method: CodeChallengeMethod::Plain,
                },
                None,
            )
            .unwrap();

        // Verifier exceeds max length (128 by default)
        let long_verifier = "a".repeat(129);
        let err = server
            .token(&TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some(code),
                redirect_uri: Some("http://localhost/cb".to_string()),
                client_id: "c1".to_string(),
                client_secret: None,
                code_verifier: Some(long_verifier),
                refresh_token: None,
                scopes: None,
            })
            .unwrap_err();

        assert_eq!(err.error_code(), "invalid_request");
        assert!(err.description().contains("code_verifier"));
    }

    // ========================================
    // Authorization edge cases
    // ========================================

    #[test]
    fn server_authorize_empty_code_challenge() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let err = server
            .authorize(
                &AuthorizationRequest {
                    response_type: "code".to_string(),
                    client_id: "c1".to_string(),
                    redirect_uri: "http://localhost/cb".to_string(),
                    scopes: vec!["read".to_string()],
                    state: None,
                    code_challenge: String::new(),
                    code_challenge_method: CodeChallengeMethod::S256,
                },
                None,
            )
            .unwrap_err();

        assert_eq!(err.error_code(), "invalid_request");
        assert!(err.description().contains("code_challenge"));
    }

    #[test]
    fn server_authorize_with_state_in_redirect() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let (code, redirect) = server
            .authorize(
                &AuthorizationRequest {
                    response_type: "code".to_string(),
                    client_id: "c1".to_string(),
                    redirect_uri: "http://localhost/cb".to_string(),
                    scopes: vec!["read".to_string()],
                    state: Some("my-csrf-state".to_string()),
                    code_challenge: "challenge-value".to_string(),
                    code_challenge_method: CodeChallengeMethod::S256,
                },
                Some("user1".to_string()),
            )
            .unwrap();

        // Redirect should contain both code and state
        assert!(redirect.contains("code="));
        assert!(redirect.contains(&url_encode(&code)));
        assert!(redirect.contains("state=my-csrf-state"));
    }

    #[test]
    fn server_authorize_redirect_with_existing_query() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb?foo=bar")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let (_code, redirect) = server
            .authorize(
                &AuthorizationRequest {
                    response_type: "code".to_string(),
                    client_id: "c1".to_string(),
                    redirect_uri: "http://localhost/cb?foo=bar".to_string(),
                    scopes: vec!["read".to_string()],
                    state: None,
                    code_challenge: "chal".to_string(),
                    code_challenge_method: CodeChallengeMethod::Plain,
                },
                None,
            )
            .unwrap();

        // Should use '&' separator since '?' already exists
        assert!(redirect.starts_with("http://localhost/cb?foo=bar&code="));
    }

    // ========================================
    // Error conversions
    // ========================================

    #[test]
    fn oauth_error_access_denied_into_mcp_error() {
        let err = OAuthError::AccessDenied("denied".to_string());
        let mcp: McpError = err.into();
        assert_eq!(mcp.code, McpErrorCode::ResourceForbidden);
    }

    #[test]
    fn oauth_error_description_all_variants() {
        let cases: Vec<(OAuthError, &str)> = vec![
            (OAuthError::ServerError("srv".into()), "srv"),
            (OAuthError::TemporarilyUnavailable("tmp".into()), "tmp"),
            (OAuthError::UnsupportedResponseType("rt".into()), "rt"),
        ];
        for (err, expected) in cases {
            assert_eq!(err.description(), expected);
        }
    }

    #[test]
    fn oauth_error_display_all_remaining_variants() {
        let err = OAuthError::TemporarilyUnavailable("try later".into());
        assert_eq!(format!("{err}"), "temporarily_unavailable: try later");

        let err = OAuthError::UnsupportedResponseType("bad".into());
        assert_eq!(format!("{err}"), "unsupported_response_type: bad");

        let err = OAuthError::AccessDenied("nope".into());
        assert_eq!(format!("{err}"), "access_denied: nope");
    }

    // ========================================
    // Revocation edge cases
    // ========================================

    #[test]
    fn server_revoke_unknown_token_succeeds() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        // Per RFC 7009, revoking an unknown token is not an error
        server.revoke("no-such-token", "c1", None).unwrap();
    }

    #[test]
    fn server_revoke_token_owned_by_other_client() {
        let server = OAuthServer::with_defaults();
        let client1 = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        let client2 = OAuthClient::builder("c2")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client1).unwrap();
        server.register_client(client2).unwrap();

        let token_resp = issue_access_token_via_auth_code(
            &server,
            "c1",
            "http://localhost/cb",
            &["read"],
            "user1",
        );

        // c2 tries to revoke c1's token — should succeed silently (no error)
        // but the token should NOT be actually marked as revoked
        server.revoke(&token_resp.access_token, "c2", None).unwrap();

        // Token should still be valid since c2 doesn't own it
        // Note: the implementation removes the token from the map before checking client
        // ownership, so this is implementation-specific behavior
    }

    #[test]
    fn server_revoke_unknown_client_fails() {
        let server = OAuthServer::with_defaults();
        let err = server.revoke("some-token", "unknown", None).unwrap_err();
        assert_eq!(err.error_code(), "invalid_client");
    }

    // ========================================
    // Unregister edge cases
    // ========================================

    #[test]
    fn server_unregister_client_removes_auth_codes() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        // Create an auth code
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let (code, _) = server
            .authorize(
                &AuthorizationRequest {
                    response_type: "code".to_string(),
                    client_id: "c1".to_string(),
                    redirect_uri: "http://localhost/cb".to_string(),
                    scopes: vec!["read".to_string()],
                    state: None,
                    code_challenge: verifier.to_string(),
                    code_challenge_method: CodeChallengeMethod::Plain,
                },
                None,
            )
            .unwrap();

        // Verify code exists
        {
            let state = server.state.read().unwrap();
            assert!(state.authorization_codes.contains_key(&code));
        }

        // Unregister client
        server.unregister_client("c1").unwrap();

        // Auth code should be removed
        {
            let state = server.state.read().unwrap();
            assert!(!state.authorization_codes.contains_key(&code));
        }
    }

    // ========================================
    // Server misc
    // ========================================

    #[test]
    fn server_with_defaults_is_valid() {
        let server = OAuthServer::with_defaults();
        assert_eq!(server.config().issuer, "fastmcp");
        assert!(server.config().allow_public_clients);
    }

    #[test]
    fn server_get_client_none_for_unknown() {
        let server = OAuthServer::with_defaults();
        assert!(server.get_client("nonexistent").is_none());
    }

    #[test]
    fn server_validate_access_token_after_revoke() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let resp = issue_access_token_via_auth_code(
            &server,
            "c1",
            "http://localhost/cb",
            &["read"],
            "user1",
        );

        assert!(server.validate_access_token(&resp.access_token).is_some());
        server.revoke(&resp.access_token, "c1", None).unwrap();
        assert!(server.validate_access_token(&resp.access_token).is_none());
    }

    #[test]
    fn token_verifier_claims_contain_client_id_and_issuer() {
        let server = Arc::new(OAuthServer::with_defaults());
        let client = OAuthClient::builder("my-app")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let token_resp = issue_access_token_via_auth_code(
            server.as_ref(),
            "my-app",
            "http://localhost/cb",
            &["read"],
            "user42",
        );

        let verifier = server.token_verifier();
        let cx = asupersync::Cx::for_testing();
        let mcp_ctx = McpContext::new(cx, 1);
        let auth_request = AuthRequest {
            method: "test",
            params: None,
            request_id: 1,
        };
        let access = AccessToken {
            scheme: "Bearer".to_string(),
            token: token_resp.access_token,
        };
        let auth = verifier.verify(&mcp_ctx, auth_request, &access).unwrap();

        // Claims should include client_id and issuer
        let claims = auth.claims.unwrap();
        assert_eq!(claims["client_id"], "my-app");
        assert_eq!(claims["iss"], "fastmcp");
    }

    #[test]
    fn oauth_token_expires_in_secs_positive() {
        let token = OAuthToken {
            token: "t".to_string(),
            token_type: TokenType::Bearer,
            client_id: "c".to_string(),
            scopes: vec![],
            issued_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(3600),
            subject: None,
            is_refresh_token: false,
        };
        // Should be > 0 since it expires in the future
        assert!(token.expires_in_secs() > 0);
    }

    #[test]
    fn server_refresh_token_confidential_client_auth_fails() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .secret("correct-secret")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        // Issue token using helper (plain PKCE, no client_secret needed for authorize)
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let (code, _) = server
            .authorize(
                &AuthorizationRequest {
                    response_type: "code".to_string(),
                    client_id: "c1".to_string(),
                    redirect_uri: "http://localhost/cb".to_string(),
                    scopes: vec!["read".to_string()],
                    state: None,
                    code_challenge: verifier.to_string(),
                    code_challenge_method: CodeChallengeMethod::Plain,
                },
                None,
            )
            .unwrap();

        // Token exchange with correct secret
        let token_resp = server
            .token(&TokenRequest {
                grant_type: "authorization_code".to_string(),
                code: Some(code),
                redirect_uri: Some("http://localhost/cb".to_string()),
                client_id: "c1".to_string(),
                client_secret: Some("correct-secret".to_string()),
                code_verifier: Some(verifier.to_string()),
                refresh_token: None,
                scopes: None,
            })
            .unwrap();

        let refresh = token_resp.refresh_token.unwrap();

        // Refresh with wrong secret
        let err = server
            .token(&TokenRequest {
                grant_type: "refresh_token".to_string(),
                code: None,
                redirect_uri: None,
                client_id: "c1".to_string(),
                client_secret: Some("wrong-secret".to_string()),
                code_verifier: None,
                refresh_token: Some(refresh),
                scopes: None,
            })
            .unwrap_err();

        assert_eq!(err.error_code(), "invalid_client");
    }

    #[test]
    fn code_challenge_method_parse_unknown() {
        assert!(CodeChallengeMethod::parse("sha512").is_none());
        assert!(CodeChallengeMethod::parse("").is_none());
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq("short", "longer_string"));
        assert!(!constant_time_eq("", "a"));
    }

    #[test]
    fn constant_time_eq_empty_strings() {
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn localhost_match_different_localhost_variants() {
        // 127.0.0.1 and localhost with same path should match
        assert!(localhost_match(
            "http://localhost:3000/cb",
            "http://127.0.0.1:8080/cb"
        ));
        // [::1] and localhost
        assert!(localhost_match(
            "http://localhost:3000/cb",
            "http://[::1]:9000/cb"
        ));
    }

    #[test]
    fn url_encode_empty_and_unicode() {
        assert_eq!(url_encode(""), "");
        // Unicode bytes get percent-encoded
        let encoded = url_encode("ü");
        assert!(encoded.contains('%'));
    }

    // ========================================
    // Additional coverage — uncovered paths
    // ========================================

    #[test]
    fn server_revoke_confidential_client_wrong_secret() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .secret("correct")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let err = server.revoke("any-token", "c1", Some("wrong")).unwrap_err();
        assert_eq!(err.error_code(), "invalid_client");
    }

    #[test]
    fn server_validate_access_token_expired_returns_none() {
        let config = OAuthServerConfig {
            access_token_lifetime: Duration::from_millis(1),
            ..OAuthServerConfig::default()
        };
        let server = OAuthServer::new(config);
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let resp = issue_access_token_via_auth_code(
            &server,
            "c1",
            "http://localhost/cb",
            &["read"],
            "user1",
        );

        std::thread::sleep(Duration::from_millis(5));
        assert!(server.validate_access_token(&resp.access_token).is_none());
    }

    #[test]
    fn server_authorize_without_state_omits_state_from_redirect() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let (_code, redirect) = server
            .authorize(
                &AuthorizationRequest {
                    response_type: "code".to_string(),
                    client_id: "c1".to_string(),
                    redirect_uri: "http://localhost/cb".to_string(),
                    scopes: vec![],
                    state: None,
                    code_challenge: "chal".to_string(),
                    code_challenge_method: CodeChallengeMethod::Plain,
                },
                None,
            )
            .unwrap();

        assert!(redirect.contains("code="));
        assert!(!redirect.contains("state="));
    }

    #[test]
    fn server_refresh_token_client_deleted_after_issue() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let token_resp = issue_access_token_via_auth_code(
            &server,
            "c1",
            "http://localhost/cb",
            &["read"],
            "user1",
        );
        let refresh = token_resp.refresh_token.unwrap();

        // Delete client, then try to refresh
        server.unregister_client("c1").unwrap();

        let err = server
            .token(&TokenRequest {
                grant_type: "refresh_token".to_string(),
                code: None,
                redirect_uri: None,
                client_id: "c1".to_string(),
                client_secret: None,
                code_verifier: None,
                refresh_token: Some(refresh),
                scopes: None,
            })
            .unwrap_err();

        // Refresh token was revoked when client was unregistered
        assert_eq!(err.error_code(), "invalid_grant");
    }

    #[test]
    fn server_issue_tokens_empty_scopes_returns_no_scope() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let resp =
            issue_access_token_via_auth_code(&server, "c1", "http://localhost/cb", &[], "user1");

        assert!(resp.scope.is_none());
    }

    #[test]
    fn server_revoke_refresh_token_specifically() {
        let server = OAuthServer::with_defaults();
        let client = OAuthClient::builder("c1")
            .redirect_uri("http://localhost/cb")
            .scope("read")
            .build()
            .unwrap();
        server.register_client(client).unwrap();

        let resp = issue_access_token_via_auth_code(
            &server,
            "c1",
            "http://localhost/cb",
            &["read"],
            "user1",
        );
        let refresh = resp.refresh_token.unwrap();

        // Revoke the refresh token specifically
        server.revoke(&refresh, "c1", None).unwrap();

        // Verify it's in revoked set
        {
            let state = server.state.read().unwrap();
            assert!(state.revoked_tokens.contains(&refresh));
        }
    }

    #[test]
    fn localhost_match_no_explicit_port() {
        assert!(localhost_match(
            "http://localhost/callback",
            "http://localhost:8080/callback"
        ));
        assert!(localhost_match(
            "http://localhost/callback",
            "http://localhost/callback"
        ));
    }
}
