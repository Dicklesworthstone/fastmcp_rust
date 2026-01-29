//! Authentication token generators for testing.
//!
//! Provides utilities for generating test tokens:
//! - Static bearer tokens
//! - JWT-like tokens (not cryptographically secure)
//! - API keys
//! - Session tokens

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// Helper Functions
// ============================================================================

/// Simple hex encoding for testing (avoids base64 dependency).
fn hex_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    data.iter()
        .fold(String::with_capacity(data.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// Simple hex decoding for testing.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// ============================================================================
// Static Tokens
// ============================================================================

/// A valid static bearer token for testing.
pub const VALID_BEARER_TOKEN: &str = "test-bearer-token-12345";

/// An invalid/expired bearer token for testing.
pub const INVALID_BEARER_TOKEN: &str = "invalid-token-00000";

/// A valid API key for testing.
pub const VALID_API_KEY: &str = "sk-test-api-key-abcdef123456";

/// An invalid API key for testing.
pub const INVALID_API_KEY: &str = "sk-invalid-key";

/// A valid session token for testing.
pub const VALID_SESSION_TOKEN: &str = "session-test-token-xyz789";

// ============================================================================
// Token Generation
// ============================================================================

/// Generates a random-looking token for testing.
///
/// Note: This is NOT cryptographically secure. Use only for testing.
#[must_use]
pub fn generate_test_token(prefix: &str, length: usize) -> String {
    use std::time::SystemTime;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let mut token = String::with_capacity(prefix.len() + length + 1);
    token.push_str(prefix);
    token.push('-');

    let mut seed = timestamp as usize;
    for _ in 0..length {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let idx = seed % chars.len();
        token.push(chars[idx]);
    }

    token
}

/// Generates a bearer token.
#[must_use]
pub fn generate_bearer_token() -> String {
    generate_test_token("bearer", 32)
}

/// Generates an API key.
#[must_use]
pub fn generate_api_key() -> String {
    generate_test_token("sk-test", 24)
}

/// Generates a session token.
#[must_use]
pub fn generate_session_token() -> String {
    generate_test_token("session", 16)
}

// ============================================================================
// JWT-like Tokens (for testing only, not secure)
// ============================================================================

/// A mock JWT token structure for testing.
///
/// WARNING: This is NOT a real JWT implementation and should only be used for testing.
#[derive(Debug, Clone)]
pub struct MockJwt {
    /// Header claims.
    pub header: HashMap<String, String>,
    /// Payload claims.
    pub payload: HashMap<String, serde_json::Value>,
    /// Mock signature (not cryptographic).
    pub signature: String,
}

impl MockJwt {
    /// Creates a new mock JWT with default header.
    #[must_use]
    pub fn new() -> Self {
        let mut header = HashMap::new();
        header.insert("alg".to_string(), "HS256".to_string());
        header.insert("typ".to_string(), "JWT".to_string());

        Self {
            header,
            payload: HashMap::new(),
            signature: "mock-signature".to_string(),
        }
    }

    /// Sets the subject claim.
    #[must_use]
    pub fn subject(mut self, sub: impl Into<String>) -> Self {
        self.payload
            .insert("sub".to_string(), serde_json::json!(sub.into()));
        self
    }

    /// Sets the issuer claim.
    #[must_use]
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.payload
            .insert("iss".to_string(), serde_json::json!(iss.into()));
        self
    }

    /// Sets the audience claim.
    #[must_use]
    pub fn audience(mut self, aud: impl Into<String>) -> Self {
        self.payload
            .insert("aud".to_string(), serde_json::json!(aud.into()));
        self
    }

    /// Sets the expiration time (seconds from now).
    #[must_use]
    pub fn expires_in(mut self, seconds: u64) -> Self {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + seconds;
        self.payload
            .insert("exp".to_string(), serde_json::json!(exp));
        self
    }

    /// Sets the token as already expired.
    #[must_use]
    pub fn expired(mut self) -> Self {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            - 3600; // 1 hour ago
        self.payload
            .insert("exp".to_string(), serde_json::json!(exp));
        self
    }

    /// Sets the issued-at time to now.
    #[must_use]
    pub fn issued_now(mut self) -> Self {
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.payload
            .insert("iat".to_string(), serde_json::json!(iat));
        self
    }

    /// Adds a custom claim.
    #[must_use]
    pub fn claim(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.payload.insert(key.into(), value);
        self
    }

    /// Encodes the token as a JWT-like string (hex encoded for testing).
    ///
    /// WARNING: This is NOT a real JWT - it uses simple hex encoding
    /// without proper signing. Use only for testing.
    #[must_use]
    pub fn encode(&self) -> String {
        let header_json = serde_json::to_string(&self.header).unwrap_or_default();
        let payload_json = serde_json::to_string(&self.payload).unwrap_or_default();

        // Use hex encoding for simplicity (testing only)
        let header_hex = hex_encode(header_json.as_bytes());
        let payload_hex = hex_encode(payload_json.as_bytes());
        let sig_hex = hex_encode(self.signature.as_bytes());

        format!("{header_hex}.{payload_hex}.{sig_hex}")
    }

    /// Checks if the token is expired (based on exp claim).
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.payload.get("exp") {
            if let Some(exp_secs) = exp.as_u64() {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                return now >= exp_secs;
            }
        }
        false
    }
}

impl Default for MockJwt {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Pre-built JWT Tokens
// ============================================================================

/// Creates a valid test JWT with standard claims.
#[must_use]
pub fn valid_jwt() -> MockJwt {
    MockJwt::new()
        .subject("test-user")
        .issuer("test-issuer")
        .audience("test-audience")
        .issued_now()
        .expires_in(3600) // 1 hour
}

/// Creates an expired JWT for testing expiration handling.
#[must_use]
pub fn expired_jwt() -> MockJwt {
    MockJwt::new()
        .subject("test-user")
        .issuer("test-issuer")
        .expired()
}

/// Creates a JWT with custom roles claim.
#[must_use]
pub fn jwt_with_roles(roles: Vec<&str>) -> MockJwt {
    let roles: Vec<String> = roles.into_iter().map(String::from).collect();
    valid_jwt().claim("roles", serde_json::json!(roles))
}

/// Creates a JWT with admin role.
#[must_use]
pub fn admin_jwt() -> MockJwt {
    jwt_with_roles(vec!["admin", "user"])
}

/// Creates a JWT with read-only role.
#[must_use]
pub fn readonly_jwt() -> MockJwt {
    jwt_with_roles(vec!["readonly"])
}

// ============================================================================
// Auth Header Helpers
// ============================================================================

/// Creates a Bearer auth header value.
#[must_use]
pub fn bearer_auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

/// Creates a Basic auth header value from username and password.
///
/// Note: Uses hex encoding instead of base64 for testing simplicity.
/// Real implementations should use proper base64 encoding.
#[must_use]
pub fn basic_auth_header(username: &str, password: &str) -> String {
    let credentials = format!("{username}:{password}");
    let encoded = hex_encode(credentials.as_bytes());
    format!("Basic {encoded}")
}

/// Creates an API key header value.
#[must_use]
pub fn api_key_header(key: &str) -> String {
    key.to_string()
}

// ============================================================================
// Test Credentials
// ============================================================================

/// Test credentials for basic auth.
#[derive(Debug, Clone)]
pub struct TestCredentials {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
}

impl TestCredentials {
    /// Creates new test credentials.
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    /// Creates valid test credentials.
    #[must_use]
    pub fn valid() -> Self {
        Self::new("test-user", "test-password-123")
    }

    /// Creates invalid test credentials.
    #[must_use]
    pub fn invalid() -> Self {
        Self::new("invalid-user", "wrong-password")
    }

    /// Creates admin test credentials.
    #[must_use]
    pub fn admin() -> Self {
        Self::new("admin", "admin-password-456")
    }

    /// Generates the Basic auth header for these credentials.
    #[must_use]
    pub fn to_basic_auth(&self) -> String {
        basic_auth_header(&self.username, &self.password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_tokens() {
        assert!(VALID_BEARER_TOKEN.len() > 10);
        assert!(INVALID_BEARER_TOKEN.len() > 0);
        assert!(VALID_API_KEY.starts_with("sk-"));
        assert!(VALID_SESSION_TOKEN.starts_with("session"));
    }

    #[test]
    fn test_generate_test_token() {
        let token1 = generate_test_token("test", 16);
        let token2 = generate_test_token("test", 16);

        assert!(token1.starts_with("test-"));
        assert!(token1.len() == "test-".len() + 16);
        // Tokens should be different (though not guaranteed with this simple generator)
        // Just verify they're generated correctly
        assert!(
            token1
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        );
    }

    #[test]
    fn test_generate_bearer_token() {
        let token = generate_bearer_token();
        assert!(token.starts_with("bearer-"));
    }

    #[test]
    fn test_generate_api_key() {
        let key = generate_api_key();
        assert!(key.starts_with("sk-test-"));
    }

    #[test]
    fn test_mock_jwt_creation() {
        let jwt = MockJwt::new()
            .subject("user123")
            .issuer("test-app")
            .expires_in(3600);

        assert!(jwt.payload.contains_key("sub"));
        assert!(jwt.payload.contains_key("iss"));
        assert!(jwt.payload.contains_key("exp"));
    }

    #[test]
    fn test_mock_jwt_encode() {
        let jwt = valid_jwt();
        let encoded = jwt.encode();

        // JWT format: header.payload.signature
        let parts: Vec<_> = encoded.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_mock_jwt_expired() {
        let expired = expired_jwt();
        assert!(expired.is_expired());

        let valid = valid_jwt();
        assert!(!valid.is_expired());
    }

    #[test]
    fn test_jwt_with_roles() {
        let jwt = jwt_with_roles(vec!["admin", "user"]);
        assert!(jwt.payload.contains_key("roles"));

        let roles = jwt.payload.get("roles").unwrap();
        let roles_arr = roles.as_array().unwrap();
        assert_eq!(roles_arr.len(), 2);
    }

    #[test]
    fn test_bearer_auth_header() {
        let header = bearer_auth_header("token123");
        assert_eq!(header, "Bearer token123");
    }

    #[test]
    fn test_basic_auth_header() {
        let header = basic_auth_header("user", "pass");
        assert!(header.starts_with("Basic "));

        // Decode and verify (using hex encoding)
        let encoded = header.strip_prefix("Basic ").unwrap();
        let decoded = hex_decode(encoded).unwrap();
        let credentials = String::from_utf8(decoded).unwrap();
        assert_eq!(credentials, "user:pass");
    }

    #[test]
    fn test_test_credentials() {
        let valid = TestCredentials::valid();
        assert!(!valid.username.is_empty());
        assert!(!valid.password.is_empty());

        let admin = TestCredentials::admin();
        assert_eq!(admin.username, "admin");
    }

    #[test]
    fn test_credentials_to_basic_auth() {
        let creds = TestCredentials::new("user", "pass");
        let header = creds.to_basic_auth();
        assert!(header.starts_with("Basic "));
    }
}
