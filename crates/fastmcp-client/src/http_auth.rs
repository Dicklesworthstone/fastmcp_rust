//! HTTPS-only bearer-credential binding for the modern HTTP client.
//!
//! HTTP-03 requires that a bearer credential is attached only when the
//! complete configured target is the same admitted HTTPS resource the
//! credential was bound to, and never to a cleartext `http:` endpoint —
//! including localhost and loopback literals. A local server behind a TLS
//! terminator is addressed by its public HTTPS URL from the client side.
//!
//! The rules are enforced structurally rather than at call sites:
//!
//! - A [`BoundBearerCredential`] can only be constructed against an `https`
//!   [`CanonicalHttpUrl`], so a cleartext binding never exists.
//! - [`BoundBearerCredential::authorization_for_target`] returns a header
//!   value only for a target canonically equal to the bound resource; every
//!   other target — different path, authority, scheme, or query — yields
//!   `None` rather than a downgraded or redirected credential.
//! - The token is redacted from `Debug` output so credentials cannot leak
//!   through diagnostics, and header-hostile bytes are refused at binding.

use core::fmt;
use std::time::Instant;

/// Interactive native-public-client authorization with a caller-owned runtime.
pub mod oauth;

pub use fastmcp_core::CanonicalHttpUrl;

/// Typed refusals raised when constructing a credential binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerBindingError {
    /// The binding resource is not an `https` URL. Cleartext HTTP —
    /// including localhost and loopback literals — can never hold a bearer
    /// credential.
    CleartextResource,
    /// The token is empty.
    EmptyToken,
    /// The token contains bytes that cannot safely become an HTTP header
    /// value.
    InvalidTokenBytes,
}

impl fmt::Display for BearerBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CleartextResource => {
                formatter.write_str("bearer credentials bind only to https resources")
            }
            Self::EmptyToken => formatter.write_str("bearer token is empty"),
            Self::InvalidTokenBytes => {
                formatter.write_str("bearer token contains header-hostile bytes")
            }
        }
    }
}

impl std::error::Error for BearerBindingError {}

/// A bearer token bound to exactly one admitted HTTPS resource.
#[derive(Clone)]
pub struct BoundBearerCredential {
    resource: CanonicalHttpUrl,
    token: String,
    expires_at: Option<Instant>,
}

impl fmt::Debug for BoundBearerCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundBearerCredential")
            .field("resource", &self.resource.as_str())
            .field("token", &"<redacted>")
            .finish()
    }
}

impl BoundBearerCredential {
    /// Binds a token to one admitted HTTPS resource.
    ///
    /// # Errors
    ///
    /// Returns a typed [`BearerBindingError`] when the resource is not
    /// `https` or the token is empty or header-hostile. There is no
    /// cleartext escape hatch: an `http:` resource — remote, localhost, or
    /// loopback — can never hold a credential.
    pub fn bind(
        resource: CanonicalHttpUrl,
        token: impl Into<String>,
    ) -> Result<Self, BearerBindingError> {
        if !resource.as_str().starts_with("https://") {
            return Err(BearerBindingError::CleartextResource);
        }
        let token = token.into();
        if token.is_empty() {
            return Err(BearerBindingError::EmptyToken);
        }
        if token
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        {
            return Err(BearerBindingError::InvalidTokenBytes);
        }
        Ok(Self { resource, token, expires_at: None })
    }

    /// Binds a token with a monotonic deadline. At and after this instant,
    /// header construction withholds the credential, even from its resource.
    /// Already-emitted headers cannot be recalled by this value.
    pub fn bind_with_expiry(
        resource: CanonicalHttpUrl,
        token: impl Into<String>,
        expires_at: Instant,
    ) -> Result<Self, BearerBindingError> {
        let mut credential = Self::bind(resource, token)?;
        credential.expires_at = Some(expires_at);
        Ok(credential)
    }

    /// Returns the bound HTTPS resource.
    #[must_use]
    pub fn resource(&self) -> &CanonicalHttpUrl {
        &self.resource
    }

    /// Returns the locally enforced expiry, when the credential has one.
    #[must_use]
    pub fn expires_at(&self) -> Option<Instant> {
        self.expires_at
    }

    /// Returns the `Authorization` header value for `target`, or `None`
    /// when the target is not canonically identical to the bound resource or
    /// the credential has expired.
    ///
    /// A `None` is not an error: the request simply proceeds without a
    /// credential, so a mismatched, downgraded, or redirected target can
    /// never observe the token.
    #[must_use]
    pub fn authorization_for_target(&self, target: &CanonicalHttpUrl) -> Option<String> {
        self.authorization_at(target, Instant::now())
    }

    fn authorization_at(&self, target: &CanonicalHttpUrl, now: Instant) -> Option<String> {
        if target.as_str() == self.resource.as_str()
            && self.expires_at.is_none_or(|deadline| now < deadline)
        {
            Some(format!("Bearer {}", self.token))
        } else {
            None
        }
    }

    /// Detects a peer reflecting this credential into an error's diagnostics.
    /// Inspect decoded strings so JSON escaping cannot hide the token.
    pub(crate) fn is_reflected_by_error(&self, error: &fastmcp_protocol::JsonRpcError) -> bool {
        error.message.contains(&self.token)
            || error
                .data
                .as_ref()
                .is_some_and(|data| self.is_reflected_by_value(data))
    }

    fn is_reflected_by_value(&self, value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::String(text) => text.contains(&self.token),
            serde_json::Value::Array(values) => {
                values.iter().any(|value| self.is_reflected_by_value(value))
            }
            serde_json::Value::Object(values) => values
                .iter()
                .any(|(key, value)| key.contains(&self.token) || self.is_reflected_by_value(value)),
            value => value.to_string().contains(&self.token),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BearerBindingError, BoundBearerCredential, CanonicalHttpUrl};

    fn url(value: &str) -> CanonicalHttpUrl {
        CanonicalHttpUrl::parse(value).expect("test URL is canonical")
    }

    #[test]
    fn binds_only_to_https_resources() {
        assert!(BoundBearerCredential::bind(url("https://mcp.example/api"), "token-1").is_ok());

        for cleartext in [
            "http://mcp.example/api",
            "http://localhost:8080/api",
            "http://127.0.0.1:8080/api",
            "http://[::1]:8080/api",
        ] {
            assert_eq!(
                BoundBearerCredential::bind(url(cleartext), "token-1").err(),
                Some(BearerBindingError::CleartextResource),
                "cleartext resource {cleartext:?} must never hold a credential"
            );
        }
    }

    #[test]
    fn refuses_empty_and_header_hostile_tokens() {
        let resource = url("https://mcp.example/api");
        assert_eq!(
            BoundBearerCredential::bind(resource.clone(), "").err(),
            Some(BearerBindingError::EmptyToken)
        );
        assert_eq!(
            BoundBearerCredential::bind(resource.clone(), "to\r\nken").err(),
            Some(BearerBindingError::InvalidTokenBytes)
        );
        assert_eq!(
            BoundBearerCredential::bind(resource, "to ken").err(),
            Some(BearerBindingError::InvalidTokenBytes)
        );
    }

    #[test]
    fn attaches_only_to_the_exact_bound_resource() {
        let credential =
            BoundBearerCredential::bind(url("https://mcp.example/api"), "token-1").expect("binds");

        assert_eq!(
            credential.authorization_for_target(&url("https://mcp.example/api")),
            Some("Bearer token-1".to_owned())
        );

        // One changed dimension per case: path, authority, scheme-equivalent
        // http twin, and added query all withhold the credential.
        for target in [
            "https://mcp.example/other",
            "https://other.example/api",
            "http://mcp.example/api",
            "https://mcp.example/api?extra=1",
        ] {
            assert_eq!(
                credential.authorization_for_target(&url(target)),
                None,
                "target {target:?} must not observe the token"
            );
        }
    }

    #[test]
    fn debug_output_redacts_the_token() {
        let credential =
            BoundBearerCredential::bind(url("https://mcp.example/api"), "super-secret-token-value")
                .expect("binds");
        let debug = format!("{credential:?}");
        assert!(debug.contains("<redacted>"));
        assert!(
            !debug.contains("super-secret-token-value"),
            "the token must never appear in diagnostics: {debug}"
        );
    }

    #[test]
    fn expiring_credential_clones_withhold_headers_at_the_exact_deadline() {
        use std::time::{Duration, Instant};

        let resource = url("https://mcp.example/api");
        let deadline = Instant::now() + Duration::from_secs(60);
        let credential = BoundBearerCredential::bind_with_expiry(
            resource.clone(), "expiring-secret", deadline,
        ).unwrap();
        for credential in [credential.clone(), credential] {
            assert_eq!(credential.expires_at(), Some(deadline));
            assert_eq!(
                credential.authorization_at(&resource, deadline - Duration::from_nanos(1)),
                Some("Bearer expiring-secret".to_owned()),
            );
            assert_eq!(credential.authorization_at(&resource, deadline), None);
            assert_eq!(credential.authorization_at(&resource, deadline + Duration::from_nanos(1)), None);
            assert_eq!(credential.authorization_at(&url("https://other.example/api"), deadline - Duration::from_secs(1)), None);
        }
        let expired = BoundBearerCredential::bind_with_expiry(resource.clone(), "expired", Instant::now()).unwrap();
        assert_eq!(expired.authorization_for_target(&resource), None);
    }
}
