//! Authentication context and access token helpers.
//!
//! This module provides lightweight types for representing authenticated
//! request context. It is transport-agnostic and can be populated by
//! server-side authentication providers.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Session state key used to store authentication context.
pub const AUTH_STATE_KEY: &str = "fastmcp.auth";

/// Parsed access token (scheme + token value).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessToken {
    /// Token scheme (e.g., "Bearer").
    pub scheme: String,
    /// Raw token value.
    pub token: String,
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessToken")
            .field("scheme", &self.scheme)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl AccessToken {
    /// Attempts to parse an Authorization header value.
    ///
    /// Accepts formats like:
    /// - `Bearer <token>`
    /// - `<token>` (treated as bearer)
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Special-case a common malformed Authorization value:
        // "Bearer " (scheme with a missing token) should be rejected, even though trimming
        // would otherwise collapse it into a single-word "Bearer" (which we treat as a
        // bare token for non-header usages).
        let leading = value.trim_start();
        if let Some(prefix) = leading.get(..6) {
            if prefix.eq_ignore_ascii_case("Bearer") {
                let rest = &leading[6..];
                if rest
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_whitespace())
                    && rest.trim().is_empty()
                {
                    return None;
                }
            }
        }

        // Authorization headers use whitespace as the delimiter between scheme and token.
        // Treat any multi-part value as invalid (tokens must not contain whitespace).
        let mut parts = trimmed.split_whitespace();
        let first = parts.next().unwrap_or_default();
        if let Some(second) = parts.next() {
            if parts.next().is_some() {
                return None;
            }
            return Some(Self {
                scheme: first.to_string(),
                token: second.to_string(),
            });
        }

        Some(Self {
            scheme: "Bearer".to_string(),
            token: trimmed.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{AccessToken, AuthContext};

    #[test]
    fn parse_rejects_empty_and_scheme_without_token() {
        assert_eq!(AccessToken::parse(""), None);
        assert_eq!(AccessToken::parse("   "), None);
        assert_eq!(AccessToken::parse("Bearer "), None);
        assert_eq!(AccessToken::parse("bearer\t"), None);
    }

    #[test]
    fn parse_accepts_bearer_scheme_and_bare_tokens() {
        assert_eq!(
            AccessToken::parse("Bearer abc"),
            Some(AccessToken {
                scheme: "Bearer".to_string(),
                token: "abc".to_string(),
            })
        );
        assert_eq!(
            AccessToken::parse("bearer\tabc"),
            Some(AccessToken {
                scheme: "bearer".to_string(),
                token: "abc".to_string(),
            })
        );
        assert_eq!(
            AccessToken::parse("abc"),
            Some(AccessToken {
                scheme: "Bearer".to_string(),
                token: "abc".to_string(),
            })
        );
        // A single "Bearer" token is accepted as a bare token.
        assert_eq!(
            AccessToken::parse("Bearer"),
            Some(AccessToken {
                scheme: "Bearer".to_string(),
                token: "Bearer".to_string(),
            })
        );
    }

    #[test]
    fn parse_rejects_values_with_multiple_whitespace_separated_parts() {
        assert_eq!(AccessToken::parse("Bearer a b"), None);
        assert_eq!(AccessToken::parse("Token a b c"), None);
    }

    #[test]
    fn parse_accepts_non_bearer_schemes() {
        assert_eq!(
            AccessToken::parse("Token abc"),
            Some(AccessToken {
                scheme: "Token".to_string(),
                token: "abc".to_string(),
            })
        );
    }

    #[test]
    fn auth_context_constructors() {
        let anon = AuthContext::anonymous();
        assert!(anon.subject.is_none());
        assert!(anon.scopes.is_empty());
        assert!(anon.token.is_none());
        assert!(anon.claims.is_none());

        let user = AuthContext::with_subject("user123");
        assert_eq!(user.subject.as_deref(), Some("user123"));
        assert!(user.scopes.is_empty());
        assert!(user.token.is_none());
        assert!(user.claims.is_none());
    }

    #[test]
    fn auth_context_serialization_skips_empty_fields() {
        let anon = AuthContext::anonymous();
        let value = serde_json::to_value(&anon).expect("serialize");
        assert_eq!(value, serde_json::json!({}));
    }

    // =========================================================================
    // Additional coverage tests (bd-1p24)
    // =========================================================================

    #[test]
    fn auth_state_key_constant() {
        assert_eq!(super::AUTH_STATE_KEY, "fastmcp.auth");
    }

    #[test]
    fn auth_context_default_is_anonymous() {
        let def = AuthContext::default();
        assert!(def.subject.is_none());
        assert!(def.scopes.is_empty());
        assert!(def.token.is_none());
        assert!(def.claims.is_none());
    }

    #[test]
    fn auth_context_debug_output() {
        let ctx = AuthContext::with_subject("alice");
        let debug = format!("{ctx:?}");
        assert!(debug.contains("AuthContext"));
        assert!(debug.contains("alice"));
    }

    #[test]
    fn auth_context_clone() {
        let ctx = AuthContext::with_subject("bob");
        let cloned = ctx.clone();
        assert_eq!(cloned.subject.as_deref(), Some("bob"));
    }

    #[test]
    fn auth_context_full_serialization_roundtrip() {
        let ctx = AuthContext {
            subject: Some("user42".to_string()),
            scopes: vec!["read".to_string(), "write".to_string()],
            token: Some(AccessToken {
                scheme: "Bearer".to_string(),
                token: "tok123".to_string(),
            }),
            claims: Some(serde_json::json!({"aud": "api"})),
        };
        let json = serde_json::to_value(&ctx).expect("serialize");
        assert_eq!(json["subject"], "user42");
        assert_eq!(json["scopes"], serde_json::json!(["read", "write"]));
        assert_eq!(json["token"]["scheme"], "Bearer");
        assert_eq!(json["token"]["token"], "tok123");
        assert_eq!(json["claims"]["aud"], "api");

        // Roundtrip
        let deserialized: AuthContext = serde_json::from_value(json).expect("deserialize");
        assert_eq!(deserialized.subject.as_deref(), Some("user42"));
        assert_eq!(deserialized.scopes.len(), 2);
        assert!(deserialized.token.is_some());
        assert!(deserialized.claims.is_some());
    }

    #[test]
    fn access_token_debug_clone_eq() {
        let token = AccessToken {
            scheme: "Bearer".to_string(),
            token: "abc".to_string(),
        };
        let debug = format!("{token:?}");
        assert!(debug.contains("AccessToken"));
        assert!(debug.contains("Bearer"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("abc"));

        let cloned = token.clone();
        assert_eq!(token, cloned);
    }

    #[test]
    fn auth_context_debug_redacts_nested_token() {
        let ctx = AuthContext {
            subject: Some("user42".to_string()),
            scopes: vec!["read".to_string()],
            token: Some(AccessToken {
                scheme: "Bearer".to_string(),
                token: "super-secret-token".to_string(),
            }),
            claims: None,
        };

        let debug = format!("{ctx:?}");
        assert!(debug.contains("AuthContext"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("super-secret-token"));
    }

    #[test]
    fn access_token_serde_roundtrip() {
        let token = AccessToken {
            scheme: "Custom".to_string(),
            token: "xyz".to_string(),
        };
        let json = serde_json::to_string(&token).expect("serialize");
        let deserialized: AccessToken = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized, token);
    }
}

/// Authentication context stored for a request/session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthContext {
    /// Subject identifier (user or client ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Authorized scopes for this subject.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Access token (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<AccessToken>,
    /// Optional raw claims (transport or provider specific).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
}

impl AuthContext {
    /// Creates an anonymous context (no subject, no scopes).
    #[must_use]
    pub fn anonymous() -> Self {
        Self::default()
    }

    /// Creates a context with a subject identifier.
    #[must_use]
    pub fn with_subject(subject: impl Into<String>) -> Self {
        Self {
            subject: Some(subject.into()),
            ..Self::default()
        }
    }
}
