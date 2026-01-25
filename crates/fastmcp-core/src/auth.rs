//! Authentication context and access token helpers.
//!
//! This module provides lightweight types for representing authenticated
//! request context. It is transport-agnostic and can be populated by
//! server-side authentication providers.

use serde::{Deserialize, Serialize};

/// Session state key used to store authentication context.
pub const AUTH_STATE_KEY: &str = "fastmcp.auth";

/// Parsed access token (scheme + token value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessToken {
    /// Token scheme (e.g., "Bearer").
    pub scheme: String,
    /// Raw token value.
    pub token: String,
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

        if let Some((scheme, token)) = trimmed.split_once(' ') {
            let scheme = scheme.trim();
            let token = token.trim();
            if scheme.is_empty() || token.is_empty() {
                return None;
            }
            return Some(Self {
                scheme: scheme.to_string(),
                token: token.to_string(),
            });
        }

        Some(Self {
            scheme: "Bearer".to_string(),
            token: trimmed.to_string(),
        })
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
