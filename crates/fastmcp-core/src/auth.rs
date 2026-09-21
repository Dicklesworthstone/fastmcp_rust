//! Authentication context and access token helpers.
//!
//! This module provides lightweight types for representing authenticated
//! request context. It is transport-agnostic and can be populated by
//! server-side authentication providers.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::crypto::Sha256Digest;

/// Maximum admitted UTF-8 bytes in one access-token value.
pub const MAX_ACCESS_TOKEN_BYTES: usize = 4 * 1024;

/// Maximum admitted UTF-8 bytes in one authorization scheme.
pub const MAX_ACCESS_SCHEME_BYTES: usize = 64;

/// Maximum admitted bytes in the complete HTTP `Authorization` field value.
///
/// Every byte between the scheme and credential counts toward this cap. The
/// formula reserves one separator space when both parts are at their own
/// maxima; callers may use more separator spaces only by using fewer bytes in
/// the scheme or credential.
const MAX_AUTHORIZATION_VALUE_BYTES: usize = MAX_ACCESS_SCHEME_BYTES + 1 + MAX_ACCESS_TOKEN_BYTES;

/// Parsed access token (scheme + token value).
///
/// Raw credentials deliberately do not implement serde's serialization or
/// deserialization traits. Use the explicit parsers at credential admission;
/// pass sanitized [`AuthContext`] facts to diagnostics and application code.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessToken {
    /// Token scheme (e.g., "Bearer").
    pub scheme: String,
    /// Raw token value.
    pub token: String,
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessToken")
            .field("scheme_bytes", &self.scheme.len())
            .field("token", &"<redacted>")
            .finish()
    }
}

impl AccessToken {
    /// Parses one HTTP `Authorization` field value carrying token68 credentials.
    ///
    /// The scheme must use RFC 9110 `token` syntax, the delimiter is one or
    /// more ASCII spaces (not a tab), and the credential must use `token68`
    /// syntax. Leading/trailing whitespace and scheme-only values are rejected.
    /// The complete field value is capped at the maximum scheme bytes, one
    /// separator byte, and the maximum credential bytes. Consequently, when
    /// both parts consume their maxima, exactly one separator space is admitted;
    /// additional separator spaces count toward and exceed the total cap.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        if value.is_empty()
            || value.len() > MAX_AUTHORIZATION_VALUE_BYTES
            || value.trim_matches([' ', '\t']) != value
            || value.bytes().any(|byte| byte < b' ' || byte == 0x7f)
        {
            return None;
        }

        let separator = value.find(' ')?;
        let scheme = &value[..separator];
        let token = value[separator..].trim_start_matches(' ');
        if !Self::is_valid_http_scheme(scheme) || !Self::is_valid_token68(token) {
            return None;
        }

        Self::from_parts(scheme, token)
    }

    /// Parses the historical in-band credential representation.
    ///
    /// This is deliberately separate from [`parse`](Self::parse): MCP request
    /// metadata has historically admitted either `Scheme credential` or a bare
    /// value (treated as Bearer), and is not an HTTP header grammar.
    #[must_use]
    pub fn parse_legacy_in_band(value: &str) -> Option<Self> {
        if value.len() > MAX_AUTHORIZATION_VALUE_BYTES {
            return None;
        }
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Special-case a common malformed Authorization value:
        // "Bearer " (scheme with a missing token) should be rejected, even though trimming
        // would otherwise collapse it into a single-word "Bearer" (which we treat as a
        // bare token for non-header usages). Match the Unicode whitespace used
        // by trim/split_whitespace so a non-ASCII separator cannot bypass this guard.
        let leading = value.trim_start();
        if let Some(prefix) = leading.get(..6) {
            if prefix.eq_ignore_ascii_case("Bearer") {
                let rest = &leading[6..];
                if rest.chars().next().is_some_and(char::is_whitespace) && rest.trim().is_empty() {
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
            return Self::from_parts(first, second);
        }

        Self::from_parts("Bearer", trimmed)
    }

    /// Constructs a bounded access token from separately parsed parts.
    ///
    /// Both parts are trimmed and must be non-empty. Whitespace inside either
    /// part is rejected so a provider never receives an ambiguous credential.
    #[must_use]
    pub fn from_parts(scheme: &str, token: &str) -> Option<Self> {
        let scheme = scheme.trim();
        let token = token.trim();
        if !Self::parts_are_valid(scheme, token) {
            return None;
        }

        Some(Self {
            scheme: scheme.to_string(),
            token: token.to_string(),
        })
    }

    fn parts_are_valid(scheme: &str, token: &str) -> bool {
        Self::is_valid_http_scheme(scheme)
            && !token.is_empty()
            && token.len() <= MAX_ACCESS_TOKEN_BYTES
            && !token
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control())
    }

    /// Returns whether `value` is a bounded RFC 9110 authentication scheme.
    ///
    /// This exposes the same canonical scheme grammar used by [`parse`](Self::parse)
    /// so authentication providers do not need to maintain a second parser.
    #[must_use]
    pub fn is_valid_http_scheme(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= MAX_ACCESS_SCHEME_BYTES
            && value.bytes().all(Self::is_http_token_byte)
    }

    /// Returns whether `value` is a bounded RFC 9110 `token68` credential.
    ///
    /// Padding (`=`) is accepted only after at least one base character and
    /// only at the end of the credential.
    #[must_use]
    pub fn is_valid_token68(value: &str) -> bool {
        if value.len() > MAX_ACCESS_TOKEN_BYTES {
            return false;
        }
        Self::is_token68(value)
    }

    /// RFC 9110 `tchar`, used by the HTTP authentication-scheme grammar.
    const fn is_http_token_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
    }

    fn is_token68(value: &str) -> bool {
        let mut saw_base = false;
        let mut saw_padding = false;
        for byte in value.bytes() {
            if byte == b'=' {
                if !saw_base {
                    return false;
                }
                saw_padding = true;
            } else if saw_padding
                || !(byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/'))
            {
                return false;
            } else {
                saw_base = true;
            }
        }
        saw_base
    }
}

#[cfg(test)]
mod tests {
    use super::{AccessToken, AuthContext, Sha256Digest};

    #[test]
    fn auth_01_a_token_is_not_serializable() {
        // A Serialize implementation introduces a second candidate for `_`
        // below, making this compile-time assertion fail with an ambiguity.
        trait AmbiguousIfSerialize<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfSerialize<()> for T {}
        impl<T: ?Sized + serde::Serialize> AmbiguousIfSerialize<u8> for T {}

        let _ = <AccessToken as AmbiguousIfSerialize<_>>::check;
        let _ = <AuthContext as AmbiguousIfSerialize<u8>>::check;
    }

    #[test]
    fn auth_01_a_token_is_not_deserializable() {
        trait AmbiguousIfDeserialize<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfDeserialize<()> for T {}
        impl<T: serde::Deserialize<'static>> AmbiguousIfDeserialize<u8> for T {}

        let _ = <AccessToken as AmbiguousIfDeserialize<_>>::check;
        let _ = <AuthContext as AmbiguousIfDeserialize<u8>>::check;
    }

    #[test]
    fn authorization_parse_rejects_empty_and_scheme_without_token() {
        assert_eq!(AccessToken::parse(""), None);
        assert_eq!(AccessToken::parse("   "), None);
        assert_eq!(AccessToken::parse("Bearer "), None);
        assert_eq!(AccessToken::parse("bearer\t"), None);
        assert_eq!(AccessToken::parse("Bearer"), None);
    }

    #[test]
    fn authorization_parse_enforces_space_and_token68_grammar() {
        assert_eq!(
            AccessToken::parse("Bearer abc"),
            Some(AccessToken {
                scheme: "Bearer".to_string(),
                token: "abc".to_string(),
            })
        );
        assert!(AccessToken::parse("bearer   abc+/==").is_some());
        assert_eq!(AccessToken::parse("bearer\tabc"), None);
        assert_eq!(AccessToken::parse("Bearer abc:def"), None);
        assert_eq!(AccessToken::parse("Bearer töken"), None);
        assert_eq!(AccessToken::parse(" Bearer abc"), None);
        assert_eq!(AccessToken::parse("Bearer abc "), None);
        assert_eq!(AccessToken::parse("\tBearer abc"), None);
        assert_eq!(AccessToken::parse("Bearer abc\t"), None);
        assert_eq!(AccessToken::parse("Bear\0er abc"), None);
        assert_eq!(AccessToken::parse("Bear\u{1f}er abc"), None);
        assert_eq!(AccessToken::parse("Bear\u{7f}er abc"), None);
        assert_eq!(AccessToken::parse("Bearer ab\0c"), None);
        assert_eq!(AccessToken::parse("Bearer ab\u{1f}c"), None);
        assert_eq!(AccessToken::parse("Bearer ab\u{7f}c"), None);
    }

    #[test]
    fn authorization_parse_enforces_part_and_total_byte_boundaries() {
        let exact_scheme = "s".repeat(super::MAX_ACCESS_SCHEME_BYTES);
        let oversized_scheme = "s".repeat(super::MAX_ACCESS_SCHEME_BYTES + 1);
        let exact_token = "x".repeat(super::MAX_ACCESS_TOKEN_BYTES);
        let oversized_token = "x".repeat(super::MAX_ACCESS_TOKEN_BYTES + 1);

        let exact = format!("{exact_scheme} {exact_token}");
        assert_eq!(exact.len(), super::MAX_AUTHORIZATION_VALUE_BYTES);
        let parsed = AccessToken::parse(&exact).expect("exact maxima fit with one separator");
        assert_eq!(parsed.scheme.len(), super::MAX_ACCESS_SCHEME_BYTES);
        assert_eq!(parsed.token.len(), super::MAX_ACCESS_TOKEN_BYTES);

        assert!(AccessToken::parse(&format!("{oversized_scheme} x")).is_none());
        assert!(AccessToken::parse(&format!("Bearer {oversized_token}")).is_none());

        let over_total = format!("{exact_scheme}  {exact_token}");
        assert_eq!(over_total.len(), super::MAX_AUTHORIZATION_VALUE_BYTES + 1);
        assert!(AccessToken::parse(&over_total).is_none());

        let shorter_scheme = "s".repeat(super::MAX_ACCESS_SCHEME_BYTES - 1);
        let reclaimed_for_separator = format!("{shorter_scheme}  {exact_token}");
        assert_eq!(
            reclaimed_for_separator.len(),
            super::MAX_AUTHORIZATION_VALUE_BYTES
        );
        assert!(AccessToken::parse(&reclaimed_for_separator).is_some());

        let reclaimed_plus_one = format!("{shorter_scheme}   {exact_token}");
        assert_eq!(
            reclaimed_plus_one.len(),
            super::MAX_AUTHORIZATION_VALUE_BYTES + 1
        );
        assert!(AccessToken::parse(&reclaimed_plus_one).is_none());
    }

    #[test]
    fn public_http_credential_validators_share_parser_grammar_and_bounds() {
        assert!(AccessToken::is_valid_http_scheme(
            &"s".repeat(super::MAX_ACCESS_SCHEME_BYTES)
        ));
        assert!(AccessToken::is_valid_http_scheme("Custom+Scheme"));
        assert!(!AccessToken::is_valid_http_scheme("Bad Scheme"));
        assert!(!AccessToken::is_valid_http_scheme("Béarer"));
        assert!(!AccessToken::is_valid_http_scheme(
            &"s".repeat(super::MAX_ACCESS_SCHEME_BYTES + 1)
        ));

        assert!(AccessToken::is_valid_token68(
            &"x".repeat(super::MAX_ACCESS_TOKEN_BYTES)
        ));
        assert!(AccessToken::is_valid_token68("abc_DEF-123+/=="));
        assert!(!AccessToken::is_valid_token68("abc:def"));
        assert!(!AccessToken::is_valid_token68("ab=c"));
        assert!(!AccessToken::is_valid_token68(
            &"x".repeat(super::MAX_ACCESS_TOKEN_BYTES + 1)
        ));
    }

    #[test]
    fn legacy_in_band_missing_bearer_credential_uses_the_tokenizer_whitespace() {
        for separator in [
            " ", "\t", "\r\n", "\u{0085}", "\u{00a0}", "\u{2003}", "\u{3000}",
        ] {
            for scheme in ["Bearer", "bearer", "BeArEr"] {
                let missing = format!("{scheme}{separator}");
                assert_eq!(AccessToken::parse_legacy_in_band(&missing), None);
                assert_eq!(
                    AccessToken::parse_legacy_in_band(&format!(" \t{missing}")),
                    None
                );
                // Change only the presence of the credential after the same
                // delimiter: a genuine legacy credential must still parse.
                let present = format!("{missing}abc");
                let parsed = AccessToken::parse_legacy_in_band(&present)
                    .expect("a legacy whitespace separator with a credential is valid");
                assert_eq!(parsed.scheme, scheme);
                assert_eq!(parsed.token, "abc");
            }
        }
    }

    #[test]
    fn legacy_in_band_bare_bearer_is_distinct_from_a_missing_credential() {
        for literal in ["Bearer", "bearer", "BeArEr"] {
            let token = AccessToken::parse_legacy_in_band(literal)
                .expect("an undelimited literal remains a supported bare token");
            assert_eq!(token.scheme, "Bearer");
            assert_eq!(token.token, literal);
            assert_eq!(
                AccessToken::parse_legacy_in_band(&format!("{literal}\u{2003}")),
                None
            );
        }
    }

    #[test]
    fn legacy_unicode_separators_do_not_relax_native_http_authorization() {
        assert!(AccessToken::parse("Bearer abc").is_some());
        for separator in ["\t", "\u{0085}", "\u{00a0}", "\u{2003}", "\u{3000}"] {
            let value = format!("Bearer{separator}abc");
            assert!(AccessToken::parse_legacy_in_band(&value).is_some());
            assert_eq!(AccessToken::parse(&value), None);
        }
    }

    #[test]
    fn legacy_unicode_credentials_preserve_part_and_total_byte_bounds() {
        for token in [
            "x".repeat(super::MAX_ACCESS_TOKEN_BYTES),
            "é".repeat(super::MAX_ACCESS_TOKEN_BYTES / "é".len()),
        ] {
            assert_eq!(token.len(), super::MAX_ACCESS_TOKEN_BYTES);
            let padding_bytes = super::MAX_AUTHORIZATION_VALUE_BYTES
                - "Bearer".len()
                - "\u{00a0}".len()
                - token.len();
            let padding = " ".repeat(padding_bytes);
            let exact = format!("Bearer{padding}\u{00a0}{token}");
            assert_eq!(exact.len(), super::MAX_AUTHORIZATION_VALUE_BYTES);
            let parsed = AccessToken::parse_legacy_in_band(&exact)
                .expect("exact UTF-8 byte maxima must remain admissible");
            assert_eq!(parsed.scheme, "Bearer");
            assert_eq!(parsed.token, token);

            // Change only one delimiter byte: each part still fits, but the
            // complete input is now over its independent envelope bound.
            let over_total = format!("Bearer {padding}\u{00a0}{token}");
            assert_eq!(over_total.len(), super::MAX_AUTHORIZATION_VALUE_BYTES + 1);
            assert!(AccessToken::parse_legacy_in_band(&over_total).is_none());

            // Conversely, this envelope fits but the credential is one byte
            // too long. Both bounds must be enforced independently.
            let over_token = format!("Bearer\u{00a0}{token}x");
            assert!(over_token.len() < super::MAX_AUTHORIZATION_VALUE_BYTES);
            assert!(AccessToken::parse_legacy_in_band(&over_token).is_none());
        }
    }

    #[test]
    fn legacy_in_band_parse_accepts_bearer_scheme_and_bare_tokens() {
        assert_eq!(
            AccessToken::parse_legacy_in_band("abc"),
            Some(AccessToken {
                scheme: "Bearer".to_string(),
                token: "abc".to_string(),
            })
        );
        // A single "Bearer" token is accepted as a bare token.
        assert_eq!(
            AccessToken::parse_legacy_in_band("Bearer"),
            Some(AccessToken {
                scheme: "Bearer".to_string(),
                token: "Bearer".to_string(),
            })
        );
    }

    #[test]
    fn legacy_in_band_parse_rejects_multiple_whitespace_separated_parts() {
        assert_eq!(AccessToken::parse_legacy_in_band("Bearer a b"), None);
        assert_eq!(AccessToken::parse_legacy_in_band("Token a b c"), None);
    }

    #[test]
    fn legacy_in_band_parse_accepts_non_bearer_schemes() {
        assert_eq!(
            AccessToken::parse_legacy_in_band("Token abc"),
            Some(AccessToken {
                scheme: "Token".to_string(),
                token: "abc".to_string(),
            })
        );
    }

    #[test]
    fn parts_reject_invalid_http_scheme_and_control_bytes() {
        assert_eq!(AccessToken::from_parts("Bea(rer", "abc"), None);
        assert_eq!(AccessToken::from_parts("Béarer", "abc"), None);
        assert_eq!(AccessToken::from_parts("Bearer", "abc\0def"), None);
        assert_eq!(AccessToken::from_parts("Bearer", "abc\u{7f}def"), None);
        assert!(AccessToken::from_parts("Custom+Scheme", "opaque:credential").is_some());
    }

    #[test]
    fn parse_enforces_access_token_utf8_byte_bounds() {
        let exact = "x".repeat(super::MAX_ACCESS_TOKEN_BYTES);
        let too_long = "x".repeat(super::MAX_ACCESS_TOKEN_BYTES + 1);
        assert_eq!(
            AccessToken::parse_legacy_in_band(&exact).map(|access| access.token.len()),
            Some(super::MAX_ACCESS_TOKEN_BYTES)
        );
        assert!(AccessToken::parse_legacy_in_band(&too_long).is_none());

        let multibyte_exact = "é".repeat(super::MAX_ACCESS_TOKEN_BYTES / 2);
        let multibyte_too_long = format!("{multibyte_exact}é");
        assert_eq!(multibyte_exact.len(), super::MAX_ACCESS_TOKEN_BYTES);
        assert!(AccessToken::parse_legacy_in_band(&multibyte_exact).is_some());
        assert!(AccessToken::parse_legacy_in_band(&multibyte_too_long).is_none());

        let oversized_scheme = "s".repeat(super::MAX_ACCESS_SCHEME_BYTES + 1);
        assert!(AccessToken::from_parts(&oversized_scheme, "token").is_none());
    }

    #[test]
    fn auth_context_constructors() {
        let anon = AuthContext::anonymous();
        assert!(anon.subject.is_none());
        assert_eq!(anon.scopes, [] as [std::string::String; 0]);
        assert!(anon.claims.is_none());

        let user = AuthContext::with_subject("user123");
        assert_eq!(user.subject.as_deref(), Some("user123"));
        assert_eq!(user.scopes, [] as [std::string::String; 0]);
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
    fn auth_context_default_is_anonymous() {
        let def = AuthContext::default();
        assert!(def.subject.is_none());
        assert_eq!(def.scopes, [] as [std::string::String; 0]);
        assert!(def.claims.is_none());
    }

    #[test]
    fn auth_context_debug_output_is_redacted() {
        let mut ctx = AuthContext::with_subject("SUBJECT_DEBUG_CANARY");
        ctx.scopes = vec!["SCOPE_DEBUG_CANARY".to_string()];
        ctx.claims = Some(serde_json::json!({"claim": "CLAIM_DEBUG_CANARY"}));
        let debug = format!("{ctx:?}");
        assert!(debug.contains("AuthContext"));
        assert!(debug.contains("has_subject"));
        assert!(debug.contains("scope_count"));
        assert!(debug.contains("has_claims"));
        assert!(!debug.contains("SUBJECT_DEBUG_CANARY"));
        assert!(!debug.contains("SCOPE_DEBUG_CANARY"));
        assert!(!debug.contains("CLAIM_DEBUG_CANARY"));
    }

    #[test]
    fn auth_context_clone() {
        let ctx = AuthContext::with_subject("bob");
        let cloned = ctx.clone();
        assert_eq!(cloned.subject.as_deref(), Some("bob"));
    }

    #[test]
    fn auth_context_full_serialization_roundtrip() {
        let owner = Sha256Digest::from_bytes([0xA5; 32]);
        let ctx = AuthContext {
            subject: Some("user42".to_string()),
            scopes: vec!["read".to_string(), "write".to_string()],
            claims: Some(serde_json::json!({"aud": "api"})),
            session_owner: None,
        }
        .with_session_owner(owner);
        let json = serde_json::to_value(&ctx).expect("serialize");
        assert_eq!(json["subject"], "user42");
        assert_eq!(json["scopes"], serde_json::json!(["read", "write"]));
        assert_eq!(json["claims"]["aud"], "api");
        assert!(json.get("session_owner").is_none());
        assert_eq!(ctx.session_owner(), Some(owner));

        // Roundtrip
        let deserialized: AuthContext = serde_json::from_value(json).expect("deserialize");
        assert_eq!(deserialized.subject.as_deref(), Some("user42"));
        assert_eq!(deserialized.scopes.len(), 2);
        assert!(deserialized.claims.is_some());
        assert!(deserialized.session_owner().is_none());
    }

    #[test]
    fn access_token_debug_clone_eq() {
        let token = AccessToken {
            scheme: "Bearer".to_string(),
            token: "abc".to_string(),
        };
        let debug = format!("{token:?}");
        assert!(debug.contains("AccessToken"));
        assert!(debug.contains("scheme_bytes"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("Bearer"));
        assert!(!debug.contains("abc"));

        let cloned = token.clone();
        assert_eq!(token, cloned);
    }

    #[test]
    fn auth_context_never_contains_access_token_material() {
        let ctx = AuthContext {
            subject: Some("user42".to_string()),
            scopes: vec!["read".to_string()],
            claims: None,
            session_owner: None,
        };

        let debug = format!("{ctx:?}");
        assert!(debug.contains("AuthContext"));
        assert!(!debug.contains("super-secret-token"));
        let serialized = serde_json::to_string(&ctx).expect("serialize auth facts");
        assert!(!serialized.contains("super-secret-token"));
    }

    #[test]
    fn access_token_from_parts_preserves_bounded_credentials() {
        let token = AccessToken::from_parts("Custom", "xyz").expect("valid credential");
        assert_eq!(token.scheme, "Custom");
        assert_eq!(token.token, "xyz");
        assert_eq!(AccessToken::from_parts(" Custom ", " xyz "), Some(token));

        let exact_scheme = "s".repeat(super::MAX_ACCESS_SCHEME_BYTES);
        let exact_token = "x".repeat(super::MAX_ACCESS_TOKEN_BYTES);
        let decoded = AccessToken::from_parts(&exact_scheme, &exact_token)
            .expect("exact scheme and token byte maxima must be admitted");
        assert_eq!(decoded.scheme.len(), super::MAX_ACCESS_SCHEME_BYTES);
        assert_eq!(decoded.token.len(), super::MAX_ACCESS_TOKEN_BYTES);
        assert!(AccessToken::from_parts(&format!("{exact_scheme}s"), &exact_token).is_none());
        assert!(AccessToken::from_parts(&exact_scheme, &format!("{exact_token}x")).is_none());
    }

    #[test]
    fn access_token_from_parts_rejects_invalid_credentials() {
        for invalid_scheme in [
            "",
            "Bear er",
            "Bea(rer",
            "Bear\0er",
            "Bear\u{1f}er",
            "Bear\u{7f}er",
        ] {
            assert!(AccessToken::from_parts(invalid_scheme, "secret").is_none());
        }
        for invalid_token in ["", "sec ret", "sec\0ret", "sec\u{1f}ret", "sec\u{7f}ret"] {
            assert!(AccessToken::from_parts("Bearer", invalid_token).is_none());
        }
    }
}

/// Verified authentication facts committed to one request context.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AuthContext {
    /// Subject identifier (user or client ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Authorized scopes for this subject.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Optional verified, handler-visible claims.
    ///
    /// Providers must not place raw credentials, cookies, private token
    /// material, or unfiltered introspection responses in this value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
    /// Stable, provider-scoped owner key used for connection/session binding
    /// and authenticated cache partitioning. It is not a credential and is
    /// omitted from serialized handler-visible authentication facts; trusted
    /// in-process consumers may incorporate it into ownership boundaries.
    #[serde(skip)]
    session_owner: Option<Sha256Digest>,
}

impl fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthContext")
            .field("has_subject", &self.subject.is_some())
            .field("scope_count", &self.scopes.len())
            .field("has_claims", &self.claims.is_some())
            .field("has_session_owner", &self.session_owner.is_some())
            .finish()
    }
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

    /// Attaches a stable, provider-scoped owner key for session binding.
    ///
    /// Providers with more than one identity namespace should derive this key
    /// with explicit domain separation and unambiguous framing. Scopes, claims,
    /// and display subjects must not be used as a substitute for that framing.
    #[must_use]
    pub fn with_session_owner(mut self, owner: Sha256Digest) -> Self {
        self.session_owner = Some(owner);
        self
    }

    /// Returns the provider-scoped owner key, when one was supplied.
    #[doc(hidden)]
    #[must_use]
    pub fn session_owner(&self) -> Option<Sha256Digest> {
        self.session_owner
    }
}
