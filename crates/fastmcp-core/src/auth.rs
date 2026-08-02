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
#[derive(Clone, PartialEq, Eq)]
pub struct AccessToken {
    /// Token scheme (e.g., "Bearer").
    pub scheme: String,
    /// Raw token value.
    pub token: String,
}

#[derive(Serialize)]
#[serde(rename = "AccessToken")]
struct AccessTokenWireRef<'a> {
    scheme: &'a str,
    token: &'a str,
}

#[derive(Deserialize)]
#[serde(rename = "AccessToken")]
struct AccessTokenWire {
    scheme: String,
    token: String,
}

impl Serialize for AccessToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if !Self::parts_are_canonical(&self.scheme, &self.token) {
            return Err(<S::Error as serde::ser::Error>::custom(
                "access token fields are not canonical",
            ));
        }

        AccessTokenWireRef {
            scheme: &self.scheme,
            token: &self.token,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AccessToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AccessTokenWire::deserialize(deserializer)?;
        if !Self::parts_are_canonical(&wire.scheme, &wire.token) {
            return Err(<D::Error as serde::de::Error>::custom(
                "access token fields are not canonical",
            ));
        }
        Ok(Self {
            scheme: wire.scheme,
            token: wire.token,
        })
    }
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

    fn parts_are_canonical(scheme: &str, token: &str) -> bool {
        scheme == scheme.trim() && token == token.trim() && Self::parts_are_valid(scheme, token)
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

    type ImpossibleName = serde::ser::Impossible<&'static str, std::fmt::Error>;

    struct StructNameSerializer;

    struct StructNameState(&'static str);

    impl serde::ser::SerializeStruct for StructNameState {
        type Ok = &'static str;
        type Error = std::fmt::Error;

        fn serialize_field<T>(&mut self, _key: &'static str, _value: &T) -> Result<(), Self::Error>
        where
            T: ?Sized + serde::Serialize,
        {
            Ok(())
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            Ok(self.0)
        }
    }

    macro_rules! reject_scalar_serializers {
        ($($method:ident($value:ty)),+ $(,)?) => {
            $(
                fn $method(self, _value: $value) -> Result<Self::Ok, Self::Error> {
                    Err(std::fmt::Error)
                }
            )+
        };
    }

    impl serde::Serializer for StructNameSerializer {
        type Ok = &'static str;
        type Error = std::fmt::Error;
        type SerializeSeq = ImpossibleName;
        type SerializeTuple = ImpossibleName;
        type SerializeTupleStruct = ImpossibleName;
        type SerializeTupleVariant = ImpossibleName;
        type SerializeMap = ImpossibleName;
        type SerializeStruct = StructNameState;
        type SerializeStructVariant = ImpossibleName;

        reject_scalar_serializers! {
            serialize_bool(bool),
            serialize_i8(i8),
            serialize_i16(i16),
            serialize_i32(i32),
            serialize_i64(i64),
            serialize_i128(i128),
            serialize_u8(u8),
            serialize_u16(u16),
            serialize_u32(u32),
            serialize_u64(u64),
            serialize_u128(u128),
            serialize_f32(f32),
            serialize_f64(f64),
            serialize_char(char),
            serialize_str(&str),
            serialize_bytes(&[u8]),
            serialize_unit_struct(&'static str),
        }

        fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
            Err(std::fmt::Error)
        }

        fn serialize_some<T>(self, _value: &T) -> Result<Self::Ok, Self::Error>
        where
            T: ?Sized + serde::Serialize,
        {
            Err(std::fmt::Error)
        }

        fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
            Err(std::fmt::Error)
        }

        fn serialize_unit_variant(
            self,
            _name: &'static str,
            _variant_index: u32,
            _variant: &'static str,
        ) -> Result<Self::Ok, Self::Error> {
            Err(std::fmt::Error)
        }

        fn serialize_newtype_struct<T>(
            self,
            _name: &'static str,
            _value: &T,
        ) -> Result<Self::Ok, Self::Error>
        where
            T: ?Sized + serde::Serialize,
        {
            Err(std::fmt::Error)
        }

        fn serialize_newtype_variant<T>(
            self,
            _name: &'static str,
            _variant_index: u32,
            _variant: &'static str,
            _value: &T,
        ) -> Result<Self::Ok, Self::Error>
        where
            T: ?Sized + serde::Serialize,
        {
            Err(std::fmt::Error)
        }

        fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
            Err(std::fmt::Error)
        }

        fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
            Err(std::fmt::Error)
        }

        fn serialize_tuple_struct(
            self,
            _name: &'static str,
            _len: usize,
        ) -> Result<Self::SerializeTupleStruct, Self::Error> {
            Err(std::fmt::Error)
        }

        fn serialize_tuple_variant(
            self,
            _name: &'static str,
            _variant_index: u32,
            _variant: &'static str,
            _len: usize,
        ) -> Result<Self::SerializeTupleVariant, Self::Error> {
            Err(std::fmt::Error)
        }

        fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
            Err(std::fmt::Error)
        }

        fn serialize_struct(
            self,
            name: &'static str,
            _len: usize,
        ) -> Result<Self::SerializeStruct, Self::Error> {
            Ok(StructNameState(name))
        }

        fn serialize_struct_variant(
            self,
            _name: &'static str,
            _variant_index: u32,
            _variant: &'static str,
            _len: usize,
        ) -> Result<Self::SerializeStructVariant, Self::Error> {
            Err(std::fmt::Error)
        }
    }

    #[test]
    fn access_token_serializes_with_stable_public_struct_name() {
        let token = AccessToken {
            scheme: "Bearer".to_string(),
            token: "secret".to_string(),
        };

        let name = serde::Serialize::serialize(&token, StructNameSerializer)
            .expect("valid access token must serialize as a struct");

        assert_eq!(name, "AccessToken");
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
        assert!(anon.scopes.is_empty());
        assert!(anon.claims.is_none());

        let user = AuthContext::with_subject("user123");
        assert_eq!(user.subject.as_deref(), Some("user123"));
        assert!(user.scopes.is_empty());
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
        assert!(def.scopes.is_empty());
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
    fn access_token_serde_roundtrip() {
        let token = AccessToken {
            scheme: "Custom".to_string(),
            token: "xyz".to_string(),
        };
        let json = serde_json::to_string(&token).expect("serialize");
        let deserialized: AccessToken = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized, token);
    }

    #[test]
    fn access_token_serde_rejects_oversized_or_noncanonical_fields() {
        let exact_scheme = "s".repeat(super::MAX_ACCESS_SCHEME_BYTES);
        let exact_token = "x".repeat(super::MAX_ACCESS_TOKEN_BYTES);
        let exact = serde_json::json!({"scheme": exact_scheme, "token": exact_token});
        let decoded = serde_json::from_value::<AccessToken>(exact)
            .expect("exact scheme and token byte maxima must deserialize");
        assert_eq!(decoded.scheme.len(), super::MAX_ACCESS_SCHEME_BYTES);
        assert_eq!(decoded.token.len(), super::MAX_ACCESS_TOKEN_BYTES);
        assert!(serde_json::to_value(&decoded).is_ok());

        for encoded in [
            serde_json::json!({
                "scheme": "s".repeat(super::MAX_ACCESS_SCHEME_BYTES + 1),
                "token": "secret"
            }),
            serde_json::json!({
                "scheme": "Bearer",
                "token": "x".repeat(super::MAX_ACCESS_TOKEN_BYTES + 1)
            }),
            serde_json::json!({"scheme": " Bearer", "token": "secret"}),
            serde_json::json!({"scheme": "Bearer ", "token": "secret"}),
            serde_json::json!({"scheme": "Bear\u{0}er", "token": "secret"}),
            serde_json::json!({"scheme": "Bear\u{1f}er", "token": "secret"}),
            serde_json::json!({"scheme": "Bear\u{7f}er", "token": "secret"}),
            serde_json::json!({"scheme": "Bea(rer", "token": "secret"}),
            serde_json::json!({"scheme": "Bearer", "token": " secret"}),
            serde_json::json!({"scheme": "Bearer", "token": "secret "}),
            serde_json::json!({"scheme": "Bearer", "token": "sec\u{0}ret"}),
            serde_json::json!({"scheme": "Bearer", "token": "sec\u{1f}ret"}),
            serde_json::json!({"scheme": "Bearer", "token": "sec\u{7f}ret"}),
        ] {
            assert!(serde_json::from_value::<AccessToken>(encoded).is_err());
        }

        for invalid in [
            AccessToken {
                scheme: "s".repeat(super::MAX_ACCESS_SCHEME_BYTES + 1),
                token: "secret".to_string(),
            },
            AccessToken {
                scheme: "Bea(rer".to_string(),
                token: "secret".to_string(),
            },
            AccessToken {
                scheme: " Bearer".to_string(),
                token: "secret".to_string(),
            },
            AccessToken {
                scheme: "Bearer ".to_string(),
                token: "secret".to_string(),
            },
            AccessToken {
                scheme: "Bear\0er".to_string(),
                token: "secret".to_string(),
            },
            AccessToken {
                scheme: "Bear\u{1f}er".to_string(),
                token: "secret".to_string(),
            },
            AccessToken {
                scheme: "Bear\u{7f}er".to_string(),
                token: "secret".to_string(),
            },
            AccessToken {
                scheme: "Bearer".to_string(),
                token: " secret".to_string(),
            },
            AccessToken {
                scheme: "Bearer".to_string(),
                token: "secret ".to_string(),
            },
            AccessToken {
                scheme: "Bearer".to_string(),
                token: "sec\0ret".to_string(),
            },
            AccessToken {
                scheme: "Bearer".to_string(),
                token: "sec\u{1f}ret".to_string(),
            },
            AccessToken {
                scheme: "Bearer".to_string(),
                token: "sec\u{7f}ret".to_string(),
            },
            AccessToken {
                scheme: "Bearer".to_string(),
                token: "x".repeat(super::MAX_ACCESS_TOKEN_BYTES + 1),
            },
        ] {
            assert!(serde_json::to_value(invalid).is_err());
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
