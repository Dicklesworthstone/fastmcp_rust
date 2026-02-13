//! Authentication provider hooks for MCP servers.
//!
//! Auth providers are transport-agnostic and operate on the JSON-RPC
//! request payload. They may populate [`AuthContext`] to be stored in
//! session state for downstream handlers.

use std::collections::HashMap;
use std::sync::Arc;

use fastmcp_core::{AccessToken, AuthContext, McpContext, McpError, McpErrorCode, McpResult};

/// Authentication request view used by providers.
#[derive(Debug, Clone, Copy)]
pub struct AuthRequest<'a> {
    /// JSON-RPC method name.
    pub method: &'a str,
    /// Raw params payload (if present).
    pub params: Option<&'a serde_json::Value>,
    /// Internal request ID (u64) used for tracing.
    pub request_id: u64,
}

impl AuthRequest<'_> {
    /// Attempts to extract an access token from the raw request params.
    #[must_use]
    pub fn access_token(&self) -> Option<AccessToken> {
        extract_access_token(self.params)
    }
}

/// Extracts an access token from request params using common field names.
fn extract_access_token(params: Option<&serde_json::Value>) -> Option<AccessToken> {
    let params = params?;
    match params {
        serde_json::Value::String(value) => AccessToken::parse(value),
        serde_json::Value::Object(map) => {
            if let Some(token) = extract_from_map(map) {
                return Some(token);
            }
            if let Some(meta) = map.get("_meta").and_then(serde_json::Value::as_object) {
                if let Some(token) = extract_from_map(meta) {
                    return Some(token);
                }
            }
            if let Some(headers) = map.get("headers").and_then(serde_json::Value::as_object) {
                if let Some(token) = extract_from_map(headers) {
                    return Some(token);
                }
            }
            None
        }
        _ => None,
    }
}

fn extract_from_map(map: &serde_json::Map<String, serde_json::Value>) -> Option<AccessToken> {
    for key in [
        "authorization",
        "Authorization",
        "auth",
        "token",
        "access_token",
        "accessToken",
    ] {
        if let Some(value) = map.get(key) {
            if let Some(token) = extract_from_value(value) {
                return Some(token);
            }
        }
    }
    None
}

fn extract_from_value(value: &serde_json::Value) -> Option<AccessToken> {
    match value {
        serde_json::Value::String(value) => AccessToken::parse(value),
        serde_json::Value::Object(map) => {
            if let (Some(scheme), Some(token)) = (
                map.get("scheme").and_then(serde_json::Value::as_str),
                map.get("token").and_then(serde_json::Value::as_str),
            ) {
                if !scheme.trim().is_empty() && !token.trim().is_empty() {
                    return Some(AccessToken {
                        scheme: scheme.trim().to_string(),
                        token: token.trim().to_string(),
                    });
                }
            }
            for key in ["authorization", "token", "access_token", "accessToken"] {
                if let Some(value) = map.get(key).and_then(serde_json::Value::as_str) {
                    if let Some(token) = AccessToken::parse(value) {
                        return Some(token);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Authentication provider interface.
///
/// Implementations decide whether a request is allowed and may return
/// an [`AuthContext`] describing the authenticated subject.
pub trait AuthProvider: Send + Sync {
    /// Authenticate an incoming request.
    ///
    /// Return `Ok(AuthContext)` to allow, or an `Err(McpError)` to deny.
    fn authenticate(&self, ctx: &McpContext, request: AuthRequest<'_>) -> McpResult<AuthContext>;
}

/// Token verifier interface used by token-based auth providers.
pub trait TokenVerifier: Send + Sync {
    /// Verify an access token and return an auth context if valid.
    fn verify(
        &self,
        ctx: &McpContext,
        request: AuthRequest<'_>,
        token: &AccessToken,
    ) -> McpResult<AuthContext>;
}

/// Token-based authentication provider.
#[derive(Clone)]
pub struct TokenAuthProvider {
    verifier: Arc<dyn TokenVerifier>,
    missing_token_error: McpError,
}

impl TokenAuthProvider {
    /// Creates a new token auth provider with the given verifier.
    #[must_use]
    pub fn new<V: TokenVerifier + 'static>(verifier: V) -> Self {
        Self {
            verifier: Arc::new(verifier),
            missing_token_error: auth_error("Missing access token"),
        }
    }

    /// Overrides the error returned when a token is missing.
    #[must_use]
    pub fn with_missing_token_error(mut self, error: McpError) -> Self {
        self.missing_token_error = error;
        self
    }
}

impl AuthProvider for TokenAuthProvider {
    fn authenticate(&self, ctx: &McpContext, request: AuthRequest<'_>) -> McpResult<AuthContext> {
        let access = request
            .access_token()
            .ok_or_else(|| self.missing_token_error.clone())?;
        self.verifier.verify(ctx, request, &access)
    }
}

/// Static token verifier backed by an in-memory token map.
#[derive(Debug, Clone)]
pub struct StaticTokenVerifier {
    tokens: HashMap<String, AuthContext>,
    allowed_schemes: Option<Vec<String>>,
}

impl StaticTokenVerifier {
    /// Creates a new static verifier from a token → context map.
    pub fn new<I, K>(tokens: I) -> Self
    where
        I: IntoIterator<Item = (K, AuthContext)>,
        K: Into<String>,
    {
        let tokens = tokens
            .into_iter()
            .map(|(token, ctx)| (token.into(), ctx))
            .collect();
        Self {
            tokens,
            allowed_schemes: None,
        }
    }

    /// Restricts accepted token schemes (case-insensitive).
    #[must_use]
    pub fn with_allowed_schemes<I, S>(mut self, schemes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_schemes = Some(schemes.into_iter().map(Into::into).collect());
        self
    }
}

impl TokenVerifier for StaticTokenVerifier {
    fn verify(
        &self,
        _ctx: &McpContext,
        _request: AuthRequest<'_>,
        token: &AccessToken,
    ) -> McpResult<AuthContext> {
        if let Some(allowed) = &self.allowed_schemes {
            if !allowed
                .iter()
                .any(|scheme| scheme.eq_ignore_ascii_case(&token.scheme))
            {
                return Err(auth_error("Unsupported auth scheme"));
            }
        }

        let Some(auth) = self.tokens.get(&token.token) else {
            return Err(auth_error("Invalid access token"));
        };

        let mut ctx = auth.clone();
        ctx.token.get_or_insert_with(|| token.clone());
        Ok(ctx)
    }
}

fn auth_error(message: impl Into<String>) -> McpError {
    McpError::new(McpErrorCode::ResourceForbidden, message)
}

#[cfg(feature = "jwt")]
mod jwt {
    use super::{AuthContext, AuthRequest, TokenVerifier, auth_error};
    use fastmcp_core::{AccessToken, McpContext, McpResult};
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};

    /// JWT verifier for HMAC-SHA tokens.
    #[derive(Debug, Clone)]
    pub struct JwtTokenVerifier {
        decoding_key: DecodingKey,
        validation: Validation,
    }

    impl JwtTokenVerifier {
        /// Creates an HS256 verifier from a shared secret.
        #[must_use]
        pub fn hs256(secret: impl AsRef<[u8]>) -> Self {
            Self {
                decoding_key: DecodingKey::from_secret(secret.as_ref()),
                validation: Validation::new(Algorithm::HS256),
            }
        }

        /// Overrides the JWT validation settings.
        #[must_use]
        pub fn with_validation(mut self, validation: Validation) -> Self {
            self.validation = validation;
            self
        }
    }

    impl TokenVerifier for JwtTokenVerifier {
        fn verify(
            &self,
            _ctx: &McpContext,
            _request: AuthRequest<'_>,
            token: &AccessToken,
        ) -> McpResult<AuthContext> {
            if !token.scheme.eq_ignore_ascii_case("Bearer") {
                return Err(auth_error("Unsupported auth scheme"));
            }

            let data =
                decode::<serde_json::Value>(&token.token, &self.decoding_key, &self.validation)
                    .map_err(|err| auth_error(format!("Invalid token: {err}")))?;

            let claims = data.claims;
            let subject = claims
                .get("sub")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            let scopes = extract_scopes(&claims);

            Ok(AuthContext {
                subject,
                scopes,
                token: Some(token.clone()),
                claims: Some(claims),
            })
        }
    }

    fn extract_scopes(claims: &serde_json::Value) -> Vec<String> {
        let mut scopes = Vec::new();
        if let Some(scope) = claims.get("scope").and_then(serde_json::Value::as_str) {
            scopes.extend(scope.split_whitespace().map(str::to_string));
        }
        if let Some(list) = claims.get("scopes").and_then(serde_json::Value::as_array) {
            scopes.extend(
                list.iter()
                    .filter_map(|value| value.as_str().map(str::to_string)),
            );
        }
        scopes
    }
}

#[cfg(feature = "jwt")]
pub use jwt::JwtTokenVerifier;

/// Default allow-all provider (returns anonymous auth context).
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllAuthProvider;

impl AuthProvider for AllowAllAuthProvider {
    fn authenticate(&self, _ctx: &McpContext, _request: AuthRequest<'_>) -> McpResult<AuthContext> {
        Ok(AuthContext::anonymous())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::Cx;

    fn ctx() -> McpContext {
        McpContext::new(Cx::for_testing(), 1)
    }

    #[test]
    fn access_token_parse_accepts_bearer_and_bare_token() {
        assert_eq!(
            fastmcp_core::AccessToken::parse("Bearer abc"),
            Some(fastmcp_core::AccessToken {
                scheme: "Bearer".to_string(),
                token: "abc".to_string(),
            })
        );
        assert_eq!(
            fastmcp_core::AccessToken::parse("abc"),
            Some(fastmcp_core::AccessToken {
                scheme: "Bearer".to_string(),
                token: "abc".to_string(),
            })
        );
        // Bare token parsing treats the entire value as a bearer token, even if it
        // happens to be the literal string "Bearer".
        assert_eq!(
            fastmcp_core::AccessToken::parse(" Bearer"),
            Some(fastmcp_core::AccessToken {
                scheme: "Bearer".to_string(),
                token: "Bearer".to_string(),
            })
        );
        assert_eq!(fastmcp_core::AccessToken::parse(""), None);
        assert_eq!(fastmcp_core::AccessToken::parse("   "), None);
        assert_eq!(fastmcp_core::AccessToken::parse("Bearer "), None);
    }

    #[test]
    fn auth_request_extracts_access_token_from_common_locations() {
        // params as string
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&serde_json::Value::String("Bearer t1".to_string())),
            request_id: 1,
        };
        assert_eq!(
            req.access_token(),
            Some(AccessToken {
                scheme: "Bearer".to_string(),
                token: "t1".to_string(),
            })
        );

        // params as object with authorization field
        let params = serde_json::json!({"authorization": "Bearer t2"});
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        assert_eq!(
            req.access_token(),
            Some(AccessToken {
                scheme: "Bearer".to_string(),
                token: "t2".to_string(),
            })
        );

        // params as object with {scheme, token}
        let params = serde_json::json!({"auth": {"scheme": "Bearer", "token": "t3"}});
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        assert_eq!(
            req.access_token(),
            Some(AccessToken {
                scheme: "Bearer".to_string(),
                token: "t3".to_string(),
            })
        );

        // params as object with _meta.authorization
        let params = serde_json::json!({"_meta": {"authorization": "Bearer t4"}});
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        assert_eq!(
            req.access_token(),
            Some(AccessToken {
                scheme: "Bearer".to_string(),
                token: "t4".to_string(),
            })
        );

        // params as object with headers.Authorization
        let params = serde_json::json!({"headers": {"Authorization": "Bearer t5"}});
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        assert_eq!(
            req.access_token(),
            Some(AccessToken {
                scheme: "Bearer".to_string(),
                token: "t5".to_string(),
            })
        );
    }

    #[test]
    fn token_auth_provider_errors_on_missing_token_and_allows_override() {
        #[derive(Debug)]
        struct AcceptAll;
        impl TokenVerifier for AcceptAll {
            fn verify(
                &self,
                _ctx: &McpContext,
                _request: AuthRequest<'_>,
                _token: &AccessToken,
            ) -> McpResult<AuthContext> {
                Ok(AuthContext::with_subject("ok"))
            }
        }

        let provider = TokenAuthProvider::new(AcceptAll);
        let req = AuthRequest {
            method: "tools/call",
            params: None,
            request_id: 1,
        };
        let err = provider.authenticate(&ctx(), req).unwrap_err();
        assert_eq!(err.code, McpErrorCode::ResourceForbidden);
        assert!(err.message.contains("Missing access token"));

        let provider =
            TokenAuthProvider::new(AcceptAll).with_missing_token_error(auth_error("no token"));
        let req = AuthRequest {
            method: "tools/call",
            params: None,
            request_id: 1,
        };
        let err = provider.authenticate(&ctx(), req).unwrap_err();
        assert!(err.message.contains("no token"));
    }

    #[test]
    fn static_token_verifier_enforces_scheme_and_sets_token_if_missing() {
        let mut base = AuthContext::with_subject("user123");
        base.scopes = vec!["read".to_string()];

        let verifier =
            StaticTokenVerifier::new([("value-1", base.clone())]).with_allowed_schemes(["Bearer"]);
        let req = AuthRequest {
            method: "tools/call",
            params: None,
            request_id: 1,
        };

        // Wrong scheme
        let err = verifier
            .verify(
                &ctx(),
                req,
                &AccessToken {
                    scheme: "Basic".to_string(),
                    token: "value-1".to_string(),
                },
            )
            .unwrap_err();
        assert!(err.message.contains("Unsupported auth scheme"));

        // Valid scheme (case-insensitive)
        let auth = verifier
            .verify(
                &ctx(),
                req,
                &AccessToken {
                    scheme: "bearer".to_string(),
                    token: "value-1".to_string(),
                },
            )
            .unwrap();
        assert_eq!(auth.subject, Some("user123".to_string()));
        assert_eq!(auth.scopes, vec!["read".to_string()]);
        assert_eq!(
            auth.token,
            Some(AccessToken {
                scheme: "bearer".to_string(),
                token: "value-1".to_string(),
            })
        );

        // If the stored context already has an access credential, keep it (do not override).
        let stored_with_access = AuthContext {
            token: Some(AccessToken {
                scheme: "Bearer".to_string(),
                token: "stored-value".to_string(),
            }),
            ..base.clone()
        };
        let verifier = StaticTokenVerifier::new([("value-2", stored_with_access)]);
        let auth = verifier
            .verify(
                &ctx(),
                req,
                &AccessToken {
                    scheme: "Bearer".to_string(),
                    token: "value-2".to_string(),
                },
            )
            .unwrap();
        assert_eq!(
            auth.token,
            Some(AccessToken {
                scheme: "Bearer".to_string(),
                token: "stored-value".to_string(),
            })
        );
    }

    #[test]
    fn allow_all_provider_returns_anonymous_context() {
        let provider = AllowAllAuthProvider;
        let req = AuthRequest {
            method: "tools/call",
            params: None,
            request_id: 1,
        };
        let auth = provider.authenticate(&ctx(), req).unwrap();
        assert_eq!(auth.subject, None);
        assert!(auth.scopes.is_empty());
    }

    #[test]
    fn access_token_from_none_params() {
        let req = AuthRequest {
            method: "tools/call",
            params: None,
            request_id: 1,
        };
        assert!(req.access_token().is_none());
    }

    #[test]
    fn access_token_from_array_params() {
        let params = serde_json::json!([1, 2, 3]);
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        assert!(req.access_token().is_none());
    }

    #[test]
    fn access_token_from_number_params() {
        let params = serde_json::json!(42);
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        assert!(req.access_token().is_none());
    }

    #[test]
    fn access_token_from_object_with_token_field() {
        let params = serde_json::json!({"token": "Bearer my-secret"});
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        let token = req.access_token().expect("should extract token");
        assert_eq!(token.scheme, "Bearer");
        assert_eq!(token.token, "my-secret");
    }

    #[test]
    fn access_token_from_object_with_access_token_field() {
        let params = serde_json::json!({"access_token": "abc123"});
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        let token = req.access_token().expect("should extract");
        // Bare token defaults to Bearer scheme
        assert_eq!(token.scheme, "Bearer");
        assert_eq!(token.token, "abc123");
    }

    #[test]
    fn access_token_from_camel_case_field() {
        let params = serde_json::json!({"accessToken": "Bearer xyz"});
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        let token = req.access_token().expect("should extract");
        assert_eq!(token.token, "xyz");
    }

    #[test]
    fn access_token_from_nested_scheme_token_object_with_empty_scheme() {
        // Empty scheme falls through to the alternate path which finds "token" as a bare string
        let params = serde_json::json!({"auth": {"scheme": "", "token": "abc"}});
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        let token = req.access_token().expect("falls through to string parse");
        assert_eq!(token.scheme, "Bearer");
        assert_eq!(token.token, "abc");
    }

    #[test]
    fn access_token_from_nested_scheme_token_object_with_whitespace_token() {
        // Whitespace-only token should be rejected by the scheme/token path
        // and also by AccessToken::parse which trims empty values
        let params = serde_json::json!({"authorization": "  "});
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        assert!(req.access_token().is_none());
    }

    #[test]
    fn static_verifier_rejects_unknown_token() {
        let verifier = StaticTokenVerifier::new([("valid-token", AuthContext::anonymous())]);
        let req = AuthRequest {
            method: "tools/call",
            params: None,
            request_id: 1,
        };
        let err = verifier
            .verify(
                &ctx(),
                req,
                &AccessToken {
                    scheme: "Bearer".to_string(),
                    token: "wrong-token".to_string(),
                },
            )
            .unwrap_err();
        assert_eq!(err.code, McpErrorCode::ResourceForbidden);
        assert!(err.message.contains("Invalid access token"));
    }

    #[test]
    fn static_verifier_no_scheme_restriction_allows_any() {
        let verifier = StaticTokenVerifier::new([("tok", AuthContext::with_subject("alice"))]);
        let req = AuthRequest {
            method: "tools/call",
            params: None,
            request_id: 1,
        };
        let auth = verifier
            .verify(
                &ctx(),
                req,
                &AccessToken {
                    scheme: "CustomScheme".to_string(),
                    token: "tok".to_string(),
                },
            )
            .unwrap();
        assert_eq!(auth.subject, Some("alice".to_string()));
    }

    #[test]
    fn token_auth_provider_succeeds_with_valid_token() {
        let verifier = StaticTokenVerifier::new([("secret", AuthContext::with_subject("bob"))]);
        let provider = TokenAuthProvider::new(verifier);
        let params = serde_json::json!({"authorization": "Bearer secret"});
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        let auth = provider.authenticate(&ctx(), req).unwrap();
        assert_eq!(auth.subject, Some("bob".to_string()));
    }

    #[test]
    fn token_auth_provider_fails_with_wrong_token() {
        let verifier = StaticTokenVerifier::new([("secret", AuthContext::with_subject("bob"))]);
        let provider = TokenAuthProvider::new(verifier);
        let params = serde_json::json!({"authorization": "Bearer wrong"});
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        let err = provider.authenticate(&ctx(), req).unwrap_err();
        assert_eq!(err.code, McpErrorCode::ResourceForbidden);
    }

    #[test]
    fn auth_request_debug() {
        let params = serde_json::json!({"key": "val"});
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 42,
        };
        let debug = format!("{req:?}");
        assert!(debug.contains("test"));
        assert!(debug.contains("42"));
    }

    #[test]
    fn auth_request_clone_copy() {
        let req = AuthRequest {
            method: "test",
            params: None,
            request_id: 1,
        };
        let req2 = req; // Copy
        assert_eq!(req.method, req2.method);
        assert_eq!(req.request_id, req2.request_id);
    }

    #[test]
    fn access_token_from_headers_nested_object() {
        // headers containing an object with scheme and token
        let params = serde_json::json!({
            "headers": {
                "Authorization": {"scheme": "Bearer", "token": "hdr-tok"}
            }
        });
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        let token = req.access_token().expect("should extract from headers");
        assert_eq!(token.scheme, "Bearer");
        assert_eq!(token.token, "hdr-tok");
    }

    #[test]
    fn access_token_from_empty_object() {
        let params = serde_json::json!({});
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        assert!(req.access_token().is_none());
    }

    // ── AllowAllAuthProvider derives ─────────────────────────────────

    #[test]
    fn allow_all_provider_debug() {
        let provider = AllowAllAuthProvider;
        let debug = format!("{provider:?}");
        assert!(debug.contains("AllowAllAuthProvider"));
    }

    #[test]
    fn allow_all_provider_default() {
        let _ = AllowAllAuthProvider;
    }

    #[test]
    fn allow_all_provider_clone_copy() {
        let provider = AllowAllAuthProvider;
        let cloned = provider.clone();
        let copied = provider; // Copy
        let _ = cloned
            .authenticate(
                &ctx(),
                AuthRequest {
                    method: "test",
                    params: None,
                    request_id: 1,
                },
            )
            .unwrap();
        let _ = copied;
    }

    // ── TokenAuthProvider ────────────────────────────────────────────

    #[test]
    fn token_auth_provider_clone() {
        let verifier = StaticTokenVerifier::new([("tok", AuthContext::anonymous())]);
        let provider = TokenAuthProvider::new(verifier);
        let cloned = provider.clone();
        let params = serde_json::json!({"authorization": "Bearer tok"});
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        let auth = cloned.authenticate(&ctx(), req).unwrap();
        assert!(auth.subject.is_none()); // anonymous
    }

    #[test]
    fn token_auth_provider_with_custom_error_and_valid_token() {
        let verifier = StaticTokenVerifier::new([("valid", AuthContext::with_subject("user"))]);
        let provider =
            TokenAuthProvider::new(verifier).with_missing_token_error(auth_error("custom missing"));
        let params = serde_json::json!({"authorization": "Bearer valid"});
        let req = AuthRequest {
            method: "tools/call",
            params: Some(&params),
            request_id: 1,
        };
        let auth = provider.authenticate(&ctx(), req).unwrap();
        assert_eq!(auth.subject, Some("user".to_string()));
    }

    // ── StaticTokenVerifier ──────────────────────────────────────────

    #[test]
    fn static_verifier_debug() {
        let verifier = StaticTokenVerifier::new([("tok", AuthContext::anonymous())]);
        let debug = format!("{verifier:?}");
        assert!(debug.contains("StaticTokenVerifier"));
    }

    #[test]
    fn static_verifier_clone() {
        let verifier = StaticTokenVerifier::new([("tok", AuthContext::with_subject("a"))]);
        let cloned = verifier.clone();
        let req = AuthRequest {
            method: "test",
            params: None,
            request_id: 1,
        };
        let auth = cloned
            .verify(
                &ctx(),
                req,
                &AccessToken {
                    scheme: "Bearer".to_string(),
                    token: "tok".to_string(),
                },
            )
            .unwrap();
        assert_eq!(auth.subject, Some("a".to_string()));
    }

    #[test]
    fn static_verifier_multiple_tokens() {
        let verifier = StaticTokenVerifier::new([
            ("alpha", AuthContext::with_subject("alice")),
            ("beta", AuthContext::with_subject("bob")),
        ]);
        let req = AuthRequest {
            method: "test",
            params: None,
            request_id: 1,
        };
        let a = verifier
            .verify(
                &ctx(),
                req,
                &AccessToken {
                    scheme: "Bearer".to_string(),
                    token: "alpha".to_string(),
                },
            )
            .unwrap();
        assert_eq!(a.subject, Some("alice".to_string()));
        let b = verifier
            .verify(
                &ctx(),
                req,
                &AccessToken {
                    scheme: "Bearer".to_string(),
                    token: "beta".to_string(),
                },
            )
            .unwrap();
        assert_eq!(b.subject, Some("bob".to_string()));
    }

    #[test]
    fn static_verifier_multiple_allowed_schemes() {
        let verifier = StaticTokenVerifier::new([("tok", AuthContext::anonymous())])
            .with_allowed_schemes(["Bearer", "Token"]);
        let req = AuthRequest {
            method: "test",
            params: None,
            request_id: 1,
        };
        // Bearer works
        assert!(
            verifier
                .verify(
                    &ctx(),
                    req,
                    &AccessToken {
                        scheme: "Bearer".to_string(),
                        token: "tok".to_string(),
                    },
                )
                .is_ok()
        );
        // Token works
        assert!(
            verifier
                .verify(
                    &ctx(),
                    req,
                    &AccessToken {
                        scheme: "Token".to_string(),
                        token: "tok".to_string(),
                    },
                )
                .is_ok()
        );
        // Basic does not
        assert!(
            verifier
                .verify(
                    &ctx(),
                    req,
                    &AccessToken {
                        scheme: "Basic".to_string(),
                        token: "tok".to_string(),
                    },
                )
                .is_err()
        );
    }

    // ── extract_from_value edge cases ────────────────────────────────

    #[test]
    fn access_token_from_bool_value_returns_none() {
        let params = serde_json::json!(true);
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        assert!(req.access_token().is_none());
    }

    #[test]
    fn access_token_from_null_params() {
        let params = serde_json::json!(null);
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        assert!(req.access_token().is_none());
    }

    #[test]
    fn access_token_from_nested_object_with_inner_authorization_string() {
        // Object with auth field pointing to object that has an inner authorization string
        let params = serde_json::json!({
            "auth": {
                "authorization": "Bearer inner-tok"
            }
        });
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        let token = req.access_token().expect("should extract from nested auth");
        assert_eq!(token.token, "inner-tok");
    }

    // ── _meta and headers fallback priority ──────────────────────────

    #[test]
    fn access_token_meta_fallback_when_top_level_empty() {
        let params = serde_json::json!({
            "other_field": 123,
            "_meta": {"authorization": "Bearer meta-tok"}
        });
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        let token = req.access_token().expect("should fallback to _meta");
        assert_eq!(token.token, "meta-tok");
    }

    #[test]
    fn access_token_headers_fallback_when_top_and_meta_empty() {
        let params = serde_json::json!({
            "other": "value",
            "_meta": {"other": "value"},
            "headers": {"authorization": "Bearer hdr-tok"}
        });
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        let token = req.access_token().expect("should fallback to headers");
        assert_eq!(token.token, "hdr-tok");
    }

    #[test]
    fn access_token_top_level_wins_over_meta() {
        let params = serde_json::json!({
            "authorization": "Bearer top-tok",
            "_meta": {"authorization": "Bearer meta-tok"}
        });
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        let token = req.access_token().expect("should extract top-level");
        assert_eq!(token.token, "top-tok");
    }

    // ── auth_error helper ────────────────────────────────────────────

    #[test]
    fn auth_error_creates_resource_forbidden() {
        let err = auth_error("denied");
        assert_eq!(err.code, McpErrorCode::ResourceForbidden);
        assert!(err.message.contains("denied"));
    }

    // ── extract_from_value with non-matching object ──────────────────

    #[test]
    fn access_token_from_object_without_any_known_key() {
        let params = serde_json::json!({"unknown_key": "Bearer tok"});
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        assert!(req.access_token().is_none());
    }

    #[test]
    fn access_token_from_scheme_token_with_whitespace_only_scheme() {
        let params = serde_json::json!({"auth": {"scheme": "  ", "token": "abc"}});
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        // Whitespace scheme is rejected, falls through to find "token" key in nested object
        let token = req.access_token().expect("falls through to token key");
        assert_eq!(token.scheme, "Bearer");
        assert_eq!(token.token, "abc");
    }

    // ── _meta / headers non-object fallthrough ──────────────────────

    #[test]
    fn access_token_meta_non_object_falls_through_to_headers() {
        let params = serde_json::json!({
            "_meta": 42,
            "headers": {"authorization": "Bearer hdr"}
        });
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        let token = req.access_token().expect("should skip non-object _meta");
        assert_eq!(token.token, "hdr");
    }

    #[test]
    fn access_token_headers_non_object_returns_none() {
        let params = serde_json::json!({
            "_meta": {"other": true},
            "headers": "not-an-object"
        });
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        assert!(req.access_token().is_none());
    }

    // ── Non-string, non-object values in map fields ─────────────────

    #[test]
    fn access_token_map_field_with_numeric_value_returns_none() {
        let params = serde_json::json!({"authorization": 12345});
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        assert!(req.access_token().is_none());
    }

    #[test]
    fn access_token_map_field_with_bool_value_returns_none() {
        let params = serde_json::json!({"token": true});
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        assert!(req.access_token().is_none());
    }

    #[test]
    fn access_token_map_field_with_array_value_returns_none() {
        let params = serde_json::json!({"authorization": ["Bearer", "tok"]});
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        assert!(req.access_token().is_none());
    }

    // ── extract_from_value nested accessToken key ───────────────────

    #[test]
    fn access_token_nested_object_with_access_token_key() {
        let params = serde_json::json!({
            "auth": {
                "accessToken": "Bearer nested-at"
            }
        });
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        let token = req
            .access_token()
            .expect("should extract from nested accessToken");
        assert_eq!(token.token, "nested-at");
    }

    // ── StaticTokenVerifier with empty allowed_schemes ──────────────

    #[test]
    fn static_verifier_empty_allowed_schemes_rejects_all() {
        let verifier = StaticTokenVerifier::new([("tok", AuthContext::anonymous())])
            .with_allowed_schemes(Vec::<String>::new());
        let req = AuthRequest {
            method: "test",
            params: None,
            request_id: 1,
        };
        let err = verifier
            .verify(
                &ctx(),
                req,
                &AccessToken {
                    scheme: "Bearer".to_string(),
                    token: "tok".to_string(),
                },
            )
            .unwrap_err();
        assert!(err.message.contains("Unsupported auth scheme"));
    }

    // ── TokenAuthProvider with scheme restriction in verifier ────────

    #[test]
    fn token_auth_provider_with_scheme_restriction() {
        let verifier = StaticTokenVerifier::new([("secret", AuthContext::with_subject("user"))])
            .with_allowed_schemes(["Bearer"]);
        let provider = TokenAuthProvider::new(verifier);

        // Basic scheme rejected by verifier
        let params = serde_json::json!({"authorization": "Basic secret"});
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        let err = provider.authenticate(&ctx(), req).unwrap_err();
        assert!(err.message.contains("Unsupported"));

        // Bearer scheme accepted
        let params = serde_json::json!({"authorization": "Bearer secret"});
        let req = AuthRequest {
            method: "test",
            params: Some(&params),
            request_id: 1,
        };
        let auth = provider.authenticate(&ctx(), req).unwrap();
        assert_eq!(auth.subject, Some("user".to_string()));
    }

    // ── AuthRequest with all fields populated ───────────────────────

    #[test]
    fn auth_request_exposes_all_fields() {
        let params = serde_json::json!({"key": "val"});
        let req = AuthRequest {
            method: "prompts/get",
            params: Some(&params),
            request_id: 99,
        };
        assert_eq!(req.method, "prompts/get");
        assert_eq!(req.request_id, 99);
        assert!(req.params.is_some());
    }
}

#[cfg(all(test, feature = "jwt"))]
mod jwt_tests {
    use super::*;
    use asupersync::Cx;
    use jsonwebtoken::{EncodingKey, Header, encode};

    fn ctx() -> McpContext {
        McpContext::new(Cx::for_testing(), 1)
    }

    fn hs256_token(signing_bytes: &[u8], claims: serde_json::Value) -> String {
        encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(signing_bytes),
        )
        .expect("encode jwt")
    }

    #[test]
    fn jwt_token_verifier_extracts_subject_and_scopes() {
        let signing_bytes = b"test-hs256-bytes";
        let exp = (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp();
        let jwt = hs256_token(
            signing_bytes,
            serde_json::json!({
                "sub": "user123",
                "scope": "openid profile",
                "scopes": ["email"],
                "exp": exp,
            }),
        );

        let verifier = JwtTokenVerifier::hs256(signing_bytes);
        let req = AuthRequest {
            method: "initialize",
            params: None,
            request_id: 1,
        };

        let access = AccessToken {
            scheme: "Bearer".to_string(),
            token: jwt,
        };
        let auth = verifier.verify(&ctx(), req, &access).unwrap();
        assert_eq!(auth.subject, Some("user123".to_string()));
        assert_eq!(
            auth.scopes,
            vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string()
            ]
        );
        assert!(auth.claims.is_some());
        assert!(auth.token.is_some());
    }

    #[test]
    fn jwt_token_verifier_rejects_wrong_scheme_and_invalid_token() {
        let signing_bytes = b"test-hs256-bytes";
        let exp = (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp();
        let jwt = hs256_token(
            signing_bytes,
            serde_json::json!({
                "sub": "user123",
                "exp": exp,
            }),
        );

        let verifier = JwtTokenVerifier::hs256(signing_bytes);
        let req = AuthRequest {
            method: "initialize",
            params: None,
            request_id: 1,
        };

        // Wrong scheme
        let err = verifier
            .verify(
                &ctx(),
                req,
                &AccessToken {
                    scheme: "Basic".to_string(),
                    token: jwt.clone(),
                },
            )
            .unwrap_err();
        assert_eq!(err.code, McpErrorCode::ResourceForbidden);
        assert!(err.message.contains("Unsupported auth scheme"));

        // Invalid token (wrong signing bytes)
        let bad = hs256_token(
            b"other-hs256-bytes",
            serde_json::json!({
                "sub": "user123",
                "exp": exp,
            }),
        );
        let err = verifier
            .verify(
                &ctx(),
                req,
                &AccessToken {
                    scheme: "Bearer".to_string(),
                    token: bad,
                },
            )
            .unwrap_err();
        assert!(err.message.contains("Invalid token"));
    }
}
