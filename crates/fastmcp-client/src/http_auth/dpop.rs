//! Explicit, caller-driven DPoP authorization for native HTTP clients.
//!
//! A session pins one HTTPS token endpoint, one exact HTTPS MCP resource,
//! and one ES256 proof key. It prepares actual token/resource request headers,
//! strictly admits DPoP token responses, and keeps AS/RS nonce state separate.
//! It never promotes a DPoP token into the existing bearer-only OAuth driver.
//!
//! The caller owns authenticated HTTPS I/O, response-size limits, cancellation
//! of in-flight I/O, and retry decisions. Feed nonce headers from the exact
//! authenticated response endpoint, including successful responses. On a nonce
//! challenge, generate new headers for a deliberately admitted retry; never
//! replay an old proof or automatically replay a possibly executed MCP call.
//! This module does not install automatic OAuth negotiation or HTTP retries.

use std::fmt;
use std::time::{Duration, Instant};

use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
/// Re-exported because this module's own public API demands them, and nothing
/// else makes them nameable from the published root.
///
/// [`DpopSession::new`] takes a [`DpopKey`] as its first argument, and
/// [`DpopClientError::Proof`] carries a [`DpopError`]. Both live in
/// `fastmcp_protocol::dpop`, which is behind that crate's `jose` feature and
/// is NOT re-exported by the `fastmcp-rust` facade — the facade forwards
/// `common_types`, `http_headers`, `methods` and `protocol_policy`, and `jose`
/// itself only under `builtin-auth-server`. So before this, a facade user
/// could reach `DpopSession` through `pub use fastmcp_client::http_auth` and
/// had no way to name the key it requires or the error it returns.
///
/// This adds no dependency: `jose` is already enabled for every non-wasm
/// target by this crate's own `[target.'cfg(not(target_arch = "wasm32"))'
/// .dependencies]` entry, which is the same predicate that gates `pub mod
/// dpop` in `http_auth.rs`. `DpopNonce` and `MAX_DPOP_TARGET_BYTES` stay
/// private because no public signature here names them.
pub use fastmcp_protocol::dpop::{DpopError, DpopKey};
use fastmcp_protocol::dpop::{DpopNonce, MAX_DPOP_TARGET_BYTES};
use fastmcp_protocol::{SecurityDocumentKind, admit_security_document_object};

use super::BoundBearerCredential;

/// Bounded explicit resource POST execution over native HTTPS.
#[cfg(not(target_arch = "wasm32"))]
pub mod native;

/// A redacted refusal from the explicit DPoP client path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpopClientError {
    /// Proof construction or nonce admission failed.
    Proof(DpopError),
    /// The response did not pass bounded, duplicate-free token admission.
    InvalidTokenResponse,
    /// A DPoP-only session will not silently downgrade to a bearer token.
    UnexpectedTokenType,
    /// The response or credential names another proof key.
    KeyMismatch,
    /// The source or destination is not the exact configured endpoint.
    EndpointMismatch,
    /// The credential expired or was revoked, including by its session owner.
    CredentialUnavailable,
    /// The receipt time or token lifetime is invalid or already exhausted.
    InvalidLifetime,
    /// Multiple DPoP-Nonce response fields are ambiguous, even if identical.
    DuplicateNonce,
    /// Existing headers already contain a field this authorization would set.
    HeaderConflict,
    /// The session owner has been irreversibly revoked.
    SessionRevoked,
}

impl fmt::Display for DpopClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proof(error) => error.fmt(formatter),
            Self::InvalidTokenResponse => formatter.write_str("invalid DPoP token response"),
            Self::UnexpectedTokenType => formatter.write_str("DPoP token type required"),
            Self::KeyMismatch => formatter.write_str("DPoP proof key does not match"),
            Self::EndpointMismatch => formatter.write_str("DPoP endpoint does not match"),
            Self::CredentialUnavailable => formatter.write_str("DPoP credential is unavailable"),
            Self::InvalidLifetime => formatter.write_str("invalid DPoP credential lifetime"),
            Self::DuplicateNonce => formatter.write_str("duplicate DPoP nonce response fields"),
            Self::HeaderConflict => formatter.write_str("conflicting DPoP request headers"),
            Self::SessionRevoked => formatter.write_str("DPoP session has been revoked"),
        }
    }
}

impl std::error::Error for DpopClientError {}

impl From<DpopError> for DpopClientError {
    fn from(error: DpopError) -> Self {
        Self::Proof(error)
    }
}

/// Newly generated sensitive headers for one request attempt.
///
/// No `Clone` or `Serialize` implementation is provided. Generate fresh
/// headers even when retrying the same method, target, and body.
pub struct DpopRequestHeaders(Vec<(String, String)>);

impl fmt::Debug for DpopRequestHeaders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopRequestHeaders(<redacted>)")
    }
}

impl DpopRequestHeaders {
    /// Consume the authorization for a caller-owned HTTPS transport.
    #[must_use]
    pub fn into_headers(self) -> Vec<(String, String)> {
        self.0
    }

    /// Append without replacing or duplicating an existing protected field.
    /// On conflict, the supplied headers are left completely unchanged.
    /// Token-endpoint proofs permit an independent Basic client-auth header;
    /// resource proofs set Authorization themselves and refuse any collision.
    pub fn apply_to(self, headers: &mut Vec<(String, String)>) -> Result<(), DpopClientError> {
        if self.0.iter().any(|(new_name, _)| {
            headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case(new_name))
        }) {
            return Err(DpopClientError::HeaderConflict);
        }
        headers.extend(self.0);
        Ok(())
    }
}

/// A DPoP-only access credential, never exposed as a bearer credential.
///
/// The private bearer binding is reused solely for the existing token grammar,
/// exact-resource admission, monotonic expiry, and clone-shared revocation.
/// There is no public conversion, dereference, or bearer-header method.
#[derive(Clone)]
pub struct DpopCredential {
    bound: BoundBearerCredential,
    key_thumbprint: String,
    token_endpoint: CanonicalHttpUrl,
}

impl fmt::Debug for DpopCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopCredential(<redacted>)")
    }
}

impl DpopCredential {
    /// Revoke this token and all its clones without revoking other tokens.
    pub fn revoke(&self) {
        self.bound.revoke();
    }

    /// Whether token-local or session-owner revocation has occurred.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.bound.is_revoked()
    }

    /// The exact resource, including query, to which this token is bound.
    #[must_use]
    pub fn resource(&self) -> &CanonicalHttpUrl {
        self.bound.resource()
    }

    /// The monotonic expiry selected during token-response admission.
    #[must_use]
    pub fn expires_at(&self) -> Option<Instant> {
        self.bound.expires_at()
    }
}

/// One owner-controlled DPoP authorization context.
///
/// The session is not clonable: nonce updates have one explicit mutable owner.
/// Keys may be imported or shared intentionally. Revocation or dropping this
/// session makes every access credential admitted by it unusable, including
/// credentials passed to another session holding the same proof key.
pub struct DpopSession {
    key: DpopKey,
    token_endpoint: CanonicalHttpUrl,
    resource: CanonicalHttpUrl,
    token_nonce: Option<DpopNonce>,
    resource_nonce: Option<DpopNonce>,
    cancellation: McpRequestCancellation,
}

impl fmt::Debug for DpopSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopSession(<redacted>)")
    }
}

impl Drop for DpopSession {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl DpopSession {
    /// Pin admitted HTTPS endpoints and the key used throughout authorization.
    pub fn new(
        key: DpopKey,
        token_endpoint: CanonicalHttpUrl,
        resource: CanonicalHttpUrl,
    ) -> Result<Self, DpopClientError> {
        for endpoint in [&token_endpoint, &resource] {
            if !endpoint.as_str().starts_with("https://") {
                return Err(DpopError::CleartextTarget.into());
            }
            if endpoint.as_str().len() > MAX_DPOP_TARGET_BYTES {
                return Err(DpopError::TargetTooLong.into());
            }
        }
        Ok(Self {
            key,
            token_endpoint,
            resource,
            token_nonce: None,
            resource_nonce: None,
            cancellation: McpRequestCancellation::new(),
        })
    }

    /// RFC 7638 thumbprint for the authorization request's `dpop_jkt`.
    #[must_use]
    pub fn authorization_jkt(&self) -> &str {
        self.key.thumbprint()
    }

    /// Revoke this owner and every credential it has issued. No HTTP is sent.
    pub fn revoke(&self) {
        self.cancellation.cancel();
    }

    fn require_active(&self) -> Result<(), DpopClientError> {
        if self.cancellation.is_cancel_requested() {
            return Err(DpopClientError::SessionRevoked);
        }
        Ok(())
    }

    /// Produce a fresh POST proof for token issuance or refresh.
    /// The proof deliberately has no access-token hash (`ath`).
    pub fn token_request_headers(
        &self,
        target: &CanonicalHttpUrl,
    ) -> Result<DpopRequestHeaders, DpopClientError> {
        self.require_active()?;
        if target.as_str() != self.token_endpoint.as_str() {
            return Err(DpopClientError::EndpointMismatch);
        }
        let proof = self
            .key
            .token_endpoint_proof(target, self.token_nonce.as_ref())?;
        self.require_active()?;
        Ok(DpopRequestHeaders(vec![(
            "DPoP".to_owned(),
            proof.into_header_value(),
        )]))
    }

    /// Admit a successful token response from the pinned HTTPS token endpoint.
    ///
    /// `received_at` must be the monotonic response-receipt time, not a later
    /// cache-read time. Missing `expires_in` uses the caller's nonzero lifetime
    /// cap; a supplied lifetime can only shorten that cap. Null, fractional,
    /// negative, zero, overflowed, and already-expired lifetimes are refused.
    ///
    /// The caller must authenticate the response's HTTPS origin. This does not
    /// decode an opaque access token or pretend unverified JWT claims are
    /// trusted. When a response supplies `cnf`, it must contain this key's jkt.
    /// Refresh-token storage and grant/client-auth policy remain caller-owned.
    pub fn admit_token_response(
        &self,
        source: &CanonicalHttpUrl,
        status: u16,
        bytes: &[u8],
        received_at: Instant,
        maximum_lifetime: Duration,
    ) -> Result<DpopCredential, DpopClientError> {
        self.require_active()?;
        if source.as_str() != self.token_endpoint.as_str() {
            return Err(DpopClientError::EndpointMismatch);
        }
        if status != 200 {
            return Err(DpopClientError::InvalidTokenResponse);
        }
        let response = admit_security_document_object(SecurityDocumentKind::TokenResponse, bytes)
            .map_err(|_| DpopClientError::InvalidTokenResponse)?;
        if response.contains_key("error") {
            return Err(DpopClientError::InvalidTokenResponse);
        }
        if !response
            .get("token_type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|kind| kind.eq_ignore_ascii_case("DPoP"))
        {
            return Err(DpopClientError::UnexpectedTokenType);
        }
        if let Some(confirmation) = response.get("cnf") {
            let confirmation = confirmation
                .as_object()
                .ok_or(DpopClientError::KeyMismatch)?;
            if confirmation.len() != 1
                || confirmation.get("jkt").and_then(serde_json::Value::as_str)
                    != Some(self.key.thumbprint())
            {
                return Err(DpopClientError::KeyMismatch);
            }
        }
        let lifetime = match response.get("expires_in") {
            Some(value) => {
                Duration::from_secs(value.as_u64().ok_or(DpopClientError::InvalidLifetime)?)
                    .min(maximum_lifetime)
            }
            None => maximum_lifetime,
        };
        let now = Instant::now();
        if lifetime.is_zero() || received_at > now {
            return Err(DpopClientError::InvalidLifetime);
        }
        let deadline = received_at
            .checked_add(lifetime)
            .ok_or(DpopClientError::InvalidLifetime)?;
        if deadline <= now {
            return Err(DpopClientError::InvalidLifetime);
        }
        let token = response
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .ok_or(DpopClientError::InvalidTokenResponse)?;
        let bound = BoundBearerCredential::bind_with_expiry(self.resource.clone(), token, deadline)
            .map_err(|_| DpopClientError::InvalidTokenResponse)?
            .for_owner(&self.cancellation)
            .ok_or(DpopClientError::SessionRevoked)?;
        self.require_active()?;
        Ok(DpopCredential {
            bound,
            key_thumbprint: self.key.thumbprint().to_owned(),
            token_endpoint: self.token_endpoint.clone(),
        })
    }

    /// Produce both Authorization: DPoP and a fresh access-token-bound proof.
    /// Binding compares the complete canonical resource, including its query,
    /// even though RFC 9449 strips that query from the proof's `htu` claim.
    pub fn resource_request_headers(
        &self,
        method: &str,
        target: &CanonicalHttpUrl,
        credential: &DpopCredential,
    ) -> Result<DpopRequestHeaders, DpopClientError> {
        self.require_active()?;
        if target.as_str() != self.resource.as_str()
            || credential.resource().as_str() != target.as_str()
            || credential.token_endpoint.as_str() != self.token_endpoint.as_str()
        {
            return Err(DpopClientError::EndpointMismatch);
        }
        if credential.key_thumbprint != self.key.thumbprint() {
            return Err(DpopClientError::KeyMismatch);
        }
        require_credential(credential)?;
        let proof = self.key.resource_proof(
            method,
            target,
            &credential.bound.token,
            self.resource_nonce.as_ref(),
        )?;
        let authorization = format!("DPoP {}", credential.bound.token);
        // Signing/allocation must not publish a credential whose admission
        // expired or was revoked while this operation was in progress.
        require_credential(credential)?;
        self.require_active()?;
        Ok(DpopRequestHeaders(vec![
            ("Authorization".to_owned(), authorization),
            ("DPoP".to_owned(), proof.into_header_value()),
        ]))
    }

    /// Observe only the token endpoint's nonce, on success or challenge.
    /// Missing headers retain the previous nonce; malformed updates are atomic.
    pub fn observe_token_nonce(
        &mut self,
        source: &CanonicalHttpUrl,
        headers: &[(String, String)],
    ) -> Result<bool, DpopClientError> {
        self.require_active()?;
        if source.as_str() != self.token_endpoint.as_str() {
            return Err(DpopClientError::EndpointMismatch);
        }
        update_nonce(&mut self.token_nonce, headers)
    }

    /// Observe only the resource server's nonce. AS and RS state are separate
    /// even if both endpoints happen to have the same origin or identical URL.
    pub fn observe_resource_nonce(
        &mut self,
        source: &CanonicalHttpUrl,
        headers: &[(String, String)],
    ) -> Result<bool, DpopClientError> {
        self.require_active()?;
        if source.as_str() != self.resource.as_str() {
            return Err(DpopClientError::EndpointMismatch);
        }
        update_nonce(&mut self.resource_nonce, headers)
    }
}

fn require_credential(credential: &DpopCredential) -> Result<(), DpopClientError> {
    if credential.is_revoked()
        || credential
            .expires_at()
            .is_none_or(|deadline| Instant::now() >= deadline)
    {
        return Err(DpopClientError::CredentialUnavailable);
    }
    Ok(())
}

fn update_nonce(
    current: &mut Option<DpopNonce>,
    headers: &[(String, String)],
) -> Result<bool, DpopClientError> {
    let mut fields = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("DPoP-Nonce"));
    let Some((_, value)) = fields.next() else {
        return Ok(false);
    };
    if fields.next().is_some() {
        return Err(DpopClientError::DuplicateNonce);
    }
    let nonce = DpopNonce::new(value)?;
    let changed = current.as_ref() != Some(&nonce);
    *current = Some(nonce);
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn url(value: &str) -> CanonicalHttpUrl {
        CanonicalHttpUrl::parse(value).unwrap()
    }

    fn session() -> DpopSession {
        DpopSession::new(
            DpopKey::generate().unwrap(),
            url("https://issuer.example/token"),
            url("https://mcp.example/api?tenant=one"),
        )
        .unwrap()
    }

    fn admit(
        session: &DpopSession,
        value: serde_json::Value,
    ) -> Result<DpopCredential, DpopClientError> {
        session.admit_token_response(
            &session.token_endpoint,
            200,
            &serde_json::to_vec(&value).unwrap(),
            Instant::now(),
            Duration::from_secs(60),
        )
    }

    fn credential(session: &DpopSession) -> DpopCredential {
        admit(
            session,
            json!({"access_token": "sensitive-token", "token_type": "DPoP", "expires_in": 60}),
        )
        .unwrap()
    }

    #[test]
    fn dpop_client_emits_separate_token_and_resource_headers_without_bearer_downgrade() {
        let session = session();
        let token = session
            .token_request_headers(&session.token_endpoint)
            .unwrap()
            .into_headers();
        assert_eq!(token.len(), 1);
        assert_eq!(token[0].0, "DPoP");
        let credential = credential(&session);
        let first = session
            .resource_request_headers("POST", &session.resource, &credential)
            .unwrap()
            .into_headers();
        let second = session
            .resource_request_headers("POST", &session.resource, &credential)
            .unwrap()
            .into_headers();
        assert_eq!(first.len(), 2);
        assert_eq!(
            first[0],
            (
                "Authorization".to_owned(),
                "DPoP sensitive-token".to_owned()
            )
        );
        assert_eq!(first[1].0, "DPoP");
        assert_ne!(first[1].1, second[1].1);
        assert_ne!(first[1].1, token[0].1);
    }

    #[test]
    fn dpop_client_nonce_updates_are_role_isolated_and_atomic() {
        let endpoint = url("https://same.example/api");
        let mut session = DpopSession::new(
            DpopKey::generate().unwrap(),
            endpoint.clone(),
            endpoint.clone(),
        )
        .unwrap();
        assert!(
            session
                .observe_token_nonce(&endpoint, &[("DPoP-Nonce".into(), "as-nonce".into())])
                .unwrap()
        );
        assert!(session.resource_nonce.is_none());
        assert!(
            session
                .observe_resource_nonce(&endpoint, &[("dpop-nonce".into(), "rs-nonce".into())])
                .unwrap()
        );
        assert_eq!(session.token_nonce.as_ref().unwrap().as_str(), "as-nonce");
        assert_eq!(
            session.resource_nonce.as_ref().unwrap().as_str(),
            "rs-nonce"
        );
        assert!(!session.observe_token_nonce(&endpoint, &[]).unwrap());
        for headers in [
            vec![
                ("DPoP-Nonce".into(), "new".into()),
                ("dpop-nonce".into(), "new".into()),
            ],
            vec![("DPoP-Nonce".into(), "bad nonce".into())],
        ] {
            assert!(session.observe_token_nonce(&endpoint, &headers).is_err());
            assert_eq!(session.token_nonce.as_ref().unwrap().as_str(), "as-nonce");
            assert_eq!(
                session.resource_nonce.as_ref().unwrap().as_str(),
                "rs-nonce"
            );
        }
        assert!(
            session
                .observe_token_nonce(
                    &url("https://other.example/api"),
                    &[("DPoP-Nonce".into(), "bad-origin".into())]
                )
                .is_err()
        );
        assert_eq!(session.token_nonce.as_ref().unwrap().as_str(), "as-nonce");
    }

    #[test]
    fn dpop_client_rejects_downgrade_wrong_key_and_ambiguous_token_json() {
        let session = session();
        for value in [
            json!({"access_token": "secret", "token_type": "Bearer"}),
            json!({"access_token": "secret", "token_type": "DPoP", "cnf": {"jkt": "wrong-key"}}),
            json!({"access_token": "secret", "token_type": "DPoP", "cnf": null}),
            json!({"access_token": "secret", "token_type": "DPoP", "error": "use_dpop_nonce"}),
            json!({"access_token": "bad token", "token_type": "DPoP"}),
        ] {
            assert!(admit(&session, value).is_err());
        }
        let duplicate = br#"{"access_token":"one","access_token":"two","token_type":"DPoP"}"#;
        assert_eq!(
            session
                .admit_token_response(
                    &session.token_endpoint,
                    200,
                    duplicate,
                    Instant::now(),
                    Duration::from_secs(60)
                )
                .unwrap_err(),
            DpopClientError::InvalidTokenResponse
        );
        assert!(admit(&session, json!({"access_token": "good", "token_type": "dpop", "cnf": {"jkt": session.authorization_jkt()}})).is_ok());
    }

    #[test]
    fn dpop_client_keeps_full_query_binding_and_refuses_other_keys_and_issuers() {
        let session = session();
        let credential = credential(&session);
        for target in [
            "https://mcp.example/api",
            "https://mcp.example/api?tenant=two",
            "https://mcp.example/other?tenant=one",
            "http://mcp.example/api?tenant=one",
        ] {
            assert_eq!(
                session
                    .resource_request_headers("POST", &url(target), &credential)
                    .unwrap_err(),
                DpopClientError::EndpointMismatch
            );
        }
        let another_key = DpopSession::new(
            DpopKey::generate().unwrap(),
            session.token_endpoint.clone(),
            session.resource.clone(),
        )
        .unwrap();
        assert_eq!(
            another_key
                .resource_request_headers("POST", &session.resource, &credential)
                .unwrap_err(),
            DpopClientError::KeyMismatch
        );
        let another_issuer = DpopSession::new(
            session.key.clone(),
            url("https://other.example/token"),
            session.resource.clone(),
        )
        .unwrap();
        assert_eq!(
            another_issuer
                .resource_request_headers("POST", &session.resource, &credential)
                .unwrap_err(),
            DpopClientError::EndpointMismatch
        );
    }

    #[test]
    fn dpop_client_lifetimes_use_receipt_time_and_cannot_exceed_local_cap() {
        let session = session();
        let received = Instant::now();
        let bytes = br#"{"access_token":"token","token_type":"DPoP","expires_in":3600}"#;
        let credential = session
            .admit_token_response(
                &session.token_endpoint,
                200,
                bytes,
                received,
                Duration::from_secs(30),
            )
            .unwrap();
        assert_eq!(
            credential.expires_at(),
            received.checked_add(Duration::from_secs(30))
        );
        for seconds in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!("60"),
            serde_json::Value::Null,
        ] {
            assert_eq!(
                admit(
                    &session,
                    json!({"access_token": "token", "token_type": "DPoP", "expires_in": seconds})
                )
                .unwrap_err(),
                DpopClientError::InvalidLifetime
            );
        }
        assert!(
            session
                .admit_token_response(
                    &session.token_endpoint,
                    200,
                    bytes,
                    received - Duration::from_secs(120),
                    Duration::from_secs(30)
                )
                .is_err()
        );
        assert!(
            session
                .admit_token_response(
                    &session.token_endpoint,
                    200,
                    bytes,
                    received + Duration::from_secs(120),
                    Duration::from_secs(30)
                )
                .is_err()
        );
        assert!(
            session
                .admit_token_response(
                    &session.token_endpoint,
                    200,
                    bytes,
                    received,
                    Duration::ZERO
                )
                .is_err()
        );
        assert!(
            session
                .admit_token_response(
                    &session.token_endpoint,
                    400,
                    bytes,
                    received,
                    Duration::from_secs(30)
                )
                .is_err()
        );
    }

    #[test]
    fn dpop_client_revocation_covers_clones_and_session_drop_without_revoking_other_tokens() {
        let session = session();
        let first = credential(&session);
        let first_clone = first.clone();
        let second = credential(&session);
        first.revoke();
        assert!(first_clone.is_revoked());
        assert!(!second.is_revoked());
        assert_eq!(
            session
                .resource_request_headers("POST", &session.resource, &first_clone)
                .unwrap_err(),
            DpopClientError::CredentialUnavailable
        );
        drop(session);
        assert!(second.is_revoked());
    }

    #[test]
    fn dpop_client_revoked_session_cannot_sign_or_admit_more_credentials() {
        let mut session = session();
        let credential = credential(&session);
        session.revoke();
        assert!(credential.is_revoked());
        assert_eq!(
            session
                .token_request_headers(&session.token_endpoint)
                .unwrap_err(),
            DpopClientError::SessionRevoked
        );
        assert_eq!(
            admit(
                &session,
                json!({"access_token": "token", "token_type": "DPoP"})
            )
            .unwrap_err(),
            DpopClientError::SessionRevoked
        );
        let source = session.resource.clone();
        assert_eq!(
            session.observe_resource_nonce(&source, &[]).unwrap_err(),
            DpopClientError::SessionRevoked
        );
    }

    #[test]
    fn dpop_client_header_merge_is_atomic_and_keeps_token_endpoint_client_auth() {
        let session = session();
        let credential = credential(&session);
        for existing in ["authorization", "dPoP"] {
            let mut headers = vec![(existing.to_owned(), "existing".to_owned())];
            let before = headers.clone();
            let fresh = session
                .resource_request_headers("POST", &session.resource, &credential)
                .unwrap();
            assert_eq!(
                fresh.apply_to(&mut headers).unwrap_err(),
                DpopClientError::HeaderConflict
            );
            assert_eq!(headers, before);
        }
        let mut headers = vec![("Authorization".to_owned(), "Basic client-auth".to_owned())];
        session
            .token_request_headers(&session.token_endpoint)
            .unwrap()
            .apply_to(&mut headers)
            .unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].1, "Basic client-auth");
    }

    #[test]
    fn dpop_client_redacts_credentials_headers_and_nonce_state() {
        let session = session();
        let credential = credential(&session);
        let headers = session
            .resource_request_headers("POST", &session.resource, &credential)
            .unwrap();
        for debug in [
            format!("{session:?}"),
            format!("{credential:?}"),
            format!("{headers:?}"),
        ] {
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("sensitive-token"));
        }
    }
}
