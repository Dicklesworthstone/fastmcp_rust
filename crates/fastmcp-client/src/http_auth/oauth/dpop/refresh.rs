//! Caller-driven, rotating refresh for explicitly renewable DPoP grants.
//!
//! Refresh custody is linear and remains bound to the exact session that
//! acquired it. A successful rotation preserves existing access snapshots at
//! their original expiry. Once renewal is admitted, a failure or dropped future
//! revokes that entire session, including all earlier access generations. The
//! old refresh secret is never restored after an ambiguous send.

use std::fmt;
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Instant;

use asupersync::Cx;
use asupersync::http::h1::{HttpClient, Method, RedirectPolicy, RetryPolicy};
use asupersync::security::SecretString;
use fastmcp_core::runtime::CallerContextFuture;
use fastmcp_protocol::{SecurityDocumentKind, admit_security_document_object};

use super::super::{
    MAX_TOKEN_RESPONSE_BYTES, TOKEN_TIMEOUT, encode_form, validate_scopes, validate_token_headers,
};
use super::{
    DpopAuthorizationError, DpopClientError, DpopCredential, DpopSession, FlowBounds,
    OAuthClientConfiguration, OAuthError, bounded, protect_response_body,
};

/// Exclusive, zeroizing custody of one rotating DPoP refresh token.
///
/// Only the explicitly renewable authorization flow or a successful rotation
/// can construct this value. It cannot be cloned, serialized, retargeted or
/// inspected for token bytes. Dropping an unused owner erases its refresh
/// token without revoking its independently held access snapshots.
pub struct DpopRefreshToken {
    configuration: OAuthClientConfiguration,
    credential: DpopCredential,
    scopes: Vec<String>,
    token: SecretString,
}

impl fmt::Debug for DpopRefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DpopRefreshToken(<redacted>)")
    }
}

impl DpopRefreshToken {
    pub(super) fn new(
        configuration: OAuthClientConfiguration,
        credential: DpopCredential,
        scopes: Vec<String>,
        token: SecretString,
    ) -> Self {
        Self {
            configuration,
            credential,
            scopes,
            token,
        }
    }

    /// The access snapshot issued alongside this refresh generation.
    pub fn credential(&self) -> &DpopCredential {
        &self.credential
    }

    /// The current grant's scope ceiling. Renewal cannot expand it again.
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Consume this grant for one native HTTPS refresh attempt.
    ///
    /// Pass the exact original session, or renew through its native client's
    /// `DpopHttpClient::refresh_authorization` method without recovering it.
    /// Access-token expiry permits renewal; local token or session revocation
    /// does not. A caller, runtime or session-binding preflight failure sends
    /// nothing and leaves the supplied session and existing access snapshots
    /// unchanged, but this consuming refresh owner is still erased.
    ///
    /// After preflight succeeds, any error or dropped future revokes the whole
    /// session and every access generation. A valid HTTP 400 `use_dpop_nonce`
    /// response may return one explicit continuation. Dropping that continuation
    /// has the same terminal effect. No request is automatically replayed.
    pub async fn refresh<'session>(
        self,
        cx: &Cx,
        session: &'session mut DpopSession,
    ) -> Result<DpopRefreshOutcome<'session>, DpopAuthorizationError> {
        Box::pin(CallerContextFuture::new(cx, async move {
            let bounds = FlowBounds::new(cx, TOKEN_TIMEOUT)?.for_token_exchange()?;
            session.validate_refresh_credential(&self.credential)?;
            let scope = self.scopes.join(" ");
            let mut fields = vec![
                ("grant_type", "refresh_token"),
                ("client_id", self.configuration.client_id.as_str()),
                ("refresh_token", self.token.as_str()),
                ("resource", self.configuration.resource.as_str()),
            ];
            if !scope.is_empty() {
                fields.push(("scope", scope.as_str()));
            }
            let form = SecretString::from_string(encode_form(&fields)?);
            bounds.check()?;
            session.validate_refresh_credential(&self.credential)?;
            RefreshExchange {
                bounds,
                retry_bounds: None,
                session,
                previous: self,
                form,
                armed: true,
            }
            .send(true)
            .await
        }))
        .await
    }
}

/// The result of one explicitly requested refresh POST.
#[derive(Debug)]
pub enum DpopRefreshOutcome<'session> {
    /// Both new token owners were admitted together under the original policy.
    Refreshed(DpopRefreshResult),
    /// The same authenticated token endpoint requires one fresh nonce proof.
    NonceRequired(DpopRefreshNonceChallenge<'session>),
}

/// A fresh access credential and its one-use successor refresh custody.
pub struct DpopRefreshResult {
    credential: DpopCredential,
    refresh: DpopRefreshToken,
}

impl fmt::Debug for DpopRefreshResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DpopRefreshResult(<redacted>)")
    }
}

impl DpopRefreshResult {
    pub fn credential(&self) -> &DpopCredential {
        &self.credential
    }

    pub fn scopes(&self) -> &[String] {
        self.refresh.scopes()
    }

    /// Transfer the access snapshot and next rotating refresh owner separately.
    pub fn into_parts(self) -> (DpopCredential, DpopRefreshToken) {
        (self.credential, self.refresh)
    }
}

/// One optional, consuming retry retaining the original refresh transaction.
///
/// The mutable session borrow prevents another request from changing its nonce
/// while this continuation owns the pending grant. The continuation retains
/// the original caller, cancellation, proof key, scopes, secret and deadline.
pub struct DpopRefreshNonceChallenge<'session> {
    exchange: RefreshExchange<'session>,
}

impl fmt::Debug for DpopRefreshNonceChallenge<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DpopRefreshNonceChallenge(<redacted>)")
    }
}

impl DpopRefreshNonceChallenge<'_> {
    /// Explicitly send the sole permitted retry with a fresh proof.
    ///
    /// The supplied caller must have the original task and region. Its budget
    /// and effect authority can only tighten those retained by the pending
    /// exchange. A second challenge, cancellation or any other failure is
    /// terminal and revokes every credential issued by this session.
    pub async fn retry(mut self, cx: &Cx) -> Result<DpopRefreshResult, DpopAuthorizationError> {
        Box::pin(CallerContextFuture::new(cx, async move {
            if cx.task_id() != self.exchange.bounds.caller.task_id()
                || cx.region_id() != self.exchange.bounds.caller.region_id()
            {
                return Err(DpopAuthorizationError::CallerMismatch);
            }
            if cx.checkpoint().is_err() {
                return Err(super::super::interruption(cx).into());
            }
            let retry_bounds = FlowBounds::new(
                cx,
                self.exchange
                    .bounds
                    .expires_at
                    .saturating_duration_since(Instant::now()),
            )?;
            self.exchange.bounds.tighten(&retry_bounds)?;
            // Retain both callers through raw I/O and final response admission.
            // An outer post-admission timeout must not discard a committed pair
            // after its family-quarantine guard has already been disarmed.
            self.exchange.retry_bounds = Some(retry_bounds);
            match self.exchange.send(false).await? {
                DpopRefreshOutcome::Refreshed(grant) => Ok(grant),
                DpopRefreshOutcome::NonceRequired(_) => {
                    Err(DpopAuthorizationError::NonceRetryLimit)
                }
            }
        }))
        .await
    }
}

struct RefreshExchange<'session> {
    bounds: FlowBounds,
    retry_bounds: Option<FlowBounds>,
    session: &'session mut DpopSession,
    previous: DpopRefreshToken,
    form: SecretString,
    armed: bool,
}

impl Drop for RefreshExchange<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Retiring only the latest credential would leave older successful
            // access snapshots alive after terminal refresh-family failure.
            self.session.revoke();
        }
    }
}

impl<'session> RefreshExchange<'session> {
    async fn send(
        self,
        allow_nonce_retry: bool,
    ) -> Result<DpopRefreshOutcome<'session>, DpopAuthorizationError> {
        let caller = self.bounds.caller.clone();
        Box::pin(CallerContextFuture::new(&caller, async move {
            self.check()?;
            let mut headers = vec![
                (
                    "Content-Type".to_owned(),
                    "application/x-www-form-urlencoded".to_owned(),
                ),
                ("Accept".to_owned(), "application/json".to_owned()),
                ("Accept-Encoding".to_owned(), "identity".to_owned()),
                ("Connection".to_owned(), "close".to_owned()),
            ];
            self.session
                .token_request_headers(&self.previous.configuration.token_endpoint)?
                .apply_to(&mut headers)?;
            let mut builder = HttpClient::builder()
                .redirect_policy(RedirectPolicy::None)
                .retry_policy(RetryPolicy::None)
                .no_proxy()
                .no_cookie_store()
                .max_body_size(MAX_TOKEN_RESPONSE_BYTES)
                .max_total_connections(1);
            for der in &self.previous.configuration.extra_root_certificates {
                builder = builder
                    .add_root_certificate(asupersync::tls::Certificate::from_der(der.clone()));
            }
            let client = builder.build();
            self.check()?;
            let started = Instant::now();
            let (status, headers, body) = self
                .wait_for_response(async {
                    let response = client
                        .request(
                            &self.bounds.caller,
                            Method::Post,
                            self.previous.configuration.token_endpoint.as_str(),
                            headers,
                            self.form.as_str().as_bytes().to_vec(),
                        )
                        .await
                        .map_err(|_| OAuthError::TransportFailed)?;
                    // The revocation and deadline waits can reject this ready
                    // response. They must drop zeroizing custody on that path too.
                    let body = protect_response_body(response.body)?;
                    if !response.trailers.is_empty() {
                        return Err(OAuthError::InvalidTokenResponse.into());
                    }
                    Ok((response.status, response.headers, body))
                })
                .await?;
            self.admit_response(
                status,
                &headers,
                body.as_bytes(),
                started,
                allow_nonce_retry,
            )
        }))
        .await
    }

    async fn wait_for_response<T>(
        &self,
        operation: impl Future<Output = Result<T, DpopAuthorizationError>>,
    ) -> Result<T, DpopAuthorizationError> {
        let operation = bounded(&self.bounds, operation);
        while_credential_live(&self.previous.credential, async {
            match &self.retry_bounds {
                Some(bounds) => bounded(bounds, operation).await,
                None => operation.await,
            }
        })
        .await
    }

    fn check(&self) -> Result<(), DpopAuthorizationError> {
        self.bounds.check()?;
        if let Some(bounds) = &self.retry_bounds {
            bounds.check()?;
        }
        self.session
            .validate_refresh_credential(&self.previous.credential)?;
        Ok(())
    }

    fn admit_response(
        mut self,
        status: u16,
        headers: &[(String, String)],
        body: &[u8],
        started: Instant,
        allow_nonce_retry: bool,
    ) -> Result<DpopRefreshOutcome<'session>, DpopAuthorizationError> {
        self.check()?;
        if !matches!(status, 200 | 400) {
            return Err(OAuthError::TokenEndpointRejected.into());
        }
        validate_token_headers(headers)?;
        let mut object = admit_security_document_object(SecurityDocumentKind::TokenResponse, body)
            .map_err(|_| OAuthError::InvalidTokenResponse)?;
        if status == 400 {
            if object.get("error").and_then(serde_json::Value::as_str) != Some("use_dpop_nonce") {
                return Err(OAuthError::TokenEndpointRejected.into());
            }
            if [
                "access_token",
                "token_type",
                "expires_in",
                "scope",
                "resource",
                "refresh_token",
                "id_token",
                "issued_token_type",
                "cnf",
            ]
            .iter()
            .any(|name| object.contains_key(*name))
                || ["error_description", "error_uri"].iter().any(|name| {
                    object.get(*name).is_some_and(|value| {
                        !value
                            .as_str()
                            .is_some_and(|value| super::super::valid_opaque(value, 4096))
                    })
                })
                || !headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("DPoP-Nonce"))
            {
                return Err(OAuthError::InvalidTokenResponse.into());
            }
            self.session
                .observe_token_nonce(&self.previous.configuration.token_endpoint, headers)?;
            if !allow_nonce_retry {
                return Err(DpopAuthorizationError::NonceRetryLimit);
            }
            self.check()?;
            return Ok(DpopRefreshOutcome::NonceRequired(
                DpopRefreshNonceChallenge { exchange: self },
            ));
        }
        if [
            "id_token",
            "issued_token_type",
            "error",
            "error_description",
            "error_uri",
        ]
        .iter()
        .any(|name| object.contains_key(*name))
            || object.get("resource").is_some_and(|value| {
                value.as_str() != Some(self.previous.configuration.resource.as_str())
            })
        {
            return Err(OAuthError::InvalidTokenResponse.into());
        }
        let token = admit_refresh_secret(object.remove("refresh_token"))?;
        if token == self.previous.token {
            return Err(OAuthError::InvalidTokenResponse.into());
        }
        let scopes = match object.get("scope") {
            None => self.previous.scopes.clone(),
            Some(value) => value
                .as_str()
                .ok_or(OAuthError::InvalidTokenResponse)?
                .split(' ')
                .map(str::to_owned)
                .collect(),
        };
        validate_scopes(&scopes)?;
        if scopes
            .iter()
            .any(|scope| !self.previous.scopes.contains(scope))
        {
            return Err(OAuthError::ScopeExpansion.into());
        }
        let credential = self.session.admit_token_response_fields(
            &self.previous.configuration.token_endpoint,
            status,
            &object,
            started,
            self.previous.configuration.max_access_token_lifetime,
        )?;
        self.session
            .observe_token_nonce(&self.previous.configuration.token_endpoint, headers)?;
        let refresh = DpopRefreshToken::new(
            self.previous.configuration.clone(),
            credential.clone(),
            scopes,
            token,
        );
        self.check()?;
        if credential
            .expires_at()
            .is_none_or(|expiry| Instant::now() >= expiry)
        {
            return Err(DpopClientError::InvalidLifetime.into());
        }
        // Commit the successor pair only after final caller/session admission.
        // Every earlier return leaves the Drop guard armed for all generations.
        self.armed = false;
        Ok(DpopRefreshOutcome::Refreshed(DpopRefreshResult {
            credential,
            refresh,
        }))
    }
}

pub(super) fn admit_refresh_secret(
    value: Option<serde_json::Value>,
) -> Result<SecretString, OAuthError> {
    let Some(serde_json::Value::String(value)) = value else {
        return Err(OAuthError::InvalidTokenResponse);
    };
    // Own the decoded allocation even when its syntax is rejected. A borrowed
    // Value plus to_owned would leave a separate unprotected refresh string.
    let token = SecretString::from_string(value);
    if !super::super::valid_opaque(token.as_str(), 4096) {
        return Err(OAuthError::InvalidTokenResponse);
    }
    Ok(token)
}

async fn while_credential_live<T>(
    credential: &DpopCredential,
    operation: impl Future<Output = Result<T, DpopAuthorizationError>>,
) -> Result<T, DpopAuthorizationError> {
    let mut revoked = std::pin::pin!(credential.cancelled());
    let mut operation = std::pin::pin!(operation);
    poll_fn(|task| {
        if credential.is_revoked() || revoked.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(OAuthError::RefreshUnavailable.into()));
        }
        let result = operation.as_mut().poll(task);
        if credential.is_revoked() {
            Poll::Ready(Err(OAuthError::RefreshUnavailable.into()))
        } else {
            result
        }
    })
    .await
}
