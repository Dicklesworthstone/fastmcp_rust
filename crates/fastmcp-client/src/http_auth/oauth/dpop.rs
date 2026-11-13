//! Public-client authorization-code acquisition for RFC 9449 DPoP credentials.
//!
//! These explicit entry points retain the ordinary OAuth callback, issuer,
//! state, S256 PKCE, scope and resource checks. The authorization request also
//! carries `dpop_jkt`, and the HTTPS token POST proves possession of that same
//! key. Success owns a separate [`DpopSession`] and [`DpopCredential`]; there
//! is no conversion to the bearer driver. The explicitly renewable entry
//! points additionally retain a rotating refresh grant for caller-driven
//! renewal through the same session, issuer and client policy.
//!
//! A token endpoint's HTTP 400 `use_dpop_nonce` response can return a linear
//! continuation. Only an explicit [`DpopNonceChallenge::retry`] sends its one
//! permitted retry, with a fresh proof and the original code and deadline.
//! Network failures, redirects and resource operations are never replayed.

use std::fmt;
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::http::h1::{HttpClient, Method, RedirectPolicy, RetryPolicy};
use asupersync::security::SecretString;
use asupersync::types::Time;
use fastmcp_core::runtime::CallerContextFuture;
use fastmcp_protocol::{SecurityDocumentKind, admit_security_document_object};

use super::{
    AuthorizationAttempt, CALLBACK_PATH, MAX_TOKEN_RESPONSE_BYTES, OAuthClient,
    OAuthClientConfiguration, OAuthError, TOKEN_TIMEOUT, admit_host_redirect_callback,
    bind_loopback, encode_form, ensure_live, operation_deadline, validate_host_redirect,
    validate_scopes, validate_token_headers, wait_for_code, with_caller, within,
};
use crate::http_auth::CanonicalHttpUrl;
use crate::http_auth::dpop::{DpopClientError, DpopCredential, DpopKey, DpopSession};

/// Explicit native renewal with exclusive rotating refresh-token custody.
pub mod refresh;
pub use refresh::{
    DpopRefreshNonceChallenge, DpopRefreshOutcome, DpopRefreshResult, DpopRefreshToken,
};

#[derive(Clone, Copy)]
enum RefreshPolicy {
    Refuse,
    RequireRotation,
}

/// Sanitized failure without a callback, code, token, proof or response body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DpopAuthorizationError {
    /// Ordinary callback, transport, scope or caller admission failed.
    OAuth(OAuthError),
    /// DPoP key, nonce, token type or credential admission failed.
    Dpop(DpopClientError),
    /// The one explicit token-nonce retry has already been used.
    NonceRetryLimit,
    /// A continuation was supplied a different caller task or region.
    CallerMismatch,
}

impl fmt::Display for DpopAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OAuth(error) => error.fmt(formatter),
            Self::Dpop(error) => error.fmt(formatter),
            Self::NonceRetryLimit => formatter.write_str("DPoP token nonce retry limit reached"),
            Self::CallerMismatch => formatter.write_str("DPoP continuation caller does not match"),
        }
    }
}

impl std::error::Error for DpopAuthorizationError {}

impl From<OAuthError> for DpopAuthorizationError {
    fn from(error: OAuthError) -> Self {
        Self::OAuth(error)
    }
}

impl From<DpopClientError> for DpopAuthorizationError {
    fn from(error: DpopClientError) -> Self {
        Self::Dpop(error)
    }
}

/// The result of one authorization-code token POST. Neither variant is clonable.
#[derive(Debug)]
pub enum DpopAuthorizationOutcome {
    /// A resource-bound credential and the sole session owner that can use it.
    Authorized(DpopAuthorization),
    /// An authenticated token endpoint explicitly requested a fresh nonce proof.
    NonceRequired(DpopNonceChallenge),
}

/// An admitted DPoP grant and its key/nonce owner.
///
/// Consume this value with [`Self::into_parts`] to construct a
/// [`crate::http_auth::dpop::native::DpopHttpClient`] using an explicit resource TLS
/// policy. Token-endpoint trust does not become resource-server trust.
/// Dropping the session revokes every access-credential clone it issued.
pub struct DpopAuthorization {
    session: DpopSession,
    credential: DpopCredential,
    scopes: Vec<String>,
    refresh: Option<DpopRefreshToken>,
}

impl fmt::Debug for DpopAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopAuthorization(<redacted>)")
    }
}

impl DpopAuthorization {
    /// The admitted credential, usable only with the matching DPoP session.
    #[must_use]
    pub fn credential(&self) -> &DpopCredential {
        &self.credential
    }

    /// The granted scope set, bounded by the original authorization request.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Whether the explicitly renewable profile retained rotating grant custody.
    #[must_use]
    pub fn has_refresh_token(&self) -> bool {
        self.refresh.is_some()
    }

    /// Transfer the session and credential together to the native DPoP client.
    /// Any retained refresh token is erased; the access credential stays usable
    /// until its original expiry or revocation.
    #[must_use]
    pub fn into_parts(self) -> (DpopSession, DpopCredential) {
        (self.session, self.credential)
    }

    /// Retain explicit renewal custody alongside the session and access token.
    ///
    /// The renewable acquisition entry points always return `Some` here. Pass
    /// the session into the native DPoP client, use the access token for calls,
    /// then recover that same session with `DpopHttpClient::into_session` when
    /// explicitly renewing. The refresh owner cannot be used with a different
    /// session, even if the proof key and endpoints are identical.
    #[must_use]
    pub fn into_renewable_parts(
        self,
    ) -> (DpopSession, DpopCredential, Option<DpopRefreshToken>) {
        (self.session, self.credential, self.refresh)
    }
}

/// Custody of one explicit token-endpoint nonce retry.
///
/// This value cannot be cloned, serialized, retargeted or inspected for code,
/// verifier, nonce or key bytes. It retains the original caller's cancellation,
/// clock and deadline. Dropping it retires the code and session locally. This
/// is an in-memory continuation, not persistent or crash-recoverable custody.
pub struct DpopNonceChallenge {
    exchange: CodeExchange,
}

impl fmt::Debug for DpopNonceChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopNonceChallenge(<redacted>)")
    }
}

impl DpopNonceChallenge {
    /// Explicitly send the single allowed nonce retry using the original code.
    ///
    /// The caller must be the original task and region. The supplied and
    /// surrounding effect ceilings can only restrict its retained authority.
    /// Cancellation, expiry, a second challenge or any other failure consumes
    /// this continuation; another login is required.
    pub async fn retry(mut self, cx: &Cx) -> Result<DpopAuthorization, DpopAuthorizationError> {
        CallerContextFuture::new(cx, async move {
            if cx.task_id() != self.exchange.bounds.caller.task_id()
                || cx.region_id() != self.exchange.bounds.caller.region_id()
            {
                return Err(DpopAuthorizationError::CallerMismatch);
            }
            if cx.checkpoint().is_err() {
                return Err(super::interruption(cx).into());
            }
            // Same identity does not make two Cx budgets or cancellation
            // signals interchangeable. Keep both waits alive: the inner
            // exchange owns its original caller and clock, while this outer
            // wait enforces the supplied caller even during a quiet socket.
            // Translate only the already-frozen monotonic remainder; neither
            // a different clock nor another retry can renew the lifetime.
            let retry_bounds = FlowBounds::new(
                cx,
                self.exchange.bounds.expires_at.saturating_duration_since(Instant::now()),
            )?;
            // The supplied caller may carry a different, currently idle timer
            // driver. Enforce its shorter remainder on the original active
            // driver too, so a quiet connection still wakes at that limit.
            self.exchange.bounds.tighten(&retry_bounds)?;
            match bounded(&retry_bounds, self.exchange.send(false)).await? {
                DpopAuthorizationOutcome::Authorized(grant) => Ok(grant),
                DpopAuthorizationOutcome::NonceRequired(_) => {
                    Err(DpopAuthorizationError::NonceRetryLimit)
                }
            }
        })
        .await
    }
}

impl OAuthClient {
    /// Acquire a separate DPoP grant through a native loopback callback.
    ///
    /// This uses the same preregistered public-client, RFC 9207 issuer and S256
    /// PKCE requirements as [`Self::authorize`]. The caller supplies the proof
    /// key and browser launcher. The key thumbprint is bound into the launch
    /// URL before any callback, and no bearer or refresh grant is admitted.
    pub async fn authorize_dpop<L, F>(
        &self,
        cx: &Cx,
        key: DpopKey,
        launch_browser: L,
    ) -> Result<DpopAuthorizationOutcome, DpopAuthorizationError>
    where
        L: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<(), OAuthError>>,
    {
        Box::pin(self.authorize_dpop_profile(cx, key, launch_browser, RefreshPolicy::Refuse)).await
    }

    /// Acquire a DPoP grant with mandatory rotating refresh-token custody.
    ///
    /// The caller explicitly selects this public-client profile. A successful
    /// token response must contain a nonempty, bounded refresh token. Native
    /// renewal is explicit, uses this same proof-key session and issuer/client
    /// policy, and requires a distinct successor refresh token each time.
    /// This does not install automatic refresh or replay an MCP operation.
    pub async fn authorize_renewable_dpop<L, F>(
        &self,
        cx: &Cx,
        key: DpopKey,
        launch_browser: L,
    ) -> Result<DpopAuthorizationOutcome, DpopAuthorizationError>
    where
        L: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<(), OAuthError>>,
    {
        Box::pin(self.authorize_dpop_profile(
            cx,
            key,
            launch_browser,
            RefreshPolicy::RequireRotation,
        ))
        .await
    }

    async fn authorize_dpop_profile<L, F>(
        &self,
        cx: &Cx,
        key: DpopKey,
        launch_browser: L,
        refresh_policy: RefreshPolicy,
    ) -> Result<DpopAuthorizationOutcome, DpopAuthorizationError>
    where
        L: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<(), OAuthError>>,
    {
        CallerContextFuture::new(cx, async move {
            let bounds = FlowBounds::new(cx, self.configuration.authorization_timeout)?;
            let attempt = AuthorizationAttempt::new()?;
            let session = self.dpop_session(key)?;
            let listener = bounded(&bounds, async { Ok(bind_loopback().await?) }).await?;
            let address = listener
                .local_addr()
                .map_err(|_| OAuthError::CallbackBindFailed)?;
            if !address.ip().is_loopback() || address.port() == 0 {
                return Err(OAuthError::CallbackBindFailed.into());
            }
            let redirect_uri = format!("http://{address}{CALLBACK_PATH}");
            let authorization_url = authorization_url(
                &attempt,
                &self.configuration,
                &redirect_uri,
                &session,
            )?;
            bounded(&bounds, async {
                launch_browser(authorization_url)
                    .await
                    .map_err(|_| OAuthError::BrowserLaunchFailed)?;
                Ok(())
            })
            .await?;
            let code = bounded(&bounds, async {
                Ok(wait_for_code(
                    &bounds.caller,
                    bounds.deadline,
                    &listener,
                    address,
                    &attempt,
                    &self.configuration,
                )
                .await?)
            })
            .await?;
            drop(listener);
            CodeExchange::new(
                bounds,
                &self.configuration,
                session,
                attempt,
                &redirect_uri,
                code,
                refresh_policy,
            )?
            .send(true)
            .await
        })
        .await
    }

    /// Acquire a DPoP grant through the host's independently registered HTTPS
    /// callback route. The driver contract and exact route/state/issuer checks
    /// are identical to [`Self::authorize_with_redirect_driver`].
    ///
    /// The host returns the raw callback URL, without normalizing or logging
    /// it. One deadline covers the driver, code exchange and any explicit
    /// nonce retry; no runtime, browser process or background task is created.
    pub async fn authorize_dpop_with_redirect_driver<D, F>(
        &self,
        cx: &Cx,
        key: DpopKey,
        redirect_uri: CanonicalHttpUrl,
        driver: D,
    ) -> Result<DpopAuthorizationOutcome, DpopAuthorizationError>
    where
        D: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<String, OAuthError>>,
    {
        Box::pin(self.authorize_dpop_redirect_profile(
            cx,
            key,
            redirect_uri,
            driver,
            RefreshPolicy::Refuse,
        ))
        .await
    }

    /// Acquire mandatory rotating DPoP grant custody through a registered
    /// host-provided HTTPS callback route.
    ///
    /// The callback, issuer, state and PKCE contract is identical to
    /// [`Self::authorize_dpop_with_redirect_driver`]. Only this explicitly
    /// renewable profile admits a refresh token, and its absence is an error.
    pub async fn authorize_renewable_dpop_with_redirect_driver<D, F>(
        &self,
        cx: &Cx,
        key: DpopKey,
        redirect_uri: CanonicalHttpUrl,
        driver: D,
    ) -> Result<DpopAuthorizationOutcome, DpopAuthorizationError>
    where
        D: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<String, OAuthError>>,
    {
        Box::pin(self.authorize_dpop_redirect_profile(
            cx,
            key,
            redirect_uri,
            driver,
            RefreshPolicy::RequireRotation,
        ))
        .await
    }

    async fn authorize_dpop_redirect_profile<D, F>(
        &self,
        cx: &Cx,
        key: DpopKey,
        redirect_uri: CanonicalHttpUrl,
        driver: D,
        refresh_policy: RefreshPolicy,
    ) -> Result<DpopAuthorizationOutcome, DpopAuthorizationError>
    where
        D: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<String, OAuthError>>,
    {
        CallerContextFuture::new(cx, async move {
            validate_host_redirect(&redirect_uri)?;
            let bounds = FlowBounds::new(cx, self.configuration.authorization_timeout)?;
            let attempt = AuthorizationAttempt::new()?;
            let session = self.dpop_session(key)?;
            let authorization_url = authorization_url(
                &attempt,
                &self.configuration,
                redirect_uri.as_str(),
                &session,
            )?;
            let callback = SecretString::from_string(
                bounded(&bounds, async { Ok(driver(authorization_url).await?) }).await?,
            );
            let code = admit_host_redirect_callback(
                callback.as_str(),
                &redirect_uri,
                &attempt,
                &self.configuration.issuer,
            )?;
            CodeExchange::new(
                bounds,
                &self.configuration,
                session,
                attempt,
                redirect_uri.as_str(),
                code,
                refresh_policy,
            )?
            .send(true)
            .await
        })
        .await
    }

    fn dpop_session(&self, key: DpopKey) -> Result<DpopSession, DpopClientError> {
        DpopSession::new(
            key,
            self.configuration.token_endpoint.clone(),
            self.configuration.resource.clone(),
        )
    }
}

fn authorization_url(
    attempt: &AuthorizationAttempt,
    configuration: &OAuthClientConfiguration,
    redirect_uri: &str,
    session: &DpopSession,
) -> Result<CanonicalHttpUrl, OAuthError> {
    let base = attempt.authorization_url(configuration, redirect_uri)?;
    let binding = encode_form(&[("dpop_jkt", session.authorization_jkt())])?;
    CanonicalHttpUrl::parse(&format!("{}&{binding}", base.as_str()))
        .map_err(|_| OAuthError::InvalidConfiguration)
}

struct FlowBounds {
    caller: Cx,
    deadline: Time,
    expires_at: Instant,
}

impl FlowBounds {
    fn new(cx: &Cx, timeout: Duration) -> Result<Self, OAuthError> {
        with_caller(cx, || {
            let caller = Cx::current().ok_or(OAuthError::RuntimeCapabilityUnavailable)?;
            let deadline = operation_deadline(&caller, timeout)?;
            let remaining = Duration::from_nanos(
                deadline.as_nanos().saturating_sub(caller.now().as_nanos()),
            );
            let bounds = Self {
                caller,
                deadline,
                expires_at: Instant::now()
                    .checked_add(remaining)
                    .ok_or(OAuthError::InvalidConfiguration)?,
            };
            bounds.check()?;
            Ok(bounds)
        })
    }

    fn for_token_exchange(mut self) -> Result<Self, OAuthError> {
        self.check()?;
        self.deadline = self.deadline.min(operation_deadline(&self.caller, TOKEN_TIMEOUT)?);
        self.expires_at = self.expires_at.min(
            Instant::now()
                .checked_add(TOKEN_TIMEOUT)
                .ok_or(OAuthError::InvalidConfiguration)?,
        );
        Ok(self)
    }

    fn tighten(&mut self, other: &Self) -> Result<(), OAuthError> {
        self.expires_at = self.expires_at.min(other.expires_at);
        let remaining = self.expires_at.saturating_duration_since(Instant::now());
        self.deadline = self.deadline.min(operation_deadline(&self.caller, remaining)?);
        self.check()
    }

    fn check(&self) -> Result<(), OAuthError> {
        ensure_live(&self.caller, self.deadline)?;
        if Instant::now() >= self.expires_at {
            return Err(OAuthError::TimedOut);
        }
        let active = Cx::current().ok_or(OAuthError::RuntimeCapabilityUnavailable)?;
        let available = active.capabilities();
        let held = self.caller.capabilities();
        if !available.time || self.caller.timer_driver().is_none() {
            return Err(OAuthError::RuntimeTimerUnavailable);
        }
        // Native HTTP receives this retained Cx. Refuse before polling it if
        // even an optional effect has since been withheld; a nested operation
        // must never receive a broader Cx than its current caller permits.
        if !available.io
            || !available.entropy
            || (held.spawn && !available.spawn)
            || (held.remote && !available.remote)
        {
            return Err(OAuthError::RuntimeCapabilityUnavailable);
        }
        Ok(())
    }
}

async fn bounded<T>(
    bounds: &FlowBounds,
    future: impl Future<Output = Result<T, DpopAuthorizationError>>,
) -> Result<T, DpopAuthorizationError> {
    let mut future = std::pin::pin!(future);
    within(&bounds.caller, bounds.deadline, poll_fn(|task| {
        if let Err(error) = bounds.check() {
            return Poll::Ready(Err(error));
        }
        let result = future.as_mut().poll(task);
        if let Err(error) = bounds.check() {
            return Poll::Ready(Err(error));
        }
        result.map(Ok)
    }))
    .await?
}

// The native HTTP adapter returns an owned body. Transfer that allocation to
// SecretString inside the request future, before a ready-response cancellation
// check can discard it. Invalid UTF-8 is erased through the same allocation.
fn protect_response_body(bytes: Vec<u8>) -> Result<SecretString, DpopAuthorizationError> {
    match String::from_utf8(bytes) {
        Ok(body) => Ok(SecretString::from_string(body)),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.fill(0);
            if let Ok(cleared) = String::from_utf8(bytes) {
                drop(SecretString::from_string(cleared));
            }
            Err(OAuthError::InvalidTokenResponse.into())
        }
    }
}

struct CodeExchange {
    bounds: FlowBounds,
    configuration: OAuthClientConfiguration,
    session: DpopSession,
    form: SecretString,
    refresh_policy: RefreshPolicy,
}

impl CodeExchange {
    fn new(
        bounds: FlowBounds,
        configuration: &OAuthClientConfiguration,
        session: DpopSession,
        attempt: AuthorizationAttempt,
        redirect_uri: &str,
        code: String,
        refresh_policy: RefreshPolicy,
    ) -> Result<Self, OAuthError> {
        let code = SecretString::from_string(code);
        let verifier = SecretString::from_string(attempt.verifier());
        let form = SecretString::from_string(encode_form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &configuration.client_id),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier.as_str()),
            ("resource", configuration.resource.as_str()),
        ])?);
        Ok(Self {
            bounds: bounds.for_token_exchange()?,
            configuration: configuration.clone(),
            session,
            form,
            refresh_policy,
        })
    }

    async fn send(self, allow_nonce_retry: bool) -> Result<DpopAuthorizationOutcome, DpopAuthorizationError> {
        let caller = self.bounds.caller.clone();
        CallerContextFuture::new(&caller, async move {
            self.bounds.check()?;
            let mut headers = vec![
                ("Content-Type".to_owned(), "application/x-www-form-urlencoded".to_owned()),
                ("Accept".to_owned(), "application/json".to_owned()),
                ("Accept-Encoding".to_owned(), "identity".to_owned()),
                ("Connection".to_owned(), "close".to_owned()),
            ];
            self.session
                .token_request_headers(&self.configuration.token_endpoint)?
                .apply_to(&mut headers)?;
            let mut builder = HttpClient::builder()
                .redirect_policy(RedirectPolicy::None)
                .retry_policy(RetryPolicy::None)
                .no_proxy()
                .no_cookie_store()
                .max_body_size(MAX_TOKEN_RESPONSE_BYTES)
                .max_total_connections(1);
            for der in &self.configuration.extra_root_certificates {
                builder = builder.add_root_certificate(asupersync::tls::Certificate::from_der(der.clone()));
            }
            let client = builder.build();
            let started = Instant::now();
            let (status, headers, body) = bounded(&self.bounds, async {
                let response = client
                    .request(
                        &self.bounds.caller,
                        Method::Post,
                        self.configuration.token_endpoint.as_str(),
                        headers,
                        self.form.as_str().as_bytes().to_vec(),
                    )
                    .await
                    .map_err(|_| OAuthError::TransportFailed)?;
                // Protect the owned allocation before the outer wait can
                // discard a completed response on its post-poll checkpoint.
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
        })
        .await
    }

    fn admit_response(
        mut self,
        status: u16,
        headers: &[(String, String)],
        body: &[u8],
        started: Instant,
        allow_nonce_retry: bool,
    ) -> Result<DpopAuthorizationOutcome, DpopAuthorizationError> {
        self.bounds.check()?;
        if !matches!(status, 200 | 400) {
            return Err(OAuthError::TokenEndpointRejected.into());
        }
        validate_token_headers(headers)?;
        let mut object = admit_security_document_object(SecurityDocumentKind::TokenResponse, body)
            .map_err(|_| OAuthError::InvalidTokenResponse)?;
        if status == 400 {
            // RFC 9449 section 8: token-endpoint nonce challenges use HTTP 400.
            // A resource server's HTTP 401 challenge cannot authorize a code retry.
            if object.get("error").and_then(serde_json::Value::as_str) != Some("use_dpop_nonce") {
                return Err(OAuthError::TokenEndpointRejected.into());
            }
            if ["access_token", "token_type", "expires_in", "scope", "resource", "refresh_token", "id_token", "issued_token_type", "cnf"]
                .iter()
                .any(|name| object.contains_key(*name))
                || ["error_description", "error_uri"].iter().any(|name| {
                    object.get(*name).is_some_and(|value| {
                        !value.as_str().is_some_and(|value| super::valid_opaque(value, 4096))
                    })
                })
            {
                return Err(OAuthError::InvalidTokenResponse.into());
            }
            if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("DPoP-Nonce")) {
                return Err(OAuthError::InvalidTokenResponse.into());
            }
            // Admission validates even an unchanged nonce. The observer's
            // boolean reports a change, not whether a valid field was present.
            self.session.observe_token_nonce(&self.configuration.token_endpoint, headers)?;
            if !allow_nonce_retry {
                return Err(DpopAuthorizationError::NonceRetryLimit);
            }
            self.bounds.check()?;
            return Ok(DpopAuthorizationOutcome::NonceRequired(DpopNonceChallenge { exchange: self }));
        }
        if ["id_token", "issued_token_type", "error", "error_description", "error_uri"]
            .iter()
            .any(|name| object.contains_key(*name))
            || object.get("resource").is_some_and(|value| {
                value.as_str() != Some(self.configuration.resource.as_str())
            })
        {
            return Err(OAuthError::InvalidTokenResponse.into());
        }
        let refresh_token = match self.refresh_policy {
            RefreshPolicy::Refuse => {
                if object.contains_key("refresh_token") {
                    return Err(OAuthError::InvalidTokenResponse.into());
                }
                None
            }
            RefreshPolicy::RequireRotation => {
                Some(refresh::admit_refresh_secret(object.remove("refresh_token"))?)
            }
        };
        let scopes = match object.get("scope") {
            None => self.configuration.scopes.clone(),
            Some(value) => value
                .as_str()
                .ok_or(OAuthError::InvalidTokenResponse)?
                .split(' ')
                .map(str::to_owned)
                .collect(),
        };
        validate_scopes(&scopes)?;
        if scopes.iter().any(|scope| !self.configuration.scopes.contains(scope)) {
            return Err(OAuthError::ScopeExpansion.into());
        }
        self.session.observe_token_nonce(&self.configuration.token_endpoint, headers)?;
        let credential = self.session.admit_token_response_fields(
            &self.configuration.token_endpoint,
            status,
            &object,
            started,
            self.configuration.max_access_token_lifetime,
        )?;
        self.bounds.check()?;
        let refresh = refresh_token.map(|token| {
            DpopRefreshToken::new(
                self.configuration.clone(),
                credential.clone(),
                scopes.clone(),
                token,
            )
        });
        self.bounds.check()?;
        if credential.expires_at().is_none_or(|expiry| Instant::now() >= expiry) {
            return Err(DpopClientError::InvalidLifetime.into());
        }
        Ok(DpopAuthorizationOutcome::Authorized(DpopAuthorization {
            session: self.session,
            credential,
            scopes,
            refresh,
        }))
    }
}

#[cfg(test)]
mod tests;
