//! Interactive OAuth authorization for explicitly configured native public clients.
//!
//! The caller supplies trusted issuer/endpoint configuration and the browser
//! launcher. The driver binds an IP-literal loopback listener *before* invoking
//! that launcher, admits one issuer- and state-bound callback, and redeems its
//! code with S256 PKCE over HTTPS. It creates no runtime or background task.
//!
//! This is the preregistered public-client slice of AUTH-07, not discovery,
//! dynamic registration, OIDC authentication, or AUTH-05 durable token custody.
//! Returned secrets stay in process memory; neither credentials nor private
//! response bodies implement serialization or diagnostic formatting.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::http::h1::{HttpClient, Method, RedirectPolicy, RetryPolicy};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::time::Sleep;
use asupersync::types::Time;
use fastmcp_core::crypto::{
    HmacSha256Key, HmacSha256Tag, SecurityIdentifier, draw_hmac_sha256_key,
    draw_security_identifier, sha256_bounded,
};
use fastmcp_core::{AccessToken, CanonicalResourceId, CanonicalResourceIdPolicy};
use serde::{Deserialize, Deserializer};

use super::{BoundBearerCredential, CanonicalHttpUrl};

const CALLBACK_PATH: &str = "/oauth/callback";
const STATE_DOMAIN: &[u8] = b"fastmcp/oauth-loopback-state/v1\0";
const MAX_CALLBACK_BYTES: usize = 16 * 1024;
const MAX_CALLBACK_CONNECTIONS: usize = 32;
const MAX_FORM_FIELDS: usize = 32;
const MAX_CODE_BYTES: usize = 4096;
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_FORM_BYTES: usize = 64 * 1024;
const CALLBACK_READ_TIMEOUT: Duration = Duration::from_secs(5);
const TOKEN_TIMEOUT: Duration = Duration::from_secs(30);

/// Sanitized errors. No variant retains a code, token, callback URL, response
/// body, or a third-party transport error that could reflect credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthError {
    InvalidConfiguration,
    RuntimeTimerUnavailable,
    Cancelled,
    TimedOut,
    RandomSourceUnavailable,
    CallbackBindFailed,
    BrowserLaunchFailed,
    CallbackRejected,
    IssuerMismatch,
    AuthorizationDenied,
    CallbackLimitExceeded,
    TransportFailed,
    TokenEndpointRejected,
    InvalidTokenResponse,
    ScopeExpansion,
    ExpiredCredential,
    CredentialBindingMismatch,
    RefreshUnavailable,
}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid native OAuth configuration",
            Self::RuntimeTimerUnavailable => "OAuth requires the caller's timer capability",
            Self::Cancelled => "OAuth operation cancelled",
            Self::TimedOut => "OAuth operation deadline exceeded",
            Self::RandomSourceUnavailable => "OAuth security randomness unavailable",
            Self::CallbackBindFailed => "OAuth loopback listener could not bind",
            Self::BrowserLaunchFailed => "OAuth browser launcher failed",
            Self::CallbackRejected => "OAuth callback rejected",
            Self::IssuerMismatch => "OAuth callback issuer does not match the configured issuer",
            Self::AuthorizationDenied => "OAuth authorization was denied",
            Self::CallbackLimitExceeded => "OAuth callback admission limit exceeded",
            Self::TransportFailed => "OAuth token transport failed",
            Self::TokenEndpointRejected => "OAuth token endpoint rejected the exchange",
            Self::InvalidTokenResponse => "OAuth token response rejected",
            Self::ScopeExpansion => "OAuth response expanded the requested scopes",
            Self::ExpiredCredential => "OAuth credential already expired",
            Self::CredentialBindingMismatch => "OAuth credential belongs to a different client binding",
            Self::RefreshUnavailable => "OAuth credential has no reusable refresh token",
        })
    }
}

impl std::error::Error for OAuthError {}

/// Immutable, administrator-supplied configuration for an RFC 8252 native
/// public client. The registration must allow the `/oauth/callback` path on
/// an IP-literal loopback URI with an ephemeral port. The authorization server
/// must return RFC 9207 `iss` on both successful and unsuccessful callbacks.
///
/// This constructor does not establish trust in URLs obtained from a peer.
/// Discovery and registration must be validated before constructing this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthClientConfiguration {
    issuer: String,
    authorization_endpoint: CanonicalHttpUrl,
    token_endpoint: CanonicalHttpUrl,
    resource: CanonicalHttpUrl,
    client_id: String,
    scopes: Vec<String>,
    authorization_timeout: Duration,
    max_access_token_lifetime: Duration,
}

impl OAuthClientConfiguration {
    pub fn from_trusted_endpoints(
        issuer: impl Into<String>,
        authorization_endpoint: CanonicalHttpUrl,
        token_endpoint: CanonicalHttpUrl,
        resource: CanonicalHttpUrl,
        client_id: impl Into<String>,
        scopes: Vec<String>,
    ) -> Result<Self, OAuthError> {
        let issuer = issuer.into();
        let issuer_url = CanonicalHttpUrl::parse(&issuer)
            .map_err(|_| OAuthError::InvalidConfiguration)?;
        for endpoint in [&issuer_url, &authorization_endpoint, &token_endpoint] {
            if endpoint.scheme() != "https"
                || endpoint.has_userinfo()
                || endpoint.query().is_some()
                || endpoint.fragment().is_some()
            {
                return Err(OAuthError::InvalidConfiguration);
            }
        }
        // Keep the original issuer spelling for the exact RFC 9207 comparison;
        // canonical network identity must not replace that comparison.
        if issuer.len() > 4096 || issuer.chars().any(char::is_whitespace) {
            return Err(OAuthError::InvalidConfiguration);
        }
        if resource.scheme() != "https" {
            return Err(OAuthError::InvalidConfiguration);
        }
        CanonicalResourceId::parse_for_endpoint(
            resource.as_str(),
            &resource,
            CanonicalResourceIdPolicy::DEFAULT,
        )
        .map_err(|_| OAuthError::InvalidConfiguration)?;
        let client_id = client_id.into();
        if client_id.is_empty()
            || client_id.len() > 1024
            || client_id.chars().any(char::is_control)
        {
            return Err(OAuthError::InvalidConfiguration);
        }
        validate_scopes(&scopes).map_err(|_| OAuthError::InvalidConfiguration)?;
        Ok(Self {
            issuer,
            authorization_endpoint,
            token_endpoint,
            resource,
            client_id,
            scopes,
            authorization_timeout: Duration::from_secs(300),
            max_access_token_lifetime: Duration::from_secs(3600),
        })
    }

    /// Sets the single deadline covering bind, browser launch, callbacks and
    /// redemption. Callback traffic cannot reset it. The caller's budget may
    /// further shorten it.
    pub fn with_authorization_timeout(mut self, timeout: Duration) -> Result<Self, OAuthError> {
        if timeout.is_zero() || timeout > Duration::from_secs(900) {
            return Err(OAuthError::InvalidConfiguration);
        }
        self.authorization_timeout = timeout;
        Ok(self)
    }

    /// Sets a local upper bound on access-token reuse, including responses
    /// omitting `expires_in`. This is a client safety limit, not an assertion
    /// about the issuer's actual expiration policy.
    pub fn with_max_access_token_lifetime(mut self, lifetime: Duration) -> Result<Self, OAuthError> {
        if lifetime.is_zero() || lifetime > Duration::from_secs(86_400) {
            return Err(OAuthError::InvalidConfiguration);
        }
        self.max_access_token_lifetime = lifetime;
        Ok(self)
    }
}

/// An admitted grant bound to one issuer, registration and MCP resource.
/// There is deliberately no `Clone`, `Debug`, `Display`, or serde implementation.
/// Use `bearer_credential()` to supply the resource-bound access token to the
/// existing HTTP client. Refresh-token bytes are not publicly exposed.
pub struct OAuthCredentials {
    configuration: OAuthClientConfiguration,
    access: BoundBearerCredential,
    refresh_token: Option<String>,
    scopes: Vec<String>,
    expires_at: Instant,
}

impl OAuthCredentials {
    pub fn bearer_credential(&self) -> &BoundBearerCredential {
        &self.access
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    pub fn has_refresh_token(&self) -> bool {
        self.refresh_token.is_some()
    }
}

/// Native OAuth driver. All I/O is polled under the supplied `Cx`, without
/// creating another runtime, detached task, browser subprocess, or global client.
#[derive(Clone, Debug)]
pub struct OAuthClient {
    configuration: OAuthClientConfiguration,
}

impl OAuthClient {
    pub fn new(configuration: OAuthClientConfiguration) -> Self {
        Self { configuration }
    }

    /// Runs a preregistered public-client authorization-code flow.
    ///
    /// `launch_browser` is invoked exactly once, after binding the callback
    /// listener. The host chooses how to present/open the URL; its future must
    /// return after launching, not wait for the OAuth callback. The launcher is
    /// part of the host's trusted computing base and must not log the URL.
    /// Dropping this future drops its listener, connection and pending exchange.
    pub async fn authorize<L, F>(
        &self,
        cx: &Cx,
        launch_browser: L,
    ) -> Result<OAuthCredentials, OAuthError>
    where
        L: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<(), OAuthError>>,
    {
        let deadline = operation_deadline(cx, self.configuration.authorization_timeout)?;
        let listener = within(cx, deadline, bind_loopback()).await?;
        let address = listener.local_addr().map_err(|_| OAuthError::CallbackBindFailed)?;
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(OAuthError::CallbackBindFailed);
        }
        let redirect_uri = format!("http://{address}{CALLBACK_PATH}");
        let attempt = AuthorizationAttempt::new()?;
        let authorization_url = attempt.authorization_url(&self.configuration, &redirect_uri)?;
        within(cx, deadline, async {
            launch_browser(authorization_url)
                .await
                .map_err(|_| OAuthError::BrowserLaunchFailed)
        })
        .await?;
        let code = wait_for_code(cx, deadline, &listener, address, &attempt, &self.configuration).await?;
        // A callback can authorize only one POST. Close the listener before
        // redemption; neither a duplicate callback nor a network error retries it.
        drop(listener);
        let verifier = attempt.verifier();
        let body = encode_form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &self.configuration.client_id),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("code_verifier", &verifier),
            ("resource", self.configuration.resource.as_str()),
        ])?;
        let started = Instant::now();
        let response = self.exchange(cx, deadline, body).await?;
        let credentials = admit_token_response(
            &self.configuration, &self.configuration.scopes, &response, started,
        )?;
        if cx.checkpoint().is_err() { return Err(OAuthError::Cancelled); }
        if cx.now() >= deadline { return Err(OAuthError::TimedOut); }
        Ok(credentials)
    }

    /// Renews an access token through the same trusted issuer, registration,
    /// resource and client policy that admitted the original grant.
    ///
    /// Exclusive access to the credentials serializes refresh operations. A
    /// successful response replaces the complete token pair at once. Narrowed
    /// scopes become the next refresh ceiling; they cannot silently re-expand.
    /// When the issuer omits a new refresh token, the previous one is retained.
    ///
    /// After dispatch becomes possible, failure or cancellation discards the
    /// old refresh token rather than retrying a possibly consumed/rotated token.
    /// The previous access token and its original expiry remain unchanged;
    /// `has_refresh_token()` becomes false and another login is required for
    /// future renewal. Preflight failures leave the entire credential untouched.
    pub async fn refresh(
        &self,
        cx: &Cx,
        credentials: &mut OAuthCredentials,
    ) -> Result<(), OAuthError> {
        let deadline = operation_deadline(cx, TOKEN_TIMEOUT)?;
        let (body, previous_refresh) = self.prepare_refresh(credentials)?;
        let started = Instant::now();
        let response = self.exchange(cx, deadline, body).await?;
        // Do not publish a new token pair after the caller has cancelled.
        if cx.checkpoint().is_err() { return Err(OAuthError::Cancelled); }
        if cx.now() >= deadline { return Err(OAuthError::TimedOut); }
        let mut replacement = self.admit_refresh(credentials, previous_refresh, &response, started)?;
        if cx.checkpoint().is_err() { return Err(OAuthError::Cancelled); }
        if cx.now() >= deadline { return Err(OAuthError::TimedOut); }
        std::mem::swap(credentials, &mut replacement);
        Ok(())
    }

    fn prepare_refresh(&self, credentials: &mut OAuthCredentials) -> Result<(String, String), OAuthError> {
        if credentials.configuration != self.configuration {
            return Err(OAuthError::CredentialBindingMismatch);
        }
        let previous = credentials.refresh_token.as_deref().ok_or(OAuthError::RefreshUnavailable)?;
        let scope = credentials.scopes.join(" ");
        let mut fields = vec![
            ("grant_type", "refresh_token"),
            ("client_id", self.configuration.client_id.as_str()),
            ("refresh_token", previous),
            ("resource", self.configuration.resource.as_str()),
        ];
        if !scope.is_empty() { fields.push(("scope", scope.as_str())); }
        let body = encode_form(&fields)?;
        // All fallible local validation precedes this ownership transfer. Once
        // an exchange is possible, cancellation cannot put this secret back.
        let previous = credentials.refresh_token.take().ok_or(OAuthError::RefreshUnavailable)?;
        Ok((body, previous))
    }

    fn admit_refresh(
        &self,
        previous: &OAuthCredentials,
        previous_refresh: String,
        response: &[u8],
        started: Instant,
    ) -> Result<OAuthCredentials, OAuthError> {
        let mut replacement = admit_token_response(
            &self.configuration, &previous.scopes, response, started,
        )?;
        if replacement.refresh_token.is_none() {
            replacement.refresh_token = Some(previous_refresh);
        }
        Ok(replacement)
    }

    async fn exchange(&self, cx: &Cx, deadline: Time, body: String) -> Result<Vec<u8>, OAuthError> {
        let deadline = deadline.min(operation_deadline(cx, TOKEN_TIMEOUT)?);
        let client = HttpClient::builder()
            .redirect_policy(RedirectPolicy::None)
            .retry_policy(RetryPolicy::None)
            .no_proxy()
            .no_cookie_store()
            .max_body_size(MAX_TOKEN_RESPONSE_BYTES)
            .max_total_connections(1)
            .build();
        let response = within(cx, deadline, async {
            client
                .request(
                    cx,
                    Method::Post,
                    self.configuration.token_endpoint.as_str(),
                    vec![
                        ("Content-Type".to_owned(), "application/x-www-form-urlencoded".to_owned()),
                        ("Accept".to_owned(), "application/json".to_owned()),
                        ("Accept-Encoding".to_owned(), "identity".to_owned()),
                        ("Connection".to_owned(), "close".to_owned()),
                    ],
                    body.into_bytes(),
                )
                .await
                .map_err(|_| OAuthError::TransportFailed)
        })
        .await?;
        if response.status != 200 {
            return Err(OAuthError::TokenEndpointRejected);
        }
        validate_token_headers(&response.headers)?;
        if response.body.len() > MAX_TOKEN_RESPONSE_BYTES {
            return Err(OAuthError::InvalidTokenResponse);
        }
        Ok(response.body)
    }
}

struct AuthorizationAttempt {
    verifier_material: SecurityIdentifier,
    state_key: HmacSha256Key,
}

impl AuthorizationAttempt {
    fn new() -> Result<Self, OAuthError> {
        Ok(Self {
            verifier_material: draw_security_identifier().map_err(|_| OAuthError::RandomSourceUnavailable)?,
            state_key: draw_hmac_sha256_key().map_err(|_| OAuthError::RandomSourceUnavailable)?,
        })
    }

    fn verifier(&self) -> String {
        // 64 unreserved ASCII characters carrying 256 independent random bits.
        hex(self.verifier_material.as_bytes())
    }

    fn state(&self) -> Result<String, OAuthError> {
        self.state_key
            .authenticate_bounded(STATE_DOMAIN, STATE_DOMAIN.len())
            .map(|tag| hex(tag.as_bytes()))
            .map_err(|_| OAuthError::InvalidConfiguration)
    }

    fn accepts_state(&self, state: &str) -> bool {
        let Some(bytes) = decode_state(state) else { return false };
        self.state_key
            .verify_bounded(STATE_DOMAIN, STATE_DOMAIN.len(), &HmacSha256Tag::from_bytes(bytes))
            .is_ok()
    }

    fn authorization_url(
        &self,
        config: &OAuthClientConfiguration,
        redirect_uri: &str,
    ) -> Result<CanonicalHttpUrl, OAuthError> {
        let state = self.state()?;
        let challenge = pkce_challenge(&self.verifier())?;
        let scopes = config.scopes.join(" ");
        let mut fields = vec![
            ("response_type", "code"),
            ("client_id", config.client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("resource", config.resource.as_str()),
            ("state", state.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ];
        if !scopes.is_empty() {
            fields.push(("scope", scopes.as_str()));
        }
        let query = encode_form(&fields)?;
        CanonicalHttpUrl::parse(&format!("{}?{query}", config.authorization_endpoint.as_str()))
            .map_err(|_| OAuthError::InvalidConfiguration)
    }
}

async fn bind_loopback() -> Result<TcpListener, OAuthError> {
    let ipv4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    if let Ok(listener) = TcpListener::bind(ipv4).await {
        return Ok(listener);
    }
    let ipv6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
    TcpListener::bind(ipv6).await.map_err(|_| OAuthError::CallbackBindFailed)
}

fn operation_deadline(cx: &Cx, timeout: Duration) -> Result<Time, OAuthError> {
    if cx.checkpoint().is_err() { return Err(OAuthError::Cancelled); }
    if cx.timer_driver().is_none() { return Err(OAuthError::RuntimeTimerUnavailable); }
    let nanos = u64::try_from(timeout.as_nanos()).map_err(|_| OAuthError::InvalidConfiguration)?;
    let end = cx.now().as_nanos().checked_add(nanos).ok_or(OAuthError::InvalidConfiguration)?;
    let end = cx.budget().deadline.map_or(Time::from_nanos(end), |parent| parent.min(Time::from_nanos(end)));
    if cx.now() >= end { return Err(OAuthError::TimedOut); }
    Ok(end)
}

async fn within<T>(
    cx: &Cx,
    deadline: Time,
    future: impl Future<Output = Result<T, OAuthError>>,
) -> Result<T, OAuthError> {
    let deadline = cx.budget().deadline.map_or(deadline, |parent| parent.min(deadline));
    let mut future = std::pin::pin!(future);
    let mut sleep = std::pin::pin!(Sleep::new(deadline));
    // A pending cancel-correct receive registers a cancellation wake even when
    // the socket or the host's browser future has no traffic of its own.
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancelled = std::pin::pin!(receiver.recv(cx));
    poll_fn(|task| {
        if cx.checkpoint().is_err() { return Poll::Ready(Err(OAuthError::Cancelled)); }
        if cx.now() >= deadline { return Poll::Ready(Err(OAuthError::TimedOut)); }
        // Install the caller only for this poll, never across an await/yield.
        let _caller = Cx::set_current(Some(cx.clone()));
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(OAuthError::Cancelled));
        }
        if sleep.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(OAuthError::TimedOut));
        }
        let result = future.as_mut().poll(task);
        if cx.checkpoint().is_err() { return Poll::Ready(Err(OAuthError::Cancelled)); }
        if cx.now() >= deadline { return Poll::Ready(Err(OAuthError::TimedOut)); }
        result
    }).await
}

async fn wait_for_code(
    cx: &Cx,
    deadline: Time,
    listener: &TcpListener,
    address: SocketAddr,
    attempt: &AuthorizationAttempt,
    config: &OAuthClientConfiguration,
) -> Result<String, OAuthError> {
    for _ in 0..MAX_CALLBACK_CONNECTIONS {
        let (mut stream, peer) = within(cx, deadline, async {
            listener.accept().await.map_err(|_| OAuthError::CallbackRejected)
        }).await?;
        if !peer.ip().is_loopback() { return Err(OAuthError::CallbackRejected); }
        let read_deadline = deadline.min(operation_deadline(cx, CALLBACK_READ_TIMEOUT)?);
        let head = within(cx, read_deadline, read_callback_head(&mut stream)).await;
        let outcome = head.and_then(|head| admit_callback(&head, address, attempt, &config.issuer));
        let accepted = outcome.is_ok();
        let response = callback_response(accepted);
        // The browser sees only receipt, not a false claim that token redemption
        // succeeded. A failed write does not erase an already-admitted callback.
        let write_deadline = deadline.min(operation_deadline(cx, Duration::from_secs(1))?);
        let _ = within(cx, write_deadline, async {
            stream.write_all(response.as_bytes()).await.map_err(|_| OAuthError::CallbackRejected)
        }).await;
        match outcome {
            Ok(code) => return Ok(code),
            Err(OAuthError::CallbackRejected | OAuthError::TimedOut) => {},
            Err(error) => return Err(error),
        }
    }
    Err(OAuthError::CallbackLimitExceeded)
}

async fn read_callback_head(stream: &mut TcpStream) -> Result<Vec<u8>, OAuthError> {
    let mut head = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let count = stream.read(&mut chunk).await.map_err(|_| OAuthError::CallbackRejected)?;
        if count == 0 || count > MAX_CALLBACK_BYTES.saturating_sub(head.len()) {
            return Err(OAuthError::CallbackRejected);
        }
        head.extend_from_slice(&chunk[..count]);
        if head.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(head);
        }
    }
}

fn admit_callback(
    head: &[u8],
    address: SocketAddr,
    attempt: &AuthorizationAttempt,
    issuer: &str,
) -> Result<String, OAuthError> {
    if head.len() > MAX_CALLBACK_BYTES { return Err(OAuthError::CallbackRejected); }
    let head = std::str::from_utf8(head).map_err(|_| OAuthError::CallbackRejected)?;
    let Some(headers) = head.strip_suffix("\r\n\r\n") else { return Err(OAuthError::CallbackRejected) };
    let mut lines = headers.split("\r\n");
    let mut request = lines.next().ok_or(OAuthError::CallbackRejected)?.split(' ');
    if request.next() != Some("GET") { return Err(OAuthError::CallbackRejected); }
    let target = request.next().ok_or(OAuthError::CallbackRejected)?;
    if request.next() != Some("HTTP/1.1") || request.next().is_some()
        || target.bytes().any(|b| !(0x21..=0x7e).contains(&b)) || target.contains('#')
    { return Err(OAuthError::CallbackRejected); }
    let (path, query) = target.split_once('?').ok_or(OAuthError::CallbackRejected)?;
    if path != CALLBACK_PATH { return Err(OAuthError::CallbackRejected); }
    let mut host = None;
    let mut content_length = false;
    for (index, line) in lines.enumerate() {
        if index >= 64 { return Err(OAuthError::CallbackRejected); }
        let (name, value) = line.split_once(':').ok_or(OAuthError::CallbackRejected)?;
        if !AccessToken::is_valid_http_scheme(name)
            || value.bytes().any(|b| b == 0x7f || (b < 0x20 && b != b'\t'))
        { return Err(OAuthError::CallbackRejected); }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value).is_some() { return Err(OAuthError::CallbackRejected); }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(OAuthError::CallbackRejected);
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length || value != "0" { return Err(OAuthError::CallbackRejected); }
            content_length = true;
        }
    }
    if host != Some(address.to_string().as_str()) { return Err(OAuthError::CallbackRejected); }
    let fields = decode_form(query)?;
    if !fields.get("state").is_some_and(|state| attempt.accepts_state(state)) {
        return Err(OAuthError::CallbackRejected);
    }
    if fields.get("iss").map(String::as_str) != Some(issuer) {
        return Err(OAuthError::IssuerMismatch);
    }
    match (fields.get("code"), fields.get("error")) {
        (None, Some(error)) if valid_opaque(error, 256) => Err(OAuthError::AuthorizationDenied),
        (Some(code), None) if valid_opaque(code, MAX_CODE_BYTES) => Ok(code.clone()),
        _ => Err(OAuthError::CallbackRejected),
    }
}

fn callback_response(accepted: bool) -> String {
    let (status, body) = if accepted {
        ("200 OK", "Authorization response received. Return to the application.")
    } else {
        ("400 Bad Request", "Authorization response rejected.")
    };
    format!("HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nPragma: no-cache\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'\r\nConnection: close\r\n\r\n{body}", body.len())
}

fn valid_opaque(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

fn validate_scopes(scopes: &[String]) -> Result<(), OAuthError> {
    if scopes.len() > 32 || scopes.iter().map(String::len).sum::<usize>() > 4096 {
        return Err(OAuthError::InvalidTokenResponse);
    }
    let mut seen = BTreeSet::new();
    for scope in scopes {
        if scope.is_empty() || scope.len() > 256 || !seen.insert(scope.as_str())
            || !scope.bytes().all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
        { return Err(OAuthError::InvalidTokenResponse); }
    }
    Ok(())
}

fn encode_form(fields: &[(&str, &str)]) -> Result<String, OAuthError> {
    let mut output = String::new();
    for (index, (name, value)) in fields.iter().enumerate() {
        if index > 0 { output.push('&'); }
        for (part_index, part) in [*name, *value].into_iter().enumerate() {
            if part_index == 1 { output.push('='); }
            for byte in part.bytes() {
                if output.len() > MAX_FORM_BYTES - 3 { return Err(OAuthError::InvalidConfiguration); }
                match byte {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => output.push(char::from(byte)),
                    b' ' => output.push('+'),
                    _ => {
                        const HEX: &[u8; 16] = b"0123456789ABCDEF";
                        output.push('%');
                        output.push(char::from(HEX[usize::from(byte >> 4)]));
                        output.push(char::from(HEX[usize::from(byte & 15)]));
                    }
                }
            }
        }
    }
    Ok(output)
}

fn decode_form(query: &str) -> Result<BTreeMap<String, String>, OAuthError> {
    if query.len() > MAX_CALLBACK_BYTES { return Err(OAuthError::CallbackRejected); }
    let mut fields = BTreeMap::new();
    for (index, field) in query.split('&').enumerate() {
        if index >= MAX_FORM_FIELDS { return Err(OAuthError::CallbackRejected); }
        let (key, value) = field.split_once('=').ok_or(OAuthError::CallbackRejected)?;
        let key = decode_component(key)?;
        let value = decode_component(value)?;
        if key.is_empty() || key.len() > 128 || value.len() > MAX_CODE_BYTES
            || fields.insert(key, value).is_some()
        { return Err(OAuthError::CallbackRejected); }
    }
    Ok(fields)
}

fn decode_component(input: &str) -> Result<String, OAuthError> {
    let mut decoded = Vec::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(byte) = bytes.next() {
        let byte = match byte {
            b'+' => b' ',
            b'%' => {
                let high = bytes.next().and_then(hex_digit).ok_or(OAuthError::CallbackRejected)?;
                let low = bytes.next().and_then(hex_digit).ok_or(OAuthError::CallbackRejected)?;
                (high << 4) | low
            }
            byte => byte,
        };
        if byte.is_ascii_control() { return Err(OAuthError::CallbackRejected); }
        decoded.push(byte);
    }
    String::from_utf8(decoded).map_err(|_| OAuthError::CallbackRejected)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 15)]));
    }
    encoded
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_state(state: &str) -> Option<[u8; 32]> {
    if state.len() != 64 || !state.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f')) {
        return None;
    }
    let mut decoded = [0; 32];
    for (index, pair) in state.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Some(decoded)
}

fn pkce_challenge(verifier: &str) -> Result<String, OAuthError> {
    if !(43..=128).contains(&verifier.len())
        || !verifier.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    { return Err(OAuthError::InvalidConfiguration); }
    let digest = sha256_bounded(verifier.as_bytes(), 128).map_err(|_| OAuthError::InvalidConfiguration)?;
    // The only Base64 input here is the fixed-width SHA-256 digest, not an
    // extensible codec. Emit the RFC 7636 URL-safe alphabet without padding.
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(43);
    let mut accumulator = 0_u32;
    let mut bits = 0;
    for byte in digest.as_bytes() {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            output.push(char::from(ALPHABET[((accumulator >> bits) & 63) as usize]));
        }
        accumulator &= (1 << bits) - 1;
    }
    if bits != 0 { output.push(char::from(ALPHABET[((accumulator << (6 - bits)) & 63) as usize])); }
    Ok(output)
}

fn validate_token_headers(headers: &[(String, String)]) -> Result<(), OAuthError> {
    let mut content_type = None;
    let mut encoding = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-type") {
            if content_type.replace(value.as_str()).is_some() { return Err(OAuthError::InvalidTokenResponse); }
        }
        if name.eq_ignore_ascii_case("content-encoding") {
            if encoding || !value.trim().eq_ignore_ascii_case("identity") { return Err(OAuthError::InvalidTokenResponse); }
            encoding = true;
        }
    }
    let value = content_type.ok_or(OAuthError::InvalidTokenResponse)?;
    let mut parts = value.split(';');
    if !parts.next().is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json")) {
        return Err(OAuthError::InvalidTokenResponse);
    }
    if let Some(parameter) = parts.next() {
        let (name, value) = parameter.trim().split_once('=').ok_or(OAuthError::InvalidTokenResponse)?;
        if !name.trim().eq_ignore_ascii_case("charset")
            || !value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8") || parts.next().is_some()
        { return Err(OAuthError::InvalidTokenResponse); }
    }
    Ok(())
}

fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where D: Deserializer<'de>, T: Deserialize<'de> {
    // `default` is absence; a present JSON null must not become absence.
    T::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    #[serde(default, deserialize_with = "present")]
    expires_in: Option<u64>,
    #[serde(default, deserialize_with = "present")]
    scope: Option<String>,
    #[serde(default, deserialize_with = "present")]
    refresh_token: Option<String>,
    #[serde(default, deserialize_with = "present")]
    resource: Option<String>,
    #[serde(default, deserialize_with = "present")]
    error: Option<String>,
}

fn admit_token_response(
    configuration: &OAuthClientConfiguration,
    scope_ceiling: &[String],
    bytes: &[u8],
    started: Instant,
) -> Result<OAuthCredentials, OAuthError> {
    if bytes.len() > MAX_TOKEN_RESPONSE_BYTES { return Err(OAuthError::InvalidTokenResponse); }
    let response: TokenResponse = serde_json::from_slice(bytes).map_err(|_| OAuthError::InvalidTokenResponse)?;
    if !response.token_type.eq_ignore_ascii_case("Bearer")
        || !AccessToken::is_valid_token68(&response.access_token)
        || response.refresh_token.as_ref().is_some_and(|token| !valid_opaque(token, MAX_CODE_BYTES))
        || response.resource.as_ref().is_some_and(|resource| resource != configuration.resource.as_str())
        || response.error.is_some()
    { return Err(OAuthError::InvalidTokenResponse); }
    let scopes = response.scope.map_or_else(|| scope_ceiling.to_vec(), |scope| scope.split(' ').map(str::to_owned).collect());
    validate_scopes(&scopes)?;
    if scopes.iter().any(|scope| !scope_ceiling.contains(scope)) { return Err(OAuthError::ScopeExpansion); }
    let lifetime = response.expires_in.map_or(configuration.max_access_token_lifetime, |seconds| {
        Duration::from_secs(seconds).min(configuration.max_access_token_lifetime)
    });
    let expires_at = started.checked_add(lifetime).ok_or(OAuthError::InvalidTokenResponse)?;
    if Instant::now() >= expires_at { return Err(OAuthError::ExpiredCredential); }
    let access = BoundBearerCredential::bind_with_expiry(configuration.resource.clone(), response.access_token, expires_at)
        .map_err(|_| OAuthError::InvalidTokenResponse)?;
    Ok(OAuthCredentials {
        configuration: configuration.clone(), access,
        refresh_token: response.refresh_token, scopes, expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }

    fn config() -> OAuthClientConfiguration {
        OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example", url("https://issuer.example/authorize"),
            url("https://issuer.example/token"), url("https://mcp.example/mcp"),
            "native-client", vec!["tools:read".to_owned(), "tools:write".to_owned()],
        ).unwrap()
    }

    fn wire(attempt: &AuthorizationAttempt, issuer: &str, extra: &str) -> Vec<u8> {
        let query = encode_form(&[("state", &attempt.state().unwrap()), ("iss", issuer), ("code", "code+/%")]).unwrap();
        format!("GET {CALLBACK_PATH}?{query}{extra} HTTP/1.1\r\nHost: 127.0.0.1:43210\r\n\r\n").into_bytes()
    }

    #[test]
    fn pkce_matches_rfc_7636_appendix_b_without_plain_fallback() {
        assert_eq!(pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assert!(pkce_challenge("too-short").is_err());
        let first = AuthorizationAttempt::new().unwrap();
        let second = AuthorizationAttempt::new().unwrap();
        assert_eq!(first.verifier().len(), 64);
        assert_ne!(first.verifier(), second.verifier());
        assert!(first.accepts_state(&first.state().unwrap()));
        assert!(!second.accepts_state(&first.state().unwrap()));
        let target = first.authorization_url(&config(), "http://127.0.0.1:43210/oauth/callback").unwrap();
        assert!(target.as_str().contains("code_challenge_method=S256"));
        assert!(!target.as_str().contains(&first.verifier()));
        let fields = decode_form(target.as_str().split_once('?').unwrap().1).unwrap();
        assert_eq!(fields["resource"], "https://mcp.example/mcp");
        assert_eq!(fields["redirect_uri"], "http://127.0.0.1:43210/oauth/callback");
    }

    #[test]
    fn callback_requires_matching_state_issuer_host_and_one_code() {
        let attempt = AuthorizationAttempt::new().unwrap();
        let address = "127.0.0.1:43210".parse().unwrap();
        let request = wire(&attempt, &config().issuer, "");
        assert_eq!(admit_callback(&request, address, &attempt, &config().issuer).unwrap(), "code+/%");
        let other = AuthorizationAttempt::new().unwrap();
        assert_eq!(admit_callback(&request, address, &other, &config().issuer), Err(OAuthError::CallbackRejected));
        assert_eq!(admit_callback(&request, address, &attempt, "https://different.example"), Err(OAuthError::IssuerMismatch));
        for suffix in ["&code=second", "&co%64e=second", "&error=access_denied", "&state=other", "&unknown=%ff"] {
            assert!(admit_callback(&wire(&attempt, &config().issuer, suffix), address, &attempt, &config().issuer).is_err());
        }
        for (from, to) in [("Host: 127.0.0.1:43210", "Host: evil.example"), ("GET /oauth/callback?", "GET /other?"), ("\r\n\r\n", "\r\nContent-Length: 1\r\n\r\nx"), ("\r\n\r\n", "\r\nHost: 127.0.0.1:43210\r\n\r\n")] {
            let changed = String::from_utf8(request.clone()).unwrap().replace(from, to);
            assert!(admit_callback(changed.as_bytes(), address, &attempt, &config().issuer).is_err());
        }
        let response = callback_response(true);
        assert!(!response.contains("code+/%"));
        assert!(!response.contains(&attempt.state().unwrap()));
        assert!(response.contains("Cache-Control: no-store"));
    }

    #[test]
    fn token_admission_binds_resource_scopes_and_expiry() {
        let config = config();
        let now = Instant::now();
        let grant = admit_token_response(&config, &config.scopes,
            br#"{"access_token":"access-secret","token_type":"Bearer","expires_in":60,"refresh_token":"refresh-secret","scope":"tools:read"}"#, now).unwrap();
        assert_eq!(grant.scopes(), &["tools:read".to_owned()]);
        assert!(grant.has_refresh_token());
        assert_eq!(grant.expires_at(), now + Duration::from_secs(60));
        assert!(grant.bearer_credential().authorization_for_target(&config.resource).is_some());
        assert!(grant.bearer_credential().authorization_for_target(&url("https://issuer.example/token")).is_none());
        for invalid in [
            r#"{"access_token":"access-secret","token_type":"Basic"}"#,
            r#"{"access_token":"access-secret","token_type":"Bearer","expires_in":0}"#,
            r#"{"access_token":"access-secret","token_type":"Bearer","expires_in":null}"#,
            r#"{"access_token":"access-secret","token_type":"Bearer","scope":"admin"}"#,
            r#"{"access_token":"access-secret","token_type":"Bearer","resource":"https://wrong.example/mcp"}"#,
            r#"{"access_token":"first","access_token":"second","token_type":"Bearer"}"#,
            r#"{"access_token":"access-secret","token_type":"Bearer","refresh_token":null}"#,
        ] {
            let error = admit_token_response(&config, &config.scopes, invalid.as_bytes(), now).err().unwrap();
            assert!(!format!("{error:?} {error}").contains("access-secret"));
        }
    }

    #[test]
    fn native_configuration_rejects_cleartext_endpoints_and_scope_ambiguity() {
        let template = config();
        for endpoint in ["http://127.0.0.1/token", "https://issuer.example/token?key=value"] {
            assert!(OAuthClientConfiguration::from_trusted_endpoints(
                template.issuer.clone(), template.authorization_endpoint.clone(), url(endpoint),
                template.resource.clone(), template.client_id.clone(), template.scopes.clone(),
            ).is_err());
        }
        for scopes in [vec!["duplicate".to_owned(); 2], vec!["two scopes".to_owned()], vec!["".to_owned()]] {
            assert!(validate_scopes(&scopes).is_err());
        }
        assert!(template.clone().with_authorization_timeout(Duration::ZERO).is_err());
        assert!(template.with_max_access_token_lifetime(Duration::from_secs(86_401)).is_err());
    }

    #[test]
    fn token_media_admission_does_not_follow_or_decode_other_representations() {
        let valid = vec![("Content-Type".to_owned(), "application/json; charset=utf-8".to_owned())];
        assert!(validate_token_headers(&valid).is_ok());
        let mut duplicate = valid.clone();
        duplicate.push(("content-type".to_owned(), "application/json".to_owned()));
        assert!(validate_token_headers(&duplicate).is_err());
        let mut coded = valid;
        coded.push(("Content-Encoding".to_owned(), "gzip".to_owned()));
        assert!(validate_token_headers(&coded).is_err());
        assert!(validate_token_headers(&[]).is_err());
        assert!(decode_form("state=one&st%61te=two").is_err());
        assert!(decode_form("code=%00").is_err());
        assert!(decode_form("code=%").is_err());
    }

    #[test]
    fn live_loopback_accepts_only_the_matching_attempt_and_releases_the_listener() {
        asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::for_request();
            let deadline = operation_deadline(&cx, Duration::from_secs(10)).unwrap();
            let listener = within(&cx, deadline, bind_loopback()).await.unwrap();
            let address = listener.local_addr().unwrap();
            assert!(address.ip().is_loopback());
            let attempt = AuthorizationAttempt::new().unwrap();
            let impostor = AuthorizationAttempt::new().unwrap();
            let config = config();

            // Both peers use real sockets and the exact production parser.
            // Only the state changes; the forged attempt cannot supply a code.
            let mut peers = Vec::new();
            for current in [&impostor, &attempt] {
                let query = encode_form(&[("state", &current.state().unwrap()), ("iss", &config.issuer), ("code", "live-code")]).unwrap();
                let request = format!("GET {CALLBACK_PATH}?{query} HTTP/1.1\r\nHost: {address}\r\n\r\n");
                let mut peer = within(&cx, deadline, async {
                    TcpStream::connect(address).await.map_err(|_| OAuthError::CallbackRejected)
                }).await.unwrap();
                within(&cx, deadline, async {
                    peer.write_all(request.as_bytes()).await.map_err(|_| OAuthError::CallbackRejected)
                }).await.unwrap();
                peers.push(peer);
            }
            let code = wait_for_code(&cx, deadline, &listener, address, &attempt, &config).await.unwrap();
            assert_eq!(code, "live-code");
            for (index, mut peer) in peers.into_iter().enumerate() {
                let mut reply = Vec::new();
                within(&cx, deadline, async {
                    peer.read_to_end(&mut reply).await.map_err(|_| OAuthError::CallbackRejected)
                }).await.unwrap();
                let reply = String::from_utf8(reply).unwrap();
                assert!(reply.starts_with(if index == 0 { "HTTP/1.1 400" } else { "HTTP/1.1 200" }));
                assert!(!reply.contains("live-code"));
            }
            drop(listener);
            assert!(within(&cx, deadline, async {
                TcpStream::connect(address).await.map_err(|_| OAuthError::CallbackRejected)
            }).await.is_err());
        });
    }

    #[test]
    fn callback_deadline_releases_idle_work_without_needing_peer_traffic() {
        asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::for_request();
            let setup_deadline = operation_deadline(&cx, Duration::from_secs(10)).unwrap();
            let listener = within(&cx, setup_deadline, bind_loopback()).await.unwrap();
            let address = listener.local_addr().unwrap();
            let attempt = AuthorizationAttempt::new().unwrap();
            let deadline = operation_deadline(&cx, Duration::from_millis(20)).unwrap();
            let outcome = wait_for_code(&cx, deadline, &listener, address, &attempt, &config()).await;
            assert_eq!(outcome, Err(OAuthError::TimedOut));
            drop(listener);
            assert!(within(&cx, setup_deadline, async {
                TcpStream::connect(address).await.map_err(|_| OAuthError::CallbackRejected)
            }).await.is_err());
        });
    }

    fn renewable_grant(config: &OAuthClientConfiguration) -> OAuthCredentials {
        admit_token_response(config, &config.scopes,
            br#"{"access_token":"access-one","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-one"}"#,
            Instant::now(),
        ).unwrap()
    }

    #[test]
    fn refresh_rotation_replaces_the_pair_and_preserves_a_narrowed_scope_ceiling() {
        let config = config();
        let client = OAuthClient::new(config.clone());
        let mut grant = renewable_grant(&config);
        let (body, previous) = client.prepare_refresh(&mut grant).unwrap();
        let fields = decode_form(&body).unwrap();
        assert_eq!(fields["grant_type"], "refresh_token");
        assert_eq!(fields["refresh_token"], "refresh-one");
        assert_eq!(fields["resource"], "https://mcp.example/mcp");
        assert!(!fields.contains_key("code_verifier"));
        assert!(!grant.has_refresh_token());
        let replacement = client.admit_refresh(&grant, previous,
            br#"{"access_token":"access-two","token_type":"Bearer","expires_in":120,"refresh_token":"refresh-two","scope":"tools:read"}"#,
            Instant::now(),
        ).unwrap();
        grant = replacement;
        assert_eq!(grant.access.authorization_for_target(&config.resource), Some("Bearer access-two".to_owned()));
        let (body, previous) = client.prepare_refresh(&mut grant).unwrap();
        let fields = decode_form(&body).unwrap();
        assert_eq!(fields["refresh_token"], "refresh-two");
        assert_eq!(fields["scope"], "tools:read");
        let invalid = client.admit_refresh(&grant, previous,
            br#"{"access_token":"access-three","token_type":"Bearer","scope":"tools:write"}"#,
            Instant::now(),
        );
        assert_eq!(invalid.err(), Some(OAuthError::ScopeExpansion));
        assert!(!grant.has_refresh_token());
        assert_eq!(grant.access.authorization_for_target(&config.resource), Some("Bearer access-two".to_owned()));
    }

    #[test]
    fn refresh_without_rotation_retains_the_previous_token_only_after_valid_admission() {
        let config = config();
        let client = OAuthClient::new(config.clone());
        let mut grant = renewable_grant(&config);
        let (_, previous) = client.prepare_refresh(&mut grant).unwrap();
        let replacement = client.admit_refresh(&grant, previous,
            br#"{"access_token":"access-two","token_type":"Bearer","expires_in":120}"#,
            Instant::now(),
        ).unwrap();
        assert_eq!(replacement.refresh_token.as_deref(), Some("refresh-one"));
        assert_eq!(replacement.scopes, config.scopes);
    }

    #[test]
    fn refresh_preflight_refuses_cross_binding_without_consuming_any_credential() {
        let config = config();
        let mut grant = renewable_grant(&config);
        let access_before = grant.access.authorization_for_target(&config.resource);
        let expiry_before = grant.expires_at;
        for dimension in 0..5 {
            let mut other = config.clone();
            match dimension {
                0 => other.issuer = "https://other.example".to_owned(),
                1 => other.token_endpoint = url("https://other.example/token"),
                2 => other.resource = url("https://other.example/mcp"),
                3 => other.client_id = "another-client".to_owned(),
                _ => other.max_access_token_lifetime = Duration::from_secs(1),
            }
            assert_eq!(OAuthClient::new(other).prepare_refresh(&mut grant).err(), Some(OAuthError::CredentialBindingMismatch));
            assert_eq!(grant.refresh_token.as_deref(), Some("refresh-one"));
            assert_eq!(grant.access.authorization_for_target(&config.resource), access_before);
            assert_eq!(grant.expires_at, expiry_before);
        }
    }

    #[test]
    fn abandoned_refresh_custody_cannot_replay_the_previous_refresh_token() {
        let config = config();
        let client = OAuthClient::new(config.clone());
        let mut grant = renewable_grant(&config);
        let access_before = grant.access.authorization_for_target(&config.resource);
        let expiry_before = grant.expires_at;
        // The transport owns the body and previous token after this point.
        // Losing that future has the same ownership outcome as a lost reply.
        drop(client.prepare_refresh(&mut grant).unwrap());
        assert_eq!(client.prepare_refresh(&mut grant).err(), Some(OAuthError::RefreshUnavailable));
        assert_eq!(grant.access.authorization_for_target(&config.resource), access_before);
        assert_eq!(grant.expires_at, expiry_before);
        assert!(!grant.has_refresh_token());
    }
}
