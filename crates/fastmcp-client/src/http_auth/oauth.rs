//! Interactive OAuth authorization for explicitly configured public clients.
//!
//! The caller supplies trusted issuer/endpoint configuration and the browser
//! launcher. The driver binds an IP-literal loopback listener *before* invoking
//! that launcher, admits one issuer- and state-bound callback, and redeems its
//! code with S256 PKCE over HTTPS. Hosts with an independently registered HTTPS
//! callback can instead supply a driver that returns their raw callback URL.
//! Both paths create no runtime or background task.
//!
//! This is the preregistered public-client slice of AUTH-07, not discovery,
//! dynamic registration or OIDC authentication. The Linux `persistence` adapter
//! connects refresh grants to caller-supplied durable protection and independently
//! anchored storage; it does not qualify those deployment providers. Credential
//! and parsed token-response types omit serialization and diagnostic formatting.

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
use fastmcp_core::{
    AccessToken, CanonicalResourceId, CanonicalResourceIdPolicy, McpRequestCancellation,
};
use fastmcp_protocol::{SecurityDocumentKind, admit_security_document};
use serde::{Deserialize, Deserializer};

use super::caller::with_caller;
use super::{BoundBearerCredential, CanonicalHttpUrl};

/// Anchored refresh-grant custody and native renewal after a Linux file reopen.
#[cfg(target_os = "linux")]
pub mod persistence;
/// RFC 7009 remote token revocation for explicitly trusted native clients.
pub mod revocation;

const CALLBACK_PATH: &str = "/oauth/callback";
const STATE_DOMAIN: &[u8] = b"fastmcp/oauth-loopback-state/v1\0";
const MAX_CALLBACK_BYTES: usize = 16 * 1024;
const MAX_CALLBACK_CONNECTIONS: usize = 32;
const MAX_FORM_FIELDS: usize = 32;
const MAX_CODE_BYTES: usize = 4096;
const MAX_TOKEN_RESPONSE_BYTES: usize = SecurityDocumentKind::TokenResponse.byte_limit();
const MAX_FORM_BYTES: usize = 64 * 1024;
const CALLBACK_READ_TIMEOUT: Duration = Duration::from_secs(5);
const TOKEN_TIMEOUT: Duration = Duration::from_secs(30);

/// Sanitized errors. No variant retains a code, token, callback URL, response
/// body, or a third-party transport error that could reflect credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthError {
    InvalidConfiguration,
    RuntimeTimerUnavailable,
    RuntimeCapabilityUnavailable,
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
            Self::RuntimeCapabilityUnavailable => {
                "OAuth requires the caller's I/O and entropy authority"
            }
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
            Self::CredentialBindingMismatch => {
                "OAuth credential belongs to a different client binding"
            }
            Self::RefreshUnavailable => "OAuth credential has no reusable refresh token",
        })
    }
}

impl std::error::Error for OAuthError {}

/// The resource-identifier policy for a configured MCP endpoint. An endpoint
/// at the origin root (`https://mcp.example.com`, a canonical server URI MCP
/// lists as valid) needs the root policy; every other endpoint keeps the safe
/// non-root, no-trailing-slash default.
pub(crate) fn endpoint_resource_policy(resource: &CanonicalHttpUrl) -> CanonicalResourceIdPolicy {
    if resource.path() == "/" {
        CanonicalResourceIdPolicy::root_endpoint()
    } else {
        CanonicalResourceIdPolicy::DEFAULT
    }
}

/// Immutable, administrator-supplied configuration for a public OAuth client.
/// Native loopback authorization requires registration of `/oauth/callback`
/// on an IP-literal loopback URI with an ephemeral port. Host-owned redirect
/// authorization requires its separately registered exact HTTPS callback.
/// The authorization server must return RFC 9207 `iss` on both successful and
/// unsuccessful callbacks. Neither path authenticates a confidential client.
///
/// This constructor does not establish trust in URLs obtained from a peer.
/// Discovery and registration must be validated before constructing this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthClientConfiguration {
    issuer: String,
    authorization_endpoint: CanonicalHttpUrl,
    token_endpoint: CanonicalHttpUrl,
    revocation_endpoint: Option<CanonicalHttpUrl>,
    resource: CanonicalHttpUrl,
    client_id: String,
    scopes: Vec<String>,
    authorization_timeout: Duration,
    max_access_token_lifetime: Duration,
    extra_root_certificates: Vec<Vec<u8>>,
    resource_tls: Option<crate::http_executor::ResourceTlsTrust>,
    // Stable, domain-separated digest of the admitted ordered resource roots.
    // Updated only after ResourceTlsTrust admission succeeds; persistent OAuth
    // bindings must not depend on Debug output or duplicate all DER buffers.
    resource_tls_fingerprint: Option<[u8; 32]>,
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
        let issuer_url =
            CanonicalHttpUrl::parse(&issuer).map_err(|_| OAuthError::InvalidConfiguration)?;
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
        if issuer.len() > 4096 || issuer.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(OAuthError::InvalidConfiguration);
        }
        if resource.scheme() != "https" {
            return Err(OAuthError::InvalidConfiguration);
        }
        CanonicalResourceId::parse_for_endpoint(
            resource.as_str(),
            &resource,
            endpoint_resource_policy(&resource),
        )
        .map_err(|_| OAuthError::InvalidConfiguration)?;
        let client_id = client_id.into();
        if client_id.is_empty() || client_id.len() > 1024 || client_id.chars().any(char::is_control)
        {
            return Err(OAuthError::InvalidConfiguration);
        }
        validate_scopes(&scopes).map_err(|_| OAuthError::InvalidConfiguration)?;
        Ok(Self {
            issuer,
            authorization_endpoint,
            token_endpoint,
            revocation_endpoint: None,
            resource,
            client_id,
            scopes,
            authorization_timeout: Duration::from_secs(300),
            max_access_token_lifetime: Duration::from_secs(3600),
            extra_root_certificates: Vec::new(),
            resource_tls: None,
            resource_tls_fingerprint: None,
        })
    }

    /// Sets the single deadline covering bind, browser launch, callbacks and
    /// redemption. Callback traffic cannot reset it. The caller's budget may
    /// further shorten it.
    pub fn with_authorization_timeout(mut self, timeout: Duration) -> Result<Self, OAuthError> {
        if timeout.is_zero() || timeout > Duration::from_mins(15) {
            return Err(OAuthError::InvalidConfiguration);
        }
        self.authorization_timeout = timeout;
        Ok(self)
    }

    /// Sets a local upper bound on access-token reuse, including responses
    /// omitting `expires_in`. This is a client safety limit, not an assertion
    /// about the issuer's actual expiration policy.
    pub fn with_max_access_token_lifetime(
        mut self,
        lifetime: Duration,
    ) -> Result<Self, OAuthError> {
        if lifetime.is_zero() || lifetime > Duration::from_hours(24) {
            return Err(OAuthError::InvalidConfiguration);
        }
        self.max_access_token_lifetime = lifetime;
        Ok(self)
    }

    /// Adds an explicitly trusted private CA for this client's token endpoint.
    /// This does not disable hostname/certificate verification or alter the
    /// host's browser trust store. The exact root bytes become part of the
    /// immutable credential binding, so refresh cannot switch trust policies.
    pub fn with_extra_root_certificate(
        mut self,
        certificate: asupersync::tls::Certificate,
    ) -> Result<Self, OAuthError> {
        let der = certificate.as_der();
        if der.is_empty()
            || der.len() > 16 * 1024
            || self.extra_root_certificates.len() >= 8
            || self
                .extra_root_certificates
                .iter()
                .any(|existing| existing.as_slice() == der)
        {
            return Err(OAuthError::InvalidConfiguration);
        }
        asupersync::tls::RootCertStore::empty()
            .add(&certificate)
            .map_err(|_| OAuthError::InvalidConfiguration)?;
        self.extra_root_certificates.push(der.to_vec());
        Ok(self)
    }

    /// Adds a private CA for this configuration's exact MCP resource. Managed
    /// sessions retain this trust through login, refresh and protected POSTs.
    /// It does not grant trust to token endpoints or the host's browser.
    pub fn with_resource_root_certificate(
        mut self,
        certificate: asupersync::tls::Certificate,
    ) -> Result<Self, OAuthError> {
        let der = certificate.as_der();
        if der.is_empty() || der.len() > 16 * 1024 {
            return Err(OAuthError::InvalidConfiguration);
        }
        let mut binding = b"fastmcp/oauth-resource-tls/v1\0".to_vec();
        binding.extend_from_slice(&self.resource_tls_fingerprint.unwrap_or([0; 32]));
        binding.extend_from_slice(&(der.len() as u32).to_be_bytes());
        binding.extend_from_slice(der);
        let fingerprint = sha256_bounded(&binding, 16 * 1024 + 128)
            .map_err(|_| OAuthError::InvalidConfiguration)?
            .into_bytes();
        crate::http_executor::ResourceTlsTrust::add_root(
            &mut self.resource_tls,
            self.resource.clone(),
            certificate,
        )
        .map_err(|_| OAuthError::InvalidConfiguration)?;
        self.resource_tls_fingerprint = Some(fingerprint);
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

// Custody has already transferred when this guard is installed. A failure or
// abandoned future must retire access clones as well as the consumed refresh
// token. A successfully admitted rotation preserves existing access snapshots
// and their original expiry; managed renewal still watches that old signal.
struct RefreshFailureQuarantine {
    revoked: McpRequestCancellation,
    armed: bool,
}

impl RefreshFailureQuarantine {
    fn new(revoked: McpRequestCancellation) -> Self {
        Self {
            revoked,
            armed: true,
        }
    }

    fn complete(&mut self) {
        self.armed = false;
    }
}

impl Drop for RefreshFailureQuarantine {
    fn drop(&mut self) {
        if self.armed {
            self.revoked.cancel();
        }
    }
}

async fn while_refresh_live<T>(
    revoked: &McpRequestCancellation,
    operation: impl Future<Output = Result<T, OAuthError>>,
) -> Result<T, OAuthError> {
    let mut revoked_wait = std::pin::pin!(revoked.cancelled());
    let mut operation = std::pin::pin!(operation);
    poll_fn(|task| {
        if revoked.is_cancel_requested() || revoked_wait.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(OAuthError::RefreshUnavailable));
        }
        let result = operation.as_mut().poll(task);
        if revoked.is_cancel_requested() {
            Poll::Ready(Err(OAuthError::RefreshUnavailable))
        } else {
            result
        }
    })
    .await
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

    pub(crate) fn resource_http_executor(&self) -> crate::http_executor::ModernHttpExecutor {
        crate::http_executor::ModernHttpExecutor::new()
            .with_resource_tls(self.configuration.resource_tls.clone())
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
        // The supplied caller owns identity and drivers; it cannot restore an
        // effect that the surrounding host scope has withheld. Draw all pending
        // secrets before binding a listener, under that same effective ceiling.
        let attempt = with_caller(cx, || {
            if !Cx::current().is_some_and(|active| active.capabilities().entropy) {
                return Err(OAuthError::RuntimeCapabilityUnavailable);
            }
            AuthorizationAttempt::new()
        })?;
        let listener = within(cx, deadline, bind_loopback()).await?;
        let address = listener
            .local_addr()
            .map_err(|_| OAuthError::CallbackBindFailed)?;
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(OAuthError::CallbackBindFailed);
        }
        let redirect_uri = format!("http://{address}{CALLBACK_PATH}");
        let authorization_url = attempt.authorization_url(&self.configuration, &redirect_uri)?;
        within(cx, deadline, async {
            launch_browser(authorization_url)
                .await
                .map_err(|_| OAuthError::BrowserLaunchFailed)
        })
        .await?;
        let code = wait_for_code(
            cx,
            deadline,
            &listener,
            address,
            &attempt,
            &self.configuration,
        )
        .await?;
        // A callback can authorize only one POST. Close the listener before
        // redemption; neither a duplicate callback nor a network error retries it.
        drop(listener);
        self.redeem_authorization_code(cx, deadline, attempt, &redirect_uri, code)
            .await
    }

    /// Authorizes through one host-owned HTTPS callback route, without binding
    /// a loopback listener or installing a web framework.
    ///
    /// The host must independently register `redirect_uri` for this exact
    /// public client. It must be HTTPS, query/fragment-free and contain no
    /// userinfo; redirects to a different spelling, origin or path are refused.
    /// The driver receives the framework's state/S256/resource-bound launch URL
    /// once and returns the raw absolute callback URL received on that route.
    /// A web handler can deliver that URL through a channel owned by its driver
    /// future. Do not normalize, reconstruct, log or persist the callback or
    /// launch URL; the driver is part of the host's trusted computing base.
    ///
    /// One deadline covers the driver wait and code redemption. The caller's
    /// cancellation, a driver error or dropping this future discards the pending
    /// state and PKCE verifier. The host must keep its wait/registration cleanup
    /// owned by the returned future. A callback is consumed once: only exact
    /// route, state, issuer and code admission permit one token POST, and no
    /// transport failure, redirect or rejected response replays it. Success is
    /// returned only after ordinary issuer/resource-bound token admission.
    pub async fn authorize_with_redirect_driver<D, F>(
        &self,
        cx: &Cx,
        redirect_uri: CanonicalHttpUrl,
        driver: D,
    ) -> Result<OAuthCredentials, OAuthError>
    where
        D: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<String, OAuthError>>,
    {
        validate_host_redirect(&redirect_uri)?;
        let (deadline, attempt, authorization_url) = with_caller(cx, || {
            let caller = Cx::current().ok_or(OAuthError::RuntimeCapabilityUnavailable)?;
            if !caller.capabilities().time {
                return Err(OAuthError::RuntimeTimerUnavailable);
            }
            let deadline = operation_deadline(&caller, self.configuration.authorization_timeout)?;
            if !caller.capabilities().entropy {
                return Err(OAuthError::RuntimeCapabilityUnavailable);
            }
            let attempt = AuthorizationAttempt::new()?;
            let authorization_url =
                attempt.authorization_url(&self.configuration, redirect_uri.as_str())?;
            Ok((deadline, attempt, authorization_url))
        })?;
        let callback = within(cx, deadline, async { driver(authorization_url).await }).await?;
        let code = admit_host_redirect_callback(
            &callback,
            &redirect_uri,
            &attempt,
            &self.configuration.issuer,
        )?;
        self.redeem_authorization_code(cx, deadline, attempt, redirect_uri.as_str(), code)
            .await
    }

    async fn redeem_authorization_code(
        &self,
        cx: &Cx,
        deadline: Time,
        attempt: AuthorizationAttempt,
        redirect_uri: &str,
        code: String,
    ) -> Result<OAuthCredentials, OAuthError> {
        let verifier = attempt.verifier();
        let body = encode_form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &self.configuration.client_id),
            ("code", &code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &verifier),
            ("resource", self.configuration.resource.as_str()),
        ])?;
        let started = Instant::now();
        let response = self.exchange(cx, deadline, body).await?;
        let credentials = admit_token_response(
            &self.configuration,
            &self.configuration.scopes,
            &response,
            started,
        )?;
        ensure_live(cx, deadline)?;
        Ok(credentials)
    }

    /// Renews an access token through the same trusted issuer, registration,
    /// resource and client policy that admitted the original grant.
    ///
    /// Exclusive access to the credentials serializes refresh operations. A
    /// successful response replaces the complete token pair at once. Narrowed
    /// scopes become the next refresh ceiling; they cannot silently re-expand.
    /// This public client requires a nonempty successor refresh token that is
    /// byte-distinct from the presented token. Omission or repetition is a
    /// terminal rotation failure, never permission to retain the old token.
    ///
    /// After dispatch becomes possible, failure or cancellation discards the
    /// old refresh token and revokes every clone of the previous access token.
    /// Dropping an in-flight refresh has the same quarantine effect. Another
    /// explicit login is required; no possibly consumed token is replayed.
    /// Preflight failures leave custody untouched. Access expiry permits renewal,
    /// but local revocation prevents dispatch and interrupts a quiet exchange.
    /// A valid rotation preserves old access snapshots until their original
    /// expiry or explicit revocation; it does not extend their lifetime.
    pub async fn refresh(
        &self,
        cx: &Cx,
        credentials: &mut OAuthCredentials,
    ) -> Result<(), OAuthError> {
        let deadline = operation_deadline(cx, TOKEN_TIMEOUT)?;
        let (body, previous_refresh) = self.prepare_refresh(credentials)?;
        let mut quarantine = RefreshFailureQuarantine::new(credentials.access.revoked.clone());
        let started = Instant::now();
        let response =
            while_refresh_live(&quarantine.revoked, self.exchange(cx, deadline, body)).await?;
        // Do not publish a new token pair after the caller has cancelled.
        ensure_live(cx, deadline)?;
        let mut replacement =
            self.admit_refresh(credentials, previous_refresh, &response, started)?;
        ensure_live(cx, deadline)?;
        if quarantine.revoked.is_cancel_requested() {
            return Err(OAuthError::RefreshUnavailable);
        }
        std::mem::swap(credentials, &mut replacement);
        quarantine.complete();
        Ok(())
    }

    fn prepare_refresh(
        &self,
        credentials: &mut OAuthCredentials,
    ) -> Result<(String, String), OAuthError> {
        if credentials.configuration != self.configuration {
            return Err(OAuthError::CredentialBindingMismatch);
        }
        if credentials.access.is_revoked() {
            return Err(OAuthError::RefreshUnavailable);
        }
        let previous = credentials
            .refresh_token
            .as_deref()
            .ok_or(OAuthError::RefreshUnavailable)?;
        let scope = credentials.scopes.join(" ");
        let mut fields = vec![
            ("grant_type", "refresh_token"),
            ("client_id", self.configuration.client_id.as_str()),
            ("refresh_token", previous),
            ("resource", self.configuration.resource.as_str()),
        ];
        if !scope.is_empty() {
            fields.push(("scope", scope.as_str()));
        }
        let body = encode_form(&fields)?;
        if credentials.access.is_revoked() {
            return Err(OAuthError::RefreshUnavailable);
        }
        // All fallible local validation precedes this ownership transfer. Once
        // an exchange is possible, cancellation cannot put this secret back.
        let previous = credentials
            .refresh_token
            .take()
            .ok_or(OAuthError::RefreshUnavailable)?;
        Ok((body, previous))
    }

    fn admit_refresh(
        &self,
        previous: &OAuthCredentials,
        previous_refresh: String,
        response: &[u8],
        started: Instant,
    ) -> Result<OAuthCredentials, OAuthError> {
        admit_refresh_response(
            &self.configuration,
            &previous.scopes,
            &previous_refresh,
            response,
            started,
        )
    }

    async fn exchange(&self, cx: &Cx, deadline: Time, body: String) -> Result<Vec<u8>, OAuthError> {
        let deadline = deadline.min(operation_deadline(cx, TOKEN_TIMEOUT)?);
        let mut builder = HttpClient::builder()
            .redirect_policy(RedirectPolicy::None)
            .retry_policy(RetryPolicy::None)
            .no_proxy()
            .no_cookie_store()
            .max_body_size(MAX_TOKEN_RESPONSE_BYTES)
            .max_total_connections(1);
        for der in &self.configuration.extra_root_certificates {
            builder =
                builder.add_root_certificate(asupersync::tls::Certificate::from_der(der.clone()));
        }
        let client = builder.build();
        let response = within(cx, deadline, async {
            client
                .request(
                    cx,
                    Method::Post,
                    self.configuration.token_endpoint.as_str(),
                    vec![
                        (
                            "Content-Type".to_owned(),
                            "application/x-www-form-urlencoded".to_owned(),
                        ),
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
            verifier_material: draw_security_identifier()
                .map_err(|_| OAuthError::RandomSourceUnavailable)?,
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
        let Some(bytes) = decode_state(state) else {
            return false;
        };
        self.state_key
            .verify_bounded(
                STATE_DOMAIN,
                STATE_DOMAIN.len(),
                &HmacSha256Tag::from_bytes(bytes),
            )
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
        CanonicalHttpUrl::parse(&format!(
            "{}?{query}",
            config.authorization_endpoint.as_str()
        ))
        .map_err(|_| OAuthError::InvalidConfiguration)
    }
}

async fn bind_loopback() -> Result<TcpListener, OAuthError> {
    let ipv4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    if let Ok(listener) = TcpListener::bind(ipv4).await {
        return Ok(listener);
    }
    let ipv6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
    TcpListener::bind(ipv6)
        .await
        .map_err(|_| OAuthError::CallbackBindFailed)
}

fn operation_deadline(cx: &Cx, timeout: Duration) -> Result<Time, OAuthError> {
    with_caller(cx, || {
        if cx.checkpoint().is_err() {
            return Err(interruption(cx));
        }
        require_native_effects(cx)?;
        let nanos =
            u64::try_from(timeout.as_nanos()).map_err(|_| OAuthError::InvalidConfiguration)?;
        let end = cx
            .now()
            .as_nanos()
            .checked_add(nanos)
            .ok_or(OAuthError::InvalidConfiguration)?;
        let end = cx
            .budget()
            .deadline
            .map_or(Time::from_nanos(end), |parent| {
                parent.min(Time::from_nanos(end))
            });
        if cx.now() >= end {
            return Err(OAuthError::TimedOut);
        }
        Ok(end)
    })
}

// Call only inside with_caller: the ambient ceiling has already been applied,
// while the explicit caller still supplies the timer and cancellation domain.
fn require_native_effects(cx: &Cx) -> Result<(), OAuthError> {
    let active = Cx::current().ok_or(OAuthError::RuntimeCapabilityUnavailable)?;
    if !active.capabilities().io {
        return Err(OAuthError::RuntimeCapabilityUnavailable);
    }
    if !active.capabilities().time || cx.timer_driver().is_none() {
        return Err(OAuthError::RuntimeTimerUnavailable);
    }
    Ok(())
}

/// Refuses an OAuth step once the caller is interrupted or `deadline` has
/// passed.
fn ensure_live(cx: &Cx, deadline: Time) -> Result<(), OAuthError> {
    if cx.checkpoint().is_err() {
        return Err(interruption(cx));
    }
    if cx.now() >= deadline {
        return Err(OAuthError::TimedOut);
    }
    Ok(())
}

/// Classifies a failed checkpoint by the runtime's recorded reason, as
/// `check_modern_http_context` does. A caller whose budget deadline passes
/// fails its checkpoint with a deadline reason, and that is a timeout. An
/// explicit cancellation, or an exhausted poll or cost budget (which the
/// runtime ranks above a deadline), is a cancellation.
fn interruption(cx: &Cx) -> OAuthError {
    if cx
        .cancel_reason()
        .is_some_and(|reason| reason.kind == asupersync::CancelKind::Deadline)
    {
        OAuthError::TimedOut
    } else {
        OAuthError::Cancelled
    }
}

/// How a checkpoint of `cx` interrupts an OAuth step, if it does.
#[cfg(target_os = "linux")]
fn interrupted(cx: &Cx) -> Option<OAuthError> {
    cx.checkpoint().is_err().then(|| interruption(cx))
}

async fn within<T>(
    cx: &Cx,
    deadline: Time,
    future: impl Future<Output = Result<T, OAuthError>>,
) -> Result<T, OAuthError> {
    let deadline = cx
        .budget()
        .deadline
        .map_or(deadline, |parent| parent.min(deadline));
    let mut future = std::pin::pin!(future);
    let sleep = with_caller(cx, || {
        ensure_live(cx, deadline)?;
        require_native_effects(cx)?;
        Ok::<_, OAuthError>(Sleep::new(deadline))
    })?;
    let mut sleep = std::pin::pin!(sleep);
    // A pending cancel-correct receive registers a cancellation wake even when
    // the socket or the host's browser future has no traffic of its own.
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancelled = std::pin::pin!(receiver.recv(cx));
    poll_fn(|task| {
        with_caller(cx, || {
            if let Err(error) = ensure_live(cx, deadline) {
                return Poll::Ready(Err(error));
            }
            // Recheck every poll: a suspended flow may resume under a stricter host
            // scope. Refuse before polling a socket, timer, or browser future there.
            if let Err(error) = require_native_effects(cx) {
                return Poll::Ready(Err(error));
            }
            if cancelled.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(OAuthError::Cancelled));
            }
            if sleep.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(OAuthError::TimedOut));
            }
            let result = future.as_mut().poll(task);
            if let Err(error) = ensure_live(cx, deadline) {
                return Poll::Ready(Err(error));
            }
            result
        })
    })
    .await
}

fn validate_host_redirect(redirect_uri: &CanonicalHttpUrl) -> Result<(), OAuthError> {
    if redirect_uri.scheme() != "https"
        || redirect_uri.has_userinfo()
        || redirect_uri.query().is_some()
        || redirect_uri.fragment().is_some()
        || redirect_uri.as_str().len() > MAX_CODE_BYTES
    {
        return Err(OAuthError::InvalidConfiguration);
    }
    Ok(())
}

fn admit_host_redirect_callback(
    callback: &str,
    redirect_uri: &CanonicalHttpUrl,
    attempt: &AuthorizationAttempt,
    issuer: &str,
) -> Result<String, OAuthError> {
    if callback.len() > MAX_CALLBACK_BYTES
        || callback.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
        || callback.contains('#')
    {
        return Err(OAuthError::CallbackRejected);
    }
    let query = callback
        .strip_prefix(redirect_uri.as_str())
        .and_then(|suffix| suffix.strip_prefix('?'))
        .ok_or(OAuthError::CallbackRejected)?;
    admit_callback_query(query, attempt, issuer)
}

/// Both callback transports admit the same authorization-code parameter union.
/// Transport-specific route and header validation must precede this boundary.
fn admit_callback_query(
    query: &str,
    attempt: &AuthorizationAttempt,
    issuer: &str,
) -> Result<String, OAuthError> {
    // Unknown response parameters are ignored only after bounded strict form
    // admission. Repeated unknown names remain inert; known names, including
    // escaped aliases and incompatible credential-bearing responses, are singletons.
    let fields = decode_form_fields(query, |name| {
        matches!(
            name,
            "state" | "iss" | "code" | "error" | "error_description" | "error_uri"
                | "access_token" | "refresh_token" | "id_token" | "token_type"
                | "client_secret" | "client_assertion"
        )
    })?;
    if [
        "access_token", "refresh_token", "id_token", "token_type", "client_secret",
        "client_assertion",
    ]
    .iter()
    .any(|name| fields.contains_key(*name))
    {
        return Err(OAuthError::CallbackRejected);
    }
    let code = admit_callback_fields(&fields, attempt, issuer)?;
    if fields.contains_key("error_description") || fields.contains_key("error_uri") {
        return Err(OAuthError::CallbackRejected);
    }
    Ok(code)
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
            listener
                .accept()
                .await
                .map_err(|_| OAuthError::CallbackRejected)
        })
        .await?;
        if !peer.ip().is_loopback() {
            return Err(OAuthError::CallbackRejected);
        }
        let read_deadline = deadline.min(operation_deadline(cx, CALLBACK_READ_TIMEOUT)?);
        let head = within(cx, read_deadline, read_callback_head(&mut stream)).await;
        let outcome = head.and_then(|head| admit_callback(&head, address, attempt, &config.issuer));
        let accepted = outcome.is_ok();
        let response = callback_response(accepted);
        // The browser sees only receipt, not a false claim that token redemption
        // succeeded. A failed write does not erase an already-admitted callback.
        let write_deadline = deadline.min(operation_deadline(cx, Duration::from_secs(1))?);
        let _ = within(cx, write_deadline, async {
            stream
                .write_all(response.as_bytes())
                .await
                .map_err(|_| OAuthError::CallbackRejected)
        })
        .await;
        match outcome {
            Ok(code) => return Ok(code),
            Err(OAuthError::CallbackRejected | OAuthError::TimedOut) => {}
            Err(error) => return Err(error),
        }
    }
    Err(OAuthError::CallbackLimitExceeded)
}

async fn read_callback_head(stream: &mut TcpStream) -> Result<Vec<u8>, OAuthError> {
    let mut head = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let count = stream
            .read(&mut chunk)
            .await
            .map_err(|_| OAuthError::CallbackRejected)?;
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
    if head.len() > MAX_CALLBACK_BYTES {
        return Err(OAuthError::CallbackRejected);
    }
    let head = std::str::from_utf8(head).map_err(|_| OAuthError::CallbackRejected)?;
    let Some(headers) = head.strip_suffix("\r\n\r\n") else {
        return Err(OAuthError::CallbackRejected);
    };
    let mut lines = headers.split("\r\n");
    let mut request = lines.next().ok_or(OAuthError::CallbackRejected)?.split(' ');
    if request.next() != Some("GET") {
        return Err(OAuthError::CallbackRejected);
    }
    let target = request.next().ok_or(OAuthError::CallbackRejected)?;
    if request.next() != Some("HTTP/1.1")
        || request.next().is_some()
        || target.bytes().any(|b| !(0x21..=0x7e).contains(&b))
        || target.contains('#')
    {
        return Err(OAuthError::CallbackRejected);
    }
    let (path, query) = target.split_once('?').ok_or(OAuthError::CallbackRejected)?;
    if path != CALLBACK_PATH {
        return Err(OAuthError::CallbackRejected);
    }
    let mut host = None;
    let mut content_length = false;
    for (index, line) in lines.enumerate() {
        if index >= 64 {
            return Err(OAuthError::CallbackRejected);
        }
        let (name, value) = line.split_once(':').ok_or(OAuthError::CallbackRejected)?;
        if !AccessToken::is_valid_http_scheme(name)
            || value.bytes().any(|b| b == 0x7f || (b < 0x20 && b != b'\t'))
        {
            return Err(OAuthError::CallbackRejected);
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value).is_some() {
                return Err(OAuthError::CallbackRejected);
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(OAuthError::CallbackRejected);
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length || value != "0" {
                return Err(OAuthError::CallbackRejected);
            }
            content_length = true;
        }
    }
    if host != Some(address.to_string().as_str()) {
        return Err(OAuthError::CallbackRejected);
    }
    admit_callback_query(query, attempt, issuer)
}

fn admit_callback_fields(
    fields: &BTreeMap<String, String>,
    attempt: &AuthorizationAttempt,
    issuer: &str,
) -> Result<String, OAuthError> {
    if !fields
        .get("state")
        .is_some_and(|state| attempt.accepts_state(state))
    {
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
        (
            "200 OK",
            "Authorization response received. Return to the application.",
        )
    } else {
        ("400 Bad Request", "Authorization response rejected.")
    };
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nPragma: no-cache\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
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
        if scope.is_empty()
            || scope.len() > 256
            || !seen.insert(scope.as_str())
            || !scope
                .bytes()
                .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
        {
            return Err(OAuthError::InvalidTokenResponse);
        }
    }
    Ok(())
}

fn encode_form(fields: &[(&str, &str)]) -> Result<String, OAuthError> {
    let mut output = String::new();
    for (index, (name, value)) in fields.iter().enumerate() {
        if index > 0 {
            output.push('&');
        }
        for (part_index, part) in [*name, *value].into_iter().enumerate() {
            if part_index == 1 {
                output.push('=');
            }
            for byte in part.bytes() {
                if output.len() > MAX_FORM_BYTES - 3 {
                    return Err(OAuthError::InvalidConfiguration);
                }
                match byte {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                        output.push(char::from(byte));
                    }
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
    decode_form_fields(query, |_| true)
}

fn decode_form_fields(
    query: &str,
    retain: impl Fn(&str) -> bool,
) -> Result<BTreeMap<String, String>, OAuthError> {
    if query.len() > MAX_CALLBACK_BYTES {
        return Err(OAuthError::CallbackRejected);
    }
    let mut fields = BTreeMap::new();
    for (index, field) in query.split('&').enumerate() {
        if index >= MAX_FORM_FIELDS {
            return Err(OAuthError::CallbackRejected);
        }
        let (key, value) = field.split_once('=').ok_or(OAuthError::CallbackRejected)?;
        let key = decode_component(key)?;
        let value = decode_component(value)?;
        if key.is_empty()
            || key.len() > 128
            || value.len() > MAX_CODE_BYTES
        {
            return Err(OAuthError::CallbackRejected);
        }
        if retain(&key) && fields.insert(key, value).is_some() {
            return Err(OAuthError::CallbackRejected);
        }
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
                let high = bytes
                    .next()
                    .and_then(hex_digit)
                    .ok_or(OAuthError::CallbackRejected)?;
                let low = bytes
                    .next()
                    .and_then(hex_digit)
                    .ok_or(OAuthError::CallbackRejected)?;
                (high << 4) | low
            }
            byte => byte,
        };
        if byte.is_ascii_control() {
            return Err(OAuthError::CallbackRejected);
        }
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
    if state.len() != 64
        || !state
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        return None;
    }
    let mut decoded = [0; 32];
    // `as_chunks` yields `[u8; 2]`, so the pair indexing below is checked at
    // compile time. The length test above makes the remainder provably empty.
    for (index, pair) in state.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        decoded[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Some(decoded)
}

fn pkce_challenge(verifier: &str) -> Result<String, OAuthError> {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(OAuthError::InvalidConfiguration);
    }
    let digest =
        sha256_bounded(verifier.as_bytes(), 128).map_err(|_| OAuthError::InvalidConfiguration)?;
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
    if bits != 0 {
        output.push(char::from(
            ALPHABET[((accumulator << (6 - bits)) & 63) as usize],
        ));
    }
    Ok(output)
}

fn validate_token_headers(headers: &[(String, String)]) -> Result<(), OAuthError> {
    super::token_response::cache_policy(headers).map_err(|_| OAuthError::InvalidTokenResponse)?;
    let mut content_type = None;
    let mut encoding = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-type") {
            if content_type.replace(value.as_str()).is_some() {
                return Err(OAuthError::InvalidTokenResponse);
            }
        }
        if name.eq_ignore_ascii_case("content-encoding") {
            if encoding || !value.trim().eq_ignore_ascii_case("identity") {
                return Err(OAuthError::InvalidTokenResponse);
            }
            encoding = true;
        }
    }
    let value = content_type.ok_or(OAuthError::InvalidTokenResponse)?;
    let mut parts = value.split(';');
    if !parts
        .next()
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(OAuthError::InvalidTokenResponse);
    }
    if let Some(parameter) = parts.next() {
        let (name, value) = parameter
            .trim()
            .split_once('=')
            .ok_or(OAuthError::InvalidTokenResponse)?;
        if !name.trim().eq_ignore_ascii_case("charset")
            || !value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
            || parts.next().is_some()
        {
            return Err(OAuthError::InvalidTokenResponse);
        }
    }
    Ok(())
}

fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
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
    // These members belong to an error or a separately negotiated identity,
    // token-exchange, or sender-constrained profile. Their presence is not an
    // ignorable OAuth extension, even when the supplied value is null.
    #[serde(default, rename = "id_token", deserialize_with = "reject_token_member")]
    _id_token: (),
    #[serde(
        default,
        rename = "issued_token_type",
        deserialize_with = "reject_token_member"
    )]
    _issued_token_type: (),
    #[serde(default, rename = "cnf", deserialize_with = "reject_token_member")]
    _confirmation: (),
    #[serde(
        default,
        rename = "error_description",
        deserialize_with = "reject_token_member"
    )]
    _error_description: (),
    #[serde(default, rename = "error_uri", deserialize_with = "reject_token_member")]
    _error_uri: (),
}

fn reject_token_member<'de, D: Deserializer<'de>>(_: D) -> Result<(), D::Error> {
    Err(serde::de::Error::custom(
        "unsupported ordinary OAuth token response member",
    ))
}

// OAuthClientConfiguration admits only the native public `none` profile.
// Share its mandatory rotation rule between live and persisted renewal; the
// initial authorization-code response may still omit a refresh token.
fn admit_refresh_response(
    configuration: &OAuthClientConfiguration,
    scope_ceiling: &[String],
    previous_refresh: &str,
    bytes: &[u8],
    started: Instant,
) -> Result<OAuthCredentials, OAuthError> {
    let replacement = admit_token_response(configuration, scope_ceiling, bytes, started)?;
    let successor = replacement
        .refresh_token
        .as_deref()
        .ok_or(OAuthError::InvalidTokenResponse)?;
    if successor == previous_refresh {
        return Err(OAuthError::InvalidTokenResponse);
    }
    Ok(replacement)
}

fn admit_token_response(
    configuration: &OAuthClientConfiguration,
    scope_ceiling: &[String],
    bytes: &[u8],
    started: Instant,
) -> Result<OAuthCredentials, OAuthError> {
    // Every code and refresh consumer, including a resumed persistent grant,
    // shares the bounded object/duplicate/depth/number admission boundary.
    // Serde alone would ignore ambiguity inside unknown extension members.
    admit_security_document(SecurityDocumentKind::TokenResponse, bytes)
        .map_err(|_| OAuthError::InvalidTokenResponse)?;
    let response: TokenResponse =
        serde_json::from_slice(bytes).map_err(|_| OAuthError::InvalidTokenResponse)?;
    if !response.token_type.eq_ignore_ascii_case("Bearer")
        || !AccessToken::is_valid_token68(&response.access_token)
        || response
            .refresh_token
            .as_ref()
            .is_some_and(|token| !valid_opaque(token, MAX_CODE_BYTES))
        || response
            .resource
            .as_ref()
            .is_some_and(|resource| resource != configuration.resource.as_str())
        || response.error.is_some()
    {
        return Err(OAuthError::InvalidTokenResponse);
    }
    let scopes = response.scope.map_or_else(
        || scope_ceiling.to_vec(),
        |scope| scope.split(' ').map(str::to_owned).collect(),
    );
    validate_scopes(&scopes)?;
    if scopes.iter().any(|scope| !scope_ceiling.contains(scope)) {
        return Err(OAuthError::ScopeExpansion);
    }
    let lifetime = response
        .expires_in
        .map_or(configuration.max_access_token_lifetime, |seconds| {
            Duration::from_secs(seconds).min(configuration.max_access_token_lifetime)
        });
    let expires_at = started
        .checked_add(lifetime)
        .ok_or(OAuthError::InvalidTokenResponse)?;
    if Instant::now() >= expires_at {
        return Err(OAuthError::ExpiredCredential);
    }
    let access = BoundBearerCredential::bind_with_expiry(
        configuration.resource.clone(),
        response.access_token,
        expires_at,
    )
    .map_err(|_| OAuthError::InvalidTokenResponse)?;
    Ok(OAuthCredentials {
        configuration: configuration.clone(),
        access,
        refresh_token: response.refresh_token,
        scopes,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};

    fn held_effects(cx: &Cx, mask: CapMask) -> Cx {
        let _caller = Cx::set_current(Some(cx.clone()));
        let _restriction = Cx::push_restriction(mask);
        Cx::current().unwrap()
    }

    fn effect_row(cx: &Cx) -> [bool; 5] {
        let c = cx.capabilities();
        [c.spawn, c.time, c.entropy, c.io, c.remote]
    }

    fn poll_under_ambient<F: Future>(
        future: std::pin::Pin<&mut F>,
        task: &mut std::task::Context<'_>,
        ambient: &Cx,
    ) -> Poll<F::Output> {
        let _ambient = Cx::set_current(Some(ambient.clone()));
        let before = Cx::current().unwrap();
        let depth = Cx::restriction_depth();
        let result = future.poll(task);
        let after = Cx::current().unwrap();
        assert_eq!(after.task_id(), before.task_id());
        assert_eq!(after.region_id(), before.region_id());
        assert_eq!(after.budget(), before.budget());
        assert_eq!(effect_row(&after), effect_row(&before));
        assert_eq!(after.is_cancel_requested(), before.is_cancel_requested());
        assert_eq!(Cx::restriction_depth(), depth);
        result
    }

    fn url(value: &str) -> CanonicalHttpUrl {
        CanonicalHttpUrl::parse(value).unwrap()
    }

    pub(super) fn config() -> OAuthClientConfiguration {
        OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example",
            url("https://issuer.example/authorize"),
            url("https://issuer.example/token"),
            url("https://mcp.example/mcp"),
            "native-client",
            vec!["tools:read".to_owned(), "tools:write".to_owned()],
        )
        .unwrap()
    }

    #[test]
    fn native_authorization_obeys_effect_ceilings_before_browser_launch() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap()
            .block_on(async {
                let healthy = Cx::current().unwrap();
                // Its identity, cancellation, budget and absent drivers are not
                // substitutes for the explicit caller's authority and lifetime.
                let foreign = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
                foreign.set_cancel_requested(true);
                let client = OAuthClient::new(config());
                for (mask, expected, launches) in [
                    (
                        CapSet::<true, true, true, false, true>::MASK,
                        OAuthError::RuntimeCapabilityUnavailable,
                        0,
                    ),
                    (
                        CapSet::<true, false, true, true, true>::MASK,
                        OAuthError::RuntimeTimerUnavailable,
                        0,
                    ),
                    (
                        CapSet::<true, true, false, true, true>::MASK,
                        OAuthError::RuntimeCapabilityUnavailable,
                        0,
                    ),
                    (
                        CapSet::<false, true, true, true, false>::MASK,
                        OAuthError::BrowserLaunchFailed,
                        1,
                    ),
                    (CapMask::all(), OAuthError::BrowserLaunchFailed, 1),
                ] {
                    for restrict_explicit in [false, true] {
                        let caller = held_effects(
                            &healthy,
                            if restrict_explicit {
                                mask
                            } else {
                                CapMask::all()
                            },
                        );
                        let ambient = held_effects(
                            &foreign,
                            if restrict_explicit {
                                CapMask::all()
                            } else {
                                mask
                            },
                        );
                        let started = AtomicUsize::new(0);
                        let expected_effects = effect_row(&held_effects(&healthy, mask));
                        let mut login = Box::pin(client.authorize(&caller, |authorization| {
                            let current = Cx::current().unwrap();
                            assert_eq!(current.task_id(), caller.task_id());
                            assert_eq!(current.budget(), caller.budget());
                            assert!(current.timer_driver().is_some());
                            assert!(!current.is_cancel_requested());
                            assert_eq!(effect_row(&current), expected_effects);
                            assert_eq!(authorization.scheme(), "https");
                            started.fetch_add(1, Ordering::SeqCst);
                            async {
                                let _nested = Cx::push_restriction(
                                    CapSet::<true, true, true, true, false>::MASK,
                                );
                                assert!(!Cx::current().unwrap().capabilities().remote);
                                Err(OAuthError::BrowserLaunchFailed)
                            }
                        }));
                        let result =
                            poll_fn(|task| poll_under_ambient(login.as_mut(), task, &ambient))
                                .await;
                        assert_eq!(result.err(), Some(expected));
                        assert_eq!(started.load(Ordering::SeqCst), launches);
                        assert!(!caller.is_cancel_requested());
                        assert!(foreign.is_cancel_requested());
                    }
                }
            });
    }

    #[test]
    fn native_pending_browser_rechecks_effects_and_preserves_caller_cancellation() {
        use asupersync::time::{TimerDriverHandle, VirtualClock};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct BrowserDrop(Arc<AtomicUsize>);
        impl Drop for BrowserDrop {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        runtime.block_on(async {
            let foreign = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
            foreign.set_cancel_requested(true);
            for stop in ["io", "time", "cancel", "deadline"] {
                let caller = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
                let client = OAuthClient::new(
                    config()
                        .with_authorization_timeout(Duration::from_secs(1))
                        .unwrap(),
                );
                let polls = Arc::new(AtomicUsize::new(0));
                let drops = Arc::new(AtomicUsize::new(0));
                let owned = BrowserDrop(Arc::clone(&drops));
                let mut login = Box::pin(client.authorize(&caller, |_| {
                    let polls = Arc::clone(&polls);
                    async move {
                        let _owned = owned;
                        poll_fn(|_| {
                            polls.fetch_add(1, Ordering::SeqCst);
                            Poll::<Result<(), OAuthError>>::Pending
                        })
                        .await
                    }
                }));
                let mut task = std::task::Context::from_waker(std::task::Waker::noop());
                assert!(poll_under_ambient(login.as_mut(), &mut task, &foreign).is_pending());
                assert_eq!(polls.load(Ordering::SeqCst), 1);
                assert_eq!(drops.load(Ordering::SeqCst), 0);
                let (mask, expected) = match stop {
                    "io" => (
                        CapSet::<true, true, true, false, true>::MASK,
                        OAuthError::RuntimeCapabilityUnavailable,
                    ),
                    "time" => (
                        CapSet::<true, false, true, true, true>::MASK,
                        OAuthError::RuntimeTimerUnavailable,
                    ),
                    "cancel" => {
                        caller.set_cancel_requested(true);
                        (CapMask::all(), OAuthError::Cancelled)
                    }
                    "deadline" => {
                        clock.advance(1_000_000_000);
                        (CapMask::all(), OAuthError::TimedOut)
                    }
                    _ => unreachable!(),
                };
                let ambient = held_effects(&foreign, mask);
                let Poll::Ready(result) = poll_under_ambient(login.as_mut(), &mut task, &ambient)
                else {
                    panic!("{stop} must retire the pending native flow without another event");
                };
                assert_eq!(result.err(), Some(expected));
                drop(login);
                assert_eq!(polls.load(Ordering::SeqCst), 1, "{stop}");
                assert_eq!(drops.load(Ordering::SeqCst), 1, "{stop}");
                assert_eq!(timer.pending_count(), 0);
                assert_eq!(caller.is_cancel_requested(), stop == "cancel");
            }
        });
    }

    fn wire(attempt: &AuthorizationAttempt, issuer: &str, extra: &str) -> Vec<u8> {
        let query = encode_form(&[
            ("state", &attempt.state().unwrap()),
            ("iss", issuer),
            ("code", "code+/%"),
        ])
        .unwrap();
        format!("GET {CALLBACK_PATH}?{query}{extra} HTTP/1.1\r\nHost: 127.0.0.1:43210\r\n\r\n")
            .into_bytes()
    }

    fn host_callback(authorization: &CanonicalHttpUrl, issuer: &str) -> String {
        let fields = decode_form(authorization.query().unwrap()).unwrap();
        format!(
            "{}?{}",
            fields["redirect_uri"],
            encode_form(&[
                ("state", &fields["state"]),
                ("iss", issuer),
                ("code", "host-issued-code"),
            ])
            .unwrap()
        )
    }

    #[test]
    fn host_https_redirect_callback_requires_exact_route_state_issuer_and_code() {
        let configuration = config();
        let attempt = AuthorizationAttempt::new().unwrap();
        let redirect = url("https://app.example/oauth/return");
        let authorization = attempt
            .authorization_url(&configuration, redirect.as_str())
            .unwrap();
        let callback = host_callback(&authorization, &configuration.issuer);
        let admit = |callback: &str| {
            admit_host_redirect_callback(callback, &redirect, &attempt, &configuration.issuer)
        };
        assert_eq!(admit(&callback), Ok("host-issued-code".to_owned()));
        assert_eq!(
            admit(&format!("{callback}&vendor=one&v%65ndor=two")),
            Ok("host-issued-code".to_owned())
        );
        for suffix in [
            "&code=other", "&co%64e=other", "&st%61te=other", "&iss=other",
            "&error=access_denied", "&error_description=private", "&error_uri=private",
            "&access_token=private", "&refresh_token=private", "&id_token=",
            "&token_type=Bearer", "&client_secret=private", "&client_assertion=private",
            "&unknown=%ff", "&unknown=%", "&unknown=%00", "#fragment",
        ] {
            assert_eq!(admit(&format!("{callback}{suffix}")), Err(OAuthError::CallbackRejected));
        }
        for (from, to) in [
            ("https://app.example/", "https://other.example/"),
            ("/oauth/return?", "/oauth/return/other?"),
            ("/oauth/return?", "/oauth/%72eturn?"),
            ("host-issued-code", ""),
            ("host-issued-code", "private code"),
        ] {
            assert_eq!(admit(&callback.replace(from, to)), Err(OAuthError::CallbackRejected));
        }
        let other = AuthorizationAttempt::new().unwrap();
        assert_eq!(
            admit_host_redirect_callback(&callback, &redirect, &other, &configuration.issuer),
            Err(OAuthError::CallbackRejected)
        );
        let denied = callback.replace("code=host-issued-code", "error=access_denied&error_description=private");
        assert_eq!(admit(&denied), Err(OAuthError::AuthorizationDenied));
        assert_eq!(
            admit_host_redirect_callback(&denied, &redirect, &attempt, "https://other.example"),
            Err(OAuthError::IssuerMismatch)
        );
        // Repeated unknown fields remain inert, but still consume the exact
        // aggregate byte bound even when every individual value is admissible.
        let mut bounded = callback.clone();
        while MAX_CALLBACK_BYTES - bounded.len() > MAX_CODE_BYTES + 3 {
            bounded.push_str("&x=");
            bounded.push_str(&"a".repeat(MAX_CODE_BYTES));
        }
        let padding = MAX_CALLBACK_BYTES - bounded.len() - 3;
        bounded.push_str("&x=");
        bounded.push_str(&"a".repeat(padding));
        assert_eq!(bounded.len(), MAX_CALLBACK_BYTES);
        assert!(admit(&bounded).is_ok());
        bounded.push('a');
        assert_eq!(admit(&bounded), Err(OAuthError::CallbackRejected));
        assert!(!format!("{}", OAuthError::CallbackRejected).contains("private"));
    }

    #[test]
    fn host_https_redirect_refuses_invalid_routes_before_invoking_driver() {
        use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let client = OAuthClient::new(config());
        let calls = AtomicUsize::new(0);
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        for redirect in [
            "http://app.example/oauth/return".to_owned(),
            "http://127.0.0.1/oauth/return".to_owned(),
            "https://user@app.example/oauth/return".to_owned(),
            "https://app.example/oauth/return?fixed=value".to_owned(),
            "https://app.example/oauth/return#fragment".to_owned(),
            format!("https://app.example/{}", "a".repeat(MAX_CODE_BYTES)),
        ] {
            let mut flow = Box::pin(client.authorize_with_redirect_driver(&cx, url(&redirect), |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Err(OAuthError::AuthorizationDenied))
            }));
            assert!(matches!(flow.as_mut().poll(&mut task), Poll::Ready(Err(OAuthError::InvalidConfiguration))));
        }
        for ambient in [false, true] {
            for (mask, expected) in [
                (CapSet::<true, false, true, true, true>::MASK, OAuthError::RuntimeTimerUnavailable),
                (CapSet::<true, true, false, true, true>::MASK, OAuthError::RuntimeCapabilityUnavailable),
                (CapSet::<true, true, true, false, true>::MASK, OAuthError::RuntimeCapabilityUnavailable),
            ] {
                let restricted = {
                    let _caller = Cx::set_current(Some(cx.clone()));
                    let _mask = Cx::push_restriction(mask);
                    Cx::current().unwrap()
                };
                let caller = if ambient { &cx } else { &restricted };
                let _ambient = Cx::set_current(Some(if ambient { restricted.clone() } else { cx.clone() }));
                let before = Cx::current().unwrap().capabilities();
                let mut flow = Box::pin(client.authorize_with_redirect_driver(
                    caller, url("https://app.example/oauth/return"), |_| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        std::future::ready(Err(OAuthError::AuthorizationDenied))
                    },
                ));
                assert!(matches!(flow.as_mut().poll(&mut task), Poll::Ready(Err(error)) if error == expected));
                let after = Cx::current().unwrap().capabilities();
                assert_eq!((before.time, before.entropy, before.io), (after.time, after.entropy, after.io));
            }
        }
        for (caller, expected) in [
            (Cx::for_testing(), OAuthError::RuntimeTimerUnavailable),
            ({ let stopped = runtime.request_cx_with_budget(asupersync::Budget::INFINITE); stopped.set_cancel_requested(true); stopped }, OAuthError::Cancelled),
        ] {
            let mut flow = Box::pin(client.authorize_with_redirect_driver(
                &caller, url("https://app.example/oauth/return"), |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Err(OAuthError::AuthorizationDenied))
                },
            ));
            assert!(matches!(flow.as_mut().poll(&mut task), Poll::Ready(Err(error)) if error == expected));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        // A foreign stopped ambient caller limits effects only. It cannot
        // replace the supplied healthy caller's identity, clock or lifetime.
        let foreign = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
        foreign.set_cancel_requested(true);
        {
            let _ambient = Cx::set_current(Some(foreign));
            let _mask = Cx::push_restriction(CapSet::<false, true, true, true, true>::MASK);
            let mut flow = Box::pin(client.authorize_with_redirect_driver(
                &cx, url("https://app.example/oauth/return"), |_| async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let active = Cx::current().unwrap();
                    assert!(!active.capabilities().spawn);
                    assert_eq!(active.task_id(), cx.task_id());
                    assert_eq!(active.region_id(), cx.region_id());
                    assert_eq!(active.budget(), cx.budget());
                    assert!(!active.is_cancel_requested());
                    Err(OAuthError::AuthorizationDenied)
                },
            ));
            assert!(matches!(flow.as_mut().poll(&mut task), Poll::Ready(Err(OAuthError::AuthorizationDenied))));
            assert!(Cx::current().unwrap().is_cancel_requested());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn host_https_redirect_driver_cancellation_deadline_and_drop_release_pending_flow() {
        use asupersync::time::{TimerDriverHandle, VirtualClock};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Wake, Waker};

        struct Owned(Arc<AtomicUsize>);
        impl Drop for Owned {
            fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
        }
        #[derive(Default)]
        struct Wakes(AtomicUsize);
        impl Wake for Wakes {
            fn wake(self: Arc<Self>) { self.wake_by_ref(); }
            fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        }
        for mode in 0..3 {
            let clock = Arc::new(VirtualClock::new());
            let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .blocking_threads(0, 0).with_timer_driver(timer.clone()).build().unwrap();
            let caller = runtime.request_cx_with_budget(
                asupersync::Budget::INFINITE.with_deadline(Time::from_nanos(1_000_000_000)),
            );
            let token_peer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            token_peer.set_nonblocking(true).unwrap();
            let mut configuration = config();
            configuration.token_endpoint = url(&format!("https://{}/token", token_peer.local_addr().unwrap()));
            let client = OAuthClient::new(configuration);
            let drops = Arc::new(AtomicUsize::new(0));
            let owned = Owned(Arc::clone(&drops));
            let calls = AtomicUsize::new(0);
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let mut task = Context::from_waker(&waker);
            let mut flow = Box::pin(client.authorize_with_redirect_driver(
                &caller, url("https://app.example/oauth/return"), |_| async {
                    let _owned = owned;
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<Result<String, OAuthError>>().await
                },
            ));
            assert!(flow.as_mut().poll(&mut task).is_pending());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            assert_eq!(timer.pending_count(), 1);
            let before = wakes.0.load(Ordering::SeqCst);
            if mode == 0 {
                caller.set_cancel_requested(true);
            } else if mode == 1 {
                // Fire with the worker on loan so this test, not the runtime's
                // background worker, observes the timers.
                let fired = runtime.block_on(async {
                    clock.advance(1_000_000_000);
                    timer.process_timers()
                });
                assert!(fired > 0);
            }
            if mode != 2 {
                assert!(wakes.0.load(Ordering::SeqCst) > before);
                let expected = if mode == 0 { OAuthError::Cancelled } else { OAuthError::TimedOut };
                let outcome = flow
                    .as_mut()
                    .poll(&mut task)
                    .map(|result| result.map(|_| ()));
                assert!(
                    matches!(&outcome, Poll::Ready(Err(error)) if *error == expected),
                    "mode {mode}: {outcome:?}"
                );
            }
            drop(flow);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), 0);
            assert!(matches!(token_peer.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
            drop(caller);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn pkce_matches_rfc_7636_appendix_b_without_plain_fallback() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(pkce_challenge("too-short").is_err());
        let first = AuthorizationAttempt::new().unwrap();
        let second = AuthorizationAttempt::new().unwrap();
        assert_eq!(first.verifier().len(), 64);
        assert_ne!(first.verifier(), second.verifier());
        assert!(first.accepts_state(&first.state().unwrap()));
        assert!(!second.accepts_state(&first.state().unwrap()));
        let target = first
            .authorization_url(&config(), "http://127.0.0.1:43210/oauth/callback")
            .unwrap();
        assert!(target.as_str().contains("code_challenge_method=S256"));
        assert!(!target.as_str().contains(&first.verifier()));
        let fields = decode_form(target.as_str().split_once('?').unwrap().1).unwrap();
        assert_eq!(fields["resource"], "https://mcp.example/mcp");
        assert_eq!(
            fields["redirect_uri"],
            "http://127.0.0.1:43210/oauth/callback"
        );
    }

    #[test]
    fn callback_transports_share_success_denial_and_singleton_admission() {
        let configuration = config();
        let attempt = AuthorizationAttempt::new().unwrap();
        let state = attempt.state().unwrap();
        let address: SocketAddr = "127.0.0.1:43210".parse().unwrap();
        let redirect = url("https://app.example/oauth/return");
        let admit_both = |query: &str| {
            let request = format!(
                "GET {CALLBACK_PATH}?{query} HTTP/1.1\r\nHost: {address}\r\n\r\n"
            );
            let callback = format!("{}?{query}", redirect.as_str());
            (
                admit_callback(request.as_bytes(), address, &attempt, &configuration.issuer),
                admit_host_redirect_callback(
                    &callback,
                    &redirect,
                    &attempt,
                    &configuration.issuer,
                ),
            )
        };
        let success = encode_form(&[
            ("state", &state),
            ("iss", &configuration.issuer),
            ("code", "code+/%"),
        ])
        .unwrap();
        for suffix in ["", "&vendor=one&v%65ndor=two"] {
            let (loopback, hosted) = admit_both(&format!("{success}{suffix}"));
            assert_eq!(loopback, Ok("code+/%".to_owned()), "{suffix}");
            assert_eq!(hosted, loopback, "{suffix}");
        }
        for suffix in [
            "&access_token=private-canary",
            "&refresh_token=private-canary",
            "&id_token=",
            "&token_type=Bearer",
            "&client_secret=private-canary",
            "&client_assertion=private-canary",
            "&a%63cess_token=private-canary",
            "&error_description=private-canary",
            "&error_%75ri=private-canary",
            "&code=other",
            "&co%64e=other",
            "&st%61te=other",
            "&i%73s=other",
            "&error=access_denied",
            "&vendor=one&v%65ndor=two&co%64e=other",
            "&unknown=%ff",
            "&unknown=%",
            "&unknown=%00",
        ] {
            let (loopback, hosted) = admit_both(&format!("{success}{suffix}"));
            assert_eq!(loopback, Err(OAuthError::CallbackRejected), "{suffix}");
            assert_eq!(hosted, loopback, "{suffix}");
        }

        let denial = encode_form(&[
            ("state", &state),
            ("iss", &configuration.issuer),
            ("error", "access_denied"),
        ])
        .unwrap();
        for suffix in [
            "",
            "&error_description=Denied&error_uri=https%3A%2F%2Fissuer.example%2Fhelp",
            "&vendor=one&v%65ndor=two",
        ] {
            let (loopback, hosted) = admit_both(&format!("{denial}{suffix}"));
            assert_eq!(loopback, Err(OAuthError::AuthorizationDenied), "{suffix}");
            assert_eq!(hosted, loopback, "{suffix}");
        }
        for suffix in [
            "&access_token=private-canary",
            "&refresh_token=private-canary",
            "&id_token=",
            "&token_type=Bearer",
            "&client_secret=private-canary",
            "&client_assertion=private-canary",
            "&client_%61ssertion=private-canary",
            "&err%6Fr=access_denied",
            "&error_description=one&error_%64escription=two",
            "&error_uri=one&error_%75ri=two",
        ] {
            let (loopback, hosted) = admit_both(&format!("{denial}{suffix}"));
            assert_eq!(loopback, Err(OAuthError::CallbackRejected), "{suffix}");
            assert_eq!(hosted, loopback, "{suffix}");
        }
    }

    #[test]
    fn callback_requires_matching_state_issuer_host_and_one_code() {
        let attempt = AuthorizationAttempt::new().unwrap();
        let address = "127.0.0.1:43210".parse().unwrap();
        let request = wire(&attempt, &config().issuer, "");
        assert_eq!(
            admit_callback(&request, address, &attempt, &config().issuer).unwrap(),
            "code+/%"
        );
        let other = AuthorizationAttempt::new().unwrap();
        assert_eq!(
            admit_callback(&request, address, &other, &config().issuer),
            Err(OAuthError::CallbackRejected)
        );
        assert_eq!(
            admit_callback(&request, address, &attempt, "https://different.example"),
            Err(OAuthError::IssuerMismatch)
        );
        for suffix in [
            "&code=second",
            "&co%64e=second",
            "&error=access_denied",
            "&state=other",
            "&unknown=%ff",
        ] {
            assert!(
                admit_callback(
                    &wire(&attempt, &config().issuer, suffix),
                    address,
                    &attempt,
                    &config().issuer
                )
                .is_err()
            );
        }
        for (from, to) in [
            ("Host: 127.0.0.1:43210", "Host: evil.example"),
            ("GET /oauth/callback?", "GET /other?"),
            ("\r\n\r\n", "\r\nContent-Length: 1\r\n\r\nx"),
            ("\r\n\r\n", "\r\nHost: 127.0.0.1:43210\r\n\r\n"),
        ] {
            let changed = String::from_utf8(request.clone())
                .unwrap()
                .replace(from, to);
            assert!(
                admit_callback(changed.as_bytes(), address, &attempt, &config().issuer).is_err()
            );
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
        assert!(
            grant
                .bearer_credential()
                .authorization_for_target(&config.resource)
                .is_some()
        );
        assert!(
            grant
                .bearer_credential()
                .authorization_for_target(&url("https://issuer.example/token"))
                .is_none()
        );
        for invalid in [
            r#"{"access_token":"access-secret","token_type":"Basic"}"#,
            r#"{"access_token":"access-secret","token_type":"Bearer","expires_in":0}"#,
            r#"{"access_token":"access-secret","token_type":"Bearer","expires_in":null}"#,
            r#"{"access_token":"access-secret","token_type":"Bearer","scope":"admin"}"#,
            r#"{"access_token":"access-secret","token_type":"Bearer","resource":"https://wrong.example/mcp"}"#,
            r#"{"access_token":"first","access_token":"second","token_type":"Bearer"}"#,
            r#"{"access_token":"access-secret","token_type":"Bearer","refresh_token":null}"#,
        ] {
            let error = admit_token_response(&config, &config.scopes, invalid.as_bytes(), now)
                .err()
                .unwrap();
            assert!(!format!("{error:?} {error}").contains("access-secret"));
        }
    }

    fn ordinary_token_response(extension: &str) -> String {
        format!(
            r#"{{"access_token":"access-two","token_type":"Bearer","expires_in":120,"refresh_token":"refresh-two","scope":"tools:read",{extension}}}"#
        )
    }

    #[test]
    fn ordinary_token_admission_rejects_presence_of_incompatible_profile_and_error_members() {
        let configuration = config();
        for member in [
            "id_token",
            "issued_token_type",
            "cnf",
            "error",
            "error_description",
            "error_uri",
        ] {
            for value in ["null", r#""peer-secret""#, "{}", "[]", "0"] {
                // The value is harmless as an unknown OAuth extension. Only
                // its field name changes the success/profile interpretation.
                let ordinary = ordinary_token_response(&format!(r#""vendor":{value}"#));
                let grant = admit_token_response(
                    &configuration,
                    &configuration.scopes,
                    ordinary.as_bytes(),
                    Instant::now(),
                )
                .unwrap();
                assert_eq!(grant.scopes(), ["tools:read"]);
                assert_eq!(grant.refresh_token.as_deref(), Some("refresh-two"));
                assert_eq!(
                    grant
                        .access
                        .authorization_for_target(&configuration.resource)
                        .as_deref(),
                    Some("Bearer access-two")
                );

                let poisoned = ordinary_token_response(&format!(r#""{member}":{value}"#));
                let error = admit_token_response(
                    &configuration,
                    &configuration.scopes,
                    poisoned.as_bytes(),
                    Instant::now(),
                )
                .err()
                .unwrap();
                assert_eq!(error, OAuthError::InvalidTokenResponse, "{member}");
                assert!(!format!("{error:?} {error}").contains("peer-secret"));
            }
        }
    }

    #[test]
    fn ordinary_token_admission_applies_shared_bounds_before_ignoring_extensions() {
        let configuration = config();
        let accepted = ordinary_token_response(r#""vendor":{"label":1,"other":[true,null]}"#);
        assert!(
            admit_token_response(
                &configuration,
                &configuration.scopes,
                accepted.as_bytes(),
                Instant::now(),
            )
            .is_ok()
        );

        let nesting = fastmcp_protocol::MAX_RAW_JSON_NESTING_DEPTH + 1;
        for extension in [
            r#""vendor":1,"v\u0065ndor":2"#.to_owned(),
            r#""vendor":{"label":1,"l\u0061bel":2}"#.to_owned(),
            r#""vendor":1e10001"#.to_owned(),
            format!(
                r#""vendor":{}0{}"#,
                "[".repeat(nesting),
                "]".repeat(nesting)
            ),
        ] {
            let response = ordinary_token_response(&extension);
            assert_eq!(
                admit_token_response(
                    &configuration,
                    &configuration.scopes,
                    response.as_bytes(),
                    Instant::now(),
                )
                .err(),
                Some(OAuthError::InvalidTokenResponse)
            );
        }

        let empty = ordinary_token_response(r#""vendor":"""#);
        let padding = "x".repeat(MAX_TOKEN_RESPONSE_BYTES - empty.len());
        let mut at_limit = ordinary_token_response(&format!(r#""vendor":"{padding}""#));
        assert_eq!(at_limit.len(), MAX_TOKEN_RESPONSE_BYTES);
        assert!(
            admit_token_response(
                &configuration,
                &configuration.scopes,
                at_limit.as_bytes(),
                Instant::now(),
            )
            .is_ok()
        );
        // A trailing space preserves the JSON document and changes only its
        // byte count. The native HTTP cap uses this same central bound.
        at_limit.push(' ');
        assert_eq!(
            admit_token_response(
                &configuration,
                &configuration.scopes,
                at_limit.as_bytes(),
                Instant::now(),
            )
            .err(),
            Some(OAuthError::InvalidTokenResponse)
        );
    }

    #[test]
    fn native_configuration_rejects_cleartext_endpoints_and_scope_ambiguity() {
        let template = config();
        for endpoint in [
            "http://127.0.0.1/token",
            "https://issuer.example/token?key=value",
        ] {
            assert!(
                OAuthClientConfiguration::from_trusted_endpoints(
                    template.issuer.clone(),
                    template.authorization_endpoint.clone(),
                    url(endpoint),
                    template.resource.clone(),
                    template.client_id.clone(),
                    template.scopes.clone(),
                )
                .is_err()
            );
        }
        for scopes in [
            vec!["duplicate".to_owned(); 2],
            vec!["two scopes".to_owned()],
            vec!["".to_owned()],
        ] {
            assert!(validate_scopes(&scopes).is_err());
        }
        assert!(
            template
                .clone()
                .with_authorization_timeout(Duration::ZERO)
                .is_err()
        );
        assert!(
            template
                .with_max_access_token_lifetime(Duration::from_secs(86_401))
                .is_err()
        );
    }

    #[test]
    fn token_media_admission_does_not_follow_or_decode_other_representations() {
        let valid = vec![(
            "Content-Type".to_owned(),
            "application/json; charset=utf-8".to_owned(),
        )];
        assert!(validate_token_headers(&valid).is_ok());
        let mut safe_cache = valid.clone();
        safe_cache.extend([
            ("Cache-Control".to_owned(), "no-store".to_owned()),
            ("cache-control".to_owned(), "private".to_owned()),
            ("Pragma".to_owned(), "no-cache".to_owned()),
        ]);
        assert!(validate_token_headers(&safe_cache).is_ok());
        for directive in ["public", "max-age=0", "no-store=1", "vendor=\"unterminated"] {
            let mut unsafe_cache = safe_cache.clone();
            unsafe_cache[2].1 = directive.to_owned();
            assert_eq!(
                validate_token_headers(&unsafe_cache),
                Err(OAuthError::InvalidTokenResponse)
            );
        }
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
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().expect("caller-owned runtime context");
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
                    let query = encode_form(&[
                        ("state", &current.state().unwrap()),
                        ("iss", &config.issuer),
                        ("code", "live-code"),
                    ])
                    .unwrap();
                    let request =
                        format!("GET {CALLBACK_PATH}?{query} HTTP/1.1\r\nHost: {address}\r\n\r\n");
                    let mut peer = within(&cx, deadline, async {
                        TcpStream::connect(address)
                            .await
                            .map_err(|_| OAuthError::CallbackRejected)
                    })
                    .await
                    .unwrap();
                    within(&cx, deadline, async {
                        peer.write_all(request.as_bytes())
                            .await
                            .map_err(|_| OAuthError::CallbackRejected)
                    })
                    .await
                    .unwrap();
                    peers.push(peer);
                }
                let code = wait_for_code(&cx, deadline, &listener, address, &attempt, &config)
                    .await
                    .unwrap();
                assert_eq!(code, "live-code");
                for (index, mut peer) in peers.into_iter().enumerate() {
                    let mut reply = Vec::new();
                    within(&cx, deadline, async {
                        peer.read_to_end(&mut reply)
                            .await
                            .map_err(|_| OAuthError::CallbackRejected)
                    })
                    .await
                    .unwrap();
                    let reply = String::from_utf8(reply).unwrap();
                    assert!(reply.starts_with(if index == 0 {
                        "HTTP/1.1 400"
                    } else {
                        "HTTP/1.1 200"
                    }));
                    assert!(!reply.contains("live-code"));
                }
                // Observe OUR listener directly rather than the port namespace.
                // See `assert_listener_drained` for why the port probe was wrong
                // here specifically.
                assert_listener_drained(&listener);
                drop(listener);
            });
    }

    #[test]
    fn callback_deadline_releases_idle_work_without_needing_peer_traffic() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().expect("caller-owned runtime context");
                let setup_deadline = operation_deadline(&cx, Duration::from_secs(10)).unwrap();
                let listener = within(&cx, setup_deadline, bind_loopback()).await.unwrap();
                let address = listener.local_addr().unwrap();
                let attempt = AuthorizationAttempt::new().unwrap();
                let deadline = operation_deadline(&cx, Duration::from_millis(20)).unwrap();
                let outcome =
                    wait_for_code(&cx, deadline, &listener, address, &attempt, &config()).await;
                assert_eq!(outcome, Err(OAuthError::TimedOut));
                // No port probe here. This test binds and drops its own listener, so
                // its release is guaranteed by ownership, not by anything
                // `wait_for_code` does - see `assert_listener_drained`. The subject of
                // this test is the deadline expiring without peer traffic, which the
                // `TimedOut` assertion above proves completely. A port probe could
                // only ever add a false positive.
                drop(listener);
            });
    }

    /// Observes THIS listener directly: no further connection is pending on it.
    ///
    /// # Why the port probe was the wrong instrument in the tests that use this
    ///
    /// A bind probe asks a question about the **port namespace**, which is shared
    /// with every other test in this binary. That is the right question when the
    /// listener is owned by something we cannot inspect - the `authorize` future
    /// in `dropping_public_login_future_closes_its_bound_callback_listener` - and
    /// it stays a bind probe there.
    ///
    /// It is the wrong question when the TEST itself binds and drops the
    /// listener, as the two callers of this helper do. There, release is
    /// guaranteed by ownership: `wait_for_code` takes `&TcpListener`, so the
    /// borrow checker forbids it retaining one, and `asupersync`'s `TcpListener`
    /// has no `Drop` of its own and closes its `std::net::TcpListener` descriptor
    /// synchronously. A port probe in that position cannot fail for a real
    /// reason - only when a concurrent test wins the freed ephemeral port, which
    /// is what happened in wave-12b.
    ///
    /// A probe that can only produce false positives is worse than no probe: it
    /// fails on schedule, gets dismissed as flake, and trains everyone to ignore
    /// the one time it means something.
    ///
    /// So this asks a question about **our own listener** instead, which no other
    /// test can influence: after `wait_for_code` has taken what it needed, is
    /// anything still queued on it? That is race-free, and it is an OAuth
    /// property rather than a restatement of Rust ownership.
    ///
    /// The probe mints its own context. `poll_accept` returns
    /// `Ready(Err(Interrupted))` whenever the ambient `Cx` is cancelled, before
    /// it looks at the accept queue, so a probe inheriting a cancelled caller
    /// would report a pending connection that does not exist. `Cx::clone` would
    /// not do - it is an alias sharing the cancelled domain.
    fn assert_listener_drained(listener: &TcpListener) {
        let _frame = Cx::set_current(Some(Cx::for_request()));
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        match listener.poll_accept(&mut task) {
            std::task::Poll::Pending => {}
            std::task::Poll::Ready(Ok((_stream, peer))) => panic!(
                "a connection from {peer} is still queued after the callback was resolved; \
                 wait_for_code must consume exactly the connections it admits"
            ),
            std::task::Poll::Ready(Err(error)) => panic!(
                "the drained-listener probe is INCONCLUSIVE ({error}); it proves neither that \
                 the listener is quiet nor that a connection is pending"
            ),
        }
    }

    /// Asserts the loopback callback listener at `address` is CLOSED, not merely
    /// that its port is unreachable.
    ///
    /// These are different claims. A `TcpStream::connect` that fails proves only
    /// that nobody answered; a connect that SUCCEEDS proves only that *somebody*
    /// is listening, never that *our* listener is. This is a lib unit test
    /// sharing one binary with ~800 others, ~100 of which bind ephemeral loopback
    /// ports in parallel, so a port freed a microsecond earlier can be handed
    /// straight to a concurrent test and satisfy a connect against a listener
    /// that has nothing to do with OAuth.
    ///
    /// Binding the same address inverts the evidence: a successful bind proves
    /// NOBODY is listening, which is direct proof the descriptor was closed, and
    /// it reclaims the port so no concurrent test can occupy it mid-observation.
    /// A genuine leak still fails here and fails harder - deterministic
    /// `AddrInUse` instead of a probabilistic connect.
    ///
    /// DO NOT add `SO_REUSEADDR` or `SO_REUSEPORT` to this bind. `SO_REUSEADDR`
    /// only permits rebinding a port left in `TIME_WAIT` by an already-closed
    /// socket; it does NOT permit two live listeners on one port, and that
    /// refusal is the entire mechanism of this probe. `SO_REUSEPORT` does permit
    /// exactly that, so setting it would let a leaked listener coexist with the
    /// probe bind and silently turn this proof into a no-op.
    ///
    /// No sleep and no timing tolerance: the close is synchronous in `Drop`, so
    /// there is nothing to wait for and a tolerance would hide the very leak
    /// being tested. The release case does run the whole experiment more than
    /// once, but that is independent sampling on a fresh port each time, not a
    /// re-observation of one port after a delay - see `RELEASE_TRIALS`.
    /// Positive control for [`probe_listener_released`], run while the login
    /// future is still alive, in every trial.
    ///
    /// Without it the release probe is vacuous in one direction: a bind that
    /// succeeds after the drop proves the port is free, but not that this
    /// listener ever held it. A callback that was never bound, or an address
    /// parsed out of the wrong field, would make the release probe pass while
    /// proving nothing. This establishes that the probe can detect *this*
    /// listener on *this* port, so the later success is a state change rather
    /// than a constant.
    ///
    /// This direction cannot be stolen by a concurrent test: we hold the port.
    fn assert_listener_bound(address: SocketAddr) {
        match std::net::TcpListener::bind(address) {
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Ok(listener) => {
                drop(listener);
                panic!(
                    "{address} was bindable while the login future was still alive, so the \
                     release probe cannot prove anything: either the callback listener was \
                     never bound or this is not the address it bound"
                );
            }
            Err(error) => panic!(
                "the bind control for {address} is INCONCLUSIVE ({error}); it establishes \
                 neither that the callback listener holds the port nor that it does not"
            ),
        }
    }

    /// Asserts the callback listener at `address` is CLOSED.
    ///
    /// SYNCHRONOUS ON PURPOSE, and this is the whole robustness argument.
    ///
    /// The previous form awaited `asupersync::net::TcpListener::bind`. That
    /// `.await` is a scheduling point: between `drop(login)` closing the
    /// descriptor and the bind syscall reaching the kernel, the runtime polls
    /// other tasks and the harness's other threads get a full async round trip
    /// in which to claim the just-freed ephemeral port. This binary runs ~655
    /// tests, ~100 of which bind ephemeral loopback ports, so that window was
    /// routinely lost: the probe reported `AddrInUse` and that failure was
    /// indistinguishable from the leak it exists to catch. A test that only
    /// passes in isolation lies in every wave.
    ///
    /// `std::net::TcpListener::bind` removes the await entirely - the drop and
    /// the bind become straight-line code in one task with no yield between
    /// them. This does not make theft impossible, since other OS threads still
    /// run, but it removes the structural cause instead of tolerating the
    /// symptom, and it costs no sleep and no timing tolerance. What remains of
    /// the theft window is closed by independent repetition, not by waiting -
    /// see `RELEASE_TRIALS`, and note that repeating the whole experiment on a
    /// new port is a different thing from re-observing this one. The
    /// close is synchronous: the listener is a local of the dropped `authorize`
    /// future, asupersync's `TcpListener` has no `Drop` of its own, and its
    /// `std::net::TcpListener` closes the descriptor in `Drop`. There is
    /// nothing to wait for.
    ///
    /// DO NOT reintroduce an `.await` between the drop and this bind, and DO
    /// NOT add `SO_REUSEADDR` or `SO_REUSEPORT`. `SO_REUSEADDR` only permits
    /// rebinding a port left in `TIME_WAIT` by an already-closed socket and
    /// that refusal is the entire mechanism; `SO_REUSEPORT` permits two live
    /// listeners on one port, which would let a leaked listener coexist with
    /// this bind and silently turn the proof into a no-op.
    ///
    /// The ambiguous arm still fails closed. It is narrower than it was, not
    /// gone, so it names both hypotheses rather than asserting either.
    /// What one release trial observed. `StillBound` is deliberately NOT a
    /// panic: a single trial cannot distinguish a leak from a stolen port, and
    /// the caller resolves that by repeating the whole experiment.
    #[derive(Debug, PartialEq, Eq)]
    enum ReleaseTrial {
        /// The bind succeeded, so nothing holds the port. The descriptor was
        /// closed. One such observation is conclusive on its own.
        Released,
        /// The port was still held. Either the listener leaked or a concurrent
        /// ephemeral bind won it inside the straight-line window.
        StillBound,
    }

    /// Number of independent release trials before a leak is declared.
    ///
    /// Sized against the two hypotheses, not against a clock. A leaked listener
    /// fails EVERY trial - the close is unconditional, so a leak is not a
    /// probabilistic event. A thief must win a fresh, kernel-assigned ephemeral
    /// port on each trial; the probability of that happening five times running
    /// is the per-trial probability raised to the fifth power. Five is where
    /// theft stops being a plausible explanation for a total failure while the
    /// cost stays at a few binds and no sleep at all.
    const RELEASE_TRIALS: usize = 5;

    /// Runs ONE release trial and reports what it saw.
    ///
    /// Everything the old assertion did, it still does: `std::net`'s blocking
    /// bind with no `.await` between the drop and the syscall, no sleep, no
    /// timing tolerance, no `SO_REUSEADDR`, no `SO_REUSEPORT`. The observation
    /// is byte-for-byte the same question. What changed is only who answers it:
    /// this reports `StillBound` instead of panicking, because that single
    /// observation is genuinely ambiguous and the ambiguity is resolvable by
    /// repetition rather than by tolerance.
    ///
    /// The distinction matters and is not a retry in the forbidden sense. A
    /// retry would re-observe THE SAME port after a delay, which is exactly the
    /// tolerance that would hide a slow close. This instead re-runs the entire
    /// experiment from a fresh `authorize` on a fresh ephemeral port, so each
    /// trial is an independent sample of the same property.
    ///
    /// The unexpected-errno arm still fails immediately and is never retried:
    /// an unrecognised error is not a race, and repeating it would only convert
    /// a clear diagnostic into a confusing one.
    fn probe_listener_released(address: SocketAddr) -> ReleaseTrial {
        match std::net::TcpListener::bind(address) {
            Ok(listener) => {
                drop(listener);
                ReleaseTrial::Released
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => ReleaseTrial::StillBound,
            Err(error) => panic!(
                "the bind probe for {address} is INCONCLUSIVE ({error}); it proves neither \
                 closure nor a leak and must not be read as either"
            ),
        }
    }

    pub(super) fn renewable_grant(config: &OAuthClientConfiguration) -> OAuthCredentials {
        admit_token_response(config, &config.scopes,
            br#"{"access_token":"access-one","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-one"}"#,
            Instant::now(),
        ).unwrap()
    }

    #[test]
    fn native_refresh_effect_refusal_preserves_custody_and_allowed_tls_rotation() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap()
            .block_on(async {
                let healthy = Cx::current().unwrap();
                let deadline = operation_deadline(&healthy, Duration::from_secs(10)).unwrap();
                let listener = within(&healthy, deadline, bind_loopback()).await.unwrap();
                let mut configuration = config().with_extra_root_certificate(test_root()).unwrap();
                configuration.token_endpoint =
                    url(&format!("https://{}/token", listener.local_addr().unwrap()));
                let client = OAuthClient::new(configuration.clone());
                let mut grant = renewable_grant(&configuration);
                let original = grant.access.clone();
                let expiry = grant.expires_at;
                let scopes = grant.scopes.clone();
                let foreign = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
                foreign.set_cancel_requested(true);

                for (mask, expected) in [
                    (
                        CapSet::<true, true, true, false, true>::MASK,
                        OAuthError::RuntimeCapabilityUnavailable,
                    ),
                    (
                        CapSet::<true, false, true, true, true>::MASK,
                        OAuthError::RuntimeTimerUnavailable,
                    ),
                ] {
                    for restrict_explicit in [false, true] {
                        let caller = held_effects(
                            &healthy,
                            if restrict_explicit { mask } else { CapMask::all() },
                        );
                        let ambient = held_effects(
                            &foreign,
                            if restrict_explicit { CapMask::all() } else { mask },
                        );
                        let mut refresh = Box::pin(client.refresh(&caller, &mut grant));
                        let result = poll_fn(|task| {
                            poll_under_ambient(refresh.as_mut(), task, &ambient)
                        })
                        .await;
                        drop(refresh);
                        assert_eq!(result, Err(expected));
                        assert_eq!(grant.refresh_token.as_deref(), Some("refresh-one"));
                        assert_eq!(grant.expires_at, expiry);
                        assert_eq!(grant.scopes, scopes);
                        assert_eq!(grant.configuration, configuration);
                        assert!(!original.is_revoked());
                        assert_eq!(
                            grant.access.authorization_for_target(&configuration.resource),
                            Some("Bearer access-one".to_owned()),
                        );
                        assert_listener_drained(&listener);
                    }
                }

                // The same unconsumed grant can still rotate over the real TLS
                // endpoint. Only the ambient I/O/time allowance changes.
                let ambient = held_effects(
                    &foreign,
                    CapSet::<false, true, true, true, false>::MASK,
                );
                let acceptor = test_acceptor();
                let server = within(&healthy, deadline, async {
                    let (socket, _) = listener
                        .accept()
                        .await
                        .map_err(|_| OAuthError::TransportFailed)?;
                    let mut tls = acceptor
                        .accept(socket)
                        .await
                        .map_err(|_| OAuthError::TransportFailed)?;
                    let (head, fields) = read_token_request(&mut tls).await?;
                    assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
                    assert_eq!(fields["grant_type"], "refresh_token");
                    assert_eq!(fields["refresh_token"], "refresh-one");
                    assert_eq!(fields["resource"], configuration.resource.as_str());
                    let body = r#"{"access_token":"access-two","token_type":"Bearer","expires_in":120,"refresh_token":"refresh-two","scope":"tools:read"}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
                        body.len(),
                    );
                    tls.write_all(response.as_bytes())
                        .await
                        .map_err(|_| OAuthError::TransportFailed)?;
                    tls.shutdown().await.map_err(|_| OAuthError::TransportFailed)?;
                    Ok(())
                });
                let mut refresh = Box::pin(client.refresh(&healthy, &mut grant));
                let refreshing = poll_fn(|task| {
                    poll_under_ambient(refresh.as_mut(), task, &ambient)
                });
                let (result, served) = Box::pin(pair(refreshing, server)).await;
                drop(refresh);
                assert_eq!(served, Ok(()));
                assert_eq!(result, Ok(()));
                assert_eq!(grant.refresh_token.as_deref(), Some("refresh-two"));
                assert_eq!(grant.scopes, ["tools:read".to_owned()]);
                assert_eq!(
                    grant.access.authorization_for_target(&configuration.resource),
                    Some("Bearer access-two".to_owned()),
                );
                assert!(!original.is_revoked());
                assert!(!healthy.is_cancel_requested());
                assert_listener_drained(&listener);
            });
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
        assert_eq!(
            grant.access.authorization_for_target(&config.resource),
            Some("Bearer access-two".to_owned())
        );
        let (body, previous) = client.prepare_refresh(&mut grant).unwrap();
        let fields = decode_form(&body).unwrap();
        assert_eq!(fields["refresh_token"], "refresh-two");
        assert_eq!(fields["scope"], "tools:read");
        let invalid = client.admit_refresh(
            &grant,
            previous,
            br#"{"access_token":"access-three","token_type":"Bearer","scope":"tools:write"}"#,
            Instant::now(),
        );
        assert_eq!(invalid.err(), Some(OAuthError::ScopeExpansion));
        assert!(!grant.has_refresh_token());
        assert_eq!(
            grant.access.authorization_for_target(&config.resource),
            Some("Bearer access-two".to_owned())
        );
    }

    #[test]
    fn refresh_admission_requires_a_distinct_public_client_successor() {
        let config = config();
        let client = OAuthClient::new(config.clone());
        for response in [
            br#"{"access_token":"access-two","token_type":"Bearer","expires_in":120}"#.as_slice(),
            br#"{"access_token":"access-two","token_type":"Bearer","expires_in":120,"refresh_token":"refresh-one"}"#,
            br#"{"access_token":"access-two","token_type":"Bearer","expires_in":120,"refresh_token":""}"#,
            br#"{"access_token":"access-two","token_type":"Bearer","expires_in":120,"refresh_token":null}"#,
        ] {
            let mut grant = renewable_grant(&config);
            let (_, previous) = client.prepare_refresh(&mut grant).unwrap();
            assert_eq!(
                client.admit_refresh(&grant, previous, response, Instant::now()).err(),
                Some(OAuthError::InvalidTokenResponse)
            );
            assert!(!grant.has_refresh_token());
        }
        // Initial authorization remains allowed to issue a nonrenewable grant.
        let initial = admit_token_response(
            &config,
            &config.scopes,
            br#"{"access_token":"access-only","token_type":"Bearer","expires_in":120}"#,
            Instant::now(),
        )
        .unwrap();
        assert!(!initial.has_refresh_token());
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
            assert_eq!(
                OAuthClient::new(other).prepare_refresh(&mut grant).err(),
                Some(OAuthError::CredentialBindingMismatch)
            );
            assert_eq!(grant.refresh_token.as_deref(), Some("refresh-one"));
            assert_eq!(
                grant.access.authorization_for_target(&config.resource),
                access_before
            );
            assert_eq!(grant.expires_at, expiry_before);
        }
        grant.access.revoke();
        assert_eq!(
            OAuthClient::new(config).prepare_refresh(&mut grant).err(),
            Some(OAuthError::RefreshUnavailable)
        );
        assert_eq!(grant.refresh_token.as_deref(), Some("refresh-one"));
        assert_eq!(grant.expires_at, expiry_before);
    }

    #[test]
    fn abandoned_refresh_custody_cannot_replay_the_previous_refresh_token() {
        let config = config();
        let client = OAuthClient::new(config.clone());
        let mut grant = renewable_grant(&config);
        let access_before = grant.access.authorization_for_target(&config.resource);
        let expiry_before = grant.expires_at;
        // Preparation transfers refresh bytes. The public driver immediately
        // adds access quarantine before its first await; this helper-level
        // check proves the consumed refresh token alone cannot be restored.
        drop(client.prepare_refresh(&mut grant).unwrap());
        assert_eq!(
            client.prepare_refresh(&mut grant).err(),
            Some(OAuthError::RefreshUnavailable)
        );
        assert_eq!(
            grant.access.authorization_for_target(&config.resource),
            access_before
        );
        assert_eq!(grant.expires_at, expiry_before);
        assert!(!grant.has_refresh_token());
    }

    // TEST ONLY credentials. The CA and localhost leaf are valid 2020-2049;
    // none of these keys are used outside this in-process TLS fixture.
    const TEST_ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
    const TEST_LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
    const TEST_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

    pub(super) fn test_root() -> asupersync::tls::Certificate {
        asupersync::tls::Certificate::from_pem(TEST_ROOT)
            .unwrap()
            .remove(0)
    }

    pub(super) fn test_acceptor() -> asupersync::tls::TlsAcceptor {
        asupersync::tls::TlsAcceptorBuilder::new(
            asupersync::tls::CertificateChain::from_pem(TEST_LEAF).unwrap(),
            asupersync::tls::PrivateKey::from_pem(TEST_KEY).unwrap(),
        )
        .alpn_protocols(vec![b"http/1.1".to_vec()])
        .build()
        .unwrap()
    }

    pub(super) async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
        let mut left = std::pin::pin!(left);
        let mut right = std::pin::pin!(right);
        let mut left_output = None;
        let mut right_output = None;
        poll_fn(|task| {
            if left_output.is_none() {
                if let Poll::Ready(value) = left.as_mut().poll(task) {
                    left_output = Some(value);
                }
            }
            if right_output.is_none() {
                if let Poll::Ready(value) = right.as_mut().poll(task) {
                    right_output = Some(value);
                }
            }
            if left_output.is_some() && right_output.is_some() {
                Poll::Ready((left_output.take().unwrap(), right_output.take().unwrap()))
            } else {
                Poll::Pending
            }
        })
        .await
    }

    pub(super) async fn read_token_request<IO: asupersync::io::AsyncRead + Unpin>(
        stream: &mut IO,
    ) -> Result<(String, BTreeMap<String, String>), OAuthError> {
        let mut wire = Vec::new();
        let mut buffer = [0; 1024];
        let head_end = loop {
            let count = stream
                .read(&mut buffer)
                .await
                .map_err(|_| OAuthError::TransportFailed)?;
            if count == 0 || wire.len() + count > MAX_FORM_BYTES {
                return Err(OAuthError::TransportFailed);
            }
            wire.extend_from_slice(&buffer[..count]);
            if let Some(index) = wire.windows(4).position(|part| part == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let head = std::str::from_utf8(&wire[..head_end])
            .map_err(|_| OAuthError::TransportFailed)?
            .to_owned();
        let count = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .ok_or(OAuthError::TransportFailed)?;
        if count > MAX_FORM_BYTES - head_end {
            return Err(OAuthError::TransportFailed);
        }
        while wire.len() < head_end + count {
            let n = stream
                .read(&mut buffer)
                .await
                .map_err(|_| OAuthError::TransportFailed)?;
            if n == 0 || wire.len() + n > MAX_FORM_BYTES {
                return Err(OAuthError::TransportFailed);
            }
            wire.extend_from_slice(&buffer[..n]);
        }
        if wire.len() != head_end + count {
            return Err(OAuthError::TransportFailed);
        }
        let form =
            std::str::from_utf8(&wire[head_end..]).map_err(|_| OAuthError::TransportFailed)?;
        Ok((head, decode_form(form)?))
    }

    async fn send_callback(
        cx: &Cx,
        authorization: CanonicalHttpUrl,
    ) -> Result<BTreeMap<String, String>, OAuthError> {
        let fields = decode_form(authorization.query().ok_or(OAuthError::CallbackRejected)?)?;
        let callback = CanonicalHttpUrl::parse(&fields["redirect_uri"])
            .map_err(|_| OAuthError::CallbackRejected)?;
        let address: SocketAddr = callback
            .as_str()
            .strip_prefix("http://")
            .unwrap()
            .split('/')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let query = encode_form(&[
            ("code", "issued-code"),
            ("iss", "https://issuer.example"),
            ("state", &fields["state"]),
        ])?;
        let request = format!("GET {CALLBACK_PATH}?{query} HTTP/1.1\r\nHost: {address}\r\n\r\n");
        let deadline = operation_deadline(cx, Duration::from_secs(10))?;
        within(cx, deadline, async {
            let mut stream = TcpStream::connect(address)
                .await
                .map_err(|_| OAuthError::CallbackRejected)?;
            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|_| OAuthError::CallbackRejected)?;
            Ok(())
        })
        .await?;
        Ok(fields)
    }

    #[test]
    fn native_https_login_and_refresh_verify_pkce_and_rotate_the_live_grant() {
        asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let deadline = operation_deadline(&cx, Duration::from_secs(20)).unwrap();
            let listener = within(&cx, deadline, bind_loopback()).await.unwrap();
            let address = listener.local_addr().unwrap();
            let mut configuration = config().with_extra_root_certificate(test_root()).unwrap();
            configuration.token_endpoint = url(&format!("https://{address}/token"));
            let client = OAuthClient::new(configuration.clone());
            let browser = std::sync::Mutex::new(None::<BTreeMap<String, String>>);
            let acceptor = test_acceptor();
            let server = within(&cx, deadline, async {
                for index in 0..2 {
                    let (socket, _) = listener.accept().await.map_err(|_| OAuthError::TransportFailed)?;
                    let mut tls = acceptor.accept(socket).await.map_err(|_| OAuthError::TransportFailed)?;
                    let (head, form) = read_token_request(&mut tls).await?;
                    assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
                    assert!(!head.to_ascii_lowercase().contains("authorization:"));
                    assert!(!head.to_ascii_lowercase().contains("cookie:"));
                    assert_eq!(form["client_id"], "native-client");
                    assert_eq!(form["resource"], "https://mcp.example/mcp");
                    let body = if index == 0 {
                        let observed = browser.lock().unwrap();
                        let observed = observed.as_ref().unwrap();
                        assert_eq!(form["grant_type"], "authorization_code");
                        assert_eq!(form["code"], "issued-code");
                        assert_eq!(pkce_challenge(&form["code_verifier"]).unwrap(), observed["code_challenge"]);
                        assert_eq!(form["redirect_uri"], observed["redirect_uri"]);
                        r#"{"access_token":"live-access-one","token_type":"Bearer","expires_in":600,"refresh_token":"live-refresh-one"}"#
                    } else {
                        assert_eq!(form["grant_type"], "refresh_token");
                        assert_eq!(form["refresh_token"], "live-refresh-one");
                        assert!(!form.contains_key("code_verifier"));
                        r#"{"access_token":"live-access-two","token_type":"Bearer","expires_in":300,"refresh_token":"live-refresh-two","scope":"tools:read"}"#
                    };
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}", body.len());
                    tls.write_all(response.as_bytes()).await.map_err(|_| OAuthError::TransportFailed)?;
                    tls.shutdown().await.map_err(|_| OAuthError::TransportFailed)?;
                }
                Ok(())
            });
            let application = async {
                let caller = &cx;
                let observed_browser = &browser;
                let mut credentials = client.authorize(&cx, |authorization| async move {
                    let fields = send_callback(caller, authorization).await?;
                    *observed_browser.lock().unwrap() = Some(fields);
                    Ok(())
                }).await?;
                assert_eq!(credentials.access.authorization_for_target(&configuration.resource), Some("Bearer live-access-one".to_owned()));
                client.refresh(&cx, &mut credentials).await?;
                assert_eq!(credentials.access.authorization_for_target(&configuration.resource), Some("Bearer live-access-two".to_owned()));
                assert_eq!(credentials.refresh_token.as_deref(), Some("live-refresh-two"));
                assert_eq!(credentials.scopes, ["tools:read".to_owned()]);
                Ok::<(), OAuthError>(())
            };
            let (server, application) = Box::pin(pair(server, application)).await;
            assert_eq!(server, Ok(()));
            assert_eq!(application, Ok(()));
        });
    }

    #[test]
    fn native_callback_refuses_mixed_credentials_before_one_valid_redemption() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let deadline = operation_deadline(&cx, Duration::from_secs(20)).unwrap();
                let listener = within(&cx, deadline, bind_loopback()).await.unwrap();
                let mut configuration = config()
                    .with_extra_root_certificate(test_root())
                    .unwrap()
                    .with_authorization_timeout(Duration::from_secs(20))
                    .unwrap();
                configuration.token_endpoint =
                    url(&format!("https://{}/token", listener.local_addr().unwrap()));
                let client = OAuthClient::new(configuration.clone());
                let acceptor = test_acceptor();
                let valid_callback_sent = AtomicBool::new(false);
                let token_posts = AtomicUsize::new(0);
                let (launch_sender, mut launch_receiver) = oneshot::channel();
                let application = client.authorize(&cx, |authorization| async move {
                    launch_sender
                        .send(authorization)
                        .map_err(|_| OAuthError::BrowserLaunchFailed)?;
                    Ok(())
                });
                let browser = within(&cx, deadline, async {
                    let authorization: CanonicalHttpUrl = launch_receiver
                        .recv(&cx)
                        .await
                        .map_err(|_| OAuthError::BrowserLaunchFailed)?;
                    let fields = decode_form(authorization.query().unwrap())?;
                    let callback = CanonicalHttpUrl::parse(&fields["redirect_uri"])
                        .map_err(|_| OAuthError::CallbackRejected)?;
                    let address: SocketAddr = callback
                        .as_str()
                        .strip_prefix("http://")
                        .unwrap()
                        .split('/')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    let query = encode_form(&[
                        ("code", "issued-code"),
                        ("iss", &configuration.issuer),
                        ("state", &fields["state"]),
                    ])?;
                    let rejected = [
                        "&access_token=private-canary",
                        "&refresh_token=private-canary",
                        "&id_token=private-canary",
                        "&token_type=Bearer",
                        "&client_secret=private-canary",
                        "&client_assertion=private-canary",
                        "&a%63cess_token=private-canary",
                        "&error_description=private-canary",
                        "&error_%75ri=private-canary",
                    ];
                    for suffix in rejected {
                        let request = format!(
                            "GET {CALLBACK_PATH}?{query}{suffix} HTTP/1.1\r\nHost: {address}\r\n\r\n"
                        );
                        let mut socket = TcpStream::connect(address)
                            .await
                            .map_err(|_| OAuthError::CallbackRejected)?;
                        socket
                            .write_all(request.as_bytes())
                            .await
                            .map_err(|_| OAuthError::CallbackRejected)?;
                        let mut response = Vec::new();
                        let mut buffer = [0_u8; 1024];
                        loop {
                            let count = socket
                                .read(&mut buffer)
                                .await
                                .map_err(|_| OAuthError::CallbackRejected)?;
                            if count == 0 {
                                break;
                            }
                            if response.len() + count > 4096 {
                                return Err(OAuthError::CallbackRejected);
                            }
                            response.extend_from_slice(&buffer[..count]);
                        }
                        let response = std::str::from_utf8(&response).unwrap();
                        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{suffix}");
                        assert!(!response.contains("private-canary"));
                        assert!(!response.contains(&fields["state"]));
                        assert_eq!(token_posts.load(Ordering::SeqCst), 0, "{suffix}");
                    }
                    // A rejected callback cannot consume the pending login.
                    // Bounded inert duplicate fields on the valid callback
                    // must not prevent its single code redemption.
                    valid_callback_sent.store(true, Ordering::SeqCst);
                    let request = format!(
                        "GET {CALLBACK_PATH}?{query}&vendor=one&v%65ndor=two HTTP/1.1\r\nHost: {address}\r\n\r\n"
                    );
                    let mut socket = TcpStream::connect(address)
                        .await
                        .map_err(|_| OAuthError::CallbackRejected)?;
                    socket
                        .write_all(request.as_bytes())
                        .await
                        .map_err(|_| OAuthError::CallbackRejected)?;
                    Ok(())
                });
                let server = within(&cx, deadline, async {
                    let (socket, _) = listener
                        .accept()
                        .await
                        .map_err(|_| OAuthError::TransportFailed)?;
                    assert!(
                        valid_callback_sent.load(Ordering::SeqCst),
                        "a rejected callback must not contact the token endpoint",
                    );
                    let mut tls = acceptor
                        .accept(socket)
                        .await
                        .map_err(|_| OAuthError::TransportFailed)?;
                    let (head, form) = read_token_request(&mut tls).await?;
                    assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
                    assert_eq!(form["grant_type"], "authorization_code");
                    assert_eq!(form["code"], "issued-code");
                    assert_eq!(form["client_id"], "native-client");
                    assert_eq!(form["resource"], configuration.resource.as_str());
                    assert!(!form.contains_key("vendor"));
                    assert!(!head.contains("private-canary"));
                    assert!(form.values().all(|value| !value.contains("private-canary")));
                    token_posts.fetch_add(1, Ordering::SeqCst);
                    let body = r#"{"access_token":"live-access","token_type":"Bearer","expires_in":600}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
                        body.len(),
                    );
                    tls.write_all(response.as_bytes())
                        .await
                        .map_err(|_| OAuthError::TransportFailed)?;
                    tls.shutdown().await.map_err(|_| OAuthError::TransportFailed)?;
                    Ok(())
                });
                let (served, (authorized, browser)) =
                    Box::pin(pair(server, Box::pin(pair(application, browser)))).await;
                assert_eq!(served, Ok(()));
                assert_eq!(browser, Ok(()));
                let credentials = authorized.expect("the later valid callback must redeem once");
                assert_eq!(
                    credentials.access.authorization_for_target(&configuration.resource),
                    Some("Bearer live-access".to_owned()),
                );
                assert_eq!(token_posts.load(Ordering::SeqCst), 1);
                assert_listener_drained(&listener);
            });
    }

    #[test]
    fn host_https_redirect_callback_rejection_prevents_token_dispatch() {
        asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let deadline = operation_deadline(&cx, Duration::from_secs(20)).unwrap();
            let listener = within(&cx, deadline, bind_loopback()).await.unwrap();
            let mut configuration = config().with_extra_root_certificate(test_root()).unwrap();
            configuration.token_endpoint = url(&format!("https://{}/token", listener.local_addr().unwrap()));
            let client = OAuthClient::new(configuration.clone());
            let redirect = url("https://app.example/oauth/return");
            let retained = std::sync::Mutex::new(None::<String>);
            let calls = std::sync::atomic::AtomicUsize::new(0);
            for case in 0..12 {
                let result = within(&cx, deadline, client.authorize_with_redirect_driver(
                    &cx, redirect.clone(), |authorization| {
                        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let valid = host_callback(&authorization, &configuration.issuer);
                        if case == 0 { *retained.lock().unwrap() = Some(valid.clone()); }
                        let changed = match case {
                            0 => valid.replace("state=", "state=wrong"),
                            1 => host_callback(&authorization, "https://other.example"),
                            2 => valid.replace("/oauth/return?", "/oauth/return/other?"),
                            3 => format!("{valid}&co%64e=other"),
                            4 => format!("{valid}&error=access_denied"),
                            5 => format!("{valid}&error_description=private-canary"),
                            6 => format!("{valid}&id_token=private-canary"),
                            7 => format!("{valid}&unknown=%ff"),
                            8 => format!("{valid}#fragment"),
                            9 => format!("{valid}&unknown={}", "a".repeat(MAX_CALLBACK_BYTES)),
                            10 => retained.lock().unwrap().clone().unwrap(),
                            _ => return std::future::ready(Err(OAuthError::AuthorizationDenied)),
                        };
                        std::future::ready(Ok(changed))
                    },
                )).await;
                let expected = match case {
                    1 => OAuthError::IssuerMismatch,
                    11 => OAuthError::AuthorizationDenied,
                    _ => OAuthError::CallbackRejected,
                };
                assert!(matches!(result, Err(error) if error == expected), "callback case {case}");
                assert_listener_drained(&listener);
            }
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 12);
        });
    }

    #[test]
    fn host_https_redirect_authorization_and_refresh_use_the_bound_pkce_flow() {
        asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let deadline = operation_deadline(&cx, Duration::from_secs(20)).unwrap();
            let listener = within(&cx, deadline, bind_loopback()).await.unwrap();
            let mut configuration = config().with_extra_root_certificate(test_root()).unwrap();
            configuration.token_endpoint = url(&format!("https://{}/token", listener.local_addr().unwrap()));
            let client = OAuthClient::new(configuration.clone());
            let redirect = url("https://app.example/oauth/return");
            let observed = std::sync::Mutex::new(None::<BTreeMap<String, String>>);
            let calls = std::sync::atomic::AtomicUsize::new(0);
            let acceptor = test_acceptor();
            let server = async {
                for index in 0..2 {
                    let (socket, _) = listener.accept().await.map_err(|_| OAuthError::TransportFailed)?;
                    let mut tls = acceptor.accept(socket).await.map_err(|_| OAuthError::TransportFailed)?;
                    let (head, form) = read_token_request(&mut tls).await?;
                    assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
                    assert!(!head.to_ascii_lowercase().contains("authorization:"));
                    assert!(!head.to_ascii_lowercase().contains("cookie:"));
                    assert_eq!(form["client_id"], "native-client");
                    assert_eq!(form["resource"], configuration.resource.as_str());
                    let body = if index == 0 {
                        assert_eq!(form.len(), 6);
                        assert_eq!(form["grant_type"], "authorization_code");
                        assert_eq!(form["code"], "host-issued-code");
                        assert_eq!(form["redirect_uri"], redirect.as_str());
                        let launch = observed.lock().unwrap();
                        assert_eq!(pkce_challenge(&form["code_verifier"]).unwrap(), launch.as_ref().unwrap()["code_challenge"]);
                        r#"{"access_token":"host-access-one","token_type":"Bearer","expires_in":600,"refresh_token":"host-refresh-one"}"#
                    } else {
                        assert_eq!(form["grant_type"], "refresh_token");
                        assert_eq!(form["refresh_token"], "host-refresh-one");
                        assert_eq!(form["scope"], "tools:read tools:write");
                        assert!(!form.contains_key("code_verifier"));
                        assert!(!form.contains_key("redirect_uri"));
                        r#"{"access_token":"host-access-two","token_type":"Bearer","expires_in":300,"refresh_token":"host-refresh-two","scope":"tools:read"}"#
                    };
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}", body.len());
                    tls.write_all(response.as_bytes()).await.map_err(|_| OAuthError::TransportFailed)?;
                    tls.shutdown().await.map_err(|_| OAuthError::TransportFailed)?;
                }
                Ok::<_, OAuthError>(())
            };
            let application = async {
                let mut credentials = client.authorize_with_redirect_driver(&cx, redirect.clone(), |authorization| {
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let fields = decode_form(authorization.query().unwrap()).unwrap();
                    assert_eq!(fields["response_type"], "code");
                    assert_eq!(fields["code_challenge_method"], "S256");
                    assert_eq!(fields["redirect_uri"], redirect.as_str());
                    assert_eq!(fields["client_id"], configuration.client_id);
                    assert_eq!(fields["resource"], configuration.resource.as_str());
                    assert_eq!(fields["scope"], "tools:read tools:write");
                    assert!(!fields.contains_key("code_verifier"));
                    *observed.lock().unwrap() = Some(fields);
                    std::future::ready(Ok(format!("{}&vendor=one&v%65ndor=two", host_callback(&authorization, &configuration.issuer))))
                }).await?;
                let original = credentials.bearer_credential().clone();
                let original_expiry = original.expires_at();
                assert_eq!(original.authorization_for_target(&configuration.resource), Some("Bearer host-access-one".to_owned()));
                client.refresh(&cx, &mut credentials).await?;
                assert!(!original.is_revoked());
                assert_eq!(original.expires_at(), original_expiry);
                assert_eq!(original.authorization_for_target(&configuration.resource), Some("Bearer host-access-one".to_owned()));
                assert_eq!(credentials.access.authorization_for_target(&configuration.resource), Some("Bearer host-access-two".to_owned()));
                assert_eq!(credentials.refresh_token.as_deref(), Some("host-refresh-two"));
                assert_eq!(credentials.scopes, ["tools:read".to_owned()]);
                Ok::<_, OAuthError>(())
            };
            let (server, application) = Box::pin(within(&cx, deadline, async { Ok(Box::pin(pair(server, application)).await) })).await.unwrap();
            assert_eq!(server, Ok(()));
            assert_eq!(application, Ok(()));
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_listener_drained(&listener);
        });
    }

    #[test]
    fn host_https_redirect_redemption_failure_and_interruption_never_replay() {
        for mode in 0..5 {
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
            let caller = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
            runtime.block_on(async {
                let healthy = Cx::current().unwrap();
                let deadline = operation_deadline(&healthy, Duration::from_secs(20)).unwrap();
                let listener = within(&healthy, deadline, bind_loopback()).await.unwrap();
                let mut configuration = config().with_extra_root_certificate(test_root()).unwrap();
                configuration.token_endpoint = url(&format!("https://{}/token", listener.local_addr().unwrap()));
                let client = OAuthClient::new(configuration.clone());
                let redirect = url("https://app.example/oauth/return");
                let retained = std::sync::Mutex::new(None::<String>);
                let posts = std::sync::atomic::AtomicUsize::new(0);
                let acceptor = test_acceptor();
                let (sent, mut received) = oneshot::channel::<()>();
                let server = async {
                    let (socket, _) = listener.accept().await.map_err(|_| OAuthError::TransportFailed)?;
                    let mut tls = acceptor.accept(socket).await.map_err(|_| OAuthError::TransportFailed)?;
                    let (_, form) = read_token_request(&mut tls).await?;
                    posts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    assert_eq!(form["grant_type"], "authorization_code");
                    assert_eq!(form["code"], "host-issued-code");
                    assert_eq!(form["redirect_uri"], redirect.as_str());
                    if mode == 1 {
                        let response = format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", configuration.token_endpoint.as_str());
                        tls.write_all(response.as_bytes()).await.map_err(|_| OAuthError::TransportFailed)?;
                        tls.shutdown().await.map_err(|_| OAuthError::TransportFailed)?;
                    } else if mode == 2 {
                        let body = r#"{"access_token":"private-canary","token_type":"Bearer","id_token":null}"#;
                        let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}", body.len());
                        tls.write_all(response.as_bytes()).await.map_err(|_| OAuthError::TransportFailed)?;
                        tls.shutdown().await.map_err(|_| OAuthError::TransportFailed)?;
                    } else if mode >= 3 {
                        if mode == 3 { caller.set_cancel_requested(true); }
                        else { sent.send(&healthy, ()).map_err(|_| OAuthError::TransportFailed)?; }
                        // A quiet, already-written exchange must release its
                        // owned connection on cancellation or caller drop.
                        let mut byte = [0];
                        assert!(!matches!(tls.read(&mut byte).await, Ok(count) if count > 0));
                    }
                    Ok::<_, OAuthError>(())
                };
                let application = async {
                    let mut flow = Box::pin(client.authorize_with_redirect_driver(&caller, redirect.clone(), |authorization| {
                        let callback = host_callback(&authorization, &configuration.issuer);
                        *retained.lock().unwrap() = Some(callback.clone());
                        std::future::ready(Ok(callback))
                    }));
                    if mode == 4 {
                        let mut signal = std::pin::pin!(received.recv(&healthy));
                        poll_fn(|task| {
                            if let Poll::Ready(result) = signal.as_mut().poll(task) {
                                assert!(result.is_ok());
                                return Poll::Ready(());
                            }
                            assert!(flow.as_mut().poll(task).is_pending(), "quiet redemption completed without a reply");
                            Poll::Pending
                        }).await;
                        drop(flow);
                        None
                    } else {
                        Some(flow.await)
                    }
                };
                let (server, result) = within(&healthy, deadline, async { Ok(Box::pin(pair(server, application)).await) }).await.unwrap();
                assert_eq!(server, Ok(()));
                let expected = match mode {
                    0 => Some(OAuthError::TransportFailed),
                    1 => Some(OAuthError::TokenEndpointRejected),
                    2 => Some(OAuthError::InvalidTokenResponse),
                    3 => Some(OAuthError::Cancelled),
                    _ => None,
                };
                assert_eq!(result.map(|result| result.err().expect("no credentials from a failed redemption")), expected);
                assert_eq!(posts.load(std::sync::atomic::Ordering::SeqCst), 1);
                assert_listener_drained(&listener);
                let callback = retained.lock().unwrap().take().unwrap();
                let replay = client.authorize_with_redirect_driver(&healthy, redirect.clone(), |_| std::future::ready(Ok(callback))).await;
                assert!(matches!(replay, Err(OAuthError::CallbackRejected)));
                assert_listener_drained(&listener);
            });
            drop(caller);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    fn native_token_admission_probe(refresh: bool) {
        for (extension, cacheable, accepted) in [
            (r#""vendor":null"#, false, true),
            (r#""id_token":null"#, false, false),
            (
                r#""issued_token_type":"urn:ietf:params:oauth:token-type:id-jag""#,
                false,
                false,
            ),
            (r#""cnf":{}"#, false, false),
            (r#""error_description":null"#, false, false),
            (r#""error_uri":"https://issuer.example/error""#, false, false),
            (r#""vendor":{"label":1,"l\u0061bel":2}"#, false, false),
            (r#""vendor":null"#, true, false),
        ] {
            asupersync::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap()
                .block_on(async {
                    let cx = Cx::current().unwrap();
                    let deadline = operation_deadline(&cx, Duration::from_secs(20)).unwrap();
                    let listener = within(&cx, deadline, bind_loopback()).await.unwrap();
                    let mut configuration = config()
                        .with_extra_root_certificate(test_root())
                        .unwrap();
                    configuration.token_endpoint =
                        url(&format!("https://{}/token", listener.local_addr().unwrap()));
                    let client = OAuthClient::new(configuration.clone());
                    let acceptor = test_acceptor();
                    let server = within(&cx, deadline, async {
                        let (socket, _) = listener
                            .accept()
                            .await
                            .map_err(|_| OAuthError::TransportFailed)?;
                        let mut tls = acceptor
                            .accept(socket)
                            .await
                            .map_err(|_| OAuthError::TransportFailed)?;
                        let (head, form) = read_token_request(&mut tls).await?;
                        assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
                        assert_eq!(form["client_id"], "native-client");
                        assert_eq!(form["resource"], configuration.resource.as_str());
                        if refresh {
                            assert_eq!(form["grant_type"], "refresh_token");
                            assert_eq!(form["refresh_token"], "refresh-one");
                        } else {
                            assert_eq!(form["grant_type"], "authorization_code");
                            assert_eq!(form["code"], "issued-code");
                            assert!(form.contains_key("code_verifier"));
                        }
                        let body = ordinary_token_response(extension);
                        let unsafe_cache = if cacheable {
                            "Cache-Control: public, max-age=60\r\n"
                        } else {
                            ""
                        };
                        let reply = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n{unsafe_cache}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        tls.write_all(reply.as_bytes())
                            .await
                            .map_err(|_| OAuthError::TransportFailed)?;
                        tls.shutdown()
                            .await
                            .map_err(|_| OAuthError::TransportFailed)?;
                        Ok(())
                    });
                    let application = async {
                        if refresh {
                            let mut credentials = renewable_grant(&configuration);
                            let original = credentials.bearer_credential().clone();
                            let expiry_before = credentials.expires_at();
                            let scopes_before = credentials.scopes().to_vec();
                            let result = Box::pin(client.refresh(&cx, &mut credentials)).await;
                            if accepted {
                                assert_eq!(result, Ok(()));
                                assert_eq!(
                                    credentials.refresh_token.as_deref(),
                                    Some("refresh-two")
                                );
                                assert_eq!(credentials.scopes(), ["tools:read"]);
                                assert_eq!(
                                    credentials
                                        .access
                                        .authorization_for_target(&configuration.resource)
                                        .as_deref(),
                                    Some("Bearer access-two")
                                );
                                assert!(!original.is_revoked());
                                assert_eq!(original.expires_at(), Some(expiry_before));
                            } else {
                                assert_eq!(result, Err(OAuthError::InvalidTokenResponse));
                                assert!(original.is_revoked());
                                assert!(
                                    original.authorization_for_target(&configuration.resource).is_none()
                                );
                                assert!(
                                    credentials
                                        .access
                                        .authorization_for_target(&configuration.resource)
                                        .is_none()
                                );
                                assert!(!credentials.has_refresh_token());
                                assert_eq!(credentials.expires_at(), expiry_before);
                                assert_eq!(credentials.scopes(), scopes_before.as_slice());
                                assert_eq!(
                                    Box::pin(client.refresh(&cx, &mut credentials)).await,
                                    Err(OAuthError::RefreshUnavailable)
                                );
                            }
                        } else {
                            let caller = &cx;
                            let result = Box::pin(client.authorize(
                                &cx,
                                |authorization| async move {
                                    send_callback(caller, authorization).await.map(|_| ())
                                },
                            ))
                            .await;
                            if accepted {
                                let credentials = result.unwrap();
                                assert_eq!(
                                    credentials.refresh_token.as_deref(),
                                    Some("refresh-two")
                                );
                                assert_eq!(credentials.scopes(), ["tools:read"]);
                                assert_eq!(
                                    credentials
                                        .access
                                        .authorization_for_target(&configuration.resource)
                                        .as_deref(),
                                    Some("Bearer access-two")
                                );
                            } else {
                                assert_eq!(result.err(), Some(OAuthError::InvalidTokenResponse));
                            }
                        }
                        assert!(cx.checkpoint().is_ok());
                        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
                        assert!(
                            listener.poll_accept(&mut task).is_pending(),
                            "a token response cannot authorize automatic replay"
                        );
                    };
                    let (server, ()) = Box::pin(pair(server, application)).await;
                    assert_eq!(server, Ok(()));
                });
        }
    }

    #[test]
    fn native_https_code_exchange_rejects_cross_profile_token_responses() {
        native_token_admission_probe(false);
    }

    #[test]
    fn native_https_refresh_rejects_cross_profile_responses_and_quarantines_family() {
        native_token_admission_probe(true);
    }

    #[test]
    fn native_https_rejects_untrusted_certificate_before_sending_the_code() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let deadline = operation_deadline(&cx, Duration::from_secs(20)).unwrap();
                let listener = within(&cx, deadline, bind_loopback()).await.unwrap();
                let mut configuration = config();
                configuration.token_endpoint =
                    url(&format!("https://{}/token", listener.local_addr().unwrap()));
                // The only changed trust dimension: do not install the test root.
                let client = OAuthClient::new(configuration);
                let acceptor = test_acceptor();
                let server = within(&cx, deadline, async {
                    let (socket, _) = listener
                        .accept()
                        .await
                        .map_err(|_| OAuthError::TransportFailed)?;
                    assert!(
                        acceptor.accept(socket).await.is_err(),
                        "untrusted TLS cannot become an HTTP request stream"
                    );
                    Ok(())
                });
                let caller = &cx;
                let application = client.authorize(&cx, |authorization| async move {
                    send_callback(caller, authorization).await.map(|_| ())
                });
                let (server, application) = Box::pin(pair(server, application)).await;
                assert_eq!(server, Ok(()));
                assert_eq!(application.err(), Some(OAuthError::TransportFailed));
            });
    }

    #[test]
    fn native_https_public_refresh_requires_rotation_and_quarantines_old_access_on_failure() {
        for successor in [Some("refresh-two"), Some("refresh-one"), None, Some("")] {
            asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let deadline = operation_deadline(&cx, Duration::from_secs(20)).unwrap();
                let listener = within(&cx, deadline, bind_loopback()).await.unwrap();
                let mut configuration = config().with_extra_root_certificate(test_root()).unwrap();
                configuration.token_endpoint = url(&format!("https://{}/token", listener.local_addr().unwrap()));
                let client = OAuthClient::new(configuration.clone());
                let mut credentials = renewable_grant(&configuration);
                let original = credentials.bearer_credential().clone();
                let expiry_before = credentials.expires_at();
                let acceptor = test_acceptor();
                let server = within(&cx, deadline, async {
                    let (socket, _) = listener.accept().await.map_err(|_| OAuthError::TransportFailed)?;
                    let mut tls = acceptor.accept(socket).await.map_err(|_| OAuthError::TransportFailed)?;
                    let (head, form) = read_token_request(&mut tls).await?;
                    assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
                    assert!(!head.to_ascii_lowercase().contains("authorization:"));
                    assert_eq!(form["grant_type"], "refresh_token");
                    assert_eq!(form["refresh_token"], "refresh-one");
                    assert_eq!(form["resource"], configuration.resource.as_str());
                    let mut body = serde_json::json!({
                        "access_token": "access-two", "token_type": "Bearer",
                        "expires_in": 120, "scope": "tools:read"
                    });
                    if let Some(successor) = successor {
                        body["refresh_token"] = serde_json::json!(successor);
                    }
                    let body = serde_json::to_string(&body).unwrap();
                    let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    tls.write_all(reply.as_bytes()).await.map_err(|_| OAuthError::TransportFailed)?;
                    tls.shutdown().await.map_err(|_| OAuthError::TransportFailed)?;
                    Ok(())
                });
                let (server, result) = Box::pin(pair(server, client.refresh(&cx, &mut credentials))).await;
                assert_eq!(server, Ok(()));
                if successor == Some("refresh-two") {
                    assert_eq!(result, Ok(()));
                    assert_eq!(credentials.refresh_token.as_deref(), Some("refresh-two"));
                    assert_eq!(credentials.scopes(), ["tools:read"]);
                    assert_eq!(credentials.access.authorization_for_target(&configuration.resource).as_deref(), Some("Bearer access-two"));
                    assert!(!original.is_revoked());
                    assert_eq!(original.expires_at(), Some(expiry_before));
                    assert_eq!(original.authorization_for_target(&configuration.resource).as_deref(), Some("Bearer access-one"));
                } else {
                    assert_eq!(result, Err(OAuthError::InvalidTokenResponse));
                    assert!(original.is_revoked());
                    assert!(original.authorization_for_target(&configuration.resource).is_none());
                    assert!(credentials.access.authorization_for_target(&configuration.resource).is_none());
                    assert_eq!(credentials.expires_at(), expiry_before);
                    assert!(!credentials.has_refresh_token());
                    assert_eq!(client.refresh(&cx, &mut credentials).await, Err(OAuthError::RefreshUnavailable));
                }
                let mut task = std::task::Context::from_waker(std::task::Waker::noop());
                assert!(listener.poll_accept(&mut task).is_pending(), "rotation failure cannot replay the old refresh token");
            });
        }
    }

    #[test]
    fn native_public_refresh_refuses_pre_revoked_access_before_network_or_custody_transfer() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let deadline = operation_deadline(&cx, Duration::from_secs(20)).unwrap();
                let listener = within(&cx, deadline, bind_loopback()).await.unwrap();
                let mut configuration = config().with_extra_root_certificate(test_root()).unwrap();
                configuration.token_endpoint =
                    url(&format!("https://{}/token", listener.local_addr().unwrap()));
                let client = OAuthClient::new(configuration.clone());
                let mut credentials = renewable_grant(&configuration);
                let expiry_before = credentials.expires_at();
                credentials.bearer_credential().clone().revoke();
                assert_eq!(
                    client.refresh(&cx, &mut credentials).await,
                    Err(OAuthError::RefreshUnavailable)
                );
                assert_eq!(credentials.refresh_token.as_deref(), Some("refresh-one"));
                assert_eq!(credentials.expires_at(), expiry_before);
                let mut task = std::task::Context::from_waker(std::task::Waker::noop());
                assert!(listener.poll_accept(&mut task).is_pending());
            });
    }

    #[test]
    fn native_public_refresh_revocation_wakes_a_quiet_exchange_and_retires_its_custody() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let deadline = operation_deadline(&cx, Duration::from_secs(20)).unwrap();
                let listener = within(&cx, deadline, bind_loopback()).await.unwrap();
                let mut configuration = config().with_extra_root_certificate(test_root()).unwrap();
                configuration.token_endpoint =
                    url(&format!("https://{}/token", listener.local_addr().unwrap()));
                let client = OAuthClient::new(configuration.clone());
                let mut credentials = renewable_grant(&configuration);
                let original = credentials.bearer_credential().clone();
                let acceptor = test_acceptor();
                let server = within(&cx, deadline, async {
                    let (socket, _) = listener
                        .accept()
                        .await
                        .map_err(|_| OAuthError::TransportFailed)?;
                    let mut tls = acceptor
                        .accept(socket)
                        .await
                        .map_err(|_| OAuthError::TransportFailed)?;
                    let (_, form) = read_token_request(&mut tls).await?;
                    assert_eq!(form["refresh_token"], "refresh-one");
                    original.revoke();
                    // No response bytes or timer activity drive this wakeup. The
                    // abandoned native exchange must release its owned socket.
                    let mut byte = [0];
                    assert!(!matches!(tls.read(&mut byte).await, Ok(count) if count > 0));
                    Ok(())
                });
                let (server, result) =
                    Box::pin(pair(server, client.refresh(&cx, &mut credentials))).await;
                assert_eq!(server, Ok(()));
                assert_eq!(result, Err(OAuthError::RefreshUnavailable));
                assert!(original.is_revoked());
                assert!(!credentials.has_refresh_token());
                assert!(
                    credentials
                        .access
                        .authorization_for_target(&configuration.resource)
                        .is_none()
                );
                assert_eq!(
                    client.refresh(&cx, &mut credentials).await,
                    Err(OAuthError::RefreshUnavailable)
                );
                let mut task = std::task::Context::from_waker(std::task::Waker::noop());
                assert!(listener.poll_accept(&mut task).is_pending());
            });
    }

    #[test]
    fn lost_https_refresh_reply_and_redirect_never_replay_a_consumed_token() {
        for redirect in [false, true] {
            asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let deadline = operation_deadline(&cx, Duration::from_secs(20)).unwrap();
                let listener = within(&cx, deadline, bind_loopback()).await.unwrap();
                let mut configuration = config().with_extra_root_certificate(test_root()).unwrap();
                configuration.token_endpoint = url(&format!("https://{}/token", listener.local_addr().unwrap()));
                let client = OAuthClient::new(configuration.clone());
                let mut credentials = renewable_grant(&configuration);
                let original = credentials.bearer_credential().clone();
                assert!(original.authorization_for_target(&configuration.resource).is_some());
                let expires_before = credentials.expires_at;
                let acceptor = test_acceptor();
                let server = within(&cx, deadline, async {
                    let (socket, _) = listener.accept().await.map_err(|_| OAuthError::TransportFailed)?;
                    let mut tls = acceptor.accept(socket).await.map_err(|_| OAuthError::TransportFailed)?;
                    let (_, form) = read_token_request(&mut tls).await?;
                    assert_eq!(form["refresh_token"], "refresh-one");
                    if redirect {
                        tls.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://127.0.0.1:9/forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.map_err(|_| OAuthError::TransportFailed)?;
                        tls.shutdown().await.map_err(|_| OAuthError::TransportFailed)?;
                    }
                    // Without a response, the client cannot know whether the
                    // server rotated the refresh token. The connection is lost.
                    Ok(())
                });
                let (server, result) = Box::pin(pair(server, client.refresh(&cx, &mut credentials))).await;
                assert_eq!(server, Ok(()));
                assert_eq!(result, Err(if redirect { OAuthError::TokenEndpointRejected } else { OAuthError::TransportFailed }));
                assert!(original.is_revoked());
                assert!(original.authorization_for_target(&configuration.resource).is_none());
                assert!(credentials.access.authorization_for_target(&configuration.resource).is_none());
                assert_eq!(credentials.expires_at, expires_before);
                assert!(!credentials.has_refresh_token());
                assert_eq!(client.refresh(&cx, &mut credentials).await, Err(OAuthError::RefreshUnavailable));
                let waker = std::task::Waker::noop();
                let mut task = std::task::Context::from_waker(waker);
                assert!(listener.poll_accept(&mut task).is_pending(), "no retry opened another connection");
            });
        }
    }

    #[test]
    fn dropping_public_login_future_closes_its_bound_callback_listener() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                // Each iteration is a COMPLETE, independent experiment: its own
                // login, its own listener, its own kernel-assigned ephemeral port.
                // A leaked listener fails all of them; a port thief would have to
                // win a different port every time.
                let mut still_bound = Vec::new();
                let mut released = false;
                for _ in 0..RELEASE_TRIALS {
                    let deadline = operation_deadline(&cx, Duration::from_secs(10)).unwrap();
                    let client = OAuthClient::new(config());
                    let bound = std::cell::Cell::new(None::<SocketAddr>);
                    let observed_bound = &bound;
                    let mut login = Box::pin(client.authorize(&cx, |authorization| async move {
                        let fields = decode_form(authorization.query().unwrap())?;
                        let address = fields["redirect_uri"]
                            .strip_prefix("http://")
                            .unwrap()
                            .split('/')
                            .next()
                            .unwrap()
                            .parse()
                            .unwrap();
                        observed_bound.set(Some(address));
                        Ok(())
                    }));
                    let address = within(
                        &cx,
                        deadline,
                        poll_fn(|task| {
                            if let Poll::Ready(result) = login.as_mut().poll(task) {
                                return Poll::Ready(Err(result
                                    .err()
                                    .unwrap_or(OAuthError::CallbackRejected)));
                            }
                            match bound.get() {
                                Some(address) => Poll::Ready(Ok(address)),
                                None => Poll::Pending,
                            }
                        }),
                    )
                    .await
                    .unwrap();
                    // Positive control BEFORE the drop: while the login future is
                    // alive its callback listener holds the port, so this bind must be
                    // refused. It makes the release probe a state change rather than a
                    // constant, and it cannot be stolen because we hold the port.
                    // It runs in EVERY trial, so no trial is vacuous.
                    assert_listener_bound(address);

                    drop(login);

                    // No await between the drop and the probe. The probe is synchronous
                    // precisely so the runtime cannot schedule another task into the
                    // window where the freed port is unclaimed - see
                    // `probe_listener_released` for the full argument.
                    match probe_listener_released(address) {
                        ReleaseTrial::Released => {
                            released = true;
                            break;
                        }
                        ReleaseTrial::StillBound => still_bound.push(address),
                    }
                }

                assert!(
                    released,
                    "the callback listener was still bound after the login future was dropped in \
                 all {RELEASE_TRIALS} independent trials, on these separately assigned \
                 ephemeral ports: {still_bound:?}. Each trial issued its bind with no await \
                 between it and the drop, and each was preceded by a positive control proving \
                 the probe can see that listener. A concurrent test can steal one freed port; \
                 it cannot steal {RELEASE_TRIALS} different ones in a row. The listener leaked."
                );
            });
    }

    #[test]
    fn private_ca_policy_is_validated_and_bound_to_refresh_credentials() {
        assert!(
            config()
                .with_extra_root_certificate(asupersync::tls::Certificate::from_der(vec![0; 32]))
                .is_err()
        );
        let configuration = config().with_extra_root_certificate(test_root()).unwrap();
        assert!(
            configuration
                .clone()
                .with_extra_root_certificate(test_root())
                .is_err()
        );
        let mut credentials = renewable_grant(&configuration);
        let before = credentials.refresh_token.clone();
        assert_eq!(
            OAuthClient::new(config())
                .prepare_refresh(&mut credentials)
                .err(),
            Some(OAuthError::CredentialBindingMismatch)
        );
        assert_eq!(credentials.refresh_token, before);
    }
}
