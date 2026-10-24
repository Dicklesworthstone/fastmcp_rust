//! Explicit RFC 8628 sign-in for headless native public clients.
//!
//! The host supplies trusted endpoints and presents the verification URI and
//! user code. No browser, loopback listener, runtime or background task is
//! created. Only `authorization_pending` and `slow_down` permit another token
//! poll; transport failures, unknown errors and cancellation never replay an
//! exchange or start a new authorization. This is an explicit alternative to
//! browser/PKCE login, not a fallback selected by untrusted metadata.
//!
//! The returned resource-bound credential works with the existing HTTP request
//! builders. This profile does not install a managed session, persist grants,
//! discover endpoints, or claim issuer-side revocation. Endpoint/CA/DNS trust
//! and presenting consent on the user's separate device remain host policy.

use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::http::h1::{HttpClient, Method, RedirectPolicy, RetryPolicy};
use asupersync::security::SecretString;
use asupersync::time::Sleep;
use asupersync::tls::{Certificate, RootCertStore};
use asupersync::types::Time;
use fastmcp_core::{CanonicalResourceId, CanonicalResourceIdPolicy, McpRequestCancellation};

use super::caller::with_caller;
use super::{BoundBearerCredential, CanonicalHttpUrl};

mod wire;
#[cfg(test)]
mod tests;

/// One error category, never a peer body, URL, code, credential or transport error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAuthorizationError {
    InvalidConfiguration,
    InvalidResponse,
    UntrustedVerificationUri,
    RuntimeUnavailable,
    Cancelled,
    TimedOut,
    PresentationFailed,
    TransportFailed,
    EndpointRejected { status: u16 },
    AccessDenied,
    ExpiredCode,
    PollLimitExceeded,
    ScopeExpansion,
}

impl fmt::Display for DeviceAuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "device authorization: {self:?}")
    }
}
impl std::error::Error for DeviceAuthorizationError {}

/// Immutable bounds for the complete sign-in and each individual exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceAuthorizationPolicy {
    timeout: Duration,
    exchange_timeout: Duration,
    maximum_polls: u16,
    maximum_token_lifetime: Duration,
}

impl DeviceAuthorizationPolicy {
    pub fn new(
        timeout: Duration,
        exchange_timeout: Duration,
        maximum_polls: u16,
        maximum_token_lifetime: Duration,
    ) -> Result<Self, DeviceAuthorizationError> {
        if timeout.is_zero() || timeout > Duration::from_secs(3600)
            || exchange_timeout.is_zero() || exchange_timeout > Duration::from_secs(120)
            || maximum_polls == 0 || maximum_polls > 1024
            || maximum_token_lifetime.is_zero()
            || maximum_token_lifetime > Duration::from_secs(86_400)
        {
            return Err(DeviceAuthorizationError::InvalidConfiguration);
        }
        Ok(Self { timeout, exchange_timeout, maximum_polls, maximum_token_lifetime })
    }
}

impl Default for DeviceAuthorizationPolicy {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(600),
            exchange_timeout: Duration::from_secs(30),
            maximum_polls: 128,
            maximum_token_lifetime: Duration::from_secs(3600),
        }
    }
}

/// An explicitly configured preregistered public client. There is no discovery
/// or client-secret fallback. Cross-origin endpoints must already be trusted.
#[derive(Clone, Eq, PartialEq)]
pub struct DeviceAuthorizationClient {
    device_endpoint: CanonicalHttpUrl,
    token_endpoint: CanonicalHttpUrl,
    verification_origin: CanonicalHttpUrl,
    resource: CanonicalHttpUrl,
    client_id: String,
    scopes: Vec<String>,
    roots: Vec<Vec<u8>>,
    policy: DeviceAuthorizationPolicy,
}

impl fmt::Debug for DeviceAuthorizationClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAuthorizationClient").finish_non_exhaustive()
    }
}

/// Information deliberately disclosed to the trusted presentation callback.
/// No device code is exposed. Do not log these values or approve automatically.
/// The complete URI is a convenience only; always show the user code as well.
pub struct DeviceVerification {
    user_code: SecretString,
    verification_uri: CanonicalHttpUrl,
    verification_uri_complete: Option<CanonicalHttpUrl>,
    expires_in: Duration,
}

impl DeviceVerification {
    pub fn user_code(&self) -> &str { self.user_code.as_str() }
    pub fn verification_uri(&self) -> &CanonicalHttpUrl { &self.verification_uri }
    pub fn verification_uri_complete(&self) -> Option<&CanonicalHttpUrl> {
        self.verification_uri_complete.as_ref()
    }
    pub fn expires_in(&self) -> Duration { self.expires_in }
}

/// Exclusively retained grant, with the existing exact-resource bearer binding.
/// Access-token expiry is local and monotonic, never persisted or extended by
/// cloning a bearer. This type deliberately has no Clone, Debug or serde surface.
pub struct DeviceOAuthCredentials {
    client: DeviceAuthorizationClient,
    access: BoundBearerCredential,
    refresh_token: Option<SecretString>,
    scopes: Vec<String>,
    expires_at: Instant,
}

impl DeviceOAuthCredentials {
    pub fn client(&self) -> &DeviceAuthorizationClient { &self.client }
    pub fn bearer_credential(&self) -> &BoundBearerCredential { &self.access }
    pub fn scopes(&self) -> &[String] { &self.scopes }
    pub fn expires_at(&self) -> Instant { self.expires_at }
    pub fn has_refresh_token(&self) -> bool { self.refresh_token.is_some() }

    /// Local-only closure, including all access-token clones. No remote request
    /// is sent and already-created headers or committed effects are not recalled.
    pub fn revoke(&mut self) {
        self.access.revoke();
        self.refresh_token = None;
    }
}

impl DeviceAuthorizationClient {
    /// Configures trusted HTTPS endpoints, a verification ORIGIN (path `/`),
    /// the exact MCP resource and a preregistered client ID. Peer responses may
    /// not redirect verification to a different origin. No URL is fetched here.
    pub fn from_trusted_endpoints(
        device_endpoint: CanonicalHttpUrl,
        token_endpoint: CanonicalHttpUrl,
        verification_origin: CanonicalHttpUrl,
        resource: CanonicalHttpUrl,
        client_id: impl Into<String>,
        scopes: Vec<String>,
    ) -> Result<Self, DeviceAuthorizationError> {
        for endpoint in [&device_endpoint, &token_endpoint, &verification_origin, &resource] {
            wire::https(endpoint, false).map_err(|_| DeviceAuthorizationError::InvalidConfiguration)?;
        }
        if verification_origin.path() != "/" {
            return Err(DeviceAuthorizationError::InvalidConfiguration);
        }
        CanonicalResourceId::parse_for_endpoint(resource.as_str(), &resource, CanonicalResourceIdPolicy::DEFAULT)
            .map_err(|_| DeviceAuthorizationError::InvalidConfiguration)?;
        let client_id = client_id.into();
        if client_id.is_empty() || client_id.len() > 1024 || client_id.chars().any(char::is_control) {
            return Err(DeviceAuthorizationError::InvalidConfiguration);
        }
        wire::validate_scopes(&scopes).map_err(|_| DeviceAuthorizationError::InvalidConfiguration)?;
        Ok(Self {
            device_endpoint, token_endpoint, verification_origin, resource, client_id, scopes,
            roots: Vec::new(), policy: DeviceAuthorizationPolicy::default(),
        })
    }

    pub fn with_policy(mut self, policy: DeviceAuthorizationPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Adds a private CA for both configured device/token endpoints, not the
    /// MCP resource or the user's separate browser. Hostname checking remains on.
    pub fn with_extra_root_certificate(mut self, root: Certificate) -> Result<Self, DeviceAuthorizationError> {
        let der = root.as_der();
        if der.is_empty() || der.len() > 16 * 1024 || self.roots.len() >= 8
            || self.roots.iter().any(|existing| existing.as_slice() == der)
        {
            return Err(DeviceAuthorizationError::InvalidConfiguration);
        }
        RootCertStore::empty().add(&root).map_err(|_| DeviceAuthorizationError::InvalidConfiguration)?;
        self.roots.push(der.to_vec());
        Ok(self)
    }

    pub fn resource(&self) -> &CanonicalHttpUrl { &self.resource }

    /// Requests one device code, presents it once, then polls at the issuer's
    /// minimum interval. `slow_down` adds five seconds permanently. Every poll
    /// follows a wait, including the first. Presentation completion is NOT
    /// authorization: only an admitted token response yields a credential.
    ///
    /// The single deadline includes device-code acquisition, presentation and
    /// all polls. Issuer code expiry can only shorten it. Dropping this future
    /// drops its owned HTTP exchange, timer and presentation future. Hosts must
    /// keep their presentation work cancellation-correct and owned by its future.
    pub async fn authorize<P, F>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        present: P,
    ) -> Result<DeviceOAuthCredentials, DeviceAuthorizationError>
    where
        P: FnOnce(DeviceVerification) -> F,
        F: Future<Output = Result<(), DeviceAuthorizationError>>,
    {
        let mut exchange = NativeExchange { roots: &self.roots };
        Box::pin(self.authorize_using(cx, cancellation, present, &mut exchange)).await
    }

    async fn authorize_using<P, F, X: FormExchange>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        present: P,
        exchange: &mut X,
    ) -> Result<DeviceOAuthCredentials, DeviceAuthorizationError>
    where
        P: FnOnce(DeviceVerification) -> F,
        F: Future<Output = Result<(), DeviceAuthorizationError>>,
    {
        let deadline = operation_deadline(cx, cancellation, self.policy.timeout)?;
        let scope = self.scopes.join(" ");
        let mut fields = vec![("client_id", self.client_id.as_str()), ("resource", self.resource.as_str())];
        if !scope.is_empty() { fields.push(("scope", scope.as_str())); }
        let body = wire::form(&fields)?;
        let started = cx.now();
        let response = self.exchange(cx, cancellation, deadline, exchange, &self.device_endpoint, body).await?;
        if response.status != 200 {
            return Err(DeviceAuthorizationError::EndpointRejected { status: response.status });
        }
        let (mut prompt, device_code, interval, lifetime) = wire::device(self, &response.body)?;
        // Count from BEFORE dispatch, not from response arrival or presentation.
        let deadline = deadline.min(add_time(started, lifetime)?);
        check(cx, cancellation, deadline)?;
        prompt.expires_in = Duration::from_nanos(deadline.as_nanos().saturating_sub(cx.now().as_nanos()));
        within(cx, cancellation, deadline, async {
            present(prompt).await.map_err(|_| DeviceAuthorizationError::PresentationFailed)
        }).await?;
        let mut schedule = PollSchedule { interval, polls: 0, maximum: self.policy.maximum_polls };
        loop {
            check(cx, cancellation, deadline)?;
            let due = schedule.next(cx.now(), deadline)?;
            within(cx, cancellation, deadline, async {
                Sleep::new(due).await;
                Ok(())
            }).await?;
            check(cx, cancellation, deadline)?;
            let body = wire::form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code.as_str()),
                ("client_id", self.client_id.as_str()),
                ("resource", self.resource.as_str()),
            ])?;
            let issued_at = Instant::now();
            let response = self.exchange(cx, cancellation, deadline, exchange, &self.token_endpoint, body).await?;
            match wire::poll_response(response.status, &response.body)? {
                wire::PollResponse::Token => {
                    let credentials = wire::credentials(self, &self.scopes, &response.body, issued_at)?;
                    check(cx, cancellation, deadline)?;
                    return Ok(credentials);
                }
                wire::PollResponse::Pending => {}
                wire::PollResponse::SlowDown => schedule.slow_down()?,
            }
        }
    }

    async fn exchange<X: FormExchange>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Time,
        exchange: &mut X,
        endpoint: &CanonicalHttpUrl,
        body: Vec<u8>,
    ) -> Result<ExchangeResponse, DeviceAuthorizationError> {
        let deadline = deadline.min(add_time(cx.now(), self.policy.exchange_timeout)?);
        within(cx, cancellation, deadline, async {
            // Use the narrowed caller captured under with_caller, including
            // ambient restrictions, rather than handing I/O an unrestricted Cx.
            let caller = require_runtime(cx)?;
            exchange.post(&caller, endpoint, body).await
        }).await
    }
}

struct PollSchedule { interval: Duration, polls: u16, maximum: u16 }
impl PollSchedule {
    fn next(&mut self, now: Time, deadline: Time) -> Result<Time, DeviceAuthorizationError> {
        if self.polls >= self.maximum { return Err(DeviceAuthorizationError::PollLimitExceeded); }
        let due = add_time(now, self.interval)?;
        if due >= deadline { return Err(DeviceAuthorizationError::TimedOut); }
        self.polls += 1;
        Ok(due)
    }
    fn slow_down(&mut self) -> Result<(), DeviceAuthorizationError> {
        self.interval = self.interval.checked_add(Duration::from_secs(5))
            .ok_or(DeviceAuthorizationError::InvalidResponse)?;
        Ok(())
    }
}

struct ExchangeResponse { status: u16, body: Vec<u8> }
type ExchangeFuture<'a> = Pin<Box<dyn Future<Output = Result<ExchangeResponse, DeviceAuthorizationError>> + Send + 'a>>;
trait FormExchange {
    fn post<'a>(&'a mut self, cx: &'a Cx, endpoint: &'a CanonicalHttpUrl, body: Vec<u8>) -> ExchangeFuture<'a>;
}
struct NativeExchange<'a> { roots: &'a [Vec<u8>] }
impl FormExchange for NativeExchange<'_> {
    fn post<'a>(&'a mut self, cx: &'a Cx, endpoint: &'a CanonicalHttpUrl, body: Vec<u8>) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let mut builder = HttpClient::builder()
                .redirect_policy(RedirectPolicy::None).retry_policy(RetryPolicy::None)
                .no_proxy().no_cookie_store().max_body_size(wire::MAX_RESPONSE_BYTES)
                .max_total_connections(1);
            for root in self.roots { builder = builder.add_root_certificate(Certificate::from_der(root.clone())); }
            let response = builder.build().request(cx, Method::Post, endpoint.as_str(), vec![
                ("Content-Type".to_owned(), "application/x-www-form-urlencoded".to_owned()),
                ("Accept".to_owned(), "application/json".to_owned()),
                ("Accept-Encoding".to_owned(), "identity".to_owned()),
                ("Connection".to_owned(), "close".to_owned()),
            ], body).await.map_err(|_| DeviceAuthorizationError::TransportFailed)?;
            wire::headers(&response.headers)?;
            if !response.trailers.is_empty() || response.body.len() > wire::MAX_RESPONSE_BYTES {
                return Err(DeviceAuthorizationError::InvalidResponse);
            }
            Ok(ExchangeResponse { status: response.status, body: response.body })
        })
    }
}

fn add_time(now: Time, duration: Duration) -> Result<Time, DeviceAuthorizationError> {
    let nanos = u64::try_from(duration.as_nanos()).map_err(|_| DeviceAuthorizationError::InvalidResponse)?;
    now.as_nanos().checked_add(nanos).map(Time::from_nanos).ok_or(DeviceAuthorizationError::InvalidResponse)
}

fn require_runtime(cx: &Cx) -> Result<Cx, DeviceAuthorizationError> {
    let active = Cx::current().ok_or(DeviceAuthorizationError::RuntimeUnavailable)?;
    let caps = active.capabilities();
    if cx.timer_driver().is_none() || !caps.time || !caps.io || !caps.remote || !caps.entropy {
        return Err(DeviceAuthorizationError::RuntimeUnavailable);
    }
    Ok(active)
}

fn operation_deadline(cx: &Cx, cancellation: &McpRequestCancellation, timeout: Duration) -> Result<Time, DeviceAuthorizationError> {
    with_caller(cx, || {
        check(cx, cancellation, Time::from_nanos(u64::MAX))?;
        require_runtime(cx)?;
        let end = add_time(cx.now(), timeout)?;
        let end = cx.budget().deadline.map_or(end, |parent| parent.min(end));
        check(cx, cancellation, end)?;
        Ok(end)
    })
}

fn check(cx: &Cx, cancellation: &McpRequestCancellation, deadline: Time) -> Result<(), DeviceAuthorizationError> {
    use asupersync::{CancelKind, error::ErrorKind};
    if cancellation.is_cancel_requested() { return Err(DeviceAuthorizationError::Cancelled); }
    if cx.now() >= deadline || cx.budget().deadline.is_some_and(|end| cx.now() >= end) {
        return Err(DeviceAuthorizationError::TimedOut);
    }
    cx.checkpoint().map_err(|error| match cx.cancel_reason().map(|reason| reason.kind) {
        Some(CancelKind::Deadline | CancelKind::Timeout) => DeviceAuthorizationError::TimedOut,
        Some(_) => DeviceAuthorizationError::Cancelled,
        None => match error.kind() {
            ErrorKind::DeadlineExceeded | ErrorKind::CancelTimeout => DeviceAuthorizationError::TimedOut,
            _ => DeviceAuthorizationError::Cancelled,
        },
    })
}

async fn within<T>(cx: &Cx, cancellation: &McpRequestCancellation, deadline: Time, future: impl Future<Output = Result<T, DeviceAuthorizationError>>) -> Result<T, DeviceAuthorizationError> {
    let deadline = cx.budget().deadline.map_or(deadline, |parent| parent.min(deadline));
    let mut timer = std::pin::pin!(Sleep::new(deadline));
    let mut cancelled = std::pin::pin!(cancellation.cancelled());
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut caller_cancelled = std::pin::pin!(receiver.recv(cx));
    let mut future = Box::pin(future);
    poll_fn(|task| with_caller(cx, || {
        check(cx, cancellation, deadline)?;
        require_runtime(cx)?;
        if cancelled.as_mut().poll(task).is_ready() || caller_cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(DeviceAuthorizationError::Cancelled));
        }
        if timer.as_mut().poll(task).is_ready() { return Poll::Ready(Err(DeviceAuthorizationError::TimedOut)); }
        let result = future.as_mut().poll(task);
        check(cx, cancellation, deadline)?;
        result
    })).await
}
