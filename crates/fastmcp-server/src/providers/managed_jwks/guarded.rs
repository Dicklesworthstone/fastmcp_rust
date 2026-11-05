//! Request-driven HTTPS renewal for resource-server JWT keys.
//!
//! The trusted deployment chooses the endpoint, roots, provider and deployment
//! identities. Neither a token's `kid` nor any other claim can select a URL or
//! trigger an extra refresh. One due request fetches; concurrent requests use
//! still-fresh keys or return service unavailable. There is no waiter queue,
//! background task, hidden runtime, redirect, ambient credential or retry.

use std::collections::HashSet;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::time::Sleep;
use fastmcp_core::{
    AccessToken, AuthContext, McpContext, McpError, McpErrorCode, McpResult, Sha256Digest,
};
use fastmcp_transport::http::{GuardedHttpFetchResponse, GuardedHttpFetcher, GuardedHttpsUrl};

use super::{
    JwksRefreshError, JwksRefreshOutcome, JwksRefreshPolicy, MAX_REFRESH_JWKS_BYTES,
    ManagedJwtResourceVerifier,
};
use crate::auth::{AuthFuture, AuthRequest, TokenVerifier};
use crate::providers::jwt_resource::{JwtResourceAuthError, JwtResourcePolicy};

const MAX_ID_BYTES: usize = 1024;
const MAX_BINDING_BYTES: usize = 8192;
const SOURCE_DOMAIN: &[u8] = b"fastmcp/guarded-jwks-source/v1\0";
const POLICY_DOMAIN: &[u8] = b"fastmcp/guarded-jwks-policy/v1\0";
const OWNER_DOMAIN: &[u8] = b"fastmcp/guarded-jwks-owner/v1\0";

/// Shared non-queuing capacity for trusted key sources in one deployment.
///
/// A source is the exact configured provider/deployment pair, independent of
/// endpoint spellings, JWT contents and client IPs. At most one unsettled fetch
/// for that source can run across all verifiers sharing this pool. Keep one
/// pool and clone it when constructing the deployment's sources.
#[derive(Clone)]
pub struct JwksFetchAdmissionPool {
    active: Arc<Mutex<HashSet<Sha256Digest>>>,
    maximum: usize,
}

impl JwksFetchAdmissionPool {
    /// Admits one through 64 concurrent sources. No reservation is acquired
    /// until a verifier actually needs a refresh.
    pub fn new(maximum: usize) -> Result<Self, JwksRefreshError> {
        if !(1..=64).contains(&maximum) {
            return Err(JwksRefreshError::InvalidPolicy);
        }
        Ok(Self {
            active: Arc::new(Mutex::new(HashSet::new())),
            maximum,
        })
    }

    fn acquire(&self, source: Sha256Digest) -> McpResult<JwksFetchPermit> {
        let mut active = self.active.lock().map_err(|_| unavailable())?;
        if active.len() >= self.maximum || active.contains(&source) {
            return Err(unavailable());
        }
        active.insert(source);
        Ok(JwksFetchPermit {
            pool: self.clone(),
            source,
        })
    }
}

impl Default for JwksFetchAdmissionPool {
    fn default() -> Self {
        Self {
            active: Arc::new(Mutex::new(HashSet::new())),
            maximum: 8,
        }
    }
}

impl fmt::Debug for JwksFetchAdmissionPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwksFetchAdmissionPool")
            .field("maximum", &self.maximum)
            .finish_non_exhaustive()
    }
}

struct JwksFetchPermit {
    pool: JwksFetchAdmissionPool,
    source: Sha256Digest,
}

impl Drop for JwksFetchPermit {
    fn drop(&mut self) {
        if let Ok(mut active) = self.pool.active.lock() {
            active.remove(&self.source);
        }
    }
}

/// One administratively selected HTTPS key source with immutable root policy.
///
/// Construction performs no I/O. The full source identity binds the exact URL,
/// provider, deployment and root-set identity into authenticated ownership.
/// Changing any of those starts a different owner partition. Routine key
/// rotation at the same source preserves ownership.
#[derive(Clone)]
pub struct GuardedJwksSource {
    endpoint: GuardedHttpsUrl,
    fetcher: Arc<GuardedHttpFetcher>,
    admission: JwksFetchAdmissionPool,
    source: Sha256Digest,
    identity: Sha256Digest,
    #[cfg(test)]
    test_exchange: Option<Arc<dyn tests::Exchange>>,
}

impl GuardedJwksSource {
    /// Requires an exact HTTPS endpoint, nonempty bounded provider/deployment
    /// identifiers, and a fetcher that allocates at most 64 KiB of response
    /// body with a total deadline of at most 30 seconds. TLS and DNS/address
    /// custody remain entirely within the supplied guarded fetcher.
    pub fn new(
        endpoint: impl Into<String>,
        provider_identity: impl Into<String>,
        deployment_identity: impl Into<String>,
        fetcher: GuardedHttpFetcher,
        admission: JwksFetchAdmissionPool,
    ) -> Result<Self, JwksRefreshError> {
        let endpoint = endpoint.into();
        let provider = provider_identity.into();
        let deployment = deployment_identity.into();
        if !valid_id(&provider)
            || !valid_id(&deployment)
            || fetcher.policy().response_body_bytes() > MAX_REFRESH_JWKS_BYTES
            || fetcher.policy().deadline() > Duration::from_secs(30)
            || fetcher.root_identity().len() > MAX_ID_BYTES
        {
            return Err(JwksRefreshError::InvalidPolicy);
        }
        let source = binding(SOURCE_DOMAIN, &[&provider, &deployment])?;
        let identity = binding(
            POLICY_DOMAIN,
            &[&provider, &deployment, &endpoint, fetcher.root_identity()],
        )?;
        let endpoint =
            GuardedHttpsUrl::parse(&endpoint).map_err(|_| JwksRefreshError::InvalidPolicy)?;
        Ok(Self {
            endpoint,
            fetcher: Arc::new(fetcher),
            admission,
            source,
            identity,
            #[cfg(test)]
            test_exchange: None,
        })
    }

    async fn fetch(
        &self,
        ctx: &McpContext,
        timeout: Duration,
        retained: &mut Option<Arc<JwksFetchPermit>>,
    ) -> McpResult<Vec<u8>> {
        checkpoint(ctx)?;
        let permit = Arc::new(self.admission.acquire(self.source)?);
        // The caller retains the reservation through parsing and publication;
        // phase children retain it independently through cancellation settlement.
        *retained = Some(permit.clone());
        let lifetime: Arc<dyn Send + Sync> = permit;
        let future = self.exchange(ctx, lifetime);
        let mut future = pin!(future);
        let cancellation = ctx.request_cancelled();
        let mut cancellation = pin!(cancellation);
        let timeout = timeout.min(self.fetcher.policy().deadline());
        let started = Instant::now();
        let nanos = u64::try_from(timeout.as_nanos()).map_err(|_| unavailable())?;
        let deadline = ctx.cx().now().saturating_add_nanos(nanos);
        let deadline = ctx
            .budget()
            .deadline
            .map_or(deadline, |limit| limit.min(deadline));
        let mut timer = pin!(Sleep::new(deadline));
        let response = poll_fn(|task| {
            let ceiling = crate::auth::ambient_auth_capability_ceiling();
            let _current = asupersync::Cx::set_current(Some(ctx.cx().clone()));
            let _restriction = asupersync::Cx::push_restriction(ceiling);
            let current = asupersync::Cx::current().expect("caller context installed");
            let capabilities = current.capabilities();
            if !capabilities.spawn
                || !capabilities.time
                || !capabilities.entropy
                || !capabilities.io
                || !capabilities.remote
            {
                return Poll::Ready(Err(unavailable()));
            }
            if let Err(error) = checkpoint(ctx) {
                return Poll::Ready(Err(error));
            }
            if cancellation.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(McpError::request_cancelled()));
            }
            if started.elapsed() >= timeout {
                return Poll::Ready(Err(unavailable()));
            }
            let response = future.as_mut().poll(task);
            if let Err(error) = checkpoint(ctx) {
                return Poll::Ready(Err(error));
            }
            if started.elapsed() >= timeout {
                return Poll::Ready(Err(unavailable()));
            }
            if let Poll::Ready(response) = response {
                return Poll::Ready(response);
            }
            // A missing or attenuated timer must never fall back to an
            // ambient process-global driver while the network future waits.
            if current.timer_driver().is_none() {
                return Poll::Ready(Err(unavailable()));
            }
            if timer.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(unavailable()));
            }
            Poll::Pending
        })
        .await?;
        checkpoint(ctx)?;
        if response.status != 200
            || response.redirect.is_some()
            || response.body.len() > MAX_REFRESH_JWKS_BYTES
        {
            return Err(unavailable());
        }
        let mut types = response
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"));
        if !types
            .next()
            .is_some_and(|(_, value)| jwks_content_type(value))
            || types.next().is_some()
        {
            return Err(unavailable());
        }
        Ok(response.body)
    }

    async fn exchange(
        &self,
        ctx: &McpContext,
        lifetime: Arc<dyn Send + Sync>,
    ) -> McpResult<GuardedHttpFetchResponse> {
        #[cfg(test)]
        if let Some(exchange) = &self.test_exchange {
            let _lifetime = lifetime;
            return exchange.get(ctx, &self.endpoint).await;
        }
        // Guarded transport installs phase deadlines on its first poll. Refuse
        // before that poll when the effective caller has no timer, otherwise a
        // pending DNS child could reach Sleep's global fallback before the
        // outer polling guard has a chance to inspect the pending result.
        if asupersync::Cx::current()
            .and_then(|current| current.timer_driver())
            .is_none()
        {
            return Err(unavailable());
        }
        self.fetcher
            .fetch_with_lifetime(ctx.cx(), &self.endpoint, lifetime)
            .await
            .map_err(|_| unavailable())
    }
}

impl fmt::Debug for GuardedJwksSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardedJwksSource")
            .field("admission", &self.admission)
            .finish_non_exhaustive()
    }
}

/// JWT authentication with automatic, bounded, request-owned key renewal.
///
/// Install a clone through [`crate::auth::TokenAuthProvider`]. Native modern
/// HTTP and secured SSE use the asynchronous verifier, which loads keys when
/// empty and renews only when the configured refresh interval is due. A failed
/// refresh does not extend old keys' hard expiry. Unknown `kid` and invalid
/// signatures do not bypass refresh backoff or cause an additional request.
///
/// The synchronous verifier uses already installed fresh keys and performs no
/// I/O. Applications can explicitly call [`Self::refresh`] for warm-up on their
/// own runtime. Administrative revocation requires explicit valid installation
/// to re-enable trust; remote refresh alone cannot undo it.
#[derive(Clone)]
pub struct GuardedJwtResourceVerifier {
    managed: ManagedJwtResourceVerifier,
    source: GuardedJwksSource,
}

impl GuardedJwtResourceVerifier {
    #[must_use]
    pub fn new(
        policy: JwtResourcePolicy,
        refresh: JwksRefreshPolicy,
        source: GuardedJwksSource,
    ) -> Self {
        Self {
            managed: ManagedJwtResourceVerifier::new(policy, refresh),
            source,
        }
    }

    /// At most one due fetch; no network effect while fresh, backing off,
    /// revoked, or another live attempt owns this verifier's refresh slot.
    pub async fn refresh(&self, ctx: &McpContext) -> Result<JwksRefreshOutcome, JwksRefreshError> {
        let mut retained = None;
        self.managed
            .refresh_with(ctx, || {
                self.source.fetch(
                    ctx,
                    self.managed.refresh_policy.attempt_timeout,
                    &mut retained,
                )
            })
            .await
    }

    /// Explicit administrative installation also fences any pending fetch.
    pub fn install_jwks(&self, jwks: &[u8]) -> Result<(), JwksRefreshError> {
        self.managed.install_jwks(jwks)
    }

    /// Disables every clone and prevents late fetches from restoring trust.
    pub fn revoke_all(&self) -> Result<bool, JwksRefreshError> {
        self.managed.revoke_all()
    }

    /// Verifies against already installed fresh keys without performing I/O.
    pub fn verify_access_token(
        &self,
        ctx: &McpContext,
        token: &AccessToken,
    ) -> McpResult<AuthContext> {
        let facts = self
            .managed
            .verify_access_token(ctx, token)
            .map_err(auth_error)?;
        let owner = facts.session_owner().ok_or_else(unavailable)?;
        let mut bytes = Vec::with_capacity(OWNER_DOMAIN.len() + 64);
        bytes.extend_from_slice(OWNER_DOMAIN);
        bytes.extend_from_slice(self.source.identity.as_bytes());
        bytes.extend_from_slice(owner.as_bytes());
        let owner = fastmcp_core::sha256_bounded(&bytes, OWNER_DOMAIN.len() + 64)
            .map_err(|_| unavailable())?;
        checkpoint(ctx)?;
        Ok(facts.with_session_owner(owner))
    }

    /// Loads or renews keys when due, then verifies exactly once. Endpoint
    /// outages/saturation with no fresh keys return service unavailable; invalid
    /// credentials return ordinary authentication denial. No token is sent to
    /// the key endpoint, retained in a cache, or used as a source selector.
    pub async fn verify_access_token_async(
        &self,
        ctx: &McpContext,
        token: &AccessToken,
    ) -> McpResult<AuthContext> {
        checkpoint(ctx)?;
        if !token.scheme.eq_ignore_ascii_case("Bearer")
            || !AccessToken::is_valid_token68(&token.token)
        {
            return Err(McpError::new(
                McpErrorCode::ResourceForbidden,
                "Invalid access token",
            ));
        }
        let refreshed = self.refresh(ctx).await;
        checkpoint(ctx)?;
        if matches!(refreshed, Err(JwksRefreshError::Cancelled)) {
            return Err(McpError::request_cancelled());
        }
        // Verification independently rechecks hard expiry and generation, so
        // failed/backed-off refreshes can use fresh keys without reviving stale
        // trust. A superseding administrative installation is checked normally.
        self.verify_access_token(ctx, token)
    }
}

impl fmt::Debug for GuardedJwtResourceVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardedJwtResourceVerifier")
            .field("managed", &self.managed)
            .field("source", &self.source)
            .finish()
    }
}

impl TokenVerifier for GuardedJwtResourceVerifier {
    fn verify(
        &self,
        ctx: &McpContext,
        _: AuthRequest<'_>,
        token: &AccessToken,
    ) -> McpResult<AuthContext> {
        self.verify_access_token(ctx, token)
    }

    fn verify_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        _: AuthRequest<'a>,
        token: &'a AccessToken,
    ) -> AuthFuture<'a> {
        Box::pin(self.verify_access_token_async(ctx, token))
    }
}

fn unavailable() -> McpError {
    McpError::new(
        crate::auth::AUTH_PROVIDER_UNAVAILABLE_CODE,
        "Authentication service unavailable",
    )
}

fn auth_error(error: JwtResourceAuthError) -> McpError {
    match error {
        JwtResourceAuthError::Cancelled | JwtResourceAuthError::TimedOut => {
            McpError::request_cancelled()
        }
        JwtResourceAuthError::KeysUnavailable
        | JwtResourceAuthError::KeysChanged
        | JwtResourceAuthError::ClockUnavailable => unavailable(),
        _ => McpError::new(McpErrorCode::ResourceForbidden, "Invalid access token"),
    }
}

fn checkpoint(ctx: &McpContext) -> McpResult<()> {
    ctx.checkpoint()?;
    if ctx.deadline_expired() {
        return Err(McpError::request_cancelled());
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_ID_BYTES && !value.chars().any(char::is_control)
}

fn binding(domain: &[u8], values: &[&str]) -> Result<Sha256Digest, JwksRefreshError> {
    let mut bytes = Vec::with_capacity(MAX_BINDING_BYTES);
    bytes.extend_from_slice(domain);
    for value in values {
        if value.len() > 2048 {
            return Err(JwksRefreshError::InvalidPolicy);
        }
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    fastmcp_core::sha256_bounded(&bytes, MAX_BINDING_BYTES)
        .map_err(|_| JwksRefreshError::InvalidPolicy)
}

fn jwks_content_type(value: &str) -> bool {
    let mut parts = value.split(';');
    if !parts.next().is_some_and(|media| {
        media.trim().eq_ignore_ascii_case("application/json")
            || media
                .trim()
                .eq_ignore_ascii_case("application/jwk-set+json")
    }) {
        return false;
    }
    match (parts.next(), parts.next()) {
        (None, None) => true,
        (Some(parameter), None) => parameter
            .trim()
            .split_once('=')
            .is_some_and(|(key, value)| {
                key.trim().eq_ignore_ascii_case("charset")
                    && value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
            }),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
