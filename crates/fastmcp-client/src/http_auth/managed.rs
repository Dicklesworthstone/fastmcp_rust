//! Shared, caller-driven OAuth renewal for long-running native clients.
//!
//! One session owns one login and one rotating refresh-token lineage. Clones
//! share that lineage; they do not independently refresh it. Renewal happens
//! before dispatch, never as a replay of a failed MCP request. No runtime,
//! worker, background refresh task or persistent credential store is created.
//!
//! This is an AUTH-04/07 client lifecycle implementation, not a protocol
//! session: modern MCP requests remain stateless. The raw HTTP dispatch helper
//! retains the existing executor's protocol, TLS and response-stream policies.

use std::fmt;
use std::future::{Future, poll_fn};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::sync::{Mutex, OwnedMutexGuard};
use asupersync::time::Sleep;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;

use super::oauth::{OAuthClient, OAuthCredentials, OAuthError};
use super::{BoundBearerCredential, CanonicalHttpUrl};
use crate::http_executor::{
    ModernHttpExecutor, ModernHttpExecutorError, ModernHttpRequest, ModernHttpResponseStream,
};

/// Bounds shared renewal and response-head admission. Response bodies retain
/// the native executor's separate idle/absolute limits after handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OAuthSessionPolicy {
    refresh_leeway: Duration,
    acquisition_timeout: Duration,
    response_head_timeout: Duration,
    max_pending_acquisitions: usize,
}

impl Default for OAuthSessionPolicy {
    fn default() -> Self {
        Self {
            refresh_leeway: Duration::from_secs(30),
            acquisition_timeout: Duration::from_secs(30),
            response_head_timeout: Duration::from_secs(120),
            max_pending_acquisitions: 64,
        }
    }
}

impl OAuthSessionPolicy {
    /// Leeway is capped to half the remaining lifetime of every newly installed
    /// token. A short-lived token therefore cannot cause an immediate renewal
    /// loop. Zero leeway explicitly selects renewal at expiry.
    pub fn new(
        refresh_leeway: Duration,
        acquisition_timeout: Duration,
        response_head_timeout: Duration,
        max_pending_acquisitions: usize,
    ) -> Result<Self, OAuthSessionError> {
        if refresh_leeway > Duration::from_secs(300)
            || acquisition_timeout.is_zero()
            || acquisition_timeout > Duration::from_secs(120)
            || response_head_timeout.is_zero()
            || response_head_timeout > Duration::from_secs(900)
            || !(1..=256).contains(&max_pending_acquisitions)
        {
            return Err(OAuthSessionError::InvalidPolicy);
        }
        Ok(Self {
            refresh_leeway,
            acquisition_timeout,
            response_head_timeout,
            max_pending_acquisitions,
        })
    }
}

/// Errors never retain the OAuth exchange's private response bodies.
#[derive(Debug)]
pub enum OAuthSessionError {
    InvalidPolicy,
    Closed,
    Cancelled,
    TimedOut,
    RuntimeTimerUnavailable,
    Saturated,
    StateUnavailable,
    LoginRequired,
    TargetMismatch,
    GenerationExhausted,
    AuthorizationRejected { status: u16 },
    OAuth(OAuthError),
    Http(ModernHttpExecutorError),
}

impl fmt::Display for OAuthSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => f.write_str("invalid managed OAuth policy"),
            Self::Closed => f.write_str("managed OAuth session is closed"),
            Self::Cancelled => f.write_str("managed OAuth operation cancelled"),
            Self::TimedOut => f.write_str("managed OAuth operation deadline exceeded"),
            Self::RuntimeTimerUnavailable => f.write_str("managed OAuth requires the caller's timer"),
            Self::Saturated => f.write_str("managed OAuth acquisition capacity exhausted"),
            Self::StateUnavailable => f.write_str("managed OAuth state is unavailable"),
            Self::LoginRequired => f.write_str("managed OAuth requires a new explicit login"),
            Self::TargetMismatch => f.write_str("request target differs from the OAuth resource"),
            Self::GenerationExhausted => f.write_str("managed OAuth generation exhausted"),
            Self::AuthorizationRejected { status } => {
                write!(f, "MCP authorization rejected with HTTP {status}; request not retried")
            }
            Self::OAuth(error) => error.fmt(f),
            Self::Http(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for OAuthSessionError {}

/// One independently owned, expiring access-token snapshot. Generation is
/// session-local and changes after every successful renewal. A consumer cache
/// must also bind session identity, resource and its own authorization policy;
/// generation alone is not a cross-session cache key.
///
/// Snapshots deliberately omit serde and Clone. A caller that extracts/clones
/// the bound credential is responsible for that copy: session closure cannot
/// recall already-issued credentials or headers.
pub struct OAuthCredentialSnapshot {
    credential: BoundBearerCredential,
    scopes: Vec<String>,
    generation: u64,
    expires_at: Instant,
}

impl OAuthCredentialSnapshot {
    pub fn credential(&self) -> &BoundBearerCredential {
        &self.credential
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }
}

impl fmt::Debug for OAuthCredentialSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthCredentialSnapshot")
            .field("generation", &self.generation)
            .field("credential", &"<redacted>")
            .finish_non_exhaustive()
    }
}

struct GrantState {
    credentials: OAuthCredentials,
    renew_after: Instant,
    generation: u64,
    // Set BEFORE awaiting refresh. If that future is abandoned after dispatch
    // becomes possible, no other waiter may reuse the possibly consumed lineage.
    renewal_failed: bool,
}

struct SessionInner {
    client: OAuthClient,
    resource: CanonicalHttpUrl,
    policy: OAuthSessionPolicy,
    state: Arc<Mutex<Option<GrantState>>>,
    closed: McpRequestCancellation,
    pending: AtomicUsize,
}

/// Shared login owner with on-demand, single-flight token renewal.
#[derive(Clone)]
pub struct ManagedOAuthSession {
    inner: Arc<SessionInner>,
}

impl fmt::Debug for ManagedOAuthSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedOAuthSession")
            .field("closed", &self.inner.closed.is_cancel_requested())
            .field("pending", &self.inner.pending.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl ManagedOAuthSession {
    /// Performs one explicit browser login and retains its rotating grant.
    /// A different principal requires a new session; no background relogin can
    /// silently replace the identity of callers sharing this session.
    pub async fn authorize<L, F>(
        cx: &Cx,
        client: OAuthClient,
        policy: OAuthSessionPolicy,
        launch_browser: L,
    ) -> Result<Self, OAuthSessionError>
    where
        L: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<(), OAuthError>>,
    {
        let credentials = client.authorize(cx, launch_browser).await.map_err(OAuthSessionError::OAuth)?;
        let resource = credentials.bearer_credential().resource().clone();
        let renew_after = renewal_time(
            Instant::now(), credentials.expires_at(), credentials.has_refresh_token(), policy.refresh_leeway,
        );
        Ok(Self {
            inner: Arc::new(SessionInner {
                client,
                resource,
                policy,
                state: Arc::new(Mutex::new(Some(GrantState {
                    credentials, renew_after, generation: 1, renewal_failed: false,
                }))),
                closed: McpRequestCancellation::new(),
                pending: AtomicUsize::new(0),
            }),
        })
    }

    pub fn resource(&self) -> &CanonicalHttpUrl {
        &self.inner.resource
    }

    /// Closes admission and wakes pending acquisitions/response-head waits
    /// without cancelling the caller's Cx or sibling sessions. This is local
    /// closure, NOT an OAuth token-revocation endpoint request. Already-issued
    /// snapshots and response streams remain independently owned by their caller.
    pub fn close(&self) {
        self.inner.closed.cancel();
        if let Ok(mut state) = self.inner.state.try_lock_owned() {
            *state = None;
        }
        // A live renewal owns the lock; its SessionGuard erases the grant on
        // drop after the closure wake selects against that renewal.
    }

    /// Obtains a valid snapshot, renewing once when due. Concurrent callers
    /// queue behind the same refresh and observe its replacement generation.
    pub async fn credential(&self, cx: &Cx) -> Result<OAuthCredentialSnapshot, OAuthSessionError> {
        self.credential_with_cancellation(cx, &McpRequestCancellation::new()).await
    }

    pub async fn credential_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> Result<OAuthCredentialSnapshot, OAuthSessionError> {
        self.check(cx, cancellation)?;
        let deadline = deadline_after(cx, self.inner.policy.acquisition_timeout)?;
        let _permit = PendingPermit::acquire(&self.inner.pending, self.inner.policy.max_pending_acquisitions)?;
        self.await_active(cx, cancellation, deadline, None, async {
            let guard = OwnedMutexGuard::lock(Arc::clone(&self.inner.state), cx)
                .await.map_err(|_| OAuthSessionError::StateUnavailable)?;
            let mut guard = SessionGuard { guard, closed: &self.inner.closed };
            self.check(cx, cancellation)?;
            let state = guard.as_mut().ok_or(OAuthSessionError::Closed)?;
            if state.renewal_failed {
                return Err(OAuthSessionError::LoginRequired);
            }
            if Instant::now() >= state.renew_after {
                if !state.credentials.has_refresh_token() {
                    return Err(OAuthSessionError::LoginRequired);
                }
                let generation = state.generation.checked_add(1)
                    .ok_or(OAuthSessionError::GenerationExhausted)?;
                state.renewal_failed = true;
                self.inner.client.refresh(cx, &mut state.credentials)
                    .await.map_err(OAuthSessionError::OAuth)?;
                self.check(cx, cancellation)?;
                state.renew_after = renewal_time(
                    Instant::now(), state.credentials.expires_at(),
                    state.credentials.has_refresh_token(), self.inner.policy.refresh_leeway,
                );
                state.generation = generation;
                state.renewal_failed = false;
            }
            if Instant::now() >= state.credentials.expires_at() {
                return Err(OAuthSessionError::LoginRequired);
            }
            Ok(OAuthCredentialSnapshot {
                credential: state.credentials.bearer_credential().clone(),
                scopes: state.credentials.scopes().to_vec(),
                generation: state.generation,
                expires_at: state.credentials.expires_at(),
            })
        }).await
    }

    /// Acquires/renews before sending exactly one modern HTTP POST. The target
    /// is checked BEFORE renewal or peer contact. HTTP 401/403, redirects and
    /// transport failures never trigger automatic tool-call replay.
    ///
    /// The default native executor supplies TLS verification and response
    /// admission. Private token-issuer CA settings do not implicitly authorize
    /// a private MCP-resource CA. After response handoff, the caller owns and
    /// closes the response stream; this helper does not implement a long-lived
    /// authorization lease for that stream.
    pub async fn execute(
        &self,
        cx: &Cx,
        request: &ModernHttpRequest,
    ) -> Result<ModernHttpResponseStream, OAuthSessionError> {
        self.execute_with_cancellation(cx, &McpRequestCancellation::new(), request).await
    }

    pub async fn execute_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: &ModernHttpRequest,
    ) -> Result<ModernHttpResponseStream, OAuthSessionError> {
        self.check(cx, cancellation)?;
        admit_target(&self.inner.resource, request.target())?;
        let snapshot = self.credential_with_cancellation(cx, cancellation).await?;
        let request = request.clone().with_authorization(snapshot.credential());
        let deadline = deadline_after(cx, self.inner.policy.response_head_timeout)?;
        let executor = ModernHttpExecutor::new();
        let response = self.await_active(cx, cancellation, deadline, Some(snapshot.expires_at), async {
            executor.execute_with_cancellation(cx, cancellation, &request)
                .await.map_err(OAuthSessionError::Http)
        }).await?;
        if matches!(response.metadata().status(), 401 | 403) {
            return Err(OAuthSessionError::AuthorizationRejected { status: response.metadata().status() });
        }
        Ok(response)
    }

    fn check(&self, cx: &Cx, cancellation: &McpRequestCancellation) -> Result<(), OAuthSessionError> {
        if self.inner.closed.is_cancel_requested() {
            return Err(OAuthSessionError::Closed);
        }
        if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
            return Err(OAuthSessionError::Cancelled);
        }
        Ok(())
    }

    async fn await_active<T>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Time,
        credential_expiry: Option<Instant>,
        future: impl Future<Output = Result<T, OAuthSessionError>>,
    ) -> Result<T, OAuthSessionError> {
        let expiry_deadline = credential_expiry.map(|expiry| {
            expiry.checked_duration_since(Instant::now())
                .ok_or(OAuthSessionError::LoginRequired)
                .and_then(|remaining| deadline_after(cx, remaining))
        }).transpose()?;
        let deadline = expiry_deadline.map_or(deadline, |expiry| expiry.min(deadline));
        let timer = cx.timer_driver().ok_or(OAuthSessionError::RuntimeTimerUnavailable)?;
        let mut sleep = std::pin::pin!(Sleep::with_timer_driver(deadline, timer));
        let mut closed = std::pin::pin!(self.inner.closed.cancelled());
        let mut cancelled = std::pin::pin!(cancellation.cancelled());
        let (_sender, mut receiver) = oneshot::channel::<()>();
        let mut ambient_cancelled = std::pin::pin!(receiver.recv(cx));
        let mut future = std::pin::pin!(future);
        poll_fn(|task| {
            self.check(cx, cancellation)?;
            if credential_expiry.is_some_and(|expiry| Instant::now() >= expiry) {
                return Poll::Ready(Err(OAuthSessionError::LoginRequired));
            }
            let _caller = Cx::set_current(Some(cx.clone()));
            if closed.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(OAuthSessionError::Closed));
            }
            if cancelled.as_mut().poll(task).is_ready() || ambient_cancelled.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(OAuthSessionError::Cancelled));
            }
            if cx.now() >= deadline || sleep.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(OAuthSessionError::TimedOut));
            }
            let result = future.as_mut().poll(task);
            self.check(cx, cancellation)?;
            if credential_expiry.is_some_and(|expiry| Instant::now() >= expiry) {
                return Poll::Ready(Err(OAuthSessionError::LoginRequired));
            }
            if cx.now() >= deadline {
                return Poll::Ready(Err(OAuthSessionError::TimedOut));
            }
            result
        }).await
    }
}

fn admit_target(resource: &CanonicalHttpUrl, target: &str) -> Result<(), OAuthSessionError> {
    let target = CanonicalHttpUrl::parse(target).map_err(|_| OAuthSessionError::TargetMismatch)?;
    if target.has_userinfo() || target.fragment().is_some() || &target != resource {
        return Err(OAuthSessionError::TargetMismatch);
    }
    Ok(())
}

fn deadline_after(cx: &Cx, duration: Duration) -> Result<Time, OAuthSessionError> {
    if cx.timer_driver().is_none() {
        return Err(OAuthSessionError::RuntimeTimerUnavailable);
    }
    let nanos = u64::try_from(duration.as_nanos()).map_err(|_| OAuthSessionError::InvalidPolicy)?;
    let nanos = cx.now().as_nanos().checked_add(nanos).ok_or(OAuthSessionError::InvalidPolicy)?;
    Ok(cx.budget().deadline.map_or(Time::from_nanos(nanos), |parent| parent.min(Time::from_nanos(nanos))))
}

fn renewal_time(now: Instant, expiry: Instant, refreshable: bool, leeway: Duration) -> Instant {
    if !refreshable {
        return expiry;
    }
    let remaining = expiry.saturating_duration_since(now);
    expiry.checked_sub(leeway.min(remaining / 2)).unwrap_or(now)
}

struct PendingPermit<'a>(&'a AtomicUsize);

impl<'a> PendingPermit<'a> {
    fn acquire(pending: &'a AtomicUsize, maximum: usize) -> Result<Self, OAuthSessionError> {
        pending.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < maximum).then(|| current + 1)
        }).map_err(|_| OAuthSessionError::Saturated)?;
        Ok(Self(pending))
    }
}

impl Drop for PendingPermit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct SessionGuard<'a> {
    guard: OwnedMutexGuard<Option<GrantState>>,
    closed: &'a McpRequestCancellation,
}

impl Deref for SessionGuard<'_> {
    type Target = Option<GrantState>;
    fn deref(&self) -> &Self::Target { &self.guard }
}

impl DerefMut for SessionGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.guard }
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        if self.closed.is_cancel_requested() {
            *self.guard = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_leeway_never_consumes_more_than_half_a_new_tokens_lifetime() {
        let now = Instant::now();
        let expiry = now + Duration::from_secs(4);
        assert_eq!(renewal_time(now, expiry, true, Duration::from_secs(30)), now + Duration::from_secs(2));
        assert_eq!(renewal_time(now, expiry, true, Duration::ZERO), expiry);
        assert_eq!(renewal_time(now, expiry, false, Duration::from_secs(30)), expiry);
        assert_eq!(renewal_time(now, now, true, Duration::from_secs(30)), now);
        let long = now + Duration::from_secs(3600);
        assert_eq!(renewal_time(now, long, true, Duration::from_secs(30)), long - Duration::from_secs(30));
    }

    #[test]
    fn pending_capacity_is_released_by_scope_exit_and_future_abandonment() {
        let pending = AtomicUsize::new(0);
        let first = PendingPermit::acquire(&pending, 2).unwrap();
        let second = PendingPermit::acquire(&pending, 2).unwrap();
        assert!(matches!(PendingPermit::acquire(&pending, 2), Err(OAuthSessionError::Saturated)));
        assert_eq!(pending.load(Ordering::Acquire), 2);
        drop(first);
        let replacement = PendingPermit::acquire(&pending, 2).unwrap();
        drop(second);
        drop(replacement);
        assert_eq!(pending.load(Ordering::Acquire), 0);
        let permit = PendingPermit::acquire(&pending, 2).unwrap();
        let future = async move {
            let _permit = permit;
            std::future::pending::<()>().await;
        };
        drop(future);
        assert_eq!(pending.load(Ordering::Acquire), 0);
    }

    #[test]
    fn wrong_resource_never_becomes_an_unauthenticated_fallback() {
        let resource = CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap();
        assert!(admit_target(&resource, "https://MCP.EXAMPLE:443/mcp").is_ok());
        for target in [
            "https://mcp.example/other", "https://other.example/mcp",
            "http://mcp.example/mcp", "https://mcp.example/mcp?other",
            "https://mcp.example/mcp#fragment", "https://user@mcp.example/mcp",
        ] {
            assert!(matches!(admit_target(&resource, target), Err(OAuthSessionError::TargetMismatch)));
        }
    }

    #[test]
    fn policy_admission_bounds_waiters_and_both_deadlines() {
        let second = Duration::from_secs(1);
        assert!(OAuthSessionPolicy::new(Duration::ZERO, second, second, 1).is_ok());
        assert!(OAuthSessionPolicy::new(second, second, second, 0).is_err());
        assert!(OAuthSessionPolicy::new(second, second, second, 257).is_err());
        assert!(OAuthSessionPolicy::new(second, Duration::ZERO, second, 1).is_err());
        assert!(OAuthSessionPolicy::new(second, second, Duration::ZERO, 1).is_err());
        assert!(OAuthSessionPolicy::new(Duration::from_secs(301), second, second, 1).is_err());
    }
}
