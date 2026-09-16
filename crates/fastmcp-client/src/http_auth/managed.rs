//! Shared, caller-driven OAuth renewal for long-running native clients.
//!
//! One session owns one login and one rotating refresh-token lineage. Clones
//! share that lineage; they do not independently refresh it. Renewal happens
//! before dispatch, never as a replay of a failed MCP request. No runtime,
//! worker, background refresh task or persistent credential store is created.
//!
//! This is an AUTH-04/07 client lifecycle implementation, not a protocol
//! session: modern MCP requests remain stateless. The HTTP dispatch helper
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
    ModernHttpExecutor, ModernHttpExecutorError, ModernHttpRequest,
    ModernHttpResponseMetadata, ModernHttpResponseStream, ModernHttpSseResponseStream,
};
use crate::sse::SseLimits;

/// Bounds shared renewal and response-head admission. Response bodies retain
/// the native executor's separate idle/absolute limits after handoff, further
/// constrained by the original access token's expiry and caller budget.
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

    /// Closes admission and wakes active credential and managed-response waits
    /// without cancelling the caller's Cx or sibling sessions. This is local
    /// closure, NOT an OAuth token-revocation endpoint request. Already-issued
    /// snapshots cannot be recalled. An unpolled response is released on its
    /// next poll or drop; no background task is created to drive abandoned work.
    /// Grant disposal is best effort while another caller retains its lock.
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
    /// a private MCP-resource CA. The returned response retains local session
    /// closure, request cancellation and the original access-token expiry for
    /// JSON/SSE reads. It does not perform issuer introspection or continuous
    /// policy revalidation and is not a full authorization lease.
    pub async fn execute(
        &self,
        cx: &Cx,
        request: &ModernHttpRequest,
    ) -> Result<ManagedOAuthResponse, OAuthSessionError> {
        self.execute_with_cancellation(cx, &McpRequestCancellation::new(), request).await
    }

    pub async fn execute_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: &ModernHttpRequest,
    ) -> Result<ManagedOAuthResponse, OAuthSessionError> {
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
        Ok(ManagedOAuthResponse {
            response,
            session: self.clone(),
            cancellation: cancellation.clone(),
            expires_at: snapshot.expires_at,
            generation: snapshot.generation,
        })
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
        self.check(cx, cancellation)?;
        let deadline = cx.budget().deadline.map_or(deadline, |parent| parent.min(deadline));
        // Do not clip the expiry clock to the caller's budget: those are two
        // distinct terminal reasons. In particular a short caller budget does
        // not make an otherwise valid credential require a new login.
        let expiry_deadline = credential_expiry.map(|expiry| credential_deadline(cx, expiry)).transpose()?;
        let expiry_wins = expiry_deadline.is_some_and(|expiry| expiry <= deadline);
        let deadline = expiry_deadline.map_or(deadline, |expiry| expiry.min(deadline));
        let elapsed = || if expiry_wins { OAuthSessionError::LoginRequired } else { OAuthSessionError::TimedOut };
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
                return Poll::Ready(Err(elapsed()));
            }
            let result = future.as_mut().poll(task);
            self.check(cx, cancellation)?;
            if credential_expiry.is_some_and(|expiry| Instant::now() >= expiry) {
                return Poll::Ready(Err(OAuthSessionError::LoginRequired));
            }
            if cx.now() >= deadline {
                return Poll::Ready(Err(elapsed()));
            }
            result
        }).await
    }
}

/// One HTTP response tied to the credential generation used for its POST.
/// Reading or dropping the response owns socket cleanup. There is no raw-body
/// extraction that would silently remove the session/expiry boundary.
/// Renewing the session cannot extend this response's original token lifetime.
pub struct ManagedOAuthResponse {
    response: ModernHttpResponseStream,
    session: ManagedOAuthSession,
    cancellation: McpRequestCancellation,
    expires_at: Instant,
    generation: u64,
}

impl ManagedOAuthResponse {
    pub fn metadata(&self) -> &ModernHttpResponseMetadata {
        self.response.metadata()
    }

    pub fn credential_generation(&self) -> u64 {
        self.generation
    }

    /// Collects a bounded body under both the original request-cancellation
    /// domain and the supplied caller's budget. Dropping this future discards
    /// the owned response, including partially read bytes and the socket.
    pub async fn read_to_end(self, cx: &Cx, maximum_bytes: usize) -> Result<Vec<u8>, OAuthSessionError> {
        let Self { response, session, cancellation, expires_at, .. } = self;
        session.check(cx, &cancellation)?;
        // await_active alone translates token expiry to runtime time. Sampling
        // it twice could misclassify nanosecond clock skew as a caller timeout.
        // The native body still owns its idle/absolute response deadlines.
        let deadline = cx.budget().deadline.unwrap_or(Time::from_nanos(u64::MAX));
        session.await_active(cx, &cancellation, deadline, Some(expires_at), async {
            response.read_to_end_with_cancellation(cx, &cancellation, maximum_bytes)
                .await.map_err(OAuthSessionError::Http)
        }).await
    }

    /// Opens bounded SSE framing without relinquishing ownership checks.
    /// This exposes raw SSE data events, not typed MCP subscription admission.
    pub fn into_sse_stream(self, limits: SseLimits) -> Result<ManagedOAuthSseStream, OAuthSessionError> {
        Ok(ManagedOAuthSseStream {
            stream: Some(self.response.into_sse_stream(limits).map_err(OAuthSessionError::Http)?),
            session: self.session,
            cancellation: self.cancellation,
            expires_at: self.expires_at,
            generation: self.generation,
            finished: false,
        })
    }
}

/// Caller-owned SSE response whose authorization lifetime cannot be renewed
/// in place. Session close or request cancellation wakes an active read;
/// credential expiry is a terminal read failure, never a reconnect trigger.
/// An unpolled stream retains its socket until its next poll, explicit close
/// or drop. Already-delivered events cannot be recalled.
pub struct ManagedOAuthSseStream {
    stream: Option<ModernHttpSseResponseStream>,
    session: ManagedOAuthSession,
    cancellation: McpRequestCancellation,
    expires_at: Instant,
    generation: u64,
    finished: bool,
}

impl ManagedOAuthSseStream {
    pub fn credential_generation(&self) -> u64 {
        self.generation
    }

    pub fn close(&mut self) {
        self.stream = None;
    }

    /// Delivers one event while preserving the native parser's bounds and
    /// idle/absolute deadlines. Abandoning a polled read closes the stream:
    /// partially consumed framing cannot later be replayed as a fresh read.
    pub async fn next_event(&mut self, cx: &Cx) -> Result<Option<String>, OAuthSessionError> {
        if self.finished {
            return Ok(None);
        }
        // Transfer the socket into this read BEFORE the first await. On drop,
        // error or cancellation it is not returned to a reusable parser.
        let mut stream = self.stream.take().ok_or(OAuthSessionError::Http(
            ModernHttpExecutorError::SseStreamClosed,
        ))?;
        self.session.check(cx, &self.cancellation)?;
        let deadline = cx.budget().deadline.unwrap_or(Time::from_nanos(u64::MAX));
        let result = self.session.await_active(
            cx, &self.cancellation, deadline, Some(self.expires_at), async {
                stream.next_event(cx).await.map_err(OAuthSessionError::Http)
            },
        ).await;
        match &result {
            Ok(Some(_)) => self.stream = Some(stream),
            Ok(None) => self.finished = true,
            Err(_) => {},
        }
        result
    }
}

fn admit_target(resource: &CanonicalHttpUrl, target: &str) -> Result<(), OAuthSessionError> {
    let target = CanonicalHttpUrl::parse(target).map_err(|_| OAuthSessionError::TargetMismatch)?;
    if target.has_userinfo() || target.fragment().is_some() || &target != resource {
        return Err(OAuthSessionError::TargetMismatch);
    }
    Ok(())
}

fn unbounded_deadline_after(cx: &Cx, duration: Duration) -> Result<Time, OAuthSessionError> {
    if cx.timer_driver().is_none() {
        return Err(OAuthSessionError::RuntimeTimerUnavailable);
    }
    let nanos = u64::try_from(duration.as_nanos()).map_err(|_| OAuthSessionError::InvalidPolicy)?;
    let nanos = cx.now().as_nanos().checked_add(nanos).ok_or(OAuthSessionError::InvalidPolicy)?;
    Ok(Time::from_nanos(nanos))
}

fn deadline_after(cx: &Cx, duration: Duration) -> Result<Time, OAuthSessionError> {
    let deadline = unbounded_deadline_after(cx, duration)?;
    Ok(cx.budget().deadline.map_or(deadline, |parent| parent.min(deadline)))
}

fn credential_deadline(cx: &Cx, expiry: Instant) -> Result<Time, OAuthSessionError> {
    let remaining = expiry.checked_duration_since(Instant::now()).ok_or(OAuthSessionError::LoginRequired)?;
    unbounded_deadline_after(cx, remaining)
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

    // These are response-custody tests, not OAuth login proofs. Their session
    // has no credential and cannot perform authenticated dispatch. Real TLS
    // login/rotation is separately exercised by tests/oauth_managed.rs.
    fn response_custody_session() -> ManagedOAuthSession {
        let url = |text| CanonicalHttpUrl::parse(text).unwrap();
        let resource = url("https://mcp.example/mcp");
        let configuration = super::super::oauth::OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example", url("https://issuer.example/authorize"),
            url("https://issuer.example/token"), resource.clone(), "native-client", vec![],
        ).unwrap();
        ManagedOAuthSession {
            inner: Arc::new(SessionInner {
                client: OAuthClient::new(configuration), resource,
                policy: OAuthSessionPolicy::default(),
                state: Arc::new(Mutex::new(None)),
                closed: McpRequestCancellation::new(), pending: AtomicUsize::new(0),
            }),
        }
    }

    fn run(future: impl Future<Output = ()>) {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                asupersync::time::timeout_at(cx.now().saturating_add_nanos(10_000_000_000), future)
                    .await.expect("response-custody fixture must settle within its bound");
            });
    }

    async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
        let mut left = std::pin::pin!(left);
        let mut right = std::pin::pin!(right);
        let mut left_result = None;
        let mut right_result = None;
        poll_fn(|task| {
            if left_result.is_none() {
                if let Poll::Ready(value) = left.as_mut().poll(task) { left_result = Some(value); }
            }
            if right_result.is_none() {
                if let Poll::Ready(value) = right.as_mut().poll(task) { right_result = Some(value); }
            }
            if left_result.is_some() && right_result.is_some() {
                Poll::Ready((left_result.take().unwrap(), right_result.take().unwrap()))
            } else { Poll::Pending }
        }).await
    }

    async fn poll_pending<F: Future>(mut future: std::pin::Pin<&mut F>) {
        poll_fn(|task| {
            assert!(future.as_mut().poll(task).is_pending(), "read must be idle before the tested transition");
            Poll::Ready(())
        }).await;
    }

    async fn response_peer(listener: &asupersync::net::TcpListener, sse: bool, stalled: bool) {
        use asupersync::io::{AsyncReadExt, AsyncWriteExt};
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut wire = Vec::new();
        let mut chunk = [0; 1024];
        let end = loop {
            let count = socket.read(&mut chunk).await.unwrap();
            assert!(count > 0 && wire.len() + count <= 4096);
            wire.extend_from_slice(&chunk[..count]);
            if let Some(index) = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n") { break index + 4; }
        };
        let head = std::str::from_utf8(&wire[..end]).unwrap();
        let length = head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
        }).unwrap();
        assert_eq!(length, 2);
        while wire.len() < end + length {
            let count = socket.read(&mut chunk).await.unwrap();
            assert!(count > 0 && wire.len() + count <= 4096);
            wire.extend_from_slice(&chunk[..count]);
        }
        let mime = if sse { "text/event-stream" } else { "application/json" };
        let body = if sse { "data: first\n\n" } else { "{}" };
        let response = if stalled {
            let prefix = if sse { format!("{:X}\r\n{body}\r\n", body.len()) } else { String::new() };
            format!("HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nTransfer-Encoding: chunked\r\n\r\n{prefix}")
        } else {
            format!("HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        };
        socket.write_all(response.as_bytes()).await.unwrap();
        socket.flush().await.unwrap();
        if stalled {
            let result = socket.read(&mut chunk).await;
            assert!(matches!(result, Ok(0)) || result.is_err(), "terminal local read must release its owned socket");
        }
    }

    async fn open_response(
        cx: &Cx,
        listener: &asupersync::net::TcpListener,
        session: &ManagedOAuthSession,
        cancellation: &McpRequestCancellation,
        lifetime: Duration,
    ) -> ManagedOAuthResponse {
        let request = ModernHttpRequest::new(
            format!("http://{}/mcp", listener.local_addr().unwrap()), b"{}".to_vec(),
            "2026-07-28", "tools/call", None,
        ).unwrap();
        let response = ModernHttpExecutor::new().execute(cx, &request).await.unwrap();
        ManagedOAuthResponse {
            response, session: session.clone(), cancellation: cancellation.clone(),
            expires_at: Instant::now() + lifetime, generation: 7,
        }
    }

    #[test]
    fn managed_response_json_and_sse_keep_successful_delivery_and_byte_bounds() {
        for sse in [false, true] {
            run(async {
                let cx = Cx::current().unwrap();
                let listener = asupersync::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let session = response_custody_session();
                let cancellation = McpRequestCancellation::new();
                let client = async {
                    let response = open_response(&cx, &listener, &session, &cancellation, Duration::from_secs(30)).await;
                    assert_eq!(response.metadata().status(), 200);
                    assert_eq!(response.credential_generation(), 7);
                    if sse {
                        let mut stream = response.into_sse_stream(SseLimits::new(4096, 65536, 8).unwrap()).unwrap();
                        assert_eq!(stream.credential_generation(), 7);
                        assert_eq!(stream.next_event(&cx).await.unwrap(), Some("first".to_owned()));
                        assert_eq!(stream.next_event(&cx).await.unwrap(), None);
                        assert_eq!(stream.next_event(&cx).await.unwrap(), None);
                    } else {
                        assert_eq!(response.read_to_end(&cx, 2).await.unwrap(), b"{}");
                    }
                };
                pair(response_peer(&listener, sse, false), client).await;
            });
        }
        run(async {
            let cx = Cx::current().unwrap();
            let listener = asupersync::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let session = response_custody_session();
            let cancellation = McpRequestCancellation::new();
            let client = async {
                let response = open_response(&cx, &listener, &session, &cancellation, Duration::from_secs(30)).await;
                assert!(matches!(response.read_to_end(&cx, 1).await, Err(OAuthSessionError::Http(
                    ModernHttpExecutorError::ResponseBodyTooLarge { maximum_bytes: 1 },
                ))));
            };
            pair(response_peer(&listener, false, false), client).await;
        });
    }

    #[test]
    fn managed_idle_json_read_observes_close_cancellation_and_original_expiry() {
        for action in 0..3 {
            run(async {
                let cx = Cx::current().unwrap();
                let listener = asupersync::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let session = response_custody_session();
                let sibling = response_custody_session();
                let cancellation = McpRequestCancellation::new();
                let client = async {
                    let lifetime = if action == 2 { Duration::from_millis(30) } else { Duration::from_secs(30) };
                    let response = open_response(&cx, &listener, &session, &cancellation, lifetime).await;
                    let mut reading = Box::pin(response.read_to_end(&cx, 4096));
                    poll_pending(reading.as_mut()).await;
                    match action {
                        0 => session.close(),
                        1 => { cancellation.cancel(); },
                        _ => {},
                    }
                    let result = reading.await;
                    match action {
                        0 => assert!(matches!(result, Err(OAuthSessionError::Closed))),
                        1 => assert!(matches!(result, Err(OAuthSessionError::Cancelled))),
                        _ => assert!(matches!(result, Err(OAuthSessionError::LoginRequired))),
                    }
                    assert!(cx.checkpoint().is_ok());
                    assert!(sibling.check(&cx, &McpRequestCancellation::new()).is_ok());
                };
                pair(response_peer(&listener, false, true), client).await;
            });
        }
    }

    #[test]
    fn managed_idle_sse_read_closes_on_terminal_transitions_without_reuse() {
        for action in 0..4 {
            run(async {
                let cx = Cx::current().unwrap();
                let listener = asupersync::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let session = response_custody_session();
                let cancellation = McpRequestCancellation::new();
                let client = async {
                    let lifetime = if action == 2 { Duration::from_millis(100) } else { Duration::from_secs(30) };
                    let response = open_response(&cx, &listener, &session, &cancellation, lifetime).await;
                    let mut stream = response.into_sse_stream(SseLimits::new(4096, 65536, 8).unwrap()).unwrap();
                    assert_eq!(stream.next_event(&cx).await.unwrap(), Some("first".to_owned()));
                    let mut reading = Box::pin(stream.next_event(&cx));
                    poll_pending(reading.as_mut()).await;
                    if action == 3 {
                        drop(reading);
                    } else {
                        match action {
                            0 => session.close(),
                            1 => { cancellation.cancel(); },
                            _ => {},
                        }
                        let result = reading.await;
                        match action {
                            0 => assert!(matches!(result, Err(OAuthSessionError::Closed))),
                            1 => assert!(matches!(result, Err(OAuthSessionError::Cancelled))),
                            _ => assert!(matches!(result, Err(OAuthSessionError::LoginRequired))),
                        }
                    }
                    assert!(matches!(stream.next_event(&cx).await, Err(OAuthSessionError::Http(
                        ModernHttpExecutorError::SseStreamClosed,
                    ))));
                    assert!(cx.checkpoint().is_ok());
                };
                pair(response_peer(&listener, true, true), client).await;
            });
        }
    }

    #[test]
    fn ordinary_deadline_does_not_relabel_a_valid_credential_as_expired() {
        run(async {
            let cx = Cx::current().unwrap();
            let session = response_custody_session();
            let cancellation = McpRequestCancellation::new();
            let result = session.await_active(
                &cx, &cancellation, deadline_after(&cx, Duration::from_millis(20)).unwrap(),
                Some(Instant::now() + Duration::from_secs(60)),
                std::future::pending::<Result<(), OAuthSessionError>>(),
            ).await;
            assert!(matches!(result, Err(OAuthSessionError::TimedOut)));
            assert!(session.check(&cx, &cancellation).is_ok());
        });
    }
}
