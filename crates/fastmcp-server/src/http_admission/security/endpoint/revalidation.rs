//! Periodic credential revalidation for an already-open secured SSE response.
//!
//! This owner never renews a token or adopts changed identity, scopes or claims.
//! A fresh provider verdict must reproduce the opening facts and still satisfy
//! the pinned request policy, including any exact named-operation rules.
//! Failure is terminal for this response only.
//!
//! The interval is an explicit maximum cached-verdict age, not an instantaneous
//! revocation guarantee. Both the caller clock and monotonic wall clock bound
//! freshness. Checks run on the caller, without a detached timer or worker.
//! Asynchronous providers retain one future through a check and are bounded by
//! cancellation and a finite timeout. Synchronous providers remain compatible;
//! they must bound their own work because a poll cannot be preempted.

use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::{Cx, types::Time};
use fastmcp_core::{AuthContext, McpContext, Sha256Digest};
use fastmcp_protocol::JsonRpcRequest;

use super::super::scope_policy::request::ScopeRequestPolicy;
use crate::{AuthAdmissionReceipt, Server, TransportAuthorization};

/// Finite provider-work and freshness policy for an individual SSE response.
/// Initial authentication is separate from the bounded revalidation count.
#[derive(Clone, Copy, Debug)]
pub struct SseRevalidationPolicy {
    interval: Duration,
    check_timeout: Duration,
    max_checks: usize,
}

impl Default for SseRevalidationPolicy {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            check_timeout: Duration::from_secs(1),
            max_checks: 1024,
        }
    }
}

impl SseRevalidationPolicy {
    /// Intervals range from 10 ms to 60 s; a provider verdict must arrive within
    /// both its check timeout and that interval. At most 4096 checks are allowed.
    /// Exhaustion closes the stream instead of silently ceasing revalidation.
    pub fn new(
        interval: Duration,
        check_timeout: Duration,
        max_checks: usize,
    ) -> Result<Self, SseAuthorizationError> {
        if interval < Duration::from_millis(10)
            || interval > Duration::from_secs(60)
            || check_timeout.is_zero()
            || check_timeout > interval
            || !(1..=4096).contains(&max_checks)
        {
            return Err(SseAuthorizationError::InvalidPolicy);
        }
        Ok(Self {
            interval,
            check_timeout,
            max_checks,
        })
    }

    pub fn interval(self) -> Duration {
        self.interval
    }
    pub fn check_timeout(self) -> Duration {
        self.check_timeout
    }
    pub fn max_checks(self) -> usize {
        self.max_checks
    }
}

/// Fixed local diagnostics. No token, provider error, original request, claim,
/// scope name or response data is retained. An HTTP status cannot be changed
/// after its SSE head has been written; callers must close that response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SseAuthorizationError {
    InvalidPolicy,
    ProviderRequired,
    Cancelled,
    TimedOut,
    Rejected,
    FactsChanged,
    CheckLimit,
    Closed,
}

impl std::fmt::Display for SseAuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid SSE revalidation policy",
            Self::ProviderRequired => "SSE revalidation requires an authentication provider",
            Self::Cancelled => "SSE authorization cancelled",
            Self::TimedOut => "SSE authorization deadline expired",
            Self::Rejected => "SSE credential revalidation rejected",
            Self::FactsChanged => "SSE authorization facts changed",
            Self::CheckLimit => "SSE revalidation work limit exhausted",
            Self::Closed => "SSE authorization owner is closed",
        })
    }
}
impl std::error::Error for SseAuthorizationError {}

/// Private custody created only from the native opening authentication receipt.
/// Deliberately neither Clone nor Debug: copying it would duplicate a work
/// budget, and formatting it could disclose request or credential material.
pub(super) struct SseAuthorizationLease {
    server: Arc<Server>,
    request: JsonRpcRequest,
    authorization: TransportAuthorization,
    principal: Sha256Digest,
    facts: Option<AuthContext>,
    scopes: ScopeRequestPolicy,
    config: SseRevalidationPolicy,
    next_check: Time,
    wall_expiry: Instant,
    checks: usize,
    closed: bool,
}

struct RevalidationCheck {
    started: Instant,
    next_check: Time,
    provider_deadline: Time,
}

impl SseAuthorizationLease {
    pub(super) fn new(
        cx: &Cx,
        server: Arc<Server>,
        request: &JsonRpcRequest,
        authorization: &TransportAuthorization,
        receipt: &AuthAdmissionReceipt,
        scopes: ScopeRequestPolicy,
        config: SseRevalidationPolicy,
    ) -> Result<Self, SseAuthorizationError> {
        check_context(cx)?;
        if server.auth_provider.is_none() {
            return Err(SseAuthorizationError::ProviderRequired);
        }
        if receipt.method != request.method || receipt.request_id != request.id {
            return Err(SseAuthorizationError::Rejected);
        }
        scopes
            .authorize_request_verified(request, receipt.authenticated.as_ref())
            .map_err(|_| SseAuthorizationError::Rejected)?;
        let started = Instant::now();
        let next_check = fresh_until(cx, cx.now(), config.interval)?;
        let wall_expiry = verification_expiry(started, config.interval, receipt.authenticated.as_ref())?;
        Ok(Self {
            server,
            request: request.clone(),
            authorization: authorization.clone(),
            principal: receipt.fingerprint,
            facts: receipt.authenticated.clone(),
            scopes,
            config,
            next_check,
            wall_expiry,
            checks: 0,
            closed: false,
        })
    }

    /// Check before the response head, before consuming each queued event, and
    /// during idle waits. A cached verdict is valid only until the earlier clock
    /// bound and never bypasses the current caller's cancellation or deadline.
    /// Failure is irreversible even if the host later restores a token.
    pub(super) fn check_cached(&mut self, cx: &Cx) -> Result<bool, SseAuthorizationError> {
        if self.closed {
            self.close();
            return Err(SseAuthorizationError::Closed);
        }
        // Credential freshness and execution liveness are independent. In
        // particular, a cached success cannot authorize a write after caller
        // cancellation, or when a later read supplies a shorter deadline.
        if let Err(error) = check_context(cx) {
            self.close();
            return Err(error);
        }
        Ok(cx.now() < self.next_check && Instant::now() < self.wall_expiry)
    }

    /// Retains one provider future while waiting. Abandoning that wait closes
    /// this lease, so an old cached verdict cannot be reused by a later poll.
    pub(super) async fn check_async(&mut self, cx: &Cx) -> Result<(), SseAuthorizationError> {
        if self.check_cached(cx)? {
            return Ok(());
        }
        self.closed = true;
        let result = self.revalidate_async(cx).await;
        if result.is_ok() {
            self.closed = false;
        } else {
            self.close();
        }
        result
    }

    // Preserve the synchronous test path for exact virtual-clock assertions.
    // Production native SSE always uses the asynchronous provider contract.
    #[cfg(test)]
    pub(super) fn check(&mut self, cx: &Cx) -> Result<(), SseAuthorizationError> {
        if self.check_cached(cx)? {
            return Ok(());
        }
        let result = self.revalidate(cx);
        if result.is_err() {
            self.close();
        }
        result
    }

    fn close(&mut self) {
        self.closed = true;
        // Dispose of retained credential/request data on irreversible refusal.
        self.authorization = TransportAuthorization::default();
        self.request.params = None;
        self.facts = None;
    }

    fn begin_check(&mut self, cx: &Cx) -> Result<RevalidationCheck, SseAuthorizationError> {
        check_context(cx)?;
        if self.checks == self.config.max_checks {
            return Err(SseAuthorizationError::CheckLimit);
        }
        self.checks += 1;
        let started = Instant::now();
        let caller_started = cx.now();
        Ok(RevalidationCheck {
            started,
            next_check: fresh_until(cx, caller_started, self.config.interval)?,
            provider_deadline: fresh_until(cx, caller_started, self.config.check_timeout)?,
        })
    }

    #[cfg(test)]
    fn revalidate(&mut self, cx: &Cx) -> Result<(), SseAuthorizationError> {
        let check = self.begin_check(cx)?;
        let facts = if cx.is_cancel_requested() {
            // check_context admitted this poll only under the already-elected
            // connection drain's runtime mask. Revalidation checks the original
            // credential; it does not admit another application request.
            self.authenticate_retained_credential_during_drain(cx)
        } else {
            self.server
                .preauthenticate_http_request(cx, &self.request, &self.authorization)
                .map(|receipt| (receipt.fingerprint, receipt.authenticated))
                .map_err(|_| SseAuthorizationError::Rejected)
        };
        self.finish_check(cx, check, facts)
    }

    async fn revalidate_async(&mut self, cx: &Cx) -> Result<(), SseAuthorizationError> {
        let check = self.begin_check(cx)?;
        let mut budget = cx.budget().meet(self.server.create_request_budget(cx));
        budget.deadline = Some(budget.deadline.map_or(
            check.provider_deadline, |deadline| deadline.min(check.provider_deadline),
        ));
        if budget.is_past_deadline(cx.now()) {
            return Err(SseAuthorizationError::TimedOut);
        }
        if budget.is_exhausted() {
            return Err(SseAuthorizationError::Cancelled);
        }
        let (context, _lease) = McpContext::new(
            cx.clone(), crate::request_id_to_u64(self.request.id.as_ref()),
        )
        .with_budget_ceiling(budget)
        .begin_request_scope()
        .ok_or(SseAuthorizationError::Rejected)?;
        let auth_request = self.authorization.auth_request(
            &self.request.method,
            self.request.params.as_ref(),
            crate::request_id_to_u64(self.request.id.as_ref()),
        );
        let facts = {
            let mut verification = std::pin::pin!(self.server
                .authenticate_request_without_commit_async(&context, auth_request));
            let mut timeout = std::pin::pin!(asupersync::time::Sleep::new(check.provider_deadline));
            poll_fn(|task| {
                let ceiling = crate::auth::ambient_auth_capability_ceiling();
                let _current = Cx::set_current(Some(cx.clone()));
                let _restriction = Cx::push_restriction(ceiling);
                check_context(cx)?;
                admit_verdict_time(cx.now(), check.provider_deadline,
                    check.started.elapsed(), self.config.check_timeout)?;
                // Only an already-elected terminal drain can pass check_context
                // with runtime cancellation requested. Mirror that permission
                // into the framework context for each poll, never across await.
                let result = if cx.is_cancel_requested() {
                    context.masked(|| verification.as_mut().poll(task))
                        .map_err(|_| SseAuthorizationError::Cancelled)?
                } else {
                    verification.as_mut().poll(task)
                };
                check_context(cx)?;
                admit_verdict_time(cx.now(), check.provider_deadline,
                    check.started.elapsed(), self.config.check_timeout)?;
                if result.is_pending()
                    && (Cx::current().and_then(|active| active.timer_driver()).is_none()
                        || timeout.as_mut().poll(task).is_ready())
                {
                    return Poll::Ready(Err(SseAuthorizationError::TimedOut));
                }
                result.map(|result| result.map_err(|_| SseAuthorizationError::Rejected))
            }).await
        };
        self.finish_check(cx, check, facts)
    }

    fn finish_check(
        &mut self,
        cx: &Cx,
        check: RevalidationCheck,
        facts: Result<(Sha256Digest, Option<AuthContext>), SseAuthorizationError>,
    ) -> Result<(), SseAuthorizationError> {
        // Local cancellation/deadlines and work bounds win over either a late
        // success or a provider refusal. Neither can extend the freshness window.
        check_context(cx)?;
        admit_verdict_time(
            cx.now(),
            check.provider_deadline,
            check.started.elapsed(),
            self.config.check_timeout,
        )?;
        let (principal, facts) = facts?;
        if principal != self.principal || !same_facts(self.facts.as_ref(), facts.as_ref()) {
            return Err(SseAuthorizationError::FactsChanged);
        }
        self.scopes
            .authorize_request_verified(&self.request, facts.as_ref())
            .map_err(|_| SseAuthorizationError::Rejected)?;
        self.wall_expiry = verification_expiry(check.started, self.config.interval, facts.as_ref())?;
        self.next_check = check.next_check;
        self.facts = facts;
        Ok(())
    }

    /// Rechecks retained facts during an elected terminal drain without minting
    /// a new ingress receipt or relaxing ordinary request admission. The outer
    /// connection owner supplies the cancellation mask; this helper cannot
    /// manufacture that permission from a raw cancellation flag.
    #[cfg(test)]
    fn authenticate_retained_credential_during_drain(
        &self,
        cx: &Cx,
    ) -> Result<(Sha256Digest, Option<AuthContext>), SseAuthorizationError> {
        check_context(cx)?;
        let budget = cx.budget().meet(self.server.create_request_budget(cx));
        if budget.is_past_deadline(cx.now()) {
            return Err(SseAuthorizationError::TimedOut);
        }
        if budget.is_exhausted() {
            return Err(SseAuthorizationError::Cancelled);
        }
        let (context, _lease) = McpContext::new(
            cx.clone(),
            crate::request_id_to_u64(self.request.id.as_ref()),
        )
        .with_budget_ceiling(budget)
        .begin_request_scope()
        .ok_or(SseAuthorizationError::Rejected)?;
        let auth_request = self.authorization.auth_request(
            &self.request.method,
            self.request.params.as_ref(),
            crate::request_id_to_u64(self.request.id.as_ref()),
        );
        // McpContext has a separate framework cancellation mask. Mirror the
        // owner's existing runtime permission only around the synchronous
        // provider call so its checkpoints can revalidate an elected frame.
        let facts = context
            .masked(|| {
                self.server
                    .authenticate_request_without_commit(&context, auth_request)
            })
            .map_err(|_| SseAuthorizationError::Cancelled)?;
        check_context(cx)?;
        let remaining = context.budget();
        if remaining.is_past_deadline(cx.now()) {
            return Err(SseAuthorizationError::TimedOut);
        }
        if remaining.is_exhausted() || context.request_cancellation().is_cancel_requested() {
            return Err(SseAuthorizationError::Cancelled);
        }
        facts.map_err(|_| SseAuthorizationError::Rejected)
    }
}

fn verification_expiry(
    started: Instant,
    interval: Duration,
    facts: Option<&AuthContext>,
) -> Result<Instant, SseAuthorizationError> {
    let interval_end = started.checked_add(interval).ok_or(SseAuthorizationError::InvalidPolicy)?;
    let deadline = facts.and_then(AuthContext::verification_valid_until)
        .map_or(interval_end, |deadline| deadline.min(interval_end));
    if Instant::now() >= deadline {
        return Err(SseAuthorizationError::Rejected);
    }
    Ok(deadline)
}

fn admit_verdict_time(
    now: Time,
    deadline: Time,
    elapsed: Duration,
    timeout: Duration,
) -> Result<(), SseAuthorizationError> {
    if now >= deadline || elapsed >= timeout {
        return Err(SseAuthorizationError::TimedOut);
    }
    Ok(())
}

fn same_facts(left: Option<&AuthContext>, right: Option<&AuthContext>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.subject == right.subject
                && left.session_owner() == right.session_owner()
                && left.scopes == right.scopes
                && left.claims == right.claims
        }
        _ => false,
    }
}

fn check_context(cx: &Cx) -> Result<(), SseAuthorizationError> {
    if cx.checkpoint().is_err() {
        return Err(SseAuthorizationError::Cancelled);
    }
    if cx
        .budget()
        .deadline
        .is_some_and(|deadline| cx.now() >= deadline)
    {
        return Err(SseAuthorizationError::TimedOut);
    }
    Ok(())
}

fn fresh_until(cx: &Cx, now: Time, interval: Duration) -> Result<Time, SseAuthorizationError> {
    let nanos =
        u64::try_from(interval.as_nanos()).map_err(|_| SseAuthorizationError::InvalidPolicy)?;
    let end = now
        .as_nanos()
        .checked_add(nanos)
        .ok_or(SseAuthorizationError::InvalidPolicy)?;
    let end = Time::from_nanos(end);
    Ok(cx
        .budget()
        .deadline
        .map_or(end, |deadline| deadline.min(end)))
}

#[cfg(test)]
mod tests {
    use super::super::super::scope_policy::{RequiredScopes, ScopeImplicationPolicy};
    use super::*;
    use crate::{AuthProvider, AuthRequest};
    use fastmcp_core::{McpContext, McpError, McpResult};
    use fastmcp_protocol::{RequestId, protocol_policy::ProtocolPolicy};
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    #[derive(Clone)]
    struct Provider {
        facts: Arc<Mutex<AuthContext>>,
        calls: Arc<AtomicUsize>,
        denied: Arc<AtomicBool>,
    }
    impl AuthProvider for Provider {
        fn authenticate(&self, _: &McpContext, request: AuthRequest<'_>) -> McpResult<AuthContext> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.denied.load(Ordering::SeqCst)
                || request.transport_authorization != Some("Bearer lease-test-token")
                || request.method != "tools/list"
            {
                return Err(McpError::internal_error("private-provider-refusal-canary"));
            }
            Ok(self.facts.lock().unwrap().clone())
        }
    }
    /// Hosts `test` on a runtime whose timer driver is a [`VirtualClock`], so
    /// `Cx::now` reads a clock the test controls instead of falling back to the
    /// wall clock.
    ///
    /// None of the `Cx::for_testing*` constructors installs a timer driver, and
    /// `Cx::now` then resolves to `wall_clock_now`. A caller clock built that
    /// way has no fixed origin and advances between any two reads. Neither a
    /// test of an *exact* deadline boundary nor a test whose premise is that
    /// the caller clock does not move can be expressed against such a clock:
    /// the deadline must be computed before the `Cx` exists, so it cannot be
    /// made relative to a reading of it. Matches the runtime idiom already used
    /// in `proxy.rs` and `fastmcp_client::http_auth::managed::logout`.
    fn with_virtual_clock(test: impl FnOnce(&asupersync::runtime::Runtime)) {
        // Not bound and never advanced: a fresh `VirtualClock` starts at
        // `Time::ZERO` and stays there, which is the property both callers want.
        //
        // No blocking threads: neither caller spawns blocking work, so this
        // runtime exists only to mint contexts bound to the timer driver above.
        // Declaring that bounds this helper's footprint the way the runtimes
        // around it are bounded -- `logout::with_runtime` at (0, 0), and the
        // `lib.rs` subscription runtimes at (2, MAX_DISPATCH_QUEUE_DEPTH).
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(asupersync::time::TimerDriverHandle::with_virtual_clock(
                Arc::new(asupersync::time::VirtualClock::new()),
            ))
            .build()
            .unwrap();
        test(&runtime);
        assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
    }

    fn fixture(config: SseRevalidationPolicy) -> (Cx, Provider, SseAuthorizationLease) {
        let cx = Cx::for_testing();
        let (provider, lease) = fixture_on(&cx, config);
        (cx, provider, lease)
    }

    /// The fixture body, opened against a caller-supplied `Cx` so a test can
    /// choose the clock the lease is established on. `fixture` keeps its
    /// original signature for every test that does not care which clock it is.
    fn fixture_on(cx: &Cx, config: SseRevalidationPolicy) -> (Provider, SseAuthorizationLease) {
        let mut facts = AuthContext::with_subject("lease-test-principal");
        facts.scopes = vec!["read".to_owned()];
        facts.claims = Some(serde_json::json!({"tenant":"original"}));
        let provider = Provider {
            facts: Arc::new(Mutex::new(facts)),
            calls: Arc::new(AtomicUsize::new(0)),
            denied: Arc::new(AtomicBool::new(false)),
        };
        let server = Arc::new(
            Server::new("lease-tests", "1")
                .protocol_policy(ProtocolPolicy::ModernOnly)
                .unwrap()
                .auth_provider(provider.clone())
                .build(),
        );
        let request = JsonRpcRequest::new("tools/list", None, RequestId::Number(7));
        let authorization =
            TransportAuthorization::from_singleton_header(Some("Bearer lease-test-token"));
        let receipt = server
            .preauthenticate_http_request(cx, &request, &authorization)
            .unwrap();
        let scopes = ScopeRequestPolicy::new(
            1,
            ScopeImplicationPolicy::exact(1).unwrap(),
            vec![(
                "tools/list".to_owned(),
                RequiredScopes::new(vec!["read".to_owned()]).unwrap(),
            )],
        )
        .unwrap();
        let lease = SseAuthorizationLease::new(
            cx,
            server,
            &request,
            &authorization,
            &receipt,
            scopes,
            config,
        )
        .unwrap();
        (provider, lease)
    }
    fn due(lease: &mut SseAuthorizationLease, cx: &Cx) {
        lease.next_check = cx.now();
    }

    #[derive(Clone)]
    struct AsyncProvider {
        inner: Provider,
        pending: Arc<AtomicBool>,
        created: Arc<AtomicUsize>,
        polls: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
    }

    struct AsyncVerification<'a> {
        provider: &'a AsyncProvider,
        context: &'a McpContext,
        request: AuthRequest<'a>,
    }
    impl Future for AsyncVerification<'_> {
        type Output = McpResult<AuthContext>;
        fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<Self::Output> {
            self.provider.polls.fetch_add(1, Ordering::SeqCst);
            if self.provider.pending.load(Ordering::SeqCst) {
                Poll::Pending
            } else {
                Poll::Ready(self.provider.inner.authenticate(self.context, self.request))
            }
        }
    }
    impl Drop for AsyncVerification<'_> {
        fn drop(&mut self) {
            self.provider.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl AuthProvider for AsyncProvider {
        fn authenticate(&self, _: &McpContext, _: AuthRequest<'_>) -> McpResult<AuthContext> {
            panic!("asynchronous SSE provider must never use synchronous authentication")
        }
        fn authenticate_async<'a>(&'a self, context: &'a McpContext, request: AuthRequest<'a>)
            -> crate::AuthFuture<'a>
        {
            self.created.fetch_add(1, Ordering::SeqCst);
            Box::pin(AsyncVerification { provider: self, context, request })
        }
    }

    fn async_fixture(cx: &Cx) -> (AsyncProvider, SseAuthorizationLease) {
        let (inner, old) = fixture_on(cx, SseRevalidationPolicy::default());
        let provider = AsyncProvider {
            inner, pending: Arc::new(AtomicBool::new(false)),
            created: Arc::new(AtomicUsize::new(0)), polls: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicUsize::new(0)),
        };
        let server = Arc::new(Server::new("async-lease", "1")
            .protocol_policy(ProtocolPolicy::ModernOnly).unwrap()
            .auth_provider(provider.clone()).build());
        let receipt = {
            let mut admission = Box::pin(server.preauthenticate_http_request_async(
                cx, &old.request, &old.authorization,
            ));
            let mut task = std::task::Context::from_waker(std::task::Waker::noop());
            let Poll::Ready(Ok(receipt)) = admission.as_mut().poll(&mut task) else {
                panic!("immediately ready async opening must authenticate")
            };
            receipt
        };
        let lease = SseAuthorizationLease::new(cx, server, &old.request, &old.authorization,
            &receipt, old.scopes.clone(), old.config).unwrap();
        (provider, lease)
    }

    #[test]
    fn async_revalidation_retains_one_future_across_wakes_and_reuses_fresh_facts() {
        with_virtual_clock(|runtime| {
            let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
            let (provider, mut lease) = async_fixture(&cx);
            provider.pending.store(true, Ordering::SeqCst);
            due(&mut lease, &cx);
            let mut check = Box::pin(lease.check_async(&cx));
            let mut task = std::task::Context::from_waker(std::task::Waker::noop());
            for _ in 0..3 { assert!(check.as_mut().poll(&mut task).is_pending()); }
            assert_eq!(provider.created.load(Ordering::SeqCst), 2);
            assert_eq!(provider.dropped.load(Ordering::SeqCst), 1);
            provider.pending.store(false, Ordering::SeqCst);
            assert_eq!(check.as_mut().poll(&mut task), Poll::Ready(Ok(())));
            drop(check);
            assert_eq!(provider.dropped.load(Ordering::SeqCst), 2);
            assert_eq!(lease.checks, 1);
            assert_eq!(lease.check_cached(&cx), Ok(true));
            let mut cached = Box::pin(lease.check_async(&cx));
            assert_eq!(cached.as_mut().poll(&mut task), Poll::Ready(Ok(())));
            assert_eq!(provider.created.load(Ordering::SeqCst), 2);
            assert_eq!(provider.polls.load(Ordering::SeqCst), 5);
        });
    }

    #[test]
    fn abandoning_async_revalidation_closes_the_lease_and_drops_the_provider() {
        with_virtual_clock(|runtime| {
            let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
            let (provider, mut lease) = async_fixture(&cx);
            provider.pending.store(true, Ordering::SeqCst);
            due(&mut lease, &cx);
            let mut check = Box::pin(lease.check_async(&cx));
            let mut task = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(check.as_mut().poll(&mut task).is_pending());
            drop(check);
            assert_eq!(provider.dropped.load(Ordering::SeqCst), 2);
            provider.pending.store(false, Ordering::SeqCst);
            assert_eq!(lease.check_cached(&cx), Err(SseAuthorizationError::Closed));
            assert!(lease.facts.is_none());
            assert_eq!(provider.created.load(Ordering::SeqCst), 2);
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[test]
    fn async_revalidation_refuses_cancellation_and_timeout_without_another_provider_poll() {
        for cancel in [false, true] {
            let clock = Arc::new(asupersync::time::VirtualClock::new());
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .blocking_threads(0, 0)
                .with_timer_driver(asupersync::time::TimerDriverHandle::with_virtual_clock(
                    Arc::clone(&clock),
                )).build().unwrap();
            let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
            let (provider, mut lease) = async_fixture(&cx);
            provider.pending.store(true, Ordering::SeqCst);
            due(&mut lease, &cx);
            let mut check = Box::pin(lease.check_async(&cx));
            let mut task = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(check.as_mut().poll(&mut task).is_pending());
            if cancel { cx.set_cancel_requested(true); }
            else { clock.advance_to(Time::from_secs(1)); }
            assert_eq!(check.as_mut().poll(&mut task), Poll::Ready(Err(if cancel {
                SseAuthorizationError::Cancelled
            } else { SseAuthorizationError::TimedOut })));
            drop(check);
            assert!(lease.closed);
            assert!(lease.facts.is_none());
            assert_eq!(provider.polls.load(Ordering::SeqCst), 2);
            assert_eq!(provider.dropped.load(Ordering::SeqCst), 2);
            assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
        }
    }

    #[test]
    fn async_revalidation_preserves_an_already_elected_terminal_drain() {
        with_virtual_clock(|runtime| {
            let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
            let (provider, mut lease) = async_fixture(&cx);
            due(&mut lease, &cx);
            cx.set_cancel_requested(true);
            let mut check = Box::pin(lease.check_async(&cx));
            let mut task = std::task::Context::from_waker(std::task::Waker::noop());
            assert_eq!(cx.masked(|| check.as_mut().poll(&mut task)), Poll::Ready(Ok(())));
            drop(check);
            assert!(!lease.closed);
            assert_eq!(provider.created.load(Ordering::SeqCst), 2);
            assert!(cx.is_cancel_requested());
            // A drain cannot manufacture a new ordinary ingress receipt.
            let mut opening = Box::pin(lease.server.preauthenticate_http_request_async(
                &cx, &lease.request, &lease.authorization,
            ));
            assert!(matches!(cx.masked(|| opening.as_mut().poll(&mut task)), Poll::Ready(Err(_))));
            assert_eq!(provider.created.load(Ordering::SeqCst), 2);
        });
    }

    #[test]
    fn credential_expiry_caps_opening_and_refreshed_sse_verdicts() {
        with_virtual_clock(|runtime| {
            let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
            let (provider, mut lease) = async_fixture(&cx);
            let deadline = Instant::now() + Duration::from_secs(2);
            let facts = provider.inner.facts.lock().unwrap().clone()
                .with_verification_valid_until(deadline);
            *provider.inner.facts.lock().unwrap() = facts;
            due(&mut lease, &cx);
            let mut task = std::task::Context::from_waker(std::task::Waker::noop());
            let mut refresh = Box::pin(lease.check_async(&cx));
            assert_eq!(refresh.as_mut().poll(&mut task), Poll::Ready(Ok(())));
            drop(refresh);
            assert_eq!(lease.wall_expiry, deadline);
            assert_eq!(lease.facts.as_ref().unwrap().verification_valid_until(), Some(deadline));
            let receipt = {
                let mut opening = Box::pin(lease.server.preauthenticate_http_request_async(
                    &cx, &lease.request, &lease.authorization,
                ));
                let Poll::Ready(Ok(receipt)) = opening.as_mut().poll(&mut task) else {
                    panic!("bounded opening receipt")
                };
                receipt
            };
            let opened = SseAuthorizationLease::new(&cx, Arc::clone(&lease.server), &lease.request,
                &lease.authorization, &receipt, lease.scopes.clone(), lease.config).unwrap();
            assert_eq!(opened.wall_expiry, deadline);
            let expired = Instant::now();
            let mut expired_receipt = receipt;
            expired_receipt.authenticated = expired_receipt.authenticated
                .map(|facts| facts.with_verification_valid_until(expired));
            assert!(matches!(SseAuthorizationLease::new(&cx, Arc::clone(&lease.server),
                &lease.request, &lease.authorization, &expired_receipt, lease.scopes.clone(), lease.config),
                Err(SseAuthorizationError::Rejected)));
        });
    }

    #[test]
    fn response_guard_waits_for_one_async_verdict_before_polling_or_releasing_work() {
        with_virtual_clock(|runtime| {
            let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
            let (provider, mut lease) = async_fixture(&cx);
            due(&mut lease, &cx);
            provider.pending.store(true, Ordering::SeqCst);
            let polls = std::cell::Cell::new(0);
            let mut authorization = Some(lease);
            let operation = poll_fn(|_| { polls.set(polls.get() + 1); Poll::Ready(17) });
            let mut guarded = Box::pin(super::super::guard_response(&cx, &mut authorization, operation));
            let mut task = std::task::Context::from_waker(std::task::Waker::noop());
            for _ in 0..3 { assert!(guarded.as_mut().poll(&mut task).is_pending()); }
            assert_eq!(polls.get(), 0);
            assert_eq!(provider.created.load(Ordering::SeqCst), 2);
            provider.pending.store(false, Ordering::SeqCst);
            assert_eq!(guarded.as_mut().poll(&mut task), Poll::Ready(Ok(17)));
            assert_eq!(polls.get(), 1);
        });
    }

    #[test]
    fn changed_async_facts_are_refused_before_queued_response_work_is_polled() {
        with_virtual_clock(|runtime| {
            let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
            let (provider, mut lease) = async_fixture(&cx);
            due(&mut lease, &cx);
            provider.inner.facts.lock().unwrap().scopes.clear();
            let polls = std::cell::Cell::new(0);
            let mut authorization = Some(lease);
            let operation = poll_fn(|_| { polls.set(polls.get() + 1); Poll::Ready(17) });
            let mut guarded = Box::pin(super::super::guard_response(&cx, &mut authorization, operation));
            let mut task = std::task::Context::from_waker(std::task::Waker::noop());
            assert_eq!(guarded.as_mut().poll(&mut task), Poll::Ready(Err(
                super::super::SecuredHttpEndpointError::Revalidation(SseAuthorizationError::FactsChanged),
            )));
            assert_eq!(polls.get(), 0);
            assert_eq!(provider.dropped.load(Ordering::SeqCst), 2);
        });
    }

    #[test]
    fn revalidation_policy_has_finite_interval_timeout_and_work_bounds() {
        let default = SseRevalidationPolicy::default();
        assert!(
            SseRevalidationPolicy::new(
                default.interval(),
                default.check_timeout(),
                default.max_checks()
            )
            .is_ok()
        );
        for (interval, timeout, checks) in [
            (Duration::ZERO, Duration::from_millis(1), 1),
            (Duration::from_secs(61), Duration::from_secs(1), 1),
            (Duration::from_secs(1), Duration::ZERO, 1),
            (Duration::from_secs(1), Duration::from_secs(2), 1),
            (Duration::from_secs(1), Duration::from_secs(1), 0),
            (Duration::from_secs(1), Duration::from_secs(1), 4097),
        ] {
            assert!(SseRevalidationPolicy::new(interval, timeout, checks).is_err());
        }
        assert!(
            SseRevalidationPolicy::new(Duration::from_millis(10), Duration::from_millis(10), 4096)
                .is_ok()
        );
    }

    #[test]
    fn fresh_verdict_is_reused_but_a_due_check_calls_the_real_provider_once() {
        let (cx, provider, mut lease) = fixture(SseRevalidationPolicy::default());
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        for _ in 0..3 {
            lease.check(&cx).unwrap();
        }
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        due(&mut lease, &cx);
        lease.check(&cx).unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        assert_eq!(lease.checks, 1);
        lease.check(&cx).unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn due_revalidation_preserves_elected_drain_and_refuses_ordinary_cancellation() {
        for elected in [false, true] {
            with_virtual_clock(|runtime| {
                let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
                let (provider, mut lease) = fixture_on(&cx, SseRevalidationPolicy::default());
                due(&mut lease, &cx);
                let original_facts = lease.facts.clone();
                let original_principal = lease.principal;
                cx.set_cancel_requested(true);

                let result = if elected {
                    cx.masked(|| lease.check(&cx))
                } else {
                    lease.check(&cx)
                };
                if elected {
                    assert_eq!(result, Ok(()));
                    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
                    assert_eq!(lease.checks, 1);
                    assert_eq!(lease.principal, original_principal);
                    assert!(same_facts(lease.facts.as_ref(), original_facts.as_ref()));
                    assert!(!lease.closed);
                    assert!(
                        cx.masked(|| lease.server.preauthenticate_http_request(
                            &cx,
                            &lease.request,
                            &lease.authorization,
                        ))
                        .is_err(),
                        "terminal revalidation must not reopen ordinary ingress"
                    );
                    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
                } else {
                    assert_eq!(result, Err(SseAuthorizationError::Cancelled));
                    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
                    assert_eq!(lease.checks, 0);
                    assert!(lease.closed);
                    assert!(lease.facts.is_none());
                    assert_eq!(
                        cx.masked(|| lease.check(&cx)),
                        Err(SseAuthorizationError::Closed),
                        "a later drain mask cannot revive a refused lease"
                    );
                    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
                }
                assert!(cx.is_cancel_requested());
            });
        }
    }

    #[test]
    fn elected_revalidation_keeps_the_original_absolute_deadline() {
        let clock = Arc::new(asupersync::time::VirtualClock::new());
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(asupersync::time::TimerDriverHandle::with_virtual_clock(
                Arc::clone(&clock),
            ))
            .build()
            .unwrap();
        let cx = runtime.request_cx_with_budget(
            asupersync::Budget::INFINITE.with_deadline(Time::from_nanos(200_000_000)),
        );
        let (provider, mut lease) = fixture_on(&cx, SseRevalidationPolicy::default());
        clock.advance_to(Time::from_nanos(100_000_000));
        due(&mut lease, &cx);
        cx.set_cancel_requested(true);
        assert_eq!(cx.masked(|| lease.check(&cx)), Ok(()));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);

        clock.advance_to(Time::from_nanos(200_000_000));
        assert_eq!(
            cx.masked(|| lease.check(&cx)),
            Err(SseAuthorizationError::TimedOut)
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        assert!(lease.closed);
        assert!(lease.facts.is_none());
        assert!(cx.is_cancel_requested());
        assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
    }

    #[test]
    fn cached_verdict_cancellation_is_terminal_without_provider_work_or_sibling_effects() {
        let (cx, provider, mut lease) = fixture(SseRevalidationPolicy::default());
        let (sibling_cx, sibling_provider, mut sibling) = fixture(SseRevalidationPolicy::default());
        assert_eq!(lease.check(&cx), Ok(()));
        assert!(lease.facts.is_some());
        let freshness = (lease.next_check, lease.wall_expiry);
        assert!(cx.now() < freshness.0 && Instant::now() < freshness.1);

        cx.set_cancel_requested(true);
        assert_eq!(lease.check(&cx), Err(SseAuthorizationError::Cancelled));
        assert!(lease.closed);
        assert!(lease.facts.is_none());
        assert_eq!(lease.checks, 0);
        assert_eq!((lease.next_check, lease.wall_expiry), freshness);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);

        cx.set_cancel_requested(false);
        assert_eq!(lease.check(&cx), Err(SseAuthorizationError::Closed));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(sibling.check(&sibling_cx), Ok(()));
        assert!(!sibling.closed);
        assert_eq!(sibling_provider.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cached_verdict_obeys_a_later_readers_exact_deadline_boundary() {
        for expired in [false, true] {
            with_virtual_clock(|runtime| {
                // The lease is opened by an unconstrained caller and then read by a
                // later caller whose deadline sits exactly on the boundary. Both
                // contexts are minted from this runtime, so they share one clock
                // and the boundary is exact rather than approximate.
                let opener = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
                let (provider, mut lease) = fixture_on(&opener, SseRevalidationPolicy::default());
                let deadline = Time::from_nanos(u64::from(!expired));
                let cx = runtime
                    .request_cx_with_budget(asupersync::Budget::new().with_deadline(deadline));
                assert_eq!(cx.now(), Time::ZERO);
                assert!(cx.now() < lease.next_check && Instant::now() < lease.wall_expiry);
                let result = lease.check(&cx);
                if expired {
                    assert!(matches!(
                        result,
                        Err(SseAuthorizationError::TimedOut | SseAuthorizationError::Cancelled)
                    ));
                    assert!(lease.closed);
                    assert!(lease.facts.is_none());
                    assert_eq!(
                        lease.check(&Cx::for_testing()),
                        Err(SseAuthorizationError::Closed)
                    );
                } else {
                    assert_eq!(result, Ok(()));
                    assert!(!lease.closed);
                    assert!(lease.facts.is_some());
                }
                assert_eq!(lease.checks, 0, "local liveness never spends provider work");
                assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
            });
        }
    }

    #[test]
    fn revoked_credential_is_terminal_and_cannot_be_restored_on_the_same_stream() {
        let (cx, provider, mut lease) = fixture(SseRevalidationPolicy::default());
        provider.denied.store(true, Ordering::SeqCst);
        due(&mut lease, &cx);
        assert_eq!(lease.check(&cx), Err(SseAuthorizationError::Rejected));
        provider.denied.store(false, Ordering::SeqCst);
        assert_eq!(lease.check(&cx), Err(SseAuthorizationError::Closed));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        assert!(lease.facts.is_none());
        assert!(lease.request.params.is_none());
    }

    #[test]
    fn changed_grants_or_claims_cannot_continue_a_handler_started_under_old_facts() {
        for change in 0..4 {
            let (cx, provider, mut lease) = fixture(SseRevalidationPolicy::default());
            {
                let mut facts = provider.facts.lock().unwrap();
                match change {
                    0 => facts.scopes.clear(),
                    1 => facts.scopes.push("write".to_owned()),
                    2 => facts.claims = Some(serde_json::json!({"tenant":"other"})),
                    _ => facts.subject = Some("different-principal".to_owned()),
                }
            }
            due(&mut lease, &cx);
            assert_eq!(lease.check(&cx), Err(SseAuthorizationError::FactsChanged));
            assert!(lease.closed);
        }
    }

    #[test]
    fn work_exhaustion_does_not_turn_a_stream_into_an_unchecked_stream() {
        let config =
            SseRevalidationPolicy::new(Duration::from_secs(5), Duration::from_secs(1), 1).unwrap();
        let (cx, provider, mut lease) = fixture(config);
        due(&mut lease, &cx);
        lease.check(&cx).unwrap();
        due(&mut lease, &cx);
        assert_eq!(lease.check(&cx), Err(SseAuthorizationError::CheckLimit));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        assert_eq!(lease.check(&cx), Err(SseAuthorizationError::Closed));
    }

    #[test]
    fn monotonic_wall_expiry_still_triggers_when_the_caller_clock_does_not_move() {
        with_virtual_clock(|runtime| {
            let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
            let (provider, mut lease) = fixture_on(&cx, SseRevalidationPolicy::default());
            let caller_time = cx.now();
            lease.wall_expiry = Instant::now();
            provider.denied.store(true, Ordering::SeqCst);
            // The premise in this test's name: a clock the runtime owns and
            // nothing advances. Only the monotonic wall bound can fire.
            assert_eq!(cx.now(), caller_time);
            assert_eq!(lease.check(&cx), Err(SseAuthorizationError::Rejected));
        });
    }

    #[test]
    fn exact_fact_comparison_includes_session_owner_even_when_subject_is_equal() {
        let mut left = AuthContext::with_subject("same-subject");
        left.scopes = vec!["read".to_owned()];
        let right = left
            .clone()
            .with_session_owner(Sha256Digest::from_bytes([8; 32]));
        assert!(!same_facts(Some(&left), Some(&right)));
        assert!(same_facts(Some(&left), Some(&left.clone())));
        assert!(!same_facts(None, Some(&AuthContext::anonymous())));
    }

    #[test]
    fn changed_request_cannot_borrow_another_opening_receipt() {
        let (cx, _, lease) = fixture(SseRevalidationPolicy::default());
        let mut request = lease.request.clone();
        let receipt = lease
            .server
            .preauthenticate_http_request(&cx, &request, &lease.authorization)
            .unwrap();
        request.id = Some(RequestId::Number(8));
        let result = SseAuthorizationLease::new(
            &cx,
            Arc::clone(&lease.server),
            &request,
            &lease.authorization,
            &receipt,
            lease.scopes.clone(),
            lease.config,
        );
        assert!(matches!(result, Err(SseAuthorizationError::Rejected)));
    }

    #[test]
    fn refused_lease_does_not_close_a_sibling_lease() {
        let (cx, provider, mut first) = fixture(SseRevalidationPolicy::default());
        let (_, sibling_provider, mut sibling) = fixture(SseRevalidationPolicy::default());
        provider.denied.store(true, Ordering::SeqCst);
        due(&mut first, &cx);
        assert!(first.check(&cx).is_err());
        due(&mut sibling, &cx);
        sibling.check(&cx).unwrap();
        assert_eq!(sibling_provider.calls.load(Ordering::SeqCst), 2);
        assert!(!sibling.closed);
    }

    #[test]
    fn rejection_diagnostics_do_not_reflect_provider_error_or_identity() {
        let (cx, provider, mut lease) = fixture(SseRevalidationPolicy::default());
        provider.denied.store(true, Ordering::SeqCst);
        due(&mut lease, &cx);
        let error = lease.check(&cx).unwrap_err();
        let diagnostic = format!("{error:?} {error}");
        for private in ["canary", "lease-test-token", "lease-test-principal", "read"] {
            assert!(!diagnostic.contains(private));
        }
    }

    #[test]
    fn provider_timeout_uses_the_shorter_check_bound_on_each_clock() {
        let cx = Cx::for_testing();
        let started = Time::from_nanos(100);
        let config = SseRevalidationPolicy::default();
        let deadline = fresh_until(&cx, started, config.check_timeout()).unwrap();
        let freshness = fresh_until(&cx, started, config.interval()).unwrap();
        assert!(deadline < freshness);
        let before = Time::from_nanos(deadline.as_nanos() - 1);
        let just_before = config.check_timeout() - Duration::from_nanos(1);
        assert_eq!(
            admit_verdict_time(before, deadline, just_before, config.check_timeout()),
            Ok(())
        );
        assert_eq!(
            admit_verdict_time(deadline, deadline, Duration::ZERO, config.check_timeout()),
            Err(SseAuthorizationError::TimedOut)
        );
        assert_eq!(
            admit_verdict_time(
                started,
                deadline,
                config.check_timeout(),
                config.check_timeout()
            ),
            Err(SseAuthorizationError::TimedOut)
        );
    }

    #[test]
    fn named_operation_lease_rechecks_the_exact_request_not_only_its_method() {
        use super::super::super::scope_policy::request::operation::{
            OperationScopePolicy, ScopedOperation,
        };
        let cx = Cx::for_testing();
        let mut facts = AuthContext::with_subject("named-lease-owner");
        facts.scopes = vec!["read".into()];
        let verifier =
            crate::StaticTokenVerifier::new([("named-lease-token".to_owned(), facts)]).unwrap();
        let server = Arc::new(
            Server::new("named-lease", "1")
                .protocol_policy(ProtocolPolicy::ModernOnly)
                .unwrap()
                .auth_provider(crate::TokenAuthProvider::new(verifier.clone()))
                .build(),
        );
        let authorization =
            TransportAuthorization::from_singleton_header(Some("Bearer named-lease-token"));
        let methods = ScopeRequestPolicy::new(
            1,
            ScopeImplicationPolicy::exact(1).unwrap(),
            vec![(
                "tools/call".into(),
                RequiredScopes::new(vec!["read".into()]).unwrap(),
            )],
        )
        .unwrap();
        let scopes = ScopeRequestPolicy::for_operations(
            OperationScopePolicy::new(
                1,
                methods,
                vec![(
                    ScopedOperation::ToolCall("allowed".into()),
                    RequiredScopes::new(vec!["read".into()]).unwrap(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
        let mut request = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({"name":"allowed"})),
            RequestId::Number(9),
        );
        let receipt = server
            .preauthenticate_http_request(&cx, &request, &authorization)
            .unwrap();
        let mut lease = SseAuthorizationLease::new(
            &cx,
            Arc::clone(&server),
            &request,
            &authorization,
            &receipt,
            scopes.clone(),
            SseRevalidationPolicy::default(),
        )
        .unwrap();
        due(&mut lease, &cx);
        assert_eq!(lease.check(&cx), Ok(()));
        assert_eq!(lease.checks, 1);
        request.params = Some(serde_json::json!({"name":"forbidden"}));
        let receipt = server
            .preauthenticate_http_request(&cx, &request, &authorization)
            .unwrap();
        assert!(matches!(
            SseAuthorizationLease::new(
                &cx,
                server,
                &request,
                &authorization,
                &receipt,
                scopes,
                SseRevalidationPolicy::default()
            ),
            Err(SseAuthorizationError::Rejected)
        ));
        assert!(
            !lease.closed,
            "a refused new target cannot close the admitted sibling"
        );
        assert!(verifier.revoke_token("named-lease-token").unwrap());
        due(&mut lease, &cx);
        assert_eq!(lease.check(&cx), Err(SseAuthorizationError::Rejected));
        assert!(lease.closed);
        assert!(lease.facts.is_none());
    }
}
