//! Caller-driven, bounded JWKS renewal for JWT resource authentication.
//!
//! Install a clone of [`ManagedJwtResourceVerifier`] through
//! [`crate::auth::TokenAuthProvider`]. Drive [`ManagedJwtResourceVerifier::refresh_with`]
//! from the application's existing runtime using its trusted key-fetch operation.
//! The fetch operation must use an administratively selected HTTPS endpoint,
//! bound response allocation, and honor the supplied caller's cancellation and
//! deadline. Tokens never select a key source. This module creates no runtime,
//! background worker, HTTP client, or unbounded retry loop.
//!
//! Fresh keys remain usable during a failed refresh, but never past their hard
//! monotonic expiry. A slow or abandoned refresh cannot hold admission hostage,
//! revive revoked trust, or overwrite a newer administrative installation.
//! Revocation and refresh affect new authentication only, not work admitted
//! earlier. This is not OIDC discovery, introspection, or individual-token revocation.

use std::fmt;
use std::future::{Future, poll_fn};
use std::sync::{Arc, RwLock};
use std::task::Poll;
use std::time::{Duration, Instant};

use fastmcp_core::{AccessToken, AuthContext, McpContext, McpError, McpErrorCode, McpResult};

use super::jwt_resource::{JwtResourceAuthError, JwtResourcePolicy, JwtResourceVerifier};
use crate::auth::{AuthRequest, TokenVerifier};

/// Maximum admitted key document, independently of the fetcher's allocation bound.
pub const MAX_REFRESH_JWKS_BYTES: usize = 64 * 1024;

/// Finite freshness, retry, and in-flight publication limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JwksRefreshPolicy {
    refresh_after: Duration,
    maximum_age: Duration,
    retry_after: Duration,
    attempt_timeout: Duration,
}

impl Default for JwksRefreshPolicy {
    fn default() -> Self {
        Self {
            refresh_after: Duration::from_secs(300),
            maximum_age: Duration::from_secs(3600),
            retry_after: Duration::from_secs(5),
            attempt_timeout: Duration::from_secs(30),
        }
    }
}

impl JwksRefreshPolicy {
    /// Requires `0 < attempt_timeout <= refresh_after < maximum_age <= 24h`
    /// and `0 < retry_after <= refresh_after`. An attempt may publish only
    /// before its timeout; the fetcher still owns cancellation of its I/O.
    pub fn new(
        refresh_after: Duration,
        maximum_age: Duration,
        retry_after: Duration,
        attempt_timeout: Duration,
    ) -> Result<Self, JwksRefreshError> {
        if refresh_after.is_zero()
            || refresh_after >= maximum_age
            || maximum_age > Duration::from_secs(86_400)
            || retry_after.is_zero()
            || retry_after > refresh_after
            || attempt_timeout.is_zero()
            || attempt_timeout > refresh_after
        {
            return Err(JwksRefreshError::InvalidPolicy);
        }
        Ok(Self { refresh_after, maximum_age, retry_after, attempt_timeout })
    }
}

/// Refresh outcomes that require no key-fetch retry in the current call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwksRefreshOutcome {
    /// A fully admitted new key generation was installed.
    Updated,
    /// Freshness or failure backoff says that no fetch is due yet.
    NotDue,
    /// Another unexpired attempt owns the shared refresh slot.
    InProgress,
}

/// Fixed, non-sensitive errors; fetched documents and peer errors are not retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwksRefreshError {
    /// Invalid or unrepresentable finite timing policy.
    InvalidPolicy,
    /// The candidate key document failed bounded public-JWKS admission.
    InvalidKeys,
    /// The host's key-fetch operation failed.
    FetchFailed,
    /// Trust was explicitly revoked; only administrative installation re-enables it.
    Revoked,
    /// A newer attempt or administrative installation superseded this attempt.
    Superseded,
    /// The caller cancelled the operation.
    Cancelled,
    /// The caller deadline or refresh publication deadline elapsed.
    TimedOut,
    /// Shared state was poisoned; it cannot be recovered into a grant.
    StateUnavailable,
}

impl fmt::Display for JwksRefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid JWKS refresh policy",
            Self::InvalidKeys => "invalid JWKS refresh keys",
            Self::FetchFailed => "JWKS fetch failed",
            Self::Revoked => "JWT resource trust revoked",
            Self::Superseded => "JWKS refresh superseded",
            Self::Cancelled => "JWKS refresh cancelled",
            Self::TimedOut => "JWKS refresh deadline exceeded",
            Self::StateUnavailable => "JWKS refresh state unavailable",
        })
    }
}

impl std::error::Error for JwksRefreshError {}

struct KeyGeneration {
    verifier: JwtResourceVerifier,
    expires_at: Instant,
}

struct RefreshTicket {
    deadline: Instant,
    expires_at: Instant,
    next_refresh_at: Instant,
}

struct State {
    active: Option<Arc<KeyGeneration>>,
    revoked: bool,
    flight: Option<Arc<RefreshTicket>>,
    next_attempt_at: Instant,
}

struct Shared {
    state: RwLock<State>,
    // Private deterministic test seam. Production always uses Instant::now.
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}

/// A shared JWT verifier with expiring keys and single-flight, caller-owned renewal.
///
/// The issuer/resource policy is immutable. Clones share keys, revocation,
/// backoff and the refresh slot; independently constructed owners do not.
/// No unguarded inner verifier is exposed, so callers cannot accidentally
/// bypass freshness or generation fencing. Initial authentication fails closed
/// until a valid refresh or explicit [`Self::install_jwks`] succeeds.
#[derive(Clone)]
pub struct ManagedJwtResourceVerifier {
    policy: JwtResourcePolicy,
    refresh_policy: JwksRefreshPolicy,
    shared: Arc<Shared>,
}

impl fmt::Debug for ManagedJwtResourceVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.shared.state.try_read().ok();
        f.debug_struct("ManagedJwtResourceVerifier")
            .field("refresh_policy", &self.refresh_policy)
            .field("has_keys", &state.as_ref().map(|state| state.active.is_some()))
            .field("revoked", &state.as_ref().map(|state| state.revoked))
            .finish_non_exhaustive()
    }
}

impl ManagedJwtResourceVerifier {
    /// Creates an empty, enabled owner without I/O or runtime creation.
    pub fn new(policy: JwtResourcePolicy, refresh_policy: JwksRefreshPolicy) -> Self {
        Self::with_clock(policy, refresh_policy, Arc::new(Instant::now))
    }

    fn with_clock(
        policy: JwtResourcePolicy,
        refresh_policy: JwksRefreshPolicy,
        clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        let now = clock();
        Self {
            policy,
            refresh_policy,
            shared: Arc::new(Shared {
                state: RwLock::new(State {
                    active: None,
                    revoked: false,
                    flight: None,
                    next_attempt_at: now,
                }),
                clock,
            }),
        }
    }

    fn admit_keys(&self, jwks: &[u8]) -> Result<JwtResourceVerifier, JwksRefreshError> {
        if jwks.len() > MAX_REFRESH_JWKS_BYTES {
            return Err(JwksRefreshError::InvalidKeys);
        }
        JwtResourceVerifier::new(self.policy.clone(), jwks)
            .map_err(|_| JwksRefreshError::InvalidKeys)
    }

    /// Administratively installs a fresh bounded generation, also re-enabling
    /// explicitly revoked trust. Invalid keys leave every field unchanged.
    /// Outstanding fetches cannot overwrite this installation, even with
    /// identical key IDs or bytes. Parsing happens outside the state lock.
    pub fn install_jwks(&self, jwks: &[u8]) -> Result<(), JwksRefreshError> {
        let verifier = self.admit_keys(jwks)?;
        let mut state = self.shared.state.write().map_err(|_| JwksRefreshError::StateUnavailable)?;
        let now = (self.shared.clock)();
        let expires_at = checked_deadline(now, self.refresh_policy.maximum_age)?;
        let next_attempt_at = checked_deadline(now, self.refresh_policy.refresh_after)?;
        let retired = state.active.replace(Arc::new(KeyGeneration { verifier, expires_at }));
        state.revoked = false;
        state.flight = None;
        state.next_attempt_at = next_attempt_at;
        drop(state);
        drop(retired);
        Ok(())
    }

    /// Revokes trust and fences all outstanding authentication and refresh
    /// candidates. Automatic renewal cannot reverse revocation. Returns true
    /// only when this call changes an enabled owner to revoked.
    pub fn revoke_all(&self) -> Result<bool, JwksRefreshError> {
        let mut state = self.shared.state.write().map_err(|_| JwksRefreshError::StateUnavailable)?;
        let changed = !state.revoked;
        state.revoked = true;
        state.flight = None;
        let retired = state.active.take();
        drop(state);
        drop(retired);
        Ok(changed)
    }

    /// Verifies through the existing RS256/claim admission path and then
    /// rechecks the exact key generation and monotonic expiry before exposing
    /// authentication facts. RSA work never holds the shared state lock.
    pub fn verify_access_token(
        &self,
        ctx: &McpContext,
        token: &AccessToken,
    ) -> Result<AuthContext, JwtResourceAuthError> {
        auth_checkpoint(ctx)?;
        let generation = self.fresh_generation()?;
        let authenticated = generation.verifier.verify_access_token(ctx, token)?;
        self.finish_authentication(ctx, &generation, authenticated)
    }

    fn fresh_generation(&self) -> Result<Arc<KeyGeneration>, JwtResourceAuthError> {
        let state = self.shared.state.read().map_err(|_| JwtResourceAuthError::KeysUnavailable)?;
        let generation = state.active.as_ref().ok_or(JwtResourceAuthError::KeysUnavailable)?;
        if state.revoked || (self.shared.clock)() >= generation.expires_at {
            return Err(JwtResourceAuthError::KeysUnavailable);
        }
        Ok(Arc::clone(generation))
    }

    fn finish_authentication(
        &self,
        ctx: &McpContext,
        generation: &Arc<KeyGeneration>,
        authenticated: AuthContext,
    ) -> Result<AuthContext, JwtResourceAuthError> {
        let state = self.shared.state.read().map_err(|_| JwtResourceAuthError::KeysUnavailable)?;
        let active = state.active.as_ref().ok_or(JwtResourceAuthError::KeysUnavailable)?;
        if state.revoked || (self.shared.clock)() >= active.expires_at {
            return Err(JwtResourceAuthError::KeysUnavailable);
        }
        if !Arc::ptr_eq(active, generation) {
            return Err(JwtResourceAuthError::KeysChanged);
        }
        auth_checkpoint(ctx)?;
        Ok(authenticated)
    }

    /// Performs at most one due refresh. `fetch` is not called when cancelled,
    /// revoked, throttled, or another live attempt owns the slot. Its errors
    /// are redacted. An unsuccessful attempt preserves still-fresh active keys
    /// without extending their expiry, and starts a finite retry backoff.
    ///
    /// The host owns the fetch future and its transport cancellation/timers.
    /// This wrapper checks cancellation, revocation, supersession and timeout
    /// before and after every poll, and before publication; it does not install
    /// a timer to wake an otherwise silent host future. Dropping this future
    /// drops the fetch and releases its slot, retaining the retry backoff.
    pub async fn refresh_with<F, Fut>(
        &self,
        ctx: &McpContext,
        fetch: F,
    ) -> Result<JwksRefreshOutcome, JwksRefreshError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = McpResult<Vec<u8>>>,
    {
        let lease = match self.begin_refresh(ctx)? {
            BeginRefresh::Skip(outcome) => return Ok(outcome),
            BeginRefresh::Run(lease) => lease,
        };
        lease.check(ctx)?;
        let mut future = std::pin::pin!(fetch());
        let bytes = poll_fn(|task| {
            if let Err(error) = lease.check(ctx) {
                return Poll::Ready(Err(error));
            }
            let result = future.as_mut().poll(task);
            if let Err(error) = lease.check(ctx) {
                return Poll::Ready(Err(error));
            }
            match result {
                Poll::Pending => Poll::Pending,
                Poll::Ready(result) => Poll::Ready(result.map_err(|_| JwksRefreshError::FetchFailed)),
            }
        }).await?;
        let verifier = self.admit_keys(&bytes)?;
        self.publish(ctx, &lease, verifier)?;
        Ok(JwksRefreshOutcome::Updated)
    }

    fn begin_refresh(&self, ctx: &McpContext) -> Result<BeginRefresh, JwksRefreshError> {
        refresh_checkpoint(ctx)?;
        let mut state = self.shared.state.write().map_err(|_| JwksRefreshError::StateUnavailable)?;
        refresh_checkpoint(ctx)?;
        if state.revoked {
            return Err(JwksRefreshError::Revoked);
        }
        let now = (self.shared.clock)();
        if state.flight.as_ref().is_some_and(|flight| now < flight.deadline) {
            return Ok(BeginRefresh::Skip(JwksRefreshOutcome::InProgress));
        }
        if now < state.next_attempt_at {
            return Ok(BeginRefresh::Skip(JwksRefreshOutcome::NotDue));
        }
        let ticket = Arc::new(RefreshTicket {
            deadline: checked_deadline(now, self.refresh_policy.attempt_timeout)?,
            // Freshness starts at fetch admission, NOT completion. A delayed
            // response cannot silently extend the trust window by its latency.
            expires_at: checked_deadline(now, self.refresh_policy.maximum_age)?,
            next_refresh_at: checked_deadline(now, self.refresh_policy.refresh_after)?,
        });
        state.next_attempt_at = checked_deadline(now, self.refresh_policy.retry_after)?;
        state.flight = Some(Arc::clone(&ticket));
        Ok(BeginRefresh::Run(RefreshLease { shared: Arc::clone(&self.shared), ticket }))
    }

    fn publish(
        &self,
        ctx: &McpContext,
        lease: &RefreshLease,
        verifier: JwtResourceVerifier,
    ) -> Result<(), JwksRefreshError> {
        let mut state = self.shared.state.write().map_err(|_| JwksRefreshError::StateUnavailable)?;
        lease.check_state(ctx, &state)?;
        let retired = state.active.replace(Arc::new(KeyGeneration {
            verifier,
            expires_at: lease.ticket.expires_at,
        }));
        state.next_attempt_at = lease.ticket.next_refresh_at;
        state.flight = None;
        drop(state);
        drop(retired);
        Ok(())
    }
}

impl TokenVerifier for ManagedJwtResourceVerifier {
    fn verify(&self, ctx: &McpContext, _request: AuthRequest<'_>, token: &AccessToken) -> McpResult<AuthContext> {
        self.verify_access_token(ctx, token).map_err(|error| match error {
            JwtResourceAuthError::Cancelled => McpError::request_cancelled(),
            JwtResourceAuthError::TimedOut => McpError::new(McpErrorCode::RequestCancelled, "Request timeout exceeded"),
            _ => McpError::new(McpErrorCode::ResourceForbidden, "Invalid access token"),
        })
    }
}

enum BeginRefresh {
    Skip(JwksRefreshOutcome),
    Run(RefreshLease),
}

struct RefreshLease {
    shared: Arc<Shared>,
    // Retaining the Arc makes pointer identity immune to allocator ABA reuse.
    ticket: Arc<RefreshTicket>,
}

impl RefreshLease {
    fn check(&self, ctx: &McpContext) -> Result<(), JwksRefreshError> {
        let state = self.shared.state.read().map_err(|_| JwksRefreshError::StateUnavailable)?;
        self.check_state(ctx, &state)
    }

    fn check_state(&self, ctx: &McpContext, state: &State) -> Result<(), JwksRefreshError> {
        refresh_checkpoint(ctx)?;
        if state.revoked {
            return Err(JwksRefreshError::Revoked);
        }
        if !state.flight.as_ref().is_some_and(|active| Arc::ptr_eq(active, &self.ticket)) {
            return Err(JwksRefreshError::Superseded);
        }
        if (self.shared.clock)() >= self.ticket.deadline {
            return Err(JwksRefreshError::TimedOut);
        }
        Ok(())
    }
}

impl Drop for RefreshLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.state.write() {
            if state.flight.as_ref().is_some_and(|active| Arc::ptr_eq(active, &self.ticket)) {
                state.flight = None;
            }
        }
    }
}

fn checked_deadline(now: Instant, duration: Duration) -> Result<Instant, JwksRefreshError> {
    now.checked_add(duration).ok_or(JwksRefreshError::InvalidPolicy)
}

fn auth_checkpoint(ctx: &McpContext) -> Result<(), JwtResourceAuthError> {
    if ctx.checkpoint().is_err() {
        return Err(if ctx.deadline_expired() { JwtResourceAuthError::TimedOut } else { JwtResourceAuthError::Cancelled });
    }
    if ctx.deadline_expired() {
        return Err(JwtResourceAuthError::TimedOut);
    }
    Ok(())
}

fn refresh_checkpoint(ctx: &McpContext) -> Result<(), JwksRefreshError> {
    auth_checkpoint(ctx).map_err(|error| match error {
        JwtResourceAuthError::TimedOut => JwksRefreshError::TimedOut,
        _ => JwksRefreshError::Cancelled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Waker};
    use serde_json::json;

    // Public, non-secret RSA fixture also used by the base verifier's tests.
    const MODULUS: &str = "t8MS7wd0l_XyiywWPK11xDRyt3e_A38aRu1KtavUW7bzh7Npv4lOKdMah3g9-WRuBRl3c4UFrX6eMncHandPfM-SRzFskeZ2lZhd-7MpJJDUsgSgOnkWH7q7ZXqfRlZa46U26hL6Ou--50i_Ts6uoVM1OHz3ZpPFNcmf6a0m4g21HB_B4K4KDh3wTNL4PWzPBFbaSibcI3NbAHxvepNkxAebUUgmqJYZKTKV3RxeswmbpB7ytQ6y1aVL2JYKz3yH7nG__FrOFsTTDoOzN-mnLWs7oHndJVaTaW0TRyIPlrLPsFLESoF4QwgJZlor3MoaCzPiY-XZ1maXqjROCenFwQ";

    fn jwks() -> Vec<u8> {
        serde_json::to_vec(&json!({"keys":[{
            "kty":"RSA", "alg":"RS256", "use":"sig", "kid":"one", "n":MODULUS, "e":"AQAB"
        }]})).unwrap()
    }

    fn ctx() -> McpContext {
        McpContext::new(asupersync::Cx::for_testing(), 1)
    }

    fn fixture() -> (ManagedJwtResourceVerifier, Arc<AtomicU64>) {
        let elapsed = Arc::new(AtomicU64::new(0));
        let clock_elapsed = Arc::clone(&elapsed);
        let origin = Instant::now();
        let policy = JwtResourcePolicy::new(
            "https://issuer.example", "https://tools.example/mcp",
            Duration::from_secs(3600), Duration::ZERO,
        ).unwrap();
        let refresh = JwksRefreshPolicy::new(
            Duration::from_secs(10), Duration::from_secs(20),
            Duration::from_secs(2), Duration::from_secs(3),
        ).unwrap();
        let verifier = ManagedJwtResourceVerifier::with_clock(policy, refresh, Arc::new(move || {
            origin + Duration::from_secs(clock_elapsed.load(Ordering::SeqCst))
        }));
        (verifier, elapsed)
    }

    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test future unexpectedly blocked"),
        }
    }

    fn lease(verifier: &ManagedJwtResourceVerifier) -> RefreshLease {
        match verifier.begin_refresh(&ctx()).unwrap() {
            BeginRefresh::Run(lease) => lease,
            BeginRefresh::Skip(_) => panic!("expected a due refresh"),
        }
    }

    #[test]
    fn refresh_installs_bounded_keys_and_clones_share_the_generation() {
        let (verifier, elapsed) = fixture();
        assert!(verifier.fresh_generation().is_err());
        assert_eq!(ready(verifier.refresh_with(&ctx(), || async { Ok(jwks()) })), Ok(JwksRefreshOutcome::Updated));
        let generation = verifier.fresh_generation().unwrap();
        assert!(Arc::ptr_eq(&generation, &verifier.clone().fresh_generation().unwrap()));
        assert_eq!(ready(verifier.refresh_with(&ctx(), || async { panic!("not due") })), Ok(JwksRefreshOutcome::NotDue));
        elapsed.store(19, Ordering::SeqCst);
        assert!(verifier.fresh_generation().is_ok());
        elapsed.store(20, Ordering::SeqCst);
        assert!(matches!(verifier.fresh_generation(), Err(JwtResourceAuthError::KeysUnavailable)));
    }

    #[test]
    fn failed_and_invalid_refreshes_preserve_fresh_keys_without_extending_expiry() {
        let (verifier, elapsed) = fixture();
        verifier.install_jwks(&jwks()).unwrap();
        let original = verifier.fresh_generation().unwrap();
        elapsed.store(10, Ordering::SeqCst);
        assert_eq!(ready(verifier.refresh_with(&ctx(), || async { Err(McpError::internal_error("private peer error")) })), Err(JwksRefreshError::FetchFailed));
        assert!(Arc::ptr_eq(&original, &verifier.fresh_generation().unwrap()));
        assert_eq!(ready(verifier.refresh_with(&ctx(), || async { panic!("backoff") })), Ok(JwksRefreshOutcome::NotDue));
        elapsed.store(12, Ordering::SeqCst);
        assert_eq!(ready(verifier.refresh_with(&ctx(), || async { Ok(b"{\"keys\":[]}".to_vec()) })), Err(JwksRefreshError::InvalidKeys));
        assert!(Arc::ptr_eq(&original, &verifier.fresh_generation().unwrap()));
        elapsed.store(20, Ordering::SeqCst);
        assert!(verifier.fresh_generation().is_err());
    }

    #[test]
    fn expired_keys_can_be_refreshed_but_explicitly_revoked_trust_cannot() {
        let (verifier, elapsed) = fixture();
        verifier.install_jwks(&jwks()).unwrap();
        elapsed.store(20, Ordering::SeqCst);
        assert!(verifier.fresh_generation().is_err());
        assert_eq!(ready(verifier.refresh_with(&ctx(), || async { Ok(jwks()) })), Ok(JwksRefreshOutcome::Updated));
        assert!(verifier.fresh_generation().is_ok());
        assert!(verifier.revoke_all().unwrap());
        assert!(!verifier.revoke_all().unwrap());
        assert_eq!(ready(verifier.refresh_with(&ctx(), || async { panic!("revoked") })), Err(JwksRefreshError::Revoked));
        assert!(verifier.install_jwks(b"{}").is_err());
        assert!(verifier.fresh_generation().is_err());
        verifier.install_jwks(&jwks()).unwrap();
        assert!(verifier.fresh_generation().is_ok());
    }

    #[test]
    fn in_flight_refresh_cannot_restore_revocation_or_overwrite_manual_rotation() {
        for revoke in [false, true] {
            let (verifier, _) = fixture();
            let attempt = lease(&verifier);
            let candidate = verifier.admit_keys(&jwks()).unwrap();
            if revoke { verifier.revoke_all().unwrap(); } else { verifier.install_jwks(&jwks()).unwrap(); }
            assert_eq!(verifier.publish(&ctx(), &attempt, candidate), Err(if revoke { JwksRefreshError::Revoked } else { JwksRefreshError::Superseded }));
            assert_eq!(verifier.fresh_generation().is_ok(), !revoke);
        }
    }

    #[test]
    fn single_flight_expires_and_old_drop_cannot_release_its_successor() {
        let (verifier, elapsed) = fixture();
        let old = lease(&verifier);
        assert_eq!(ready(verifier.refresh_with(&ctx(), || async { panic!("duplicate fetch") })), Ok(JwksRefreshOutcome::InProgress));
        elapsed.store(3, Ordering::SeqCst);
        assert_eq!(old.check(&ctx()), Err(JwksRefreshError::TimedOut));
        let next = lease(&verifier);
        assert_eq!(old.check(&ctx()), Err(JwksRefreshError::Superseded));
        drop(old);
        assert!(next.check(&ctx()).is_ok());
        verifier.publish(&ctx(), &next, verifier.admit_keys(&jwks()).unwrap()).unwrap();
        assert!(verifier.fresh_generation().is_ok());
    }

    #[test]
    fn abandoned_future_releases_its_slot_but_not_failure_backoff() {
        let (verifier, elapsed) = fixture();
        let context = ctx();
        let mut future = Box::pin(verifier.refresh_with(&context, std::future::pending::<McpResult<Vec<u8>>>));
        assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        drop(future);
        assert!(verifier.shared.state.read().unwrap().flight.is_none());
        assert_eq!(ready(verifier.refresh_with(&context, || async { panic!("backoff") })), Ok(JwksRefreshOutcome::NotDue));
        elapsed.store(2, Ordering::SeqCst);
        assert_eq!(ready(verifier.refresh_with(&context, || async { Ok(jwks()) })), Ok(JwksRefreshOutcome::Updated));
    }

    #[test]
    fn fetch_latency_is_not_added_to_key_freshness() {
        let (verifier, elapsed) = fixture();
        assert_eq!(ready(verifier.refresh_with(&ctx(), || async {
            elapsed.store(2, Ordering::SeqCst);
            Ok(jwks())
        })), Ok(JwksRefreshOutcome::Updated));
        elapsed.store(20, Ordering::SeqCst);
        assert!(verifier.fresh_generation().is_err());
    }

    #[test]
    fn late_or_revoking_ready_fetch_cannot_publish() {
        for revoke in [false, true] {
            let (verifier, elapsed) = fixture();
            let result = ready(verifier.refresh_with(&ctx(), || async {
                if revoke { verifier.revoke_all().unwrap(); } else { elapsed.store(3, Ordering::SeqCst); }
                Ok(jwks())
            }));
            assert_eq!(result, Err(if revoke { JwksRefreshError::Revoked } else { JwksRefreshError::TimedOut }));
            assert!(verifier.fresh_generation().is_err());
        }
    }

    #[test]
    fn final_authentication_admission_rechecks_expiry_and_identical_key_rotation() {
        let (verifier, elapsed) = fixture();
        verifier.install_jwks(&jwks()).unwrap();
        let candidate = verifier.fresh_generation().unwrap();
        assert!(verifier.finish_authentication(&ctx(), &candidate, AuthContext::with_subject("alice")).is_ok());
        verifier.install_jwks(&jwks()).unwrap();
        assert!(matches!(verifier.finish_authentication(&ctx(), &candidate, AuthContext::with_subject("alice")), Err(JwtResourceAuthError::KeysChanged)));
        let current = verifier.fresh_generation().unwrap();
        elapsed.store(20, Ordering::SeqCst);
        assert!(matches!(verifier.finish_authentication(&ctx(), &current, AuthContext::with_subject("alice")), Err(JwtResourceAuthError::KeysUnavailable)));
    }

    #[test]
    fn invalid_policy_or_oversized_keys_cannot_change_trust() {
        for (refresh, age, retry, timeout) in [(0,20,2,3), (20,20,2,3), (10,86_401,2,3), (10,20,0,3), (10,20,11,3), (10,20,2,0), (10,20,2,11)] {
            assert!(JwksRefreshPolicy::new(Duration::from_secs(refresh), Duration::from_secs(age), Duration::from_secs(retry), Duration::from_secs(timeout)).is_err());
        }
        let (verifier, _) = fixture();
        verifier.install_jwks(&jwks()).unwrap();
        let current = verifier.fresh_generation().unwrap();
        assert_eq!(verifier.install_jwks(&vec![b' '; MAX_REFRESH_JWKS_BYTES + 1]), Err(JwksRefreshError::InvalidKeys));
        assert!(Arc::ptr_eq(&current, &verifier.fresh_generation().unwrap()));
        assert!(!format!("{verifier:?}").contains(MODULUS));
    }
}
