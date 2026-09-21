//! Managed OAuth logout with local-first closure and single-attempt remote revocation.
//!
//! Logout closes the shared session before waiting for grant custody, so issued
//! snapshots stop constructing new Authorization headers immediately. Once the
//! grant lock is acquired, the grant is removed from session state before any
//! network await. Remote outcomes are diagnostic facts, never retry authority.
//! Already-sent requests and headers cannot be recalled.

use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::Poll;

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::sync::OwnedMutexGuard;
use asupersync::time::Sleep;
use asupersync::types::Time;

use super::{ManagedOAuthSession, OAuthSessionError, deadline_after};
use crate::http_auth::oauth::revocation::{OAuthRevocationError, OAuthRevocationReport};

/// Why remote revocation did not produce a complete token report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedOAuthRemoteRevocation {
    /// No retained grant remained after local closure.
    NoGrant,
    /// The trusted configuration did not enable RFC 7009 revocation.
    EndpointUnavailable,
    /// Both token attempts reached a terminal per-token outcome.
    Completed(OAuthRevocationReport),
    /// The caller cancelled after local closure.
    Cancelled,
    /// The logout acquisition/revocation deadline expired after local closure.
    TimedOut,
    /// Grant custody or revocation preflight failed after local closure.
    Failed,
}

/// Logout always reports that local session admission was closed once this
/// value exists. Remote failure does not resurrect the grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedOAuthLogoutReport {
    remote: ManagedOAuthRemoteRevocation,
}

impl ManagedOAuthLogoutReport {
    pub fn local_closed(&self) -> bool {
        true
    }

    pub fn remote(&self) -> ManagedOAuthRemoteRevocation {
        self.remote
    }
}

// SessionGuard may preserve a refresh-held grant only while an actual logout
// owner can receive it. Keep this obligation live across the lock await and
// retire it on cancellation, future abandonment, and unwinding as well as on
// ordinary completion. Cleanup never waits for the grant lock or reopens the
// session; a still-active SessionGuard resumes its ordinary close-on-drop rule.
struct LogoutHandoff<'a>(&'a ManagedOAuthSession);

impl<'a> LogoutHandoff<'a> {
    fn begin(session: &'a ManagedOAuthSession) -> Result<Self, OAuthSessionError> {
        session
            .inner
            .logout_handoff
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| OAuthSessionError::Closed)?;
        let handoff = Self(session);
        // A concurrent close may have won since logout's initial preflight.
        if session.inner.closed.is_cancel_requested() {
            return Err(OAuthSessionError::Closed);
        }
        session.inner.closed.cancel();
        Ok(handoff)
    }
}

impl Drop for LogoutHandoff<'_> {
    fn drop(&mut self) {
        self.0.inner.logout_handoff.store(false, Ordering::Release);
        // A refresh can have released its preserved grant before this waiter
        // was polled again. Attempt disposal even when no SessionGuard remains
        // to observe the restored cleanup policy.
        self.0.close();
    }
}

impl ManagedOAuthSession {
    /// Closes this shared login and attempts RFC 7009 revocation exactly once
    /// for each retained token when a trusted endpoint is configured.
    ///
    /// If the caller is already cancelled or the session already closed, no new
    /// logout effect is started. After closure begins, every returned exit has a
    /// report rather than an error implying rollback: snapshots remain locally
    /// revoked and any retained grant is never put back into session state.
    /// Dropping a pending logout also retires its grant-handoff claim and
    /// restores the ordinary nonblocking, best-effort closed-session cleanup.
    pub async fn logout(
        &self,
        cx: &Cx,
    ) -> Result<ManagedOAuthLogoutReport, OAuthSessionError> {
        if self.inner.closed.is_cancel_requested() {
            return Err(OAuthSessionError::Closed);
        }
        if cx.checkpoint().is_err() {
            return Err(OAuthSessionError::Cancelled);
        }
        if cx.timer_driver().is_none() {
            return Err(OAuthSessionError::RuntimeTimerUnavailable);
        }
        let deadline = deadline_after(cx, self.inner.policy.acquisition_timeout)?;
        let handoff = LogoutHandoff::begin(self)?;

        let mut guard = match lock_grant(cx, deadline, Arc::clone(&self.inner.state)).await {
            Ok(guard) => guard,
            Err(remote) => return Ok(ManagedOAuthLogoutReport { remote }),
        };
        let state = guard.take();
        drop(guard);
        drop(handoff);
        let Some(mut state) = state else {
            return Ok(ManagedOAuthLogoutReport {
                remote: ManagedOAuthRemoteRevocation::NoGrant,
            });
        };

        let remote = match self
            .inner
            .client
            .revoke_credentials(cx, &mut state.credentials)
            .await
        {
            Ok(report) => ManagedOAuthRemoteRevocation::Completed(report),
            Err(OAuthRevocationError::EndpointUnavailable) => {
                // Local closure still disposes the retained grant.
                state.credentials.bearer_credential().revoke();
                ManagedOAuthRemoteRevocation::EndpointUnavailable
            }
            Err(OAuthRevocationError::Cancelled) => ManagedOAuthRemoteRevocation::Cancelled,
            Err(OAuthRevocationError::TimedOut) => ManagedOAuthRemoteRevocation::TimedOut,
            Err(_) => ManagedOAuthRemoteRevocation::Failed,
        };
        Ok(ManagedOAuthLogoutReport { remote })
    }
}

async fn lock_grant(
    cx: &Cx,
    deadline: Time,
    state: Arc<asupersync::sync::Mutex<Option<super::GrantState>>>,
) -> Result<OwnedMutexGuard<Option<super::GrantState>>, ManagedOAuthRemoteRevocation> {
    let mut sleep = pin!(Sleep::new(deadline));
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancelled = pin!(receiver.recv(cx));
    let mut lock = pin!(OwnedMutexGuard::lock(state, cx));
    poll_fn(|task| {
        if cx.checkpoint().is_err() {
            return Poll::Ready(Err(ManagedOAuthRemoteRevocation::Cancelled));
        }
        if cx.now() >= deadline {
            return Poll::Ready(Err(ManagedOAuthRemoteRevocation::TimedOut));
        }
        let _caller = Cx::set_current(Some(cx.clone()));
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(ManagedOAuthRemoteRevocation::Cancelled));
        }
        if sleep.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(ManagedOAuthRemoteRevocation::TimedOut));
        }
        match lock.as_mut().poll(task) {
            Poll::Ready(Ok(guard)) => Poll::Ready(Ok(guard)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(ManagedOAuthRemoteRevocation::Failed)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::task::{Context, Waker};
    use std::time::Duration;

    use asupersync::runtime::RuntimeBuilder;
    use asupersync::sync::Mutex;
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use fastmcp_core::McpRequestCancellation;

    use super::super::{OAuthSessionPolicy, SessionInner};
    use crate::http_auth::CanonicalHttpUrl;
    use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration};

    // Exercise production logout and grant-lock custody without an issuer or
    // retained credentials. These are not live login/revocation proofs.
    fn session() -> ManagedOAuthSession {
        let url = |text| CanonicalHttpUrl::parse(text).unwrap();
        let resource = url("https://mcp.example/mcp");
        let configuration = OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example",
            url("https://issuer.example/authorize"),
            url("https://issuer.example/token"),
            resource.clone(),
            "native-client",
            vec![],
        )
        .unwrap();
        ManagedOAuthSession {
            inner: Arc::new(SessionInner {
                client: OAuthClient::new(configuration),
                resource,
                policy: OAuthSessionPolicy::new(
                    Duration::ZERO,
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                    1,
                )
                .unwrap(),
                state: Arc::new(Mutex::new(None)),
                closed: McpRequestCancellation::new(),
                logout_handoff: AtomicBool::new(false),
                pending: AtomicUsize::new(0),
            }),
        }
    }

    fn with_runtime(test: impl FnOnce(&Cx, &VirtualClock, &TimerDriverHandle)) {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        test(&cx, &clock, &timer);
        assert_eq!(timer.pending_count(), 0);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn dropping_pending_logout_retires_handoff_with_or_without_lock_contention() {
        for release_before_drop in [false, true] {
            with_runtime(|cx, _, _| {
                let session = session();
                let sibling = self::session();
                let mut held = Some(session.inner.state.try_lock_owned().unwrap());
                let mut logout = Box::pin(session.logout(cx));
                let mut task = Context::from_waker(Waker::noop());
                assert!(logout.as_mut().poll(&mut task).is_pending());
                assert!(session.inner.closed.is_cancel_requested());
                assert!(session.inner.logout_handoff.load(Ordering::Acquire));
                if release_before_drop {
                    drop(held.take());
                }
                drop(logout);
                assert!(!session.inner.logout_handoff.load(Ordering::Acquire));
                assert!(session.inner.closed.is_cancel_requested());
                assert!(!sibling.inner.closed.is_cancel_requested());
                assert!(cx.checkpoint().is_ok());
                drop(held);
                assert!(session.inner.state.try_lock_owned().unwrap().is_none());
                let mut retry = Box::pin(session.logout(cx));
                assert!(matches!(
                    retry.as_mut().poll(&mut task),
                    Poll::Ready(Err(OAuthSessionError::Closed))
                ));
            });
        }
    }

    #[test]
    fn logout_keeps_handoff_until_the_contended_lock_is_received() {
        with_runtime(|cx, _, _| {
            let session = session();
            let held = session.inner.state.try_lock_owned().unwrap();
            let mut logout = Box::pin(session.logout(cx));
            let mut task = Context::from_waker(Waker::noop());
            assert!(logout.as_mut().poll(&mut task).is_pending());
            assert!(session.inner.logout_handoff.load(Ordering::Acquire));
            drop(held);
            let Poll::Ready(Ok(report)) = logout.as_mut().poll(&mut task) else {
                panic!("logout must complete after the grant lock is released");
            };
            assert!(report.local_closed());
            assert_eq!(report.remote(), ManagedOAuthRemoteRevocation::NoGrant);
            assert!(!session.inner.logout_handoff.load(Ordering::Acquire));
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[test]
    fn cancellation_and_deadline_exit_retire_the_pending_handoff() {
        for cancel in [false, true] {
            with_runtime(|cx, clock, timer| {
                let session = session();
                let held = session.inner.state.try_lock_owned().unwrap();
                let mut logout = Box::pin(session.logout(cx));
                let mut task = Context::from_waker(Waker::noop());
                assert!(logout.as_mut().poll(&mut task).is_pending());
                if cancel {
                    cx.set_cancel_requested(true);
                } else {
                    clock.advance(1_000_000_000);
                    assert!(timer.process_timers() > 0);
                }
                let Poll::Ready(Ok(report)) = logout.as_mut().poll(&mut task) else {
                    panic!("inactive logout must return a local-closure report");
                };
                assert_eq!(
                    report.remote(),
                    if cancel {
                        ManagedOAuthRemoteRevocation::Cancelled
                    } else {
                        ManagedOAuthRemoteRevocation::TimedOut
                    }
                );
                assert!(report.local_closed());
                assert!(!session.inner.logout_handoff.load(Ordering::Acquire));
                assert!(session.inner.closed.is_cancel_requested());
                drop(held);
            });
        }
    }

    #[test]
    fn competing_handoff_cannot_release_an_active_owners_claim() {
        let session = session();
        let handoff = LogoutHandoff::begin(&session).unwrap();
        assert!(matches!(
            LogoutHandoff::begin(&session),
            Err(OAuthSessionError::Closed)
        ));
        assert!(session.inner.logout_handoff.load(Ordering::Acquire));
        drop(handoff);
        assert!(!session.inner.logout_handoff.load(Ordering::Acquire));
        assert!(session.inner.closed.is_cancel_requested());
    }

    #[test]
    fn logout_preflight_refusal_does_not_close_or_claim_the_session() {
        for cancel in [false, true] {
            let session = session();
            let cx = Cx::for_testing();
            if cancel {
                cx.set_cancel_requested(true);
            }
            let mut logout = Box::pin(session.logout(&cx));
            let mut task = Context::from_waker(Waker::noop());
            let Poll::Ready(Err(error)) = logout.as_mut().poll(&mut task) else {
                panic!("logout preflight must refuse without waiting");
            };
            assert!(matches!(
                (cancel, error),
                (true, OAuthSessionError::Cancelled)
                    | (false, OAuthSessionError::RuntimeTimerUnavailable)
            ));
            assert!(!session.inner.closed.is_cancel_requested());
            assert!(!session.inner.logout_handoff.load(Ordering::Acquire));
        }
    }

    #[test]
    fn logout_report_never_implies_local_reopen() {
        for remote in [
            ManagedOAuthRemoteRevocation::NoGrant,
            ManagedOAuthRemoteRevocation::EndpointUnavailable,
            ManagedOAuthRemoteRevocation::Cancelled,
            ManagedOAuthRemoteRevocation::TimedOut,
            ManagedOAuthRemoteRevocation::Failed,
        ] {
            let report = ManagedOAuthLogoutReport { remote };
            assert!(report.local_closed());
            assert_eq!(report.remote(), remote);
        }
    }
}
