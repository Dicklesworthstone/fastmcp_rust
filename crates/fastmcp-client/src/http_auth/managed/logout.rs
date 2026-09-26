//! Managed OAuth logout with local-first closure and single-attempt remote revocation.
//!
//! Logout closes the shared session before waiting for grant custody, so issued
//! snapshots stop constructing new Authorization headers immediately. Once the
//! grant lock is acquired, the grant is removed from session state before any
//! network await. Remote outcomes are diagnostic facts, never retry authority.
//! One caller-bounded deadline covers acquisition and remote revocation together.
//! Already-sent requests and headers cannot be recalled.

// Access replacement must serialize with the same grant owner as logout.
#[cfg(target_os = "linux")]
pub(crate) mod rotation;

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
    /// Runs caller-owned work only while this shared login remains open.
    ///
    /// This extends local logout/close wakeups to work between HTTP requests,
    /// such as a pending model, browser-consent or input-resolution future.
    /// Closure is checked before every poll and again before publishing a ready
    /// result. An already closed session never polls `operation`; closing any
    /// session clone wakes the guard and drops pending work on its next poll.
    /// No caller Cx or independently owned session is cancelled.
    ///
    /// This is a local lifetime guard, not an authorization lease. It neither
    /// renews credentials nor checks token expiry, and does not add a deadline:
    /// retain the operation's existing caller budget and cancellation guard.
    /// Its future must not block a poll and must be safe to drop. Construct
    /// side-effecting callbacks inside the guarded async block, not before
    /// calling this method. Already committed effects cannot be undone, and
    /// closure after the final check cannot recall a result already delivered.
    /// Dropping the guard unregisters its wakeup without closing the session.
    pub async fn run_while_open<T>(
        &self,
        operation: impl Future<Output = T>,
    ) -> Result<T, OAuthSessionError> {
        let mut closed = pin!(self.inner.closed.cancelled());
        let mut operation = pin!(operation);
        poll_fn(|task| {
            if self.inner.closed.is_cancel_requested() || closed.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(OAuthSessionError::Closed));
            }
            let result = operation.as_mut().poll(task);
            // A ready callback may itself close the login. Withhold and drop
            // its result rather than allowing one last continuation to escape.
            if self.inner.closed.is_cancel_requested() {
                return Poll::Ready(Err(OAuthSessionError::Closed));
            }
            result.map(Ok)
        })
        .await
    }

    /// Closes this shared login and attempts RFC 7009 revocation at most once
    /// for each retained token when a trusted endpoint is configured.
    ///
    /// If the caller is already cancelled or the session already closed, no new
    /// logout effect is started. After closure begins, every returned exit has a
    /// report rather than an error implying rollback: snapshots remain locally
    /// revoked and any retained grant is never put back into session state.
    /// Dropping a pending logout also retires its grant-handoff claim and
    /// restores the ordinary nonblocking, best-effort closed-session cleanup.
    /// The acquisition timeout bounds the complete logout, including revocation;
    /// obtaining the grant lock does not restart that budget.
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
        if cx.now() >= deadline {
            return Err(OAuthSessionError::TimedOut);
        }
        let handoff = LogoutHandoff::begin(self)?;

        let result = within_logout(cx, deadline, async {
            let mut guard = OwnedMutexGuard::lock(Arc::clone(&self.inner.state), cx)
                .await
                .map_err(|_| ManagedOAuthRemoteRevocation::Failed)?;
            let state = guard.take();
            drop(guard);
            drop(handoff);
            let Some(mut state) = state else {
                return Ok(ManagedOAuthRemoteRevocation::NoGrant);
            };

            // This grant has already left reusable session custody. Remote
            // preflight can still refuse, but cannot undo local revocation.
            state.credentials.bearer_credential().revoke();
            check_logout(cx, deadline)?;
            let remote = match self
                .inner
                .client
                .revoke_credentials(cx, &mut state.credentials)
                .await
            {
                Ok(report) => ManagedOAuthRemoteRevocation::Completed(report),
                Err(OAuthRevocationError::EndpointUnavailable) => {
                    ManagedOAuthRemoteRevocation::EndpointUnavailable
                }
                Err(OAuthRevocationError::Cancelled) => ManagedOAuthRemoteRevocation::Cancelled,
                Err(OAuthRevocationError::TimedOut) => ManagedOAuthRemoteRevocation::TimedOut,
                Err(_) => ManagedOAuthRemoteRevocation::Failed,
            };
            Ok(remote)
        })
        .await;
        let remote = result.unwrap_or_else(std::convert::identity);
        Ok(ManagedOAuthLogoutReport { remote })
    }
}

fn check_logout(cx: &Cx, deadline: Time) -> Result<(), ManagedOAuthRemoteRevocation> {
    if cx.checkpoint().is_err() {
        return Err(ManagedOAuthRemoteRevocation::Cancelled);
    }
    if cx.now() >= deadline {
        return Err(ManagedOAuthRemoteRevocation::TimedOut);
    }
    Ok(())
}

// One owned operation spans every logout phase. In particular, do not use the
// closed session's ordinary await_active guard: local closure is intentional
// here and must not prevent the remaining single-attempt revocation work.
async fn within_logout<T>(
    cx: &Cx,
    deadline: Time,
    operation: impl Future<Output = Result<T, ManagedOAuthRemoteRevocation>>,
) -> Result<T, ManagedOAuthRemoteRevocation> {
    let mut sleep = pin!(Sleep::new(deadline));
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancelled = pin!(receiver.recv(cx));
    let mut operation = pin!(operation);
    poll_fn(|task| {
        check_logout(cx, deadline)?;
        let _caller = Cx::set_current(Some(cx.clone()));
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(ManagedOAuthRemoteRevocation::Cancelled));
        }
        if sleep.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(ManagedOAuthRemoteRevocation::TimedOut));
        }
        let result = operation.as_mut().poll(task);
        // User wakeups and a completing operation may consume the remaining
        // budget during this poll. Withhold and drop their late result too.
        check_logout(cx, deadline)?;
        result
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::task::{Context, Wake, Waker};
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

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Owner(Arc<AtomicUsize>);

    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn logout_wait_keeps_one_deadline_across_multiple_phases() {
        for ready in [false, true] {
            with_runtime(|cx, clock, timer| {
                let first_phase = AtomicUsize::new(0);
                let second_phase = AtomicUsize::new(0);
                let dropped = Arc::new(AtomicUsize::new(0));
                let owner = Owner(Arc::clone(&dropped));
                let operation = async {
                    let _owner = owner;
                    first_phase.fetch_add(1, Ordering::SeqCst);
                    // Acquiring custody consumed most of the total budget.
                    clock.advance(900_000_000);
                    poll_fn(|_| {
                        second_phase.fetch_add(1, Ordering::SeqCst);
                        if ready {
                            Poll::Ready(Ok(17_u8))
                        } else {
                            Poll::Pending
                        }
                    })
                    .await
                };
                let mut waiting = Box::pin(within_logout(
                    cx,
                    Time::from_nanos(1_000_000_000),
                    operation,
                ));
                let counter = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&counter));
                let mut task = Context::from_waker(&waker);
                let result = waiting.as_mut().poll(&mut task);
                assert_eq!(first_phase.load(Ordering::SeqCst), 1);
                assert_eq!(second_phase.load(Ordering::SeqCst), 1);
                if ready {
                    assert_eq!(result, Poll::Ready(Ok(17)));
                } else {
                    assert!(result.is_pending());
                    assert_eq!(dropped.load(Ordering::SeqCst), 0);
                    assert!(waiting.as_mut().poll(&mut task).is_pending());
                    assert_eq!(first_phase.load(Ordering::SeqCst), 1);
                    assert_eq!(second_phase.load(Ordering::SeqCst), 2);
                    let before = counter.0.load(Ordering::SeqCst);
                    clock.advance(100_000_000);
                    assert!(timer.process_timers() > 0);
                    assert!(counter.0.load(Ordering::SeqCst) > before);
                    assert_eq!(
                        waiting.as_mut().poll(&mut task),
                        Poll::Ready(Err(ManagedOAuthRemoteRevocation::TimedOut))
                    );
                    assert_eq!(second_phase.load(Ordering::SeqCst), 2);
                }
                assert_eq!(dropped.load(Ordering::SeqCst), 1);
                assert_eq!(timer.pending_count(), 0);
                assert!(cx.checkpoint().is_ok());
            });
        }
    }

    #[test]
    fn logout_wait_rechecks_cancellation_and_expiry_before_publishing() {
        for transition in [0, 1, 2] {
            with_runtime(|cx, clock, _| {
                let dropped = Arc::new(AtomicUsize::new(0));
                let operation = poll_fn(|_| {
                    match transition {
                        1 => cx.set_cancel_requested(true),
                        2 => clock.advance(1_000_000_000),
                        _ => {}
                    }
                    Poll::Ready(Ok(Owner(Arc::clone(&dropped))))
                });
                let mut waiting = Box::pin(within_logout(
                    cx,
                    Time::from_nanos(1_000_000_000),
                    operation,
                ));
                let mut task = Context::from_waker(Waker::noop());
                match (transition, waiting.as_mut().poll(&mut task)) {
                    (0, Poll::Ready(Ok(owner))) => {
                        assert_eq!(dropped.load(Ordering::SeqCst), 0);
                        drop(owner);
                    }
                    (1, Poll::Ready(Err(ManagedOAuthRemoteRevocation::Cancelled)))
                    | (2, Poll::Ready(Err(ManagedOAuthRemoteRevocation::TimedOut))) => {}
                    _ => panic!("logout must not publish a result after its budget becomes inactive"),
                }
                assert_eq!(dropped.load(Ordering::SeqCst), 1);
            });
        }
    }

    #[test]
    fn abandoned_logout_wait_releases_its_operation_and_wake_registrations() {
        with_runtime(|cx, clock, timer| {
            let dropped = Arc::new(AtomicUsize::new(0));
            let owner = Owner(Arc::clone(&dropped));
            let operation = async move {
                let _owner = owner;
                std::future::pending::<Result<(), ManagedOAuthRemoteRevocation>>().await
            };
            let mut waiting = Box::pin(within_logout(
                cx,
                Time::from_nanos(1_000_000_000),
                operation,
            ));
            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&counter));
            let mut task = Context::from_waker(&waker);
            assert!(waiting.as_mut().poll(&mut task).is_pending());
            assert!(timer.pending_count() > 0);
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            drop(waiting);
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), 0);
            assert_eq!(Arc::strong_count(&counter), 2);
            let before = counter.0.load(Ordering::SeqCst);
            clock.advance(1_000_000_000);
            assert_eq!(timer.process_timers(), 0);
            cx.set_cancel_requested(true);
            assert_eq!(counter.0.load(Ordering::SeqCst), before);
        });
    }

    #[test]
    fn expired_logout_wait_never_polls_a_ready_operation() {
        with_runtime(|cx, _, timer| {
            let polls = AtomicUsize::new(0);
            let dropped = Arc::new(AtomicUsize::new(0));
            let owner = Owner(Arc::clone(&dropped));
            let operation = async {
                let _owner = owner;
                polls.fetch_add(1, Ordering::SeqCst);
                Ok(17_u8)
            };
            let mut waiting = Box::pin(within_logout(cx, cx.now(), operation));
            let mut task = Context::from_waker(Waker::noop());
            assert_eq!(
                waiting.as_mut().poll(&mut task),
                Poll::Ready(Err(ManagedOAuthRemoteRevocation::TimedOut))
            );
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), 0);
            assert!(cx.checkpoint().is_ok());
        });
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

    #[test]
    fn closed_session_never_polls_guarded_host_work() {
        let session = session();
        session.close();
        let polls = AtomicUsize::new(0);
        let dropped = Arc::new(AtomicUsize::new(0));
        let owner = Owner(Arc::clone(&dropped));
        let operation = async {
            let _owner = owner;
            polls.fetch_add(1, Ordering::SeqCst);
            17_u8
        };
        let mut guarded = Box::pin(session.run_while_open(operation));
        let mut task = Context::from_waker(Waker::noop());
        assert!(matches!(guarded.as_mut().poll(&mut task), Poll::Ready(Err(OAuthSessionError::Closed))));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn close_and_logout_wake_pending_host_work_without_cancelling_siblings() {
        for logout in [false, true] {
            with_runtime(|cx, _, _| {
                let session = session();
                let closer = session.clone();
                let sibling = self::session();
                let polls = AtomicUsize::new(0);
                let dropped = Arc::new(AtomicUsize::new(0));
                let owner = Owner(Arc::clone(&dropped));
                let operation = async {
                    let _owner = owner;
                    poll_fn(|_| {
                        polls.fetch_add(1, Ordering::SeqCst);
                        Poll::<()>::Pending
                    }).await;
                };
                let counter = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&counter));
                let mut task = Context::from_waker(&waker);
                let mut guarded = Box::pin(session.run_while_open(operation));
                assert!(guarded.as_mut().poll(&mut task).is_pending());
                assert_eq!(polls.load(Ordering::SeqCst), 1);
                let before = counter.0.load(Ordering::SeqCst);
                if logout {
                    let mut closing = Box::pin(closer.logout(cx));
                    assert!(matches!(closing.as_mut().poll(&mut task), Poll::Ready(Ok(_))));
                } else {
                    closer.close();
                }
                assert!(counter.0.load(Ordering::SeqCst) > before);
                assert!(matches!(guarded.as_mut().poll(&mut task), Poll::Ready(Err(OAuthSessionError::Closed))));
                assert_eq!(polls.load(Ordering::SeqCst), 1);
                assert_eq!(dropped.load(Ordering::SeqCst), 1);
                assert!(!sibling.inner.closed.is_cancel_requested());
                assert!(cx.checkpoint().is_ok());
            });
        }
    }

    #[test]
    fn closure_during_host_poll_withholds_and_drops_its_ready_result() {
        for close in [false, true] {
            let session = session();
            let dropped = Arc::new(AtomicUsize::new(0));
            let operation = async {
                if close { session.close(); }
                Owner(Arc::clone(&dropped))
            };
            let mut guarded = Box::pin(session.run_while_open(operation));
            let mut task = Context::from_waker(Waker::noop());
            match (close, guarded.as_mut().poll(&mut task)) {
                (false, Poll::Ready(Ok(owner))) => {
                    assert_eq!(dropped.load(Ordering::SeqCst), 0);
                    drop(owner);
                    assert!(!session.inner.closed.is_cancel_requested());
                }
                (true, Poll::Ready(Err(OAuthSessionError::Closed))) => {}
                _ => panic!("only an open login may publish host output"),
            }
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn dropping_host_guard_unregisters_wakeup_and_keeps_login_usable() {
        let session = session();
        let dropped = Arc::new(AtomicUsize::new(0));
        let owner = Owner(Arc::clone(&dropped));
        let operation = async move {
            let _owner = owner;
            std::future::pending::<()>().await;
        };
        let counter = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut task = Context::from_waker(&waker);
        let mut guarded = Box::pin(session.run_while_open(operation));
        assert!(guarded.as_mut().poll(&mut task).is_pending());
        drop(guarded);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(!session.inner.closed.is_cancel_requested());
        assert_eq!(Arc::strong_count(&counter), 2);
        let mut ready = Box::pin(session.run_while_open(std::future::ready(17_u8)));
        assert!(matches!(ready.as_mut().poll(&mut task), Poll::Ready(Ok(17))));
        let before = counter.0.load(Ordering::SeqCst);
        session.close();
        assert_eq!(counter.0.load(Ordering::SeqCst), before);
    }
}
