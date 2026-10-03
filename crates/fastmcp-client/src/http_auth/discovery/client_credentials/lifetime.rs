//! Token-local revocation for machine dispatch and replacement acquisition.
//!
//! A response observes its original snapshot; a renewal observes only the old
//! token's revocation, not its expired access lifetime. The enclosing active()
//! guard remains responsible for caller/owner cancellation and the deadline.

use std::future::{Future, poll_fn};
use std::task::Poll;

use fastmcp_core::McpRequestCancellation;

use super::ClientCredentialsError;

// Retain a wake registration, not another bearer copy or a timer. A missing
// token (initial acquisition) has no token-local authority to observe.
pub(super) async fn unless_revoked<T>(
    revocation: Option<&McpRequestCancellation>,
    operation: impl Future<Output = Result<T, ClientCredentialsError>>,
) -> Result<T, ClientCredentialsError> {
    let Some(revocation) = revocation else {
        return operation.await;
    };
    let mut revoked = std::pin::pin!(revocation.cancelled());
    let mut operation = std::pin::pin!(operation);
    poll_fn(|task| {
        if revocation.is_cancel_requested() || revoked.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(ClientCredentialsError::Expired));
        }
        let result = operation.as_mut().poll(task);
        // The operation or a concurrent revoker can revoke on its final poll.
        // Drop the unpublished value rather than installing/releasing it.
        if revocation.is_cancel_requested() {
            Poll::Ready(Err(ClientCredentialsError::Expired))
        } else {
            result
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};
    use std::time::{Duration, Instant};

    use super::super::{ClientCredentialsSnapshot, OAuthDiscoveryError, active};
    use crate::http_auth::BoundBearerCredential;
    use asupersync::Cx;
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use fastmcp_core::CanonicalHttpUrl;

    #[derive(Default)]
    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    struct Owned(Arc<AtomicUsize>);
    impl Drop for Owned {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn bearer() -> BoundBearerCredential {
        BoundBearerCredential::bind(
            CanonicalHttpUrl::parse("https://machine.example/mcp").unwrap(),
            "same-secret",
        )
        .unwrap()
    }
    fn runtime(test: impl FnOnce(&Cx, &VirtualClock, &TimerDriverHandle)) {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
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
    fn prior_revocation_never_polls_work_and_releases_its_owner() {
        let token = bearer();
        token.revoke();
        let polls = AtomicUsize::new(0);
        let drops = Arc::new(AtomicUsize::new(0));
        let owned = Owned(drops.clone());
        let operation = async {
            let _owned = owned;
            polls.fetch_add(1, Ordering::SeqCst);
            Ok(7)
        };
        let mut guarded = Box::pin(unless_revoked(Some(&token.revoked), operation));
        let mut task = Context::from_waker(Waker::noop());
        assert!(matches!(
            guarded.as_mut().poll(&mut task),
            Poll::Ready(Err(ClientCredentialsError::Expired))
        ));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn revocation_during_ready_poll_withholds_result_and_preserves_live_control() {
        for revoke in [false, true] {
            let token = bearer();
            let drops = Arc::new(AtomicUsize::new(0));
            let operation = async {
                if revoke {
                    token.revoke();
                }
                Ok(Owned(drops.clone()))
            };
            let mut guarded = Box::pin(unless_revoked(Some(&token.revoked), operation));
            let mut task = Context::from_waker(Waker::noop());
            match (revoke, guarded.as_mut().poll(&mut task)) {
                (false, Poll::Ready(Ok(owned))) => {
                    assert_eq!(drops.load(Ordering::SeqCst), 0);
                    drop(owned);
                }
                (true, Poll::Ready(Err(ClientCredentialsError::Expired))) => {}
                _ => panic!("only a live token may publish its result"),
            }
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn revoking_a_clone_wakes_all_idle_original_token_waiters() {
        let token = bearer();
        let clone = token.clone();
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut task = Context::from_waker(&waker);
        let polls = AtomicUsize::new(0);
        let pending = || {
            poll_fn(|_| {
                polls.fetch_add(1, Ordering::SeqCst);
                Poll::<Result<(), ClientCredentialsError>>::Pending
            })
        };
        let mut first = Box::pin(unless_revoked(Some(&token.revoked), pending()));
        let mut second = Box::pin(unless_revoked(Some(&clone.revoked), pending()));
        assert!(first.as_mut().poll(&mut task).is_pending());
        assert!(second.as_mut().poll(&mut task).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        clone.revoke();
        assert!(wakes.0.load(Ordering::SeqCst) >= 2);
        let after = wakes.0.load(Ordering::SeqCst);
        token.revoke();
        assert_eq!(wakes.0.load(Ordering::SeqCst), after);
        assert!(matches!(
            first.as_mut().poll(&mut task),
            Poll::Ready(Err(ClientCredentialsError::Expired))
        ));
        assert!(matches!(
            second.as_mut().poll(&mut task),
            Poll::Ready(Err(ClientCredentialsError::Expired))
        ));
        assert_eq!(polls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn abandoned_guard_removes_wakeup_without_revoking_any_credential() {
        let token = bearer();
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut task = Context::from_waker(&waker);
        let drops = Arc::new(AtomicUsize::new(0));
        let owned = Owned(drops.clone());
        let operation = async move {
            let _owned = owned;
            std::future::pending::<Result<(), ClientCredentialsError>>().await
        };
        let mut guarded = Box::pin(unless_revoked(Some(&token.revoked), operation));
        assert!(guarded.as_mut().poll(&mut task).is_pending());
        drop(guarded);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(!token.is_revoked());
        assert_eq!(Arc::strong_count(&wakes), 2);
        let before = wakes.0.load(Ordering::SeqCst);
        token.revoke();
        assert_eq!(wakes.0.load(Ordering::SeqCst), before);
    }

    #[test]
    fn identical_token_text_in_an_independent_binding_does_not_share_revocation() {
        let original = bearer();
        let independent = bearer();
        original.revoke();
        let mut task = Context::from_waker(Waker::noop());
        let mut guarded = Box::pin(unless_revoked(
            Some(&independent.revoked),
            std::future::ready(Ok(17)),
        ));
        assert!(matches!(
            guarded.as_mut().poll(&mut task),
            Poll::Ready(Ok(17))
        ));
        assert!(!independent.is_revoked());
        assert!(
            independent
                .authorization_for_target(independent.resource())
                .is_some()
        );
    }

    #[test]
    fn initial_acquisition_preserves_output_and_errors_without_a_token_signal() {
        let mut task = Context::from_waker(Waker::noop());
        let mut success = Box::pin(unless_revoked(None, std::future::ready(Ok(19))));
        assert!(matches!(
            success.as_mut().poll(&mut task),
            Poll::Ready(Ok(19))
        ));
        let mut error = Box::pin(unless_revoked(
            None,
            std::future::ready(Err::<(), _>(ClientCredentialsError::Transport)),
        ));
        assert!(matches!(
            error.as_mut().poll(&mut task),
            Poll::Ready(Err(ClientCredentialsError::Transport))
        ));
    }

    #[test]
    fn expired_access_does_not_prevent_renewal_but_revocation_does() {
        let token = BoundBearerCredential::bind_with_expiry(
            bearer().resource().clone(),
            "expired-secret",
            Instant::now(),
        )
        .unwrap();
        assert!(token.authorization_for_target(token.resource()).is_none());
        let mut task = Context::from_waker(Waker::noop());
        let mut replacement = Box::pin(unless_revoked(
            Some(&token.revoked),
            std::future::ready(Ok(23)),
        ));
        assert!(matches!(
            replacement.as_mut().poll(&mut task),
            Poll::Ready(Ok(23))
        ));
        token.revoke();
        let mut refused = Box::pin(unless_revoked(
            Some(&token.revoked),
            std::future::ready(Ok(29)),
        ));
        assert!(matches!(
            refused.as_mut().poll(&mut task),
            Poll::Ready(Err(ClientCredentialsError::Expired))
        ));
    }

    #[test]
    fn machine_active_observes_token_wakes_without_peer_or_timer_activity() {
        runtime(|cx, _, timer| {
            let owner = McpRequestCancellation::new();
            let cancellation = McpRequestCancellation::new();
            let snapshot = ClientCredentialsSnapshot {
                bearer: bearer(),
                scopes: vec![],
                expires_at: Instant::now() + Duration::from_secs(60),
                generation: 7,
            };
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(wakes.clone());
            let mut task = Context::from_waker(&waker);
            let mut guarded = Box::pin(active(
                cx,
                cx.now().saturating_add_nanos(10_000_000_000),
                &owner,
                &cancellation,
                Some(&snapshot),
                std::future::pending::<Result<(), ClientCredentialsError>>(),
            ));
            assert!(guarded.as_mut().poll(&mut task).is_pending());
            assert!(timer.pending_count() > 0);
            let before = wakes.0.load(Ordering::SeqCst);
            snapshot.credential().revoke();
            assert!(wakes.0.load(Ordering::SeqCst) > before);
            assert!(matches!(
                guarded.as_mut().poll(&mut task),
                Poll::Ready(Err(ClientCredentialsError::Expired))
            ));
            drop(guarded);
            assert_eq!(timer.pending_count(), 0);
            assert_eq!(Arc::strong_count(&wakes), 2);
            assert!(!owner.is_cancel_requested());
            assert!(!cancellation.is_cancel_requested());
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[test]
    fn machine_active_keeps_original_owner_caller_and_deadline_dispositions() {
        for transition in 0..3 {
            runtime(|cx, clock, timer| {
                let owner = McpRequestCancellation::new();
                let cancellation = McpRequestCancellation::new();
                let snapshot = ClientCredentialsSnapshot {
                    bearer: bearer(),
                    scopes: vec![],
                    expires_at: Instant::now() + Duration::from_secs(60),
                    generation: 7,
                };
                let mut task = Context::from_waker(Waker::noop());
                let mut guarded = Box::pin(active(
                    cx,
                    cx.now().saturating_add_nanos(1_000_000_000),
                    &owner,
                    &cancellation,
                    Some(&snapshot),
                    std::future::pending::<Result<(), ClientCredentialsError>>(),
                ));
                assert!(guarded.as_mut().poll(&mut task).is_pending());
                match transition {
                    0 => {
                        owner.cancel();
                    }
                    1 => {
                        cancellation.cancel();
                    }
                    _ => {
                        clock.advance(1_000_000_000);
                        let _ = timer.process_timers();
                    }
                }
                match (transition, guarded.as_mut().poll(&mut task)) {
                    (0, Poll::Ready(Err(ClientCredentialsError::Closed)))
                    | (
                        1,
                        Poll::Ready(Err(ClientCredentialsError::Discovery(
                            OAuthDiscoveryError::Cancelled,
                        ))),
                    )
                    | (
                        2,
                        Poll::Ready(Err(ClientCredentialsError::Discovery(
                            OAuthDiscoveryError::TimedOut,
                        ))),
                    ) => {}
                    _ => {
                        panic!("revocation observation must not replace other lifetime boundaries")
                    }
                }
                drop(guarded);
                assert!(!snapshot.credential().is_revoked());
                assert!(cx.checkpoint().is_ok());
            });
        }
    }
}
