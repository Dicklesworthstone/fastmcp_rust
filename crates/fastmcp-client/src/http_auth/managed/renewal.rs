//! Revocation-bound replacement of the managed session's current token pair.
//!
//! Access expiry permits renewal; revocation does not. The caller already owns
//! the session grant lock and the acquisition deadline. Keep the old token's
//! signal until refresh admission finishes, even if the issuer rotated its pair.

use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Instant;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;

use super::{GrantState, ManagedOAuthSession, OAuthSessionError, renewal_time};

pub(super) async fn refresh(
    session: &ManagedOAuthSession,
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    state: &mut GrantState,
) -> Result<(), OAuthSessionError> {
    let generation = state
        .generation
        .checked_add(1)
        .ok_or(OAuthSessionError::GenerationExhausted)?;
    // Capture the signal, not the bearer text or its expired access lifetime.
    // OAuthClient::refresh may replace credentials before its final poll returns.
    let revoked = state.credentials.bearer_credential().revoked.clone();
    state.renewal_failed = true;
    unless_revoked(&revoked, async {
        session
            .inner
            .client
            .refresh(cx, &mut state.credentials)
            .await
            .map_err(OAuthSessionError::OAuth)
    })
    .await?;
    session.check(cx, cancellation)?;
    if revoked.is_cancel_requested() {
        return Err(OAuthSessionError::LoginRequired);
    }
    state.renew_after = renewal_time(
        Instant::now(),
        state.credentials.expires_at(),
        state.credentials.has_refresh_token(),
        session.inner.policy.refresh_leeway,
    );
    state.generation = generation;
    // Clear quarantine only after the entire replacement was admitted. A
    // failed/abandoned exchange may have consumed a rotating refresh token;
    // queued callers must require login, not retry or publish the replacement.
    state.renewal_failed = false;
    Ok(())
}

async fn unless_revoked<T>(
    revocation: &McpRequestCancellation,
    operation: impl Future<Output = Result<T, OAuthSessionError>>,
) -> Result<T, OAuthSessionError> {
    let mut revoked = std::pin::pin!(revocation.cancelled());
    let mut operation = std::pin::pin!(operation);
    poll_fn(|task| {
        if revocation.is_cancel_requested() || revoked.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(OAuthSessionError::LoginRequired));
        }
        let result = operation.as_mut().poll(task);
        // A ready refresh may have installed a pair during this poll. Keep the
        // session quarantined rather than publishing it after old-token revocation.
        if revocation.is_cancel_requested() {
            Poll::Ready(Err(OAuthSessionError::LoginRequired))
        } else {
            result
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    use super::*;
    use crate::http_auth::{BoundBearerCredential, CanonicalHttpUrl};

    #[cfg(feature = "native-tls-roots")]
    mod tls;

    fn credential() -> BoundBearerCredential {
        BoundBearerCredential::bind(
            CanonicalHttpUrl::parse("https://resource.example/mcp").unwrap(),
            "same-token",
        )
        .unwrap()
    }

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

    #[test]
    fn prior_revocation_prevents_even_ready_refresh_work() {
        let credential = credential();
        credential.revoke();
        let polls = AtomicUsize::new(0);
        let drops = Arc::new(AtomicUsize::new(0));
        let owned = Owned(Arc::clone(&drops));
        let mut wait = Box::pin(unless_revoked(&credential.revoked, async {
            let _owned = owned;
            polls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        assert!(matches!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(OAuthSessionError::LoginRequired))
        ));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn revocation_wakes_the_latest_waiter_without_refresh_or_timer_activity() {
        let credential = credential();
        let clone = credential.clone();
        let first = Arc::new(Wakes::default());
        let last = Arc::new(Wakes::default());
        let first_waker = Waker::from(Arc::clone(&first));
        let last_waker = Waker::from(Arc::clone(&last));
        let polls = AtomicUsize::new(0);
        let mut wait = Box::pin(unless_revoked(
            &credential.revoked,
            poll_fn(|_| {
                polls.fetch_add(1, Ordering::SeqCst);
                Poll::<Result<(), OAuthSessionError>>::Pending
            }),
        ));
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(&first_waker))
                .is_pending()
        );
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(&last_waker))
                .is_pending()
        );
        clone.revoke();
        assert_eq!(first.0.load(Ordering::SeqCst), 0);
        assert!(last.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            wait.as_mut().poll(&mut Context::from_waker(&last_waker)),
            Poll::Ready(Err(OAuthSessionError::LoginRequired))
        ));
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        drop(wait);
        assert_eq!(Arc::strong_count(&first), 2);
        assert_eq!(Arc::strong_count(&last), 2);
    }

    #[test]
    fn revocation_during_a_ready_poll_discards_the_unpublished_result() {
        for revoke in [false, true] {
            let credential = credential();
            let drops = Arc::new(AtomicUsize::new(0));
            let mut wait = Box::pin(unless_revoked(&credential.revoked, async {
                if revoke {
                    credential.revoke();
                }
                Ok(Owned(Arc::clone(&drops)))
            }));
            match wait.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Ok(value)) if !revoke => {
                    assert_eq!(drops.load(Ordering::SeqCst), 0);
                    drop(value);
                }
                Poll::Ready(Err(OAuthSessionError::LoginRequired)) if revoke => {}
                _ => panic!("revocation must win over refresh completion"),
            }
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn abandoned_refresh_retires_its_wakeup_and_work_without_revoking_the_token() {
        let credential = credential();
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let drops = Arc::new(AtomicUsize::new(0));
        let owned = Owned(Arc::clone(&drops));
        let mut wait = Box::pin(unless_revoked(&credential.revoked, async move {
            let _owned = owned;
            std::future::pending::<Result<(), OAuthSessionError>>().await
        }));
        assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        drop(wait);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(Arc::strong_count(&wakes), 2);
        assert!(!credential.is_revoked());
        credential.revoke();
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn access_expiry_allows_refresh_but_local_revocation_does_not() {
        let credential = BoundBearerCredential::bind_with_expiry(
            credential().resource().clone(),
            "expired-access",
            Instant::now(),
        )
        .unwrap();
        assert!(
            credential
                .authorization_for_target(credential.resource())
                .is_none()
        );
        let mut wait = Box::pin(unless_revoked(
            &credential.revoked,
            std::future::ready(Ok(42)),
        ));
        assert!(matches!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(42))
        ));
        drop(wait);
        credential.revoke();
        let mut wait = Box::pin(unless_revoked(
            &credential.revoked,
            std::future::ready(Ok(42)),
        ));
        assert!(matches!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(OAuthSessionError::LoginRequired))
        ));
    }

    #[test]
    fn independent_generations_and_original_errors_keep_their_own_dispositions() {
        let old = credential();
        let new = credential();
        old.revoke();
        let mut wait = Box::pin(unless_revoked(
            &new.revoked,
            std::future::ready(Err::<(), _>(OAuthSessionError::StateUnavailable)),
        ));
        assert!(matches!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(OAuthSessionError::StateUnavailable))
        ));
        assert!(!new.is_revoked());
    }
}
