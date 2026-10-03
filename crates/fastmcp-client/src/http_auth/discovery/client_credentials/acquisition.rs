//! Caller-owned single-flight machine grant acquisition.
//!
//! The cache lock elects a leader and registers followers, but is never held
//! across signer or HTTP work. Followers retain this exact flight, not whichever
//! cache generation happens to exist when they are next polled. The leader's
//! drop completes the flight as failed; no follower takes over its dispatch.

use std::future::{Future, poll_fn};
use std::sync::{Arc, OnceLock};
use std::task::Poll;

use asupersync::Cx;
use asupersync::http::h1::Method;
use asupersync::sync::OwnedMutexGuard;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;

use super::super::{OAuthDiscoveryError, validate_headers};
use super::{
    AcquisitionPermit, ClientCredentialsClient, ClientCredentialsError, ClientCredentialsSnapshot,
    ServiceToken, active, admit_token, check_context, check_token, discovery_deadline,
    token_transport, unless_revoked,
};
use std::time::Instant;

// An immutable result slot avoids a bookkeeping lock in Drop. The completion
// signal invokes wakers only after the outcome is installed, outside the cache
// lock. Failed flights retain no peer error, token, request or signer state.
pub(super) struct GrantFlight {
    outcome: OnceLock<Option<ClientCredentialsSnapshot>>,
    completed: McpRequestCancellation,
    previous_revocation: Option<McpRequestCancellation>,
}

impl GrantFlight {
    fn new(previous_revocation: Option<McpRequestCancellation>) -> Self {
        Self {
            outcome: OnceLock::new(),
            completed: McpRequestCancellation::new(),
            previous_revocation,
        }
    }

    fn finished(&self) -> bool {
        self.outcome.get().is_some()
    }

    fn publish(&self, outcome: Option<ClientCredentialsSnapshot>) {
        if self.outcome.set(outcome).is_ok() {
            // Never run a follower's waker under the credential-cache lock.
            self.completed.cancel();
        }
    }

    async fn wait(&self) -> Result<ClientCredentialsSnapshot, ClientCredentialsError> {
        // Access expiry must allow renewal. Observe only predecessor revocation
        // while acquiring its replacement; returned access has its OWN expiry.
        let mut completed = std::pin::pin!(self.completed.cancelled());
        let mut revoked = std::pin::pin!(async {
            match &self.previous_revocation {
                Some(signal) => signal.cancelled().await,
                None => std::future::pending::<()>().await,
            }
        });
        poll_fn(|task| {
            // Success belongs to the new generation. Revocation of the old
            // generation after installation must not revoke a delayed follower.
            if let Some(outcome) = self.outcome.get() {
                return Poll::Ready(self.delivery(outcome));
            }
            if completed.as_mut().poll(task).is_ready() {
                return Poll::Ready(
                    self.outcome
                        .get()
                        .ok_or(ClientCredentialsError::StateUnavailable)
                        .and_then(|outcome| self.delivery(outcome)),
                );
            }
            if revoked.as_mut().poll(task).is_ready() {
                // Publication may have raced the revocation poll. A completed
                // replacement, if present, is judged by its own token signal.
                return Poll::Ready(match self.outcome.get() {
                    Some(outcome) => self.delivery(outcome),
                    None => Err(ClientCredentialsError::Expired),
                });
            }
            Poll::Pending
        })
        .await
    }

    fn delivery(
        &self,
        outcome: &Option<ClientCredentialsSnapshot>,
    ) -> Result<ClientCredentialsSnapshot, ClientCredentialsError> {
        match outcome {
            Some(snapshot) => {
                check_token(&snapshot.bearer, snapshot.expires_at)?;
                Ok(copy_snapshot(snapshot))
            }
            None if self
                .previous_revocation
                .as_ref()
                .is_some_and(McpRequestCancellation::is_cancel_requested) =>
            {
                Err(ClientCredentialsError::Expired)
            }
            None => Err(ClientCredentialsError::ConcurrentAcquisitionFailed),
        }
    }
}

// This value is owned exclusively by the elected caller. Its cancellation,
// deadline, panic unwind or abandoned future terminates all joined observers,
// without making one of them silently issue another grant. The caller runtime
// continues to own all signer/network work; nothing is spawned or detached.
struct GrantLeader(Arc<GrantFlight>);
impl Drop for GrantLeader {
    fn drop(&mut self) {
        self.0.publish(None);
    }
}

fn copy_snapshot(snapshot: &ClientCredentialsSnapshot) -> ClientCredentialsSnapshot {
    ClientCredentialsSnapshot {
        bearer: snapshot.bearer.clone(),
        scopes: snapshot.scopes.clone(),
        expires_at: snapshot.expires_at,
        generation: snapshot.generation,
    }
}

fn snapshot(
    token: &ServiceToken,
    generation: u64,
) -> Result<ClientCredentialsSnapshot, ClientCredentialsError> {
    check_token(&token.bearer, token.expires_at)?;
    Ok(ClientCredentialsSnapshot {
        bearer: token.bearer.clone(),
        scopes: token.scopes.clone(),
        expires_at: token.expires_at,
        generation,
    })
}

pub(super) async fn credential(
    client: &ClientCredentialsClient,
    cx: &Cx,
    cancellation: &McpRequestCancellation,
) -> Result<ClientCredentialsSnapshot, ClientCredentialsError> {
    let deadline = discovery_deadline(cx, client.inner.timeout)?;
    // Includes the leader, followers, lock waiters and a ready result not yet
    // returned by this future. Flight retention therefore has the same bound.
    let _permit = AcquisitionPermit::new(&client.inner.pending)?;
    active(
        cx,
        deadline,
        &client.inner.closed,
        cancellation,
        None,
        async {
            client.inner.authentication.check()?;
            let mut state = OwnedMutexGuard::lock(Arc::clone(&client.inner.state), cx)
                .await
                .map_err(|_| ClientCredentialsError::StateUnavailable)?;
            check_live(client, cx, deadline, cancellation)?;
            if state
                .current
                .as_ref()
                .is_some_and(|token| token.bearer.is_revoked())
            {
                return Err(ClientCredentialsError::Expired);
            }
            if let Some(flight) = state.flight.as_ref().filter(|flight| !flight.finished()) {
                let flight = Arc::clone(flight);
                drop(state);
                // No loop, cache lookup or leader election follows this await.
                return flight.wait().await;
            }
            if let Some(token) = state
                .current
                .as_ref()
                .filter(|token| Instant::now() < token.renew_after)
            {
                return snapshot(token, state.generation);
            }
            let generation = state
                .generation
                .checked_add(1)
                .ok_or(ClientCredentialsError::GenerationExhausted)?;
            let flight = Arc::new(GrantFlight::new(
                state.current.as_ref().map(|old| old.bearer.revoked.clone()),
            ));
            let leader = GrantLeader(Arc::clone(&flight));
            state.flight = Some(Arc::clone(&flight));
            drop(state);

            let token = unless_revoked(
                flight.previous_revocation.as_ref(),
                request_grant(client, cx, deadline, cancellation),
            )
            .await?;
            let mut state = OwnedMutexGuard::lock(Arc::clone(&client.inner.state), cx)
                .await
                .map_err(|_| ClientCredentialsError::StateUnavailable)?;
            check_live(client, cx, deadline, cancellation)?;
            if state
                .current
                .as_ref()
                .is_some_and(|old| old.bearer.is_revoked())
            {
                return Err(ClientCredentialsError::Expired);
            }
            if !state
                .flight
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &flight))
                || state.generation.checked_add(1) != Some(generation)
            {
                return Err(ClientCredentialsError::StateUnavailable);
            }
            let admitted = snapshot(&token, generation)?;
            // Prepare both handoffs before committing. No fallible operation or
            // suspension lies between the cache replacement and flight publication.
            let shared = copy_snapshot(&admitted);
            state.current = Some(token);
            state.generation = generation;
            state.flight = None;
            drop(state);
            flight.publish(Some(shared));
            drop(leader); // The one-shot outcome cannot be replaced by Drop.
            Ok(admitted)
        },
    )
    .await
}

fn check_live(
    client: &ClientCredentialsClient,
    cx: &Cx,
    deadline: Time,
    cancellation: &McpRequestCancellation,
) -> Result<(), ClientCredentialsError> {
    check_context(cx, deadline)?;
    if client.inner.closed.is_cancel_requested() {
        return Err(ClientCredentialsError::Closed);
    }
    if cancellation.is_cancel_requested() {
        return Err(OAuthDiscoveryError::Cancelled.into());
    }
    client.inner.authentication.check()
}

async fn request_grant(
    client: &ClientCredentialsClient,
    cx: &Cx,
    deadline: Time,
    cancellation: &McpRequestCancellation,
) -> Result<ServiceToken, ClientCredentialsError> {
    let started = Instant::now();
    let grant = client
        .inner
        .authentication
        .prepare(
            cx,
            deadline,
            &client.inner.client_id,
            client.resource(),
            &client.inner.scopes,
        )
        .await?;
    let mut headers = vec![
        (
            "Content-Type".to_owned(),
            "application/x-www-form-urlencoded".to_owned(),
        ),
        ("Accept".to_owned(), "application/json".to_owned()),
        ("Accept-Encoding".to_owned(), "identity".to_owned()),
        ("Connection".to_owned(), "close".to_owned()),
    ];
    if let Some(authorization) = grant.authorization {
        headers.push(("Authorization".to_owned(), authorization));
    }
    let transport = token_transport(&client.inner.issuer_roots);
    let response = active(
        cx,
        grant.deadline,
        &client.inner.closed,
        cancellation,
        None,
        async {
            transport
                .request(
                    cx,
                    Method::Post,
                    client.inner.token_endpoint.as_str(),
                    headers,
                    grant.body,
                )
                .await
                .map_err(|_| ClientCredentialsError::Transport)
        },
    )
    .await?;
    if response.status != 200 {
        return Err(ClientCredentialsError::TokenEndpointRejected);
    }
    validate_headers(&response.headers)?;
    if !response.trailers.is_empty() {
        return Err(ClientCredentialsError::InvalidToken);
    }
    client.inner.authentication.check()?;
    admit_token(&client.inner, &response.body, started)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_auth::BoundBearerCredential;
    use fastmcp_core::CanonicalHttpUrl;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};
    use std::time::Duration;

    fn admitted() -> ClientCredentialsSnapshot {
        let expires_at = Instant::now() + Duration::from_secs(60);
        ClientCredentialsSnapshot {
            bearer: BoundBearerCredential::bind_with_expiry(
                CanonicalHttpUrl::parse("https://resource.example/mcp").unwrap(),
                "singleflight-secret",
                expires_at,
            )
            .unwrap(),
            scopes: vec!["read".to_owned()],
            expires_at,
            generation: 7,
        }
    }
    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn leader_drop_wakes_every_registered_follower_without_a_takeover() {
        let flight = Arc::new(GrantFlight::new(None));
        let leader = GrantLeader(flight.clone());
        let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut first = Box::pin(flight.wait());
        let mut second = Box::pin(flight.wait());
        assert!(first.as_mut().poll(&mut cx).is_pending());
        assert!(second.as_mut().poll(&mut cx).is_pending());
        let before = wakes.0.load(Ordering::SeqCst);
        drop(leader);
        assert!(wakes.0.load(Ordering::SeqCst) > before);
        for mut wait in [first, second] {
            assert!(matches!(
                wait.as_mut().poll(&mut cx),
                Poll::Ready(Err(ClientCredentialsError::ConcurrentAcquisitionFailed))
            ));
        }
        assert!(flight.finished());
    }

    #[test]
    fn successful_flight_preserves_exact_snapshot_and_survives_leader_drop() {
        let flight = Arc::new(GrantFlight::new(None));
        let leader = GrantLeader(flight.clone());
        let token = admitted();
        let expiry = token.expires_at;
        flight.publish(Some(copy_snapshot(&token)));
        drop(leader);
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        for _ in 0..2 {
            let mut wait = Box::pin(flight.wait());
            let Poll::Ready(Ok(result)) = wait.as_mut().poll(&mut cx) else {
                panic!("shared success");
            };
            assert_eq!(result.generation(), 7);
            assert_eq!(result.expires_at(), expiry);
            assert_eq!(result.scopes(), ["read"]);
            assert!(!format!("{result:?}").contains("singleflight-secret"));
        }
        token.bearer.revoke();
        assert!(matches!(
            Box::pin(flight.wait()).as_mut().poll(&mut cx),
            Poll::Ready(Err(ClientCredentialsError::Expired))
        ));
    }

    #[test]
    fn follower_drop_neither_finishes_nor_cancels_the_flight() {
        let flight = Arc::new(GrantFlight::new(None));
        let leader = GrantLeader(flight.clone());
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut abandoned = Box::pin(flight.wait());
        assert!(abandoned.as_mut().poll(&mut cx).is_pending());
        drop(abandoned);
        assert!(!flight.finished());
        flight.publish(Some(admitted()));
        assert!(matches!(
            Box::pin(flight.wait()).as_mut().poll(&mut cx),
            Poll::Ready(Ok(_))
        ));
        drop(leader);
    }

    #[test]
    fn predecessor_revocation_wakes_followers_without_finishing_the_leader() {
        let revoked = McpRequestCancellation::new();
        let flight = Arc::new(GrantFlight::new(Some(revoked.clone())));
        let leader = GrantLeader(flight.clone());
        let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut wait = Box::pin(flight.wait());
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        revoked.cancel();
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            wait.as_mut().poll(&mut cx),
            Poll::Ready(Err(ClientCredentialsError::Expired))
        ));
        assert!(!flight.finished());
        drop(leader);
    }

    #[test]
    fn failure_cannot_be_replaced_by_later_success_or_another_flight() {
        let failed = Arc::new(GrantFlight::new(None));
        drop(GrantLeader(failed.clone()));
        failed.publish(Some(admitted()));
        let fresh = Arc::new(GrantFlight::new(None));
        fresh.publish(Some(admitted()));
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(matches!(
            Box::pin(failed.wait()).as_mut().poll(&mut cx),
            Poll::Ready(Err(ClientCredentialsError::ConcurrentAcquisitionFailed))
        ));
        assert!(matches!(
            Box::pin(fresh.wait()).as_mut().poll(&mut cx),
            Poll::Ready(Ok(_))
        ));
    }

    #[test]
    fn delayed_follower_cannot_receive_an_expired_snapshot_or_renew_it() {
        let flight = Arc::new(GrantFlight::new(None));
        let mut token = admitted();
        token.expires_at = Instant::now();
        flight.publish(Some(token));
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(matches!(
            Box::pin(flight.wait()).as_mut().poll(&mut cx),
            Poll::Ready(Err(ClientCredentialsError::Expired))
        ));
    }

    #[test]
    fn old_revocation_after_publication_cannot_revoke_the_replacement_handoff() {
        let old = McpRequestCancellation::new();
        let flight = Arc::new(GrantFlight::new(Some(old.clone())));
        let leader = GrantLeader(flight.clone());
        let token = admitted();
        let expiry = token.expires_at;
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut follower = Box::pin(flight.wait());
        assert!(follower.as_mut().poll(&mut cx).is_pending());
        flight.publish(Some(copy_snapshot(&token)));
        old.cancel();
        let Poll::Ready(Ok(result)) = follower.as_mut().poll(&mut cx) else {
            panic!("completed replacement has independent revocation");
        };
        assert_eq!(result.generation(), 7);
        assert_eq!(result.expires_at(), expiry);
        token.bearer.revoke();
        assert!(matches!(
            Box::pin(flight.wait()).as_mut().poll(&mut cx),
            Poll::Ready(Err(ClientCredentialsError::Expired))
        ));
        drop(leader);
    }

    #[test]
    fn live_follower_cancellation_does_not_spend_leader_ownership() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let flight = Arc::new(GrantFlight::new(None));
                let leader = GrantLeader(flight.clone());
                let owner = McpRequestCancellation::new();
                let cancellation = McpRequestCancellation::new();
                let deadline = cx.now().saturating_add_nanos(5_000_000_000);
                let mut wait = Box::pin(active(
                    &cx,
                    deadline,
                    &owner,
                    &cancellation,
                    None,
                    flight.wait(),
                ));
                poll_fn(|cx| {
                    assert!(wait.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                cancellation.cancel();
                assert!(matches!(
                    wait.await,
                    Err(ClientCredentialsError::Discovery(
                        OAuthDiscoveryError::Cancelled
                    ))
                ));
                assert!(!flight.finished());
                flight.publish(Some(admitted()));
                assert_eq!(flight.wait().await.unwrap().generation(), 7);
                drop(leader);
            });
    }
}
