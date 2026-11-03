//! Token-local revocation for machine dispatch and replacement acquisition.
//!
//! A response observes its original snapshot; a renewal observes only the old
//! token's revocation, not its expired access lifetime. The enclosing active()
//! guard remains responsible for caller/owner cancellation and the deadline.
//! Explicit logout additionally owns one local-first RFC 7009 retirement.

use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::http::h1::{HttpClient, Method, RedirectPolicy, RetryPolicy};
use asupersync::sync::OwnedMutexGuard;
use asupersync::time::Sleep;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use serde::Deserialize;

use super::{
    CanonicalHttpUrl, ClientCredentialsClient, ClientCredentialsError, MachineAuthentication,
    OAuthDiscoveryError, PreparedMachineGrant, TrustedOAuthIssuer, basic, check_context,
    decode_metadata, discovery_deadline, form, has, present, validate_optional_array,
};
use crate::http_auth::caller::with_caller;

/// Remote observation for one retained machine access token. No variant grants
/// retry authority or reopens the locally closed client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientCredentialsRemoteRevocation {
    /// No cached access token existed. Logout never acquires one to revoke it.
    NoToken,
    /// The admitted issuer document contained no revocation endpoint.
    EndpointUnavailable,
    /// That endpoint did not support the client's already selected method or
    /// the selected RS256 algorithm. No authentication fallback was attempted.
    AuthenticationUnavailable,
    /// JWT authentication had no separately imported revocation registration.
    RegistrationUnavailable,
    /// A complete HTTP 200 response acknowledged the request. RFC 7009 also
    /// returns 200 for invalid tokens; this is not independent evidence of
    /// issuer-side invalidation or propagation to every resource server.
    Acknowledged,
    /// An HTTP response was received without RFC 7009 acknowledgement.
    Rejected { status: u16 },
    /// Dispatch or remote outcome is uncertain; no response/token is retained.
    Uncertain,
    /// Caller cancellation ended logout after local closure.
    Cancelled,
    /// The original logout or shorter assertion deadline expired.
    TimedOut,
    /// Custody, runtime policy, or assertion preparation failed after closure.
    Failed,
}

/// Local admission is irreversibly closed whenever this report exists.
/// Only the current cached generation is submitted remotely; older snapshots
/// are closed locally, but there is no retained history of their raw tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientCredentialsLogoutReport {
    remote: ClientCredentialsRemoteRevocation,
}

impl ClientCredentialsLogoutReport {
    pub fn local_closed(&self) -> bool {
        true
    }

    pub fn remote(&self) -> ClientCredentialsRemoteRevocation {
        self.remote
    }
}

#[derive(Clone, Default)]
pub(super) enum RevocationTarget {
    #[default]
    EndpointUnavailable,
    AuthenticationUnavailable,
    RegistrationUnavailable,
    Endpoint(CanonicalHttpUrl),
}

#[derive(Deserialize)]
struct RevocationMetadata {
    #[serde(default, deserialize_with = "present")]
    revocation_endpoint: Option<String>,
    #[serde(default, deserialize_with = "present")]
    revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
}

pub(super) fn admit_revocation(
    issuer: &TrustedOAuthIssuer,
    body: &[u8],
    authentication: &MachineAuthentication,
) -> Result<RevocationTarget, ClientCredentialsError> {
    let metadata: RevocationMetadata = decode_metadata(body)?;
    let methods = metadata.revocation_endpoint_auth_methods_supported.as_deref();
    let algorithms = metadata
        .revocation_endpoint_auth_signing_alg_values_supported
        .as_deref();
    validate_optional_array(methods)?;
    validate_optional_array(algorithms)?;
    if algorithms.is_some_and(|values| has(values, "none"))
        || (methods.is_some_and(|values| {
            has(values, "private_key_jwt") || has(values, "client_secret_jwt")
        }) && algorithms.is_none())
    {
        return Err(OAuthDiscoveryError::InvalidMetadata.into());
    }
    let Some(advertised) = metadata.revocation_endpoint.as_deref() else {
        return Ok(RevocationTarget::EndpointUnavailable);
    };
    let endpoint = issuer.endpoint(advertised)?;
    #[cfg(all(not(target_arch = "wasm32"), feature = "builtin-auth-server"))]
    let registered = match authentication {
        MachineAuthentication::PrivateKeyJwt(selected) => selected.admits_revocation(advertised)?,
        _ => true,
    };
    // RFC 8414 section 2 defaults ONLY an omitted method list to Basic.
    // Token-endpoint declarations never supply revocation-endpoint authority.
    let supported = methods.map_or(authentication.method() == "client_secret_basic", |values| {
        has(values, authentication.method())
    });
    if !supported {
        return Ok(RevocationTarget::AuthenticationUnavailable);
    }
    #[cfg(all(not(target_arch = "wasm32"), feature = "builtin-auth-server"))]
    if matches!(authentication, MachineAuthentication::PrivateKeyJwt(_)) {
        if !algorithms.is_some_and(|values| has(values, "RS256")) {
            return Ok(RevocationTarget::AuthenticationUnavailable);
        }
        if !registered {
            return Ok(RevocationTarget::RegistrationUnavailable);
        }
    }
    Ok(RevocationTarget::Endpoint(endpoint))
}

struct LogoutCleanup<'a>(&'a ClientCredentialsClient);

impl Drop for LogoutCleanup<'_> {
    fn drop(&mut self) {
        // Nonblocking, just like explicit close. No lock is held while a
        // cancellation signal invokes arbitrary waiter wakers.
        self.0.close();
    }
}

impl ClientCredentialsClient {
    /// Closes this shared machine client, then attempts RFC 7009 revocation of
    /// its current cached access token once, if an admitted endpoint exists.
    ///
    /// Pre-cancellation, unavailable runtime, invalid registration, and an
    /// already closed owner have no new effect. After closure starts, every
    /// ordinary exit is a report: missing endpoint/authentication, issuer
    /// rejection, response loss, timeout, and cancellation never restore
    /// cached credentials. Dropping a pending future keeps the client closed
    /// and releases its owned request. Disposal before acquiring the cache
    /// lock is best effort: if another thread holds it, the bounded cached
    /// token can remain until another close or final owner drop. Its shared
    /// owner signal already forbids every subsequent use.
    ///
    /// The same finite caller budget spans custody, fresh JWT signing when
    /// selected, dispatch, and bounded response consumption. No redirect,
    /// retry, new grant, refresh token, or other authentication method is used.
    /// Old generations and a remotely issued but unobserved concurrent grant
    /// cannot be enumerated: their local use is closed, but remote revocation
    /// of those tokens is not claimed. Already-sent effects cannot be recalled.
    pub async fn logout(
        &self,
        cx: &Cx,
    ) -> Result<ClientCredentialsLogoutReport, ClientCredentialsError> {
        self.logout_with_cancellation(cx, &McpRequestCancellation::new())
            .await
    }

    pub async fn logout_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> Result<ClientCredentialsLogoutReport, ClientCredentialsError> {
        let deadline = with_caller(cx, || {
            if self.inner.closed.is_cancel_requested() {
                return Err(ClientCredentialsError::Closed);
            }
            check_logout(cx, cancellation, Time::from_nanos(u64::MAX))?;
            require_logout_runtime(cx)?;
            self.inner.authentication.check()?;
            let deadline = discovery_deadline(cx, self.inner.timeout)?;
            check_logout(cx, cancellation, deadline)?;
            Ok(deadline)
        })?;
        // This CAS elects one logout owner and closes every snapshot before
        // waiting for custody. Acquisition checks this signal before commit.
        if !self.inner.closed.cancel() {
            return Err(ClientCredentialsError::Closed);
        }
        let cleanup = LogoutCleanup(self);
        let result = within_logout(cx, cancellation, deadline, async {
            let mut state = OwnedMutexGuard::lock(Arc::clone(&self.inner.state), cx)
                .await
                .map_err(|_| ClientCredentialsError::StateUnavailable)?;
            let token = state.current.take();
            let target = state.revocation.clone();
            state.flight = None;
            drop(state);
            drop(cleanup);
            let Some(token) = token else {
                return Ok(ClientCredentialsRemoteRevocation::NoToken);
            };
            token.bearer.revoke();
            let endpoint = match target {
                RevocationTarget::Endpoint(endpoint) => endpoint,
                RevocationTarget::EndpointUnavailable => {
                    return Ok(ClientCredentialsRemoteRevocation::EndpointUnavailable);
                }
                RevocationTarget::AuthenticationUnavailable => {
                    return Ok(ClientCredentialsRemoteRevocation::AuthenticationUnavailable);
                }
                RevocationTarget::RegistrationUnavailable => {
                    return Ok(ClientCredentialsRemoteRevocation::RegistrationUnavailable);
                }
            };
            let grant =
                prepare_revocation(self, cx, deadline, &endpoint, &token.bearer.token).await?;
            let mut headers = vec![
                (
                    "Content-Type".to_owned(),
                    "application/x-www-form-urlencoded".to_owned(),
                ),
                ("Accept-Encoding".to_owned(), "identity".to_owned()),
                ("Connection".to_owned(), "close".to_owned()),
            ];
            if let Some(authorization) = grant.authorization {
                headers.push(("Authorization".to_owned(), authorization));
            }
            let mut builder = HttpClient::builder()
                .redirect_policy(RedirectPolicy::None)
                .retry_policy(RetryPolicy::None)
                .no_proxy()
                .no_cookie_store()
                .max_body_size(4096)
                .max_total_connections(1);
            for root in &self.inner.issuer_roots {
                builder = builder.add_root_certificate(root.clone());
            }
            let transport = builder.build();
            within_logout(cx, cancellation, grant.deadline, async {
                let response = transport
                    .request(cx, Method::Post, endpoint.as_str(), headers, grant.body)
                    .await;
                // RFC 7009 ignores response content. Neither peer bodies nor
                // transport diagnostics containing credentials escape here.
                Ok(match response {
                    Ok(response) if response.status == 200 => {
                        ClientCredentialsRemoteRevocation::Acknowledged
                    }
                    Ok(response) => ClientCredentialsRemoteRevocation::Rejected {
                        status: response.status,
                    },
                    Err(_) => ClientCredentialsRemoteRevocation::Uncertain,
                })
            })
            .await
        })
        .await;
        let remote = match result {
            Ok(outcome) => outcome,
            Err(ClientCredentialsError::Discovery(OAuthDiscoveryError::Cancelled)) => {
                ClientCredentialsRemoteRevocation::Cancelled
            }
            Err(ClientCredentialsError::Discovery(OAuthDiscoveryError::TimedOut)) => {
                ClientCredentialsRemoteRevocation::TimedOut
            }
            Err(_) => ClientCredentialsRemoteRevocation::Failed,
        };
        Ok(ClientCredentialsLogoutReport { remote })
    }
}

#[allow(
    clippy::unused_async,
    reason = "the optional private-key branch awaits a fresh external assertion"
)]
async fn prepare_revocation(
    client: &ClientCredentialsClient,
    cx: &Cx,
    deadline: Time,
    endpoint: &CanonicalHttpUrl,
    token: &str,
) -> Result<PreparedMachineGrant, ClientCredentialsError> {
    client.inner.authentication.check()?;
    check_context(cx, deadline)?;
    let mut fields = vec![("token", token), ("token_type_hint", "access_token")];
    let authorization = match &client.inner.authentication {
        MachineAuthentication::Basic(secret) => Some(basic(&client.inner.client_id, &secret.0)?),
        MachineAuthentication::Post(secret) => {
            fields.push(("client_id", &client.inner.client_id));
            fields.push(("client_secret", &secret.0));
            None
        }
        #[cfg(all(not(target_arch = "wasm32"), feature = "builtin-auth-server"))]
        MachineAuthentication::PrivateKeyJwt(selected) => {
            return selected
                .prepare_revocation(cx, deadline, endpoint, token)
                .await;
        }
    };
    // Keep endpoint relevant in password-only builds without another profile.
    let _ = endpoint;
    let body = form(&fields).into_bytes();
    if body.len() > super::MAX_TOKEN_BYTES {
        return Err(ClientCredentialsError::RequestTooLarge);
    }
    Ok(PreparedMachineGrant {
        body,
        authorization,
        deadline,
    })
}

fn require_logout_runtime(cx: &Cx) -> Result<(), ClientCredentialsError> {
    let active = Cx::current().ok_or(OAuthDiscoveryError::RuntimeUnavailable)?;
    let capabilities = active.capabilities();
    if cx.timer_driver().is_none() || !capabilities.time || !capabilities.io || !capabilities.remote {
        return Err(OAuthDiscoveryError::RuntimeUnavailable.into());
    }
    Ok(())
}

fn check_logout(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    deadline: Time,
) -> Result<(), ClientCredentialsError> {
    if cancellation.is_cancel_requested() {
        return Err(OAuthDiscoveryError::Cancelled.into());
    }
    check_context(cx, deadline)?;
    Ok(())
}

async fn within_logout<T>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    deadline: Time,
    future: impl Future<Output = Result<T, ClientCredentialsError>>,
) -> Result<T, ClientCredentialsError> {
    let deadline = cx.budget().deadline.map_or(deadline, |parent| parent.min(deadline));
    let mut timer = std::pin::pin!(Sleep::new(deadline));
    let mut cancelled = std::pin::pin!(cancellation.cancelled());
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut caller_cancelled = std::pin::pin!(receiver.recv(cx));
    let mut future = Box::pin(future);
    poll_fn(|task| {
        with_caller(cx, || {
            check_logout(cx, cancellation, deadline)?;
            require_logout_runtime(cx)?;
            if cancelled.as_mut().poll(task).is_ready()
                || caller_cancelled.as_mut().poll(task).is_ready()
            {
                return Poll::Ready(Err(OAuthDiscoveryError::Cancelled.into()));
            }
            if timer.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(OAuthDiscoveryError::TimedOut.into()));
            }
            let result = future.as_mut().poll(task);
            check_logout(cx, cancellation, deadline)?;
            result
        })
    })
    .await
}

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

#[cfg(test)]
mod logout_tests {
    use super::*;
    use super::super::{
        ClientCredentialsPlan, ClientInner, ClientSecret, ServiceToken, TokenState,
    };
    use crate::http_auth::BoundBearerCredential;
    use asupersync::sync::Mutex;
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Waker};
    use std::time::{Duration, Instant};

    fn url(value: &str) -> CanonicalHttpUrl {
        CanonicalHttpUrl::parse(value).unwrap()
    }

    fn client() -> (ClientCredentialsClient, BoundBearerCredential) {
        let closed = McpRequestCancellation::new();
        let expires_at = Instant::now() + Duration::from_secs(120);
        let bearer = BoundBearerCredential::bind_with_expiry(
            url("https://machine.example/mcp"), "cached-secret", expires_at,
        ).unwrap().for_owner(&closed).unwrap();
        let client = ClientCredentialsClient {
            inner: Arc::new(ClientInner {
                resource: url("https://machine.example/mcp"),
                token_endpoint: url("https://issuer.example/token"),
                client_id: "service-client".to_owned(),
                scopes: vec!["read".to_owned()],
                authentication: MachineAuthentication::Basic(Arc::new(ClientSecret("secret".to_owned()))),
                issuer_roots: vec![],
                resource_tls: None,
                timeout: Duration::from_secs(1),
                maximum_lifetime: Duration::from_secs(120),
                leeway: Duration::ZERO,
                closed,
                pending: AtomicUsize::new(0),
                state: Arc::new(Mutex::new(TokenState {
                    current: Some(ServiceToken {
                        bearer: bearer.clone(),
                        scopes: vec!["read".to_owned()],
                        expires_at,
                        renew_after: expires_at,
                    }),
                    generation: 1,
                    ..TokenState::default()
                })),
            }),
        };
        (client, bearer)
    }

    fn runtime(test: impl FnOnce(&Cx, &VirtualClock, &TimerDriverHandle)) {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build().unwrap();
        let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        test(&cx, &clock, &timer);
        assert_eq!(timer.pending_count(), 0);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn revocation_metadata_presence_and_duplicates_cannot_impersonate_defaults() {
        let issuer = TrustedOAuthIssuer::new("https://issuer.example").unwrap();
        let plan = ClientCredentialsPlan::new(
            url("https://machine.example/mcp"), issuer.clone(),
            "service-client", "secret", vec!["read".to_owned()],
        ).unwrap();
        let good = br#"{"revocation_endpoint":"https://issuer.example/revoke"}"#;
        assert!(matches!(
            admit_revocation(&issuer, good, &plan.authentication),
            Ok(RevocationTarget::Endpoint(_))
        ));
        for bad in [
            r#"{"revocation_endpoint":null}"#,
            r#"{"revocation_endpoint":"https://issuer.example/revoke","revocation\u005fendpoint":"https://issuer.example/revoke"}"#,
            r#"{"revocation_endpoint":"https://issuer.example/revoke","revocation_endpoint_auth_methods_supported":null}"#,
            r#"{"revocation_endpoint_auth_methods_supported":["client_secret_basic"],"revocation_endpoint_auth_methods_supported":["client_secret_basic"]}"#,
            r#"{"revocation_endpoint_auth_signing_alg_values_supported":["RS256"],"revocation_endpoint_auth_signing_alg_values_supported":["RS256"]}"#,
            r#"{"revocation_endpoint_auth_methods_supported":["private_key_jwt"]}"#,
        ] {
            assert!(admit_revocation(&issuer, bad.as_bytes(), &plan.authentication).is_err());
            assert!(matches!(
                admit_revocation(&issuer, good, &plan.authentication),
                Ok(RevocationTarget::Endpoint(_))
            ));
        }
    }

    #[test]
    fn dropped_logout_closes_snapshots_even_when_contended_cache_cleanup_cannot_run() {
        for release_before_drop in [false, true] {
            runtime(|cx, _, _| {
                let (client, snapshot) = client();
                let mut held = Some(client.inner.state.try_lock_owned().unwrap());
                let mut logout = Box::pin(client.logout(cx));
                let mut task = Context::from_waker(Waker::noop());
                assert!(logout.as_mut().poll(&mut task).is_pending());
                assert!(client.inner.closed.is_cancel_requested());
                assert!(snapshot.is_revoked());
                assert!(held.as_ref().unwrap().current.is_some());
                if release_before_drop { drop(held.take()); }
                drop(logout);
                drop(held);
                let state = client.inner.state.try_lock_owned().unwrap();
                assert_eq!(state.current.is_some(), !release_before_drop,
                    "best-effort cleanup cannot take another owner's lock");
                drop(state);
                assert_eq!(snapshot.authorization_for_target(client.resource()), None);
                let mut retry = Box::pin(client.logout(cx));
                assert!(matches!(retry.as_mut().poll(&mut task),
                    Poll::Ready(Err(ClientCredentialsError::Closed))));
                drop(retry);
                client.close();
                assert!(client.inner.state.try_lock_owned().unwrap().current.is_none());
                assert!(cx.checkpoint().is_ok());
            });
        }
    }

    #[test]
    fn logout_custody_wait_keeps_its_original_deadline_and_cancellation() {
        for cancel in [false, true] {
            runtime(|cx, clock, timer| {
                let (client, snapshot) = client();
                let held = client.inner.state.try_lock_owned().unwrap();
                let cancellation = McpRequestCancellation::new();
                let mut logout = Box::pin(client.logout_with_cancellation(cx, &cancellation));
                let mut task = Context::from_waker(Waker::noop());
                assert!(logout.as_mut().poll(&mut task).is_pending());
                assert!(timer.pending_count() > 0);
                if cancel {
                    cancellation.cancel();
                } else {
                    clock.advance(1_000_000_000);
                    let _ = timer.process_timers();
                }
                let Poll::Ready(Ok(report)) = logout.as_mut().poll(&mut task) else {
                    panic!("logout must settle while custody remains contended");
                };
                assert!(report.local_closed());
                assert_eq!(report.remote(), if cancel {
                    ClientCredentialsRemoteRevocation::Cancelled
                } else {
                    ClientCredentialsRemoteRevocation::TimedOut
                });
                assert!(snapshot.is_revoked());
                drop(logout);
                drop(held);
                client.close();
                assert!(client.inner.state.try_lock_owned().unwrap().current.is_none());
            });
        }
    }
}
