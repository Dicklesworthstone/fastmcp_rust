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
use crate::http_auth::oauth::revocation::{
    OAuthRevocationError, OAuthRevocationReport,
};

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
    pub fn local_closed(&self) -> bool { true }
    pub fn remote(&self) -> ManagedOAuthRemoteRevocation { self.remote }
}

impl ManagedOAuthSession {
    /// Closes this shared login and attempts RFC 7009 revocation exactly once
    /// for each retained token when a trusted endpoint is configured.
    ///
    /// If the caller is already cancelled or the session already closed, no new
    /// logout effect is started. After closure begins, every exit returns a
    /// report rather than an error implying rollback: snapshots remain locally
    /// revoked and any retained grant is never put back into session state.
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
        // SessionGuard normally erases a refresh-owned grant on close. Logout
        // instead transfers that grant into this operation so its tokens can be
        // revoked. The flag never reopens request/snapshot admission.
        self.inner.logout_handoff.store(true, Ordering::Release);
        self.inner.closed.cancel();

        let mut guard = match lock_grant(cx, deadline, Arc::clone(&self.inner.state)).await {
            Ok(guard) => guard,
            Err(remote) => {
                self.inner.logout_handoff.store(false, Ordering::Release);
                return Ok(ManagedOAuthLogoutReport { remote });
            }
        };
        let state = guard.take();
        self.inner.logout_handoff.store(false, Ordering::Release);
        let Some(mut state) = state else {
            return Ok(ManagedOAuthLogoutReport { remote: ManagedOAuthRemoteRevocation::NoGrant });
        };
        drop(guard);

        let remote = match self.inner.client.revoke_credentials(cx, &mut state.credentials).await {
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
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;

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
