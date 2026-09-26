//! The grant-lock half of persistent access installation.
//!
//! This is crate-private authority: only a completed persistent renewal exposes
//! the public installation operation. Reservation can suspend, but never moves
//! a credential. The final comparison and replacement cannot suspend.

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use asupersync::Cx;
use asupersync::sync::OwnedMutexGuard;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;

use super::super::{ManagedOAuthSession, OAuthSessionError, PendingPermit, SessionGuard, deadline_after};
use crate::http_auth::oauth::{OAuthCredentials, OAuthError};

/// A local access-installation refusal. It does not undo a completed durable
/// renewal, and contains no token, grant, file path or peer response.
#[derive(Debug)]
pub enum OAuthAccessRotationError {
    Context(OAuthError),
    Session(OAuthSessionError),
    NotComplete,
    GenerationMismatch,
    InMemoryRefreshOwnership,
    ScopeExpansion,
}

impl fmt::Display for OAuthAccessRotationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Context(error) => fmt::Display::fmt(error, f),
            Self::Session(error) => fmt::Display::fmt(error, f),
            Self::NotComplete => f.write_str("persistent renewal has no completed access grant to install"),
            Self::GenerationMismatch => f.write_str("managed OAuth generation changed before access installation"),
            Self::InMemoryRefreshOwnership => f.write_str("persistent access installation cannot replace in-memory refresh ownership"),
            Self::ScopeExpansion => f.write_str("persistent access installation would expand the current session scopes"),
        }
    }
}
impl std::error::Error for OAuthAccessRotationError {}
impl From<OAuthSessionError> for OAuthAccessRotationError {
    fn from(error: OAuthSessionError) -> Self { Self::Session(error) }
}

pub(crate) struct AccessRotation<'a> {
    session: &'a ManagedOAuthSession,
    // Return the lock before making another acquisition slot available.
    guard: SessionGuard<'a>,
    _permit: PendingPermit<'a>,
    cx: &'a Cx,
    cancellation: &'a McpRequestCancellation,
    deadline: Time,
    expected_generation: u64,
}

impl ManagedOAuthSession {
    pub(crate) async fn reserve_access_rotation<'a>(
        &'a self,
        cx: &'a Cx,
        cancellation: &'a McpRequestCancellation,
        expected_generation: u64,
        candidate: &OAuthCredentials,
    ) -> Result<AccessRotation<'a>, OAuthAccessRotationError> {
        self.check(cx, cancellation)?;
        admit_candidate(self, candidate)?;
        let deadline = deadline_after(cx, self.inner.policy.acquisition_timeout)?;
        let permit = PendingPermit::acquire(&self.inner.pending, self.inner.policy.max_pending_acquisitions)?;
        // Expiry of the OLD access token must not prevent its replacement.
        // Session closure, cancellation and acquisition time still apply.
        let guard = self.await_active(cx, cancellation, deadline, None, async {
            let guard = OwnedMutexGuard::lock(Arc::clone(&self.inner.state), cx)
                .await.map_err(|_| OAuthSessionError::StateUnavailable)?;
            Ok(SessionGuard {
                guard,
                closed: &self.inner.closed,
                logout_handoff: &self.inner.logout_handoff,
            })
        }).await?;
        let reserved = AccessRotation {
            session: self, guard, _permit: permit, cx, cancellation, deadline, expected_generation,
        };
        reserved.admit(candidate)?;
        Ok(reserved)
    }
}

impl AccessRotation<'_> {
    fn admit(&self, candidate: &OAuthCredentials) -> Result<u64, OAuthAccessRotationError> {
        self.session.check(self.cx, self.cancellation)?;
        if self.cx.now() >= self.deadline {
            return Err(OAuthSessionError::TimedOut.into());
        }
        admit_candidate(self.session, candidate)?;
        let state = self.guard.as_ref().ok_or(OAuthSessionError::Closed)?;
        if state.generation != self.expected_generation {
            return Err(OAuthAccessRotationError::GenerationMismatch);
        }
        if state.credentials.has_refresh_token() {
            return Err(OAuthAccessRotationError::InMemoryRefreshOwnership);
        }
        // Expiry is recoverable through an explicit persisted renewal;
        // revocation and an uncertain in-memory exchange are not.
        if state.renewal_failed || state.credentials.bearer_credential().is_revoked() {
            return Err(OAuthSessionError::LoginRequired.into());
        }
        if candidate.scopes().iter().any(|scope| !state.credentials.scopes().contains(scope)) {
            return Err(OAuthAccessRotationError::ScopeExpansion);
        }
        state.generation.checked_add(1).ok_or(OAuthSessionError::GenerationExhausted.into())
    }

    /// Every refusal returns the original candidate without changing state.
    /// No await, callback, serialization, or further fallible step follows the
    /// ownership election. Existing response/snapshot lifetimes are untouched.
    pub(crate) fn commit(mut self, candidate: OAuthCredentials)
        -> Result<u64, (OAuthAccessRotationError, OAuthCredentials)>
    {
        let generation = match self.admit(&candidate) {
            Ok(generation) => generation,
            Err(error) => return Err((error, candidate)),
        };
        let Some(state) = self.guard.as_mut() else {
            return Err((OAuthSessionError::Closed.into(), candidate));
        };
        state.renew_after = candidate.expires_at();
        state.credentials = candidate;
        state.generation = generation;
        Ok(generation)
    }
}

fn admit_candidate(session: &ManagedOAuthSession, candidate: &OAuthCredentials)
    -> Result<(), OAuthAccessRotationError>
{
    if !session.inner.client.accepts_credentials(candidate) {
        return Err(OAuthSessionError::OAuth(OAuthError::CredentialBindingMismatch).into());
    }
    if candidate.has_refresh_token() {
        return Err(OAuthAccessRotationError::InMemoryRefreshOwnership);
    }
    if candidate.bearer_credential().is_revoked() || Instant::now() >= candidate.expires_at() {
        return Err(OAuthSessionError::LoginRequired.into());
    }
    Ok(())
}
