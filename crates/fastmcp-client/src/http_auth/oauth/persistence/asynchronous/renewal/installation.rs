//! Reuse a shared managed session after a completed persistent renewal.
//!
//! Only local access ownership changes here. The existing renewal must already
//! have consumed, exchanged and persisted the refresh lineage. Installation
//! neither repeats those operations nor changes in-flight response lifetimes.

use asupersync::Cx;

use super::{
    AsyncOAuthRefreshStore, ManagedOAuthSession, OAuthError, OAuthRefreshRenewal,
    OAuthRefreshRenewalCustody, SlotRevision, within,
};

pub use crate::http_auth::managed::logout::rotation::OAuthAccessRotationError;

/// Successful local access installation after a separately completed durable
/// commit. The session generation and stored revision are different namespaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OAuthAccessInstallation {
    session_generation: u64,
    stored_revision: SlotRevision,
}
impl OAuthAccessInstallation {
    pub fn session_generation(self) -> u64 { self.session_generation }
    pub fn stored_revision(self) -> SlotRevision { self.stored_revision }
}

impl<A, P> OAuthRefreshRenewal<A, P> {
    /// Replaces an existing access-only session's grant without replacing the
    /// session itself. Every clone subsequently acquires the new generation;
    /// existing snapshots/responses keep their original expiry and generation.
    /// No browser, issuer request, storage operation, or automatic retry occurs.
    ///
    /// The host MUST select the same principal/renewal lineage that created the
    /// target session. Matching client configuration is not proof of principal
    /// equivalence, and opaque OAuth access tokens are not decoded to invent it.
    /// Use the session previously returned with this store by
    /// `take_managed_session`. A different identity requires a new session.
    ///
    /// `expected_generation` is the last generation acquired from that exact
    /// session, never a file revision. A competing installation makes it stale.
    /// Closed/revoked sessions, scope expansion, in-memory refresh ownership,
    /// and mismatched client/resource/issuer/trust policy are refused unchanged.
    /// The old access token may have expired; the candidate must still be live.
    ///
    /// Waiting consumes existing acquisition capacity and retains the original
    /// renewal caller/cancellation/deadline plus the observer's bounds. Dropping
    /// that wait, a timeout, or any refusal leaves completed custody here for
    /// explicit handling; neither the grant nor the store is reconstructed.
    /// Success consumes that custody once and returns the same persistent store.
    /// There is no suspension or fallible check after local installation. A
    /// concurrent close may immediately revoke the newly installed generation,
    /// just as it may revoke a freshly delivered credential snapshot.
    pub async fn install_managed_access(
        &mut self,
        observer: &Cx,
        session: &ManagedOAuthSession,
        expected_generation: u64,
    ) -> Result<(AsyncOAuthRefreshStore<A, P>, OAuthAccessInstallation), OAuthAccessRotationError> {
        self.check_installation_context(observer)?;
        let OAuthRefreshRenewalCustody::Complete { credentials, .. } = &self.custody else {
            return Err(OAuthAccessRotationError::NotComplete);
        };
        // Clone only lifetime handles, not grant/store custody. The reservation
        // then borrows no part of self while the final ownership election runs.
        let origin = self.origin.clone();
        let cancellation = self.cancellation.clone();
        let deadline = self.deadline;
        let observer_deadline = observer.now().saturating_add_nanos(
            deadline.as_nanos().saturating_sub(origin.now().as_nanos()),
        );
        // Acquisition is the ONLY asynchronous phase. Keep the candidate in
        // Complete until all wait guards have returned, so a post-poll timeout
        // cannot hide a completed installation or discard a usable candidate.
        let reservation = within(observer, observer_deadline, async {
            Ok(within(&origin, deadline, async {
                Ok(session.reserve_access_rotation(
                    observer, &cancellation, expected_generation, credentials,
                ).await)
            }).await)
        }).await.map_err(OAuthAccessRotationError::Context)?
            .map_err(OAuthAccessRotationError::Context)??;
        self.check_installation_context(observer)?;
        let previous = std::mem::replace(
            &mut self.custody, OAuthRefreshRenewalCustody::Stopped { store: None, credentials: None },
        );
        let OAuthRefreshRenewalCustody::Complete { store, credentials, revision } = previous else {
            self.custody = previous;
            return Err(OAuthAccessRotationError::NotComplete);
        };
        match reservation.commit(credentials) {
            Ok(session_generation) => Ok((store, OAuthAccessInstallation { session_generation, stored_revision: revision })),
            Err((error, credentials)) => {
                self.custody = OAuthRefreshRenewalCustody::Complete { store, credentials, revision };
                Err(error)
            }
        }
    }

    fn check_installation_context(&self, observer: &Cx) -> Result<(), OAuthAccessRotationError> {
        if self.cancellation.is_cancel_requested() || self.origin.checkpoint().is_err() || observer.checkpoint().is_err() {
            return Err(OAuthAccessRotationError::Context(OAuthError::Cancelled));
        }
        if self.origin.now() >= self.deadline
            || self.origin.budget().deadline.is_some_and(|end| self.origin.now() >= end)
            || observer.budget().deadline.is_some_and(|end| observer.now() >= end)
        {
            return Err(OAuthAccessRotationError::Context(OAuthError::TimedOut));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
