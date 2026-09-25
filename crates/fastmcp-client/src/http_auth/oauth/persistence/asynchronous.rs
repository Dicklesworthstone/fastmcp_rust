//! Async persistent refresh custody on the caller's bounded credential-I/O lane.
//!
//! Each submitted operation moves the WHOLE synchronous store and protection
//! provider to one caller-owned blocking job. The existing anchored transaction
//! still decides transfer, tombstone, quarantine and commit disposition. There
//! is no split load/decrypt/take sequence between separately admitted workers.

use std::fmt;
use std::fs::File;

use asupersync::Cx;
use fastmcp_core::partition::{CredentialStoreKey, PartitionAuthorization};

use super::{
    MAX_CONFIGURATION_BYTES, MAX_ENCODED_REFRESH_GRANT_BYTES,
    MAX_PROTECTED_REFRESH_GRANT_BYTES, OAuthClient, OAuthCredentials,
    OAuthGrantProtector, OAuthRefreshGrant, OAuthRefreshStore, OAuthRefreshStoreError,
    configuration_digest,
};
use crate::http_auth::secure_file::SecureAtomicFile;
use crate::http_auth::secure_file::slot::{CredentialSlotError, SlotRecoveryOutcome, SlotRevision};
use crate::http_auth::secure_file::slot::coordinator::{CoordinatedSlotError, CredentialCommitAnchor};
use crate::http_auth::secure_file::slot::coordinator::asynchronous::{
    CredentialIoError, CredentialIoLane, CredentialSlotTask,
    composed::ComposedCredentialIo,
};

// Reserve complete upper bounds, not serialized secret-dependent measurements:
// store/client/credential/decoded-grant configurations and secret encodings can
// coexist during handoff. File buffers have their separate operation charge.
// Provider-internal storage and returned application values are not counted.
const EXTRA_WORK_BYTES: usize = 4 * MAX_CONFIGURATION_BYTES
    + 4 * MAX_ENCODED_REFRESH_GRANT_BYTES + 2 * MAX_PROTECTED_REFRESH_GRANT_BYTES;
const MAX_FILE_BYTES: usize = MAX_PROTECTED_REFRESH_GRANT_BYTES + 256;

/// Submission/preflight failures, not a transaction's commit disposition.
/// Inputs are consumed on submission failure; no worker can have executed the
/// failed submission. Reopen to recover already-persisted custody. A transaction
/// error is instead returned WITH its owner in `OAuthRefreshCompletion`.
#[derive(Debug)]
pub enum AsyncOAuthRefreshError {
    Io(CredentialIoError),
    Store(OAuthRefreshStoreError),
}
impl fmt::Display for AsyncOAuthRefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Store(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for AsyncOAuthRefreshError {}
impl From<CredentialIoError> for AsyncOAuthRefreshError {
    fn from(error: CredentialIoError) -> Self { Self::Io(error) }
}
impl From<OAuthRefreshStoreError> for AsyncOAuthRefreshError {
    fn from(error: OAuthRefreshStoreError) -> Self { Self::Store(error) }
}

/// Completion custody: the same store owner plus the exact operation outcome.
/// Store writes also return the original access credentials, even when sealing
/// or the transaction failed. Their refresh token remains present only when the
/// synchronous store proved transfer had not started. Never infer that from a
/// cancelled wait. Neither this type nor the contained secrets implement Clone,
/// Debug or serialization.
pub struct OAuthRefreshCompletion<A, P, T> {
    owner: AsyncOAuthRefreshStore<A, P>,
    outcome: T,
}
impl<A, P, T> OAuthRefreshCompletion<A, P, T> {
    pub fn into_parts(self) -> (AsyncOAuthRefreshStore<A, P>, T) {
        (self.owner, self.outcome)
    }
}

pub type OAuthRefreshOpen<A, P> = Result<
    (AsyncOAuthRefreshStore<A, P>, Option<SlotRecoveryOutcome>), OAuthRefreshStoreError,
>;
pub type OAuthRefreshWrite<A, P> = OAuthRefreshCompletion<
    A, P, (OAuthCredentials, Result<SlotRevision, OAuthRefreshStoreError>),
>;
pub type OAuthRefreshTake<A, P> = OAuthRefreshCompletion<
    A, P, Result<Option<OAuthRefreshGrant>, OAuthRefreshStoreError>,
>;

/// Exclusive owner of a Linux persistent OAuth refresh store.
///
/// Encryption, file I/O, anchor calls and successful explicit closure execute
/// off the async poller. Every operation consumes this owner and returns it in
/// the existing `CredentialSlotTask` one-use mailbox. Keep that task after an
/// interrupted wait to retrieve the SAME outcome without another transaction.
/// Dropping a task requests cancellation but cannot preempt a running provider.
///
/// Uses the host's shared `CredentialIoLane`: other stores compete for the same
/// slot/job/byte limits and participate in the same shutdown/drain. Close keeps
/// its reserved cleanup path after shutdown. Provider memory and destructors
/// remain provider-owned; destructors must not block. Failed submission/drop
/// can release their ownership synchronously without calling provider methods.
///
/// This does not supply a production protection service or independent anchor,
/// renew a token automatically, or store access tokens. Both deployment-provider
/// contracts in `OAuthRefreshStore` remain mandatory across process restarts.
pub struct AsyncOAuthRefreshStore<A, P> {
    // Destroy provider and file lock before returning slot capacity.
    store: OAuthRefreshStore<A, P>,
    io: ComposedCredentialIo,
}

impl<A, P> AsyncOAuthRefreshStore<A, P>
where A: CredentialCommitAnchor + 'static, P: OAuthGrantProtector + 'static,
{
    /// Opens/reconciles custody on a worker using a host-opened directory handle.
    /// All configuration admission is local and precedes filesystem/provider
    /// work. `client` is copied only after its bounded binding is admitted.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        cx: &Cx, lane: &CredentialIoLane, directory: File, leaf: String,
        key: CredentialStoreKey, authorization: PartitionAuthorization,
        namespace: String, anchor: A, protector: P, client: &OAuthClient,
    ) -> Result<CredentialSlotTask<OAuthRefreshOpen<A, P>>, AsyncOAuthRefreshError> {
        if leaf.is_empty() || leaf.len() > 96 || namespace.is_empty() || namespace.len() > 128 {
            return Err(CredentialIoError::InvalidSlotConfiguration.into());
        }
        configuration_digest(&client.configuration)?;
        let _ = super::CredentialAnchorBinding::for_store(&namespace, &key, &authorization)
            .map_err(OAuthRefreshStoreError::from)?;
        let io = ComposedCredentialIo::reserve(cx, lane, MAX_FILE_BYTES, EXTRA_WORK_BYTES)?;
        let client = client.clone();
        let leaf = leaf.into_boxed_str();
        let namespace = namespace.into_boxed_str();
        Ok(io.submit(cx, move |worker, io| {
            let file = SecureAtomicFile::open(worker, directory, &leaf, MAX_FILE_BYTES)
                .map_err(|error| OAuthRefreshStoreError::Storage(CoordinatedSlotError::Slot(CredentialSlotError::Storage(error))))?;
            let (store, recovery) = OAuthRefreshStore::open(
                worker, file, &key, &authorization, &namespace, anchor, protector, &client,
            )?;
            Ok((Self { store, io }, recovery))
        })?)
    }

    pub fn revision(&self) -> Option<SlotRevision> { self.store.revision() }
    pub fn requires_recovery(&self) -> bool { self.store.requires_recovery() }

    /// Transfers a native grant into protected custody. Success leaves the
    /// returned credentials' original access token and expiry unchanged, with
    /// refresh ownership removed. Pre-transfer refusal returns it untouched;
    /// uncertain storage failure returns it WITHOUT renewal ownership.
    pub fn store_refresh(
        self, cx: &Cx, authorization: PartitionAuthorization,
        expected: Option<SlotRevision>, mut credentials: OAuthCredentials,
    ) -> Result<CredentialSlotTask<OAuthRefreshWrite<A, P>>, AsyncOAuthRefreshError> {
        configuration_digest(&credentials.configuration)?;
        // Credentials are native admitted values, but discard spare capacities
        // before queueing their secret/map buffers under a fixed reservation.
        if let Some(token) = &mut credentials.refresh_token { token.shrink_to_fit(); }
        for scope in &mut credentials.scopes { scope.shrink_to_fit(); }
        credentials.scopes.shrink_to_fit();
        let Self { store, io } = self;
        Ok(io.submit(cx, move |worker, io| {
            // Reassemble before calling the provider so unwinding also drops
            // the store/file lock before releasing its slot admission.
            let mut owner = Self { store, io };
            let result = owner.store.store_refresh(worker, &authorization, expected, &mut credentials);
            OAuthRefreshCompletion { owner, outcome: (credentials, result) }
        })?)
    }

    /// Validates/decrypts and durably tombstones in one admitted worker before
    /// returning a renewal grant. No plaintext/access credential is reconstructed
    /// outside the protection contract, and an uncertain take is not retried.
    pub fn take_refresh(self, cx: &Cx, authorization: PartitionAuthorization)
        -> Result<CredentialSlotTask<OAuthRefreshTake<A, P>>, AsyncOAuthRefreshError>
    {
        let Self { store, io } = self;
        Ok(io.submit(cx, move |worker, io| {
            let mut owner = Self { store, io };
            let outcome = owner.store.take_refresh(worker, &authorization);
            OAuthRefreshCompletion { owner, outcome }
        })?)
    }

    /// Persistent local invalidation, not issuer-side revocation. Already
    /// handed-out grants and access tokens remain the application's custody.
    pub fn invalidate(self, cx: &Cx, authorization: PartitionAuthorization)
        -> Result<CredentialSlotTask<OAuthRefreshCompletion<A, P, Result<SlotRevision, OAuthRefreshStoreError>>>, AsyncOAuthRefreshError>
    {
        let Self { store, io } = self;
        Ok(io.submit(cx, move |worker, io| {
            let mut owner = Self { store, io };
            let outcome = owner.store.invalidate(worker, &authorization);
            OAuthRefreshCompletion { owner, outcome }
        })?)
    }

    /// Drops the provider and retained file lock on the caller's blocking lane.
    /// This remains admitted during lane shutdown or ordinary-work saturation.
    pub fn close(self, cx: &Cx) -> Result<CredentialSlotTask<()>, AsyncOAuthRefreshError> {
        let Self { store, io } = self;
        Ok(io.close(cx, store)?)
    }
}

#[cfg(test)]
mod tests;
