//! Move one existing managed login into persistent refresh custody.
//!
//! Storage authorization and the expected file revision are checked before
//! taking the session's refresh grant. Transfer is serialized with in-memory
//! renewal, installation and logout. The source session and its clones retain
//! access at its original generation/expiry but can no longer renew in memory.
//! No browser login, issuer exchange, access-token persistence or automatic
//! retry is performed by this driver.

use std::fmt;
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;

use super::{
    AsyncOAuthRefreshError, AsyncOAuthRefreshStore, CredentialCommitAnchor,
    CredentialIoError, CredentialSlotTask, OAuthClient, OAuthCredentials,
    OAuthGrantProtector, OAuthRefreshCompletion, OAuthRefreshStoreError,
    OAuthRefreshSubmissionFailure, OAuthRefreshWrite, PartitionAuthorization, SlotRevision,
};
use crate::http_auth::managed::{ManagedOAuthSession, OAuthSessionError};
use crate::http_auth::oauth::{OAuthError, operation_deadline, within};
pub use crate::http_auth::managed::logout::rotation::OAuthRefreshTransferError;

pub type OAuthRefreshCaptureCheck<A, P> = OAuthRefreshCompletion<
    A, P, Result<(), OAuthRefreshStoreError>,
>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthRefreshCaptureStage {
    ReadyToCheck,
    Checking,
    ReadyToTransfer,
    ReadyToStore,
    Storing,
    Complete,
    Stopped,
}

/// Exclusive custody, including storage outcomes not yet observed by this run.
/// Before transfer, the refresh token is still in the source managed session.
/// ReadyToStore owns it instead; the source is then permanently access-only.
/// Complete proves persistence, not revocation or validity of the access token.
///
/// Inspect credentials.has_refresh_token() in a stopped storage result: a
/// failed seal retains it, but an uncertain commit does not. Never reconstruct
/// it from prior bytes. Pending tasks can be observed under another live caller
/// to learn the SAME transaction's disposition; they are not retry commands.
pub enum OAuthRefreshCaptureCustody<A, P> {
    ReadyToCheck(AsyncOAuthRefreshStore<A, P>),
    Checking(CredentialSlotTask<OAuthRefreshCaptureCheck<A, P>>),
    ReadyToTransfer(AsyncOAuthRefreshStore<A, P>),
    ReadyToStore { store: AsyncOAuthRefreshStore<A, P>, credentials: OAuthCredentials },
    Storing(CredentialSlotTask<OAuthRefreshWrite<A, P>>),
    Complete { store: AsyncOAuthRefreshStore<A, P>, revision: SlotRevision },
    Stopped { store: Option<AsyncOAuthRefreshStore<A, P>>, credentials: Option<OAuthCredentials> },
}

#[derive(Debug)]
pub enum OAuthRefreshCaptureError {
    Context(OAuthError),
    Session(OAuthSessionError),
    Transfer(OAuthRefreshTransferError),
    Submission(AsyncOAuthRefreshError),
    Completion(CredentialIoError),
    Storage(OAuthRefreshStoreError),
    NotComplete,
    Stopped,
}
impl fmt::Display for OAuthRefreshCaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Context(error) => fmt::Display::fmt(error, f),
            Self::Session(error) => fmt::Display::fmt(error, f),
            Self::Transfer(error) => fmt::Display::fmt(error, f),
            Self::Submission(error) => fmt::Display::fmt(error, f),
            Self::Completion(error) => fmt::Display::fmt(error, f),
            Self::Storage(error) => fmt::Display::fmt(error, f),
            Self::NotComplete => f.write_str("managed refresh capture has not completed persistence"),
            Self::Stopped => f.write_str("managed refresh capture stopped; inspect its retained custody"),
        }
    }
}
impl std::error::Error for OAuthRefreshCaptureError {}

/// Caller-driven migration, not a task or an automatic renewal scheduler.
/// One original context, cancellation domain and deadline cover storage checks,
/// session-lock acquisition, pauses and persistence. A source session closure
/// stops further work, but cannot reverse an already-committed storage operation.
/// Explicitly invalidate captured storage when logout, rather than local access
/// closure, is intended.
///
/// An abandoned storage wait preserves its mailbox. An abandoned session-lock
/// wait has not moved the grant. Once transfer succeeds, admission refusal can
/// retain the exact candidate for another EXPLICIT attempt to schedule storage.
/// No path restores refresh ownership to the session or automatically retries a
/// dispatched transaction. The owner exposes actual custody on every exit.
///
/// The host must select the correct store partition for this principal. Exact
/// client/issuer/resource/trust matching is necessary but does not establish
/// principal identity. Protection/anchor qualification remains the deployment's
/// responsibility; there is no plaintext or process-local encryption fallback.
#[must_use = "drive capture to completion or inspect its exclusive custody"]
pub struct OAuthRefreshCapture<A, P> {
    origin: Cx,
    cancellation: McpRequestCancellation,
    deadline: Time,
    session: ManagedOAuthSession,
    client: OAuthClient,
    authorization: PartitionAuthorization,
    expected_revision: Option<SlotRevision>,
    expected_generation: u64,
    custody: OAuthRefreshCaptureCustody<A, P>,
}

impl<A, P> AsyncOAuthRefreshStore<A, P>
where A: CredentialCommitAnchor + 'static, P: OAuthGrantProtector + 'static,
{
    /// Prepare without transferring credentials or contacting a provider.
    /// `expected_revision` authorizes only that exact replacement, including
    /// None for a never-written store; existing renewal lineages are not silently
    /// overwritten. A fresh authoritative storage read precedes session transfer.
    /// `expected_generation` binds the host's selected managed access generation.
    /// A racing in-memory renewal makes it stale instead of silently changing
    /// the grant being captured. Timeout must be positive and at most 5 minutes.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_capture(
        self, cx: &Cx, session: &ManagedOAuthSession, expected_generation: u64,
        authorization: PartitionAuthorization, expected_revision: Option<SlotRevision>,
        cancellation: &McpRequestCancellation, timeout: Duration,
    ) -> Result<OAuthRefreshCapture<A, P>, OAuthRefreshSubmissionFailure<A, P, ()>> {
        let admitted = (|| {
            if expected_generation == 0 || timeout.is_zero() || timeout > Duration::from_secs(300) {
                return Err(AsyncOAuthRefreshError::Io(CredentialIoError::InvalidLimits));
            }
            if session.resource() != &self.store.configuration.resource {
                return Err(OAuthRefreshStoreError::ConfigurationMismatch.into());
            }
            if self.revision() != expected_revision {
                return Err(OAuthRefreshStoreError::RevisionMismatch.into());
            }
            if cancellation.is_cancel_requested() {
                return Err(OAuthRefreshStoreError::ContextStopped.into());
            }
            operation_deadline(cx, timeout)
                .map_err(|_| AsyncOAuthRefreshError::Store(OAuthRefreshStoreError::ContextStopped))
        })();
        let deadline = match admitted {
            Ok(deadline) => deadline,
            Err(cause) => return Err(OAuthRefreshSubmissionFailure { cause, retained: Some((self, ())) }),
        };
        let client = OAuthClient::new(self.store.configuration.clone());
        Ok(OAuthRefreshCapture {
            origin: cx.clone(), cancellation: cancellation.clone(), deadline,
            session: session.clone(), client, authorization, expected_revision,
            expected_generation, custody: OAuthRefreshCaptureCustody::ReadyToCheck(self),
        })
    }
}

impl<A, P> OAuthRefreshCapture<A, P> {
    pub fn stage(&self) -> OAuthRefreshCaptureStage {
        use OAuthRefreshCaptureCustody as C;
        use OAuthRefreshCaptureStage as S;
        match &self.custody {
            C::ReadyToCheck(_) => S::ReadyToCheck,
            C::Checking(_) => S::Checking,
            C::ReadyToTransfer(_) => S::ReadyToTransfer,
            C::ReadyToStore { .. } => S::ReadyToStore,
            C::Storing(_) => S::Storing,
            C::Complete { .. } => S::Complete,
            C::Stopped { .. } => S::Stopped,
        }
    }

    pub fn into_custody(self) -> OAuthRefreshCaptureCustody<A, P> { self.custody }

    /// Returns only proven completed persistent custody. This remains usable
    /// for cleanup after the source session closes or the capture deadline ends.
    /// It grants no access token or new authority to execute a transaction.
    pub fn take_store(&mut self) -> Result<(AsyncOAuthRefreshStore<A, P>, SlotRevision), OAuthRefreshCaptureError> {
        if self.stage() != OAuthRefreshCaptureStage::Complete { return Err(OAuthRefreshCaptureError::NotComplete); }
        let OAuthRefreshCaptureCustody::Complete { store, revision } = std::mem::replace(
            &mut self.custody, OAuthRefreshCaptureCustody::Stopped { store: None, credentials: None },
        ) else { return Err(OAuthRefreshCaptureError::NotComplete); };
        Ok((store, revision))
    }

    /// Requests local cancellation, not issuer revocation or durable logout.
    /// A running provider may finish a transaction; retain its task to observe it.
    pub fn cancel(&self) { self.cancellation.cancel(); self.cancel_worker(); }

    fn cancel_worker(&self) {
        match &self.custody {
            OAuthRefreshCaptureCustody::Checking(task) => { let _ = task.request_cancel(); }
            OAuthRefreshCaptureCustody::Storing(task) => { let _ = task.request_cancel(); }
            _ => {},
        }
    }
}

impl<A, P> OAuthRefreshCapture<A, P>
where A: CredentialCommitAnchor + 'static, P: OAuthGrantProtector + 'static,
{
    /// Stops on the first refusal. No provider/transaction failure is retried.
    pub async fn run(&mut self, observer: &Cx) -> Result<(), OAuthRefreshCaptureError> {
        loop {
            if self.advance(observer).await? == OAuthRefreshCaptureStage::Complete { return Ok(()); }
        }
    }

    pub async fn advance(&mut self, observer: &Cx) -> Result<OAuthRefreshCaptureStage, OAuthRefreshCaptureError> {
        let origin = self.origin.clone();
        let cancellation = self.cancellation.clone();
        let session = self.session.clone();
        let deadline = self.deadline;
        let observer_deadline = observer.now().saturating_add_nanos(
            deadline.as_nanos().saturating_sub(origin.now().as_nanos()),
        );
        let result = {
            let work = async {
                let mut step = std::pin::pin!(self.advance_inner(&origin));
                let mut cancelled = std::pin::pin!(cancellation.cancelled());
                poll_fn(|task| {
                    if cancelled.as_mut().poll(task).is_ready() {
                        return Poll::Ready(Err(OAuthRefreshCaptureError::Context(OAuthError::Cancelled)));
                    }
                    let result = step.as_mut().poll(task);
                    if cancellation.is_cancel_requested() {
                        Poll::Ready(Err(OAuthRefreshCaptureError::Context(OAuthError::Cancelled)))
                    } else { result }
                }).await
            };
            within(observer, observer_deadline, async {
                Ok(within(&origin, deadline, async {
                    Ok(session.run_while_open(work).await)
                }).await)
            }).await
                .map_err(OAuthRefreshCaptureError::Context)
                .and_then(|r| r.map_err(OAuthRefreshCaptureError::Context))
                .and_then(|r| r.map_err(OAuthRefreshCaptureError::Session))
                .and_then(|r| r)
        };
        if cancellation.is_cancel_requested() || origin.is_cancel_requested() || origin.now() >= deadline
            || matches!(&result, Err(OAuthRefreshCaptureError::Session(OAuthSessionError::Closed)))
        {
            self.cancel_worker();
        }
        result
    }

    async fn advance_inner(&mut self, cx: &Cx) -> Result<OAuthRefreshCaptureStage, OAuthRefreshCaptureError> {
        use OAuthRefreshCaptureCustody as C;
        match &mut self.custody {
            C::Checking(task) => {
                let completion = match task.wait(cx).await {
                    Ok(completion) => completion,
                    Err(error) => {
                        if terminal_completion(error) { self.custody = C::Stopped { store: None, credentials: None }; }
                        return Err(OAuthRefreshCaptureError::Completion(error));
                    }
                };
                let (store, outcome) = completion.into_parts();
                match outcome {
                    Ok(()) => self.custody = C::ReadyToTransfer(store),
                    Err(error) => {
                        self.custody = C::Stopped { store: Some(store), credentials: None };
                        return Err(OAuthRefreshCaptureError::Storage(error));
                    }
                }
                return Ok(self.stage());
            }
            C::Storing(task) => {
                let completion = match task.wait(cx).await {
                    Ok(completion) => completion,
                    Err(error) => {
                        if terminal_completion(error) { self.custody = C::Stopped { store: None, credentials: None }; }
                        return Err(OAuthRefreshCaptureError::Completion(error));
                    }
                };
                let (store, (credentials, outcome)) = completion.into_parts();
                match outcome {
                    Ok(revision) => {
                        // Only refresh custody was persisted; release the extra
                        // access handle without revoking the source's token.
                        drop(credentials);
                        self.custody = C::Complete { store, revision };
                    }
                    Err(error) => {
                        self.custody = C::Stopped { store: Some(store), credentials: Some(credentials) };
                        return Err(OAuthRefreshCaptureError::Storage(error));
                    }
                }
                return Ok(self.stage());
            }
            C::ReadyToTransfer(_) => {
                // The store remains HERE during the lock wait. A dropped wait
                // cannot lose it or extract credentials. Use cloned context and
                // client handles so final custody movement borrows no self field.
                let session = self.session.clone();
                let cancellation = self.cancellation.clone();
                let client = self.client.clone();
                let reservation = session.reserve_refresh_transfer(
                    cx, &cancellation, self.expected_generation, &client,
                ).await.map_err(OAuthRefreshCaptureError::Transfer)?;
                let credentials = reservation.commit().map_err(OAuthRefreshCaptureError::Transfer)?;
                // No await or fallible work after transfer and before retaining
                // the sole refresh owner. Later guard refusal keeps this custody.
                let C::ReadyToTransfer(store) = std::mem::replace(
                    &mut self.custody, C::Stopped { store: None, credentials: None },
                ) else { unreachable!("exclusive capture changed during synchronous transfer"); };
                self.custody = C::ReadyToStore { store, credentials };
                return Ok(self.stage());
            }
            _ => {},
        }
        let previous = std::mem::replace(&mut self.custody, C::Stopped { store: None, credentials: None });
        match previous {
            C::ReadyToCheck(store) => {
                let authorization = self.authorization;
                let expected = self.expected_revision;
                match store.try_operate(cx, (), move |store, worker, ()| {
                    if store.revision() != expected { return Err(OAuthRefreshStoreError::RevisionMismatch); }
                    // Fresh partition/anchor/file admission BEFORE taking any
                    // refresh credential from the live session. No decryption.
                    drop(store.slot.load(worker, &authorization)?);
                    Ok(())
                }) {
                    Ok(task) => self.custody = C::Checking(task),
                    Err(failure) => {
                        let (cause, retained) = failure.into_parts();
                        if let Some((store, ())) = retained { self.custody = C::ReadyToCheck(store); }
                        return Err(OAuthRefreshCaptureError::Submission(cause));
                    }
                }
            }
            C::ReadyToStore { store, credentials } => {
                match store.try_store_refresh(cx, self.authorization, self.expected_revision, credentials) {
                    Ok(task) => self.custody = C::Storing(task),
                    Err(failure) => {
                        let (cause, retained) = failure.into_parts();
                        if let Some((store, credentials)) = retained { self.custody = C::ReadyToStore { store, credentials }; }
                        return Err(OAuthRefreshCaptureError::Submission(cause));
                    }
                }
            }
            other => {
                self.custody = other;
                if self.stage() != OAuthRefreshCaptureStage::Complete { return Err(OAuthRefreshCaptureError::Stopped); }
            }
        }
        Ok(self.stage())
    }
}

fn terminal_completion(error: CredentialIoError) -> bool {
    matches!(error, CredentialIoError::WorkerStopped | CredentialIoError::WorkerPanicked
        | CredentialIoError::AlreadyReceived | CredentialIoError::ProcessChanged)
}

impl OAuthCredentials {
    // Only the managed grant-lock transfer uses this. Allocation and validation
    // precede taking the token. Access is already clonable, but refresh is MOVED.
    // Neither the original nor the copy gets a new access lifetime or scopes.
    pub(crate) fn take_persistence_credentials(&mut self, owner: &McpRequestCancellation) -> Result<Self, OAuthError> {
        let token = self.refresh_token.as_deref().ok_or(OAuthError::RefreshUnavailable)?;
        super::super::validate_refresh(token, &self.scopes, &self.configuration)
            .map_err(|_| OAuthError::InvalidTokenResponse)?;
        let configuration = self.configuration.clone();
        // Do not let cleanup custody become a way to escape source-session
        // closure. Refresh persistence is independent; access remains bound
        // to the same local owner as every already-issued snapshot.
        let access = self.access.for_owner(owner).ok_or(OAuthError::CredentialBindingMismatch)?;
        let scopes = self.scopes.clone();
        Ok(Self { configuration, access, scopes, expires_at: self.expires_at,
            refresh_token: self.refresh_token.take() })
    }
}

#[cfg(test)]
mod tests;
