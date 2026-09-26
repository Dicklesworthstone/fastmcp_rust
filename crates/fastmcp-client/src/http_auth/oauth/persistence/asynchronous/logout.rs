//! Persistent refresh-grant retirement using the native revocation transport.
//!
//! A refresh grant is not an access credential. Revoking it must not first
//! renew it, invent an access token, or reconstruct an old access lifetime.
//! Revocation and local durable removal are distinct outcomes.

use std::fmt;
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;

use super::{
    AsyncOAuthRefreshError, AsyncOAuthRefreshStore, CredentialCommitAnchor,
    CredentialIoError, CredentialSlotTask, OAuthClient, OAuthGrantProtector,
    OAuthRefreshCompletion, OAuthRefreshGrant, OAuthRefreshStoreError,
    OAuthRefreshSubmissionFailure, PartitionAuthorization, SlotRevision,
};
use crate::http_auth::managed::ManagedOAuthSession;
use crate::http_auth::oauth::{OAuthError, operation_deadline, within};
use crate::http_auth::oauth::revocation::{
    OAuthRevocationError, OAuthTokenRevocationOutcome, REVOCATION_TIMEOUT, map_preflight,
};

impl OAuthClient {
    /// Consumes an exclusively owned refresh grant and attempts its revocation
    /// once, without acquiring or sending an access token. The complete native
    /// client configuration must match, including resource, issuer, registration,
    /// scope ceiling and explicitly configured trust and revocation endpoint.
    ///
    /// This consumes the grant even on preflight refusal or future abandonment.
    /// After dispatch a lost reply is Uncertain, not authorization to recreate
    /// the grant or send it again. No redirects, cookies, proxy or retries are
    /// enabled; request encoding, response bounds and TLS are the same path used
    /// by `revoke_credentials`. The endpoint's HTTP 200 is an acknowledgement,
    /// not proof that the token was previously valid or that all related access
    /// tokens have been revoked. No access-token revocation is attempted here.
    ///
    /// Take persistent custody before calling this method. It does not itself
    /// access storage or close previously created managed sessions; the caller
    /// must retire those owners separately. Already-delivered credentials and
    /// already-sent network bytes cannot be recalled.
    pub async fn revoke_refresh_grant(
        &self,
        cx: &Cx,
        grant: OAuthRefreshGrant,
    ) -> Result<OAuthTokenRevocationOutcome, OAuthRevocationError> {
        if grant.configuration != self.configuration {
            return Err(OAuthRevocationError::CredentialBindingMismatch);
        }
        let endpoint = self.configuration.revocation_endpoint.as_ref()
            .ok_or(OAuthRevocationError::EndpointUnavailable)?;
        let deadline = operation_deadline(cx, REVOCATION_TIMEOUT).map_err(map_preflight)?;
        Ok(self.revoke_one(cx, deadline, endpoint, &grant.refresh_token, "refresh_token").await)
    }
}

/// The issuer half of persistent logout. No variant implies access-token
/// revocation, even when the refresh-token request received HTTP 200.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthPersistentRevocation {
    NotAttempted,
    NoStoredGrant,
    EndpointUnavailable,
    /// Local invalidation succeeded, but the protected grant could not be read.
    GrantUnavailable,
    /// A request may have been sent; interrupted observation cannot repeat it.
    Uncertain,
    Outcome(OAuthTokenRevocationOutcome),
    PreflightRefused(OAuthRevocationError),
}

/// Independent facts, not an all-or-nothing logout success flag. A locally
/// closed session can coexist with failed/unresolved durable retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OAuthRefreshLogoutReport {
    local_session_closed: bool,
    retired_revision: Option<SlotRevision>,
    remote: OAuthPersistentRevocation,
}
impl OAuthRefreshLogoutReport {
    pub fn local_session_closed(&self) -> bool { self.local_session_closed }
    /// Some only after the coordinator proved a settled tombstone. It remains
    /// known after remote failure or cancellation; no new revision is invented.
    pub fn retired_revision(&self) -> Option<SlotRevision> { self.retired_revision }
    pub fn remote(&self) -> OAuthPersistentRevocation { self.remote }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthRefreshLogoutStage { ReadyToRetire, Retiring, ReadyToRevoke, Complete, Stopped }

/// One completed local retirement. The grant, when present, has ALREADY left
/// persistent custody. Explicit extraction transfers it, never reconstructs it.
/// No Clone, Debug or serialization can duplicate or log the handoff.
pub struct OAuthRefreshRetirement {
    revision: SlotRevision,
    grant: Option<OAuthRefreshGrant>,
    remote: OAuthPersistentRevocation,
}
impl OAuthRefreshRetirement {
    pub fn into_parts(self) -> (SlotRevision, Option<OAuthRefreshGrant>, OAuthPersistentRevocation) {
        (self.revision, self.grant, self.remote)
    }
}
pub type OAuthRefreshRetirementCompletion<A, P> = OAuthRefreshCompletion<
    A, P, Result<OAuthRefreshRetirement, OAuthRefreshStoreError>,
>;

/// Actual ownership on interrupted observation, usable for explicit cleanup.
/// Pending storage completion may be observed with another live Cx to learn
/// its disposition. No stopped network attempt retains a token to resubmit.
pub enum OAuthRefreshLogoutCustody<A, P> {
    ReadyToRetire(AsyncOAuthRefreshStore<A, P>),
    Retiring(CredentialSlotTask<OAuthRefreshRetirementCompletion<A, P>>),
    // The grant is boxed so this variant is no larger than the store-only
    // ones (bd-19tqe); its secret already lives in a heap String.
    ReadyToRevoke { store: AsyncOAuthRefreshStore<A, P>, grant: Box<OAuthRefreshGrant> },
    Complete(AsyncOAuthRefreshStore<A, P>),
    Stopped(Option<AsyncOAuthRefreshStore<A, P>>),
}

#[derive(Debug)]
pub enum OAuthRefreshLogoutError {
    Context(OAuthError),
    Submission(AsyncOAuthRefreshError),
    Completion(CredentialIoError),
    Storage(OAuthRefreshStoreError),
    Stopped,
}
impl fmt::Display for OAuthRefreshLogoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Context(error) => error.fmt(f),
            Self::Submission(error) => error.fmt(f),
            Self::Completion(error) => error.fmt(f),
            Self::Storage(error) => error.fmt(f),
            Self::Stopped => f.write_str("persistent OAuth logout stopped; inspect retained custody and report"),
        }
    }
}
impl std::error::Error for OAuthRefreshLogoutError {}

/// Explicit local-first logout for one stored renewal lineage. The supplied
/// managed session is closed synchronously at successful preparation, before
/// any blocking-provider or issuer wait. This does not revoke unrelated
/// sessions or already-delivered headers; the host must supply the session
/// associated with this store. Resource equality is NOT principal equivalence.
///
/// Retirement uses ONE existing bounded blocking job: authenticate custody,
/// decrypt if remote revocation is configured, durably tombstone, then return
/// the exact result through the existing cancellation-safe mailbox. When no
/// endpoint is configured, no decryption is necessary. A protection/encoding
/// refusal can still be locally invalidated by its authorized owner; uncertain
/// storage or anchor errors never trigger a second mutation automatically.
///
/// The caller drives progress. Pauses count against the original deadline.
/// Abandoning a storage wait leaves its mailbox here; abandoning an issuer
/// wait stops the run without restoring its token. This is not restart-safe
/// remote revocation: a crash after tombstoning can lose the revocation handoff.
/// Production protection/anchor requirements and shutdown admission still apply.
#[must_use = "drive logout and inspect both local retirement and remote outcomes"]
pub struct OAuthRefreshLogout<A, P> {
    origin: Cx,
    cancellation: McpRequestCancellation,
    deadline: Time,
    client: OAuthClient,
    authorization: PartitionAuthorization,
    report: OAuthRefreshLogoutReport,
    custody: OAuthRefreshLogoutCustody<A, P>,
}

impl<A, P> AsyncOAuthRefreshStore<A, P>
where A: CredentialCommitAnchor + 'static, P: OAuthGrantProtector + 'static,
{
    /// Prepares one logout with no storage or network effects. Configuration,
    /// timeout and caller admission precede optional session closure; refusal
    /// returns the original store and leaves the supplied session unchanged.
    /// A missing revocation endpoint does NOT prevent durable local logout.
    ///
    /// `session` is an explicit host-selected local owner, not one inferred
    /// from a stored token. It must name the same resource. Its closure is
    /// irreversible even if later partition authorization/storage fails. Other
    /// sessions and issuer-side access tokens are outside this operation.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_logout(
        self, cx: &Cx, client: &OAuthClient, authorization: PartitionAuthorization,
        session: Option<&ManagedOAuthSession>, cancellation: &McpRequestCancellation,
        timeout: Duration,
    ) -> Result<OAuthRefreshLogout<A, P>, OAuthRefreshSubmissionFailure<A, P, ()>> {
        let admitted = (|| {
            if timeout.is_zero() || timeout > Duration::from_secs(300) {
                return Err(AsyncOAuthRefreshError::Io(CredentialIoError::InvalidLimits));
            }
            if self.store.configuration != client.configuration
                || session.is_some_and(|session| session.resource() != &client.configuration.resource)
            {
                return Err(AsyncOAuthRefreshError::Store(OAuthRefreshStoreError::ConfigurationMismatch));
            }
            if cancellation.is_cancel_requested() {
                return Err(AsyncOAuthRefreshError::Store(OAuthRefreshStoreError::ContextStopped));
            }
            operation_deadline(cx, timeout)
                .map_err(|_| AsyncOAuthRefreshError::Store(OAuthRefreshStoreError::ContextStopped))
        })();
        let deadline = match admitted {
            Ok(deadline) => deadline,
            Err(cause) => return Err(OAuthRefreshSubmissionFailure { cause, retained: Some(Box::new((self, ()))) }),
        };
        if let Some(session) = session { session.close(); }
        Ok(OAuthRefreshLogout {
            origin: cx.clone(), cancellation: cancellation.clone(), deadline,
            client: client.clone(), authorization,
            report: OAuthRefreshLogoutReport { local_session_closed: session.is_some(),
                retired_revision: None, remote: OAuthPersistentRevocation::NotAttempted },
            custody: OAuthRefreshLogoutCustody::ReadyToRetire(self),
        })
    }
}

impl<A, P> OAuthRefreshLogout<A, P> {
    pub fn report(&self) -> OAuthRefreshLogoutReport { self.report }

    pub fn stage(&self) -> OAuthRefreshLogoutStage {
        use OAuthRefreshLogoutCustody as C;
        match &self.custody {
            C::ReadyToRetire(_) => OAuthRefreshLogoutStage::ReadyToRetire,
            C::Retiring(_) => OAuthRefreshLogoutStage::Retiring,
            C::ReadyToRevoke { .. } => OAuthRefreshLogoutStage::ReadyToRevoke,
            C::Complete(_) => OAuthRefreshLogoutStage::Complete,
            C::Stopped(_) => OAuthRefreshLogoutStage::Stopped,
        }
    }

    /// Keep a pending task to observe its SAME transaction, then close its
    /// returned store through the lane's cleanup path. A stopped revocation has
    /// no token handoff. A ReadyToRevoke handoff has not entered network I/O.
    pub fn into_custody(self) -> (OAuthRefreshLogoutReport, OAuthRefreshLogoutCustody<A, P>) {
        (self.report, self.custody)
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
        self.cancel_worker();
    }

    fn cancel_worker(&self) {
        if let OAuthRefreshLogoutCustody::Retiring(task) = &self.custody {
            let _ = task.request_cancel();
        }
    }
}

impl<A, P> OAuthRefreshLogout<A, P>
where A: CredentialCommitAnchor + 'static, P: OAuthGrantProtector + 'static,
{
    /// No automatic submission or issuer retry. A completed remote refusal is
    /// returned in the report, not disguised as reversal of local retirement.
    pub async fn run(&mut self, observer: &Cx) -> Result<OAuthRefreshLogoutReport, OAuthRefreshLogoutError> {
        loop {
            if self.advance(observer).await? == OAuthRefreshLogoutStage::Complete {
                return Ok(self.report);
            }
        }
    }

    /// Advances one boundary. Cancelling an observer does not replace the
    /// original operation's cancellation/deadline or resubmit a pending job.
    pub async fn advance(&mut self, observer: &Cx) -> Result<OAuthRefreshLogoutStage, OAuthRefreshLogoutError> {
        let origin = self.origin.clone();
        let cancellation = self.cancellation.clone();
        let deadline = self.deadline;
        let observer_deadline = observer.now().saturating_add_nanos(
            deadline.as_nanos().saturating_sub(origin.now().as_nanos()),
        );
        let result = {
            let work = async {
                // Boxed at its source (bd-19tqe): the logout step holds the
                // network revocation and would push every caller past 16 KiB.
                let mut step = Box::pin(self.advance_inner(&origin));
                let mut cancelled = std::pin::pin!(cancellation.cancelled());
                poll_fn(|task| {
                    if cancelled.as_mut().poll(task).is_ready() {
                        return Poll::Ready(Err(OAuthRefreshLogoutError::Context(OAuthError::Cancelled)));
                    }
                    let result = step.as_mut().poll(task);
                    if cancellation.is_cancel_requested() {
                        Poll::Ready(Err(OAuthRefreshLogoutError::Context(OAuthError::Cancelled)))
                    } else { result }
                }).await
            };
            within(observer, observer_deadline, async {
                Ok(within(&origin, deadline, async { Ok(work.await) }).await)
            }).await.map_err(OAuthRefreshLogoutError::Context)
                .and_then(|result| result.map_err(OAuthRefreshLogoutError::Context))
                .and_then(|result| result)
        };
        if cancellation.is_cancel_requested() || origin.is_cancel_requested() || origin.now() >= deadline {
            self.cancel_worker();
        }
        result
    }

    async fn advance_inner(&mut self, cx: &Cx) -> Result<OAuthRefreshLogoutStage, OAuthRefreshLogoutError> {
        use OAuthRefreshLogoutCustody as C;
        if let C::Retiring(task) = &mut self.custody {
            let completion = match task.wait(cx).await {
                Ok(completion) => completion,
                Err(error) => {
                    if matches!(error, CredentialIoError::WorkerStopped | CredentialIoError::WorkerPanicked
                        | CredentialIoError::AlreadyReceived | CredentialIoError::ProcessChanged)
                    { self.custody = C::Stopped(None); }
                    return Err(OAuthRefreshLogoutError::Completion(error));
                }
            };
            let (store, outcome) = completion.into_parts();
            match outcome {
                Ok(retired) => {
                    self.report.retired_revision = Some(retired.revision);
                    self.report.remote = retired.remote;
                    self.custody = match retired.grant {
                        Some(grant) => C::ReadyToRevoke {
                            store,
                            grant: Box::new(grant),
                        },
                        None => C::Complete(store),
                    };
                }
                Err(error) => {
                    // A post-settlement cancellation proves retirement but
                    // withheld the token. Record that fact without fabricating
                    // a remote attempt or erasing the original storage error.
                    if let OAuthRefreshStoreError::Storage(super::CoordinatedSlotError::CommittedWithoutDelivery(revision)) = error {
                        self.report.retired_revision = Some(revision);
                        self.report.remote = OAuthPersistentRevocation::GrantUnavailable;
                    }
                    self.custody = C::Stopped(Some(store));
                    return Err(OAuthRefreshLogoutError::Storage(error));
                }
            }
            return Ok(self.stage());
        }
        let previous = std::mem::replace(&mut self.custody, C::Stopped(None));
        match previous {
            C::ReadyToRetire(store) => {
                let authorization = self.authorization;
                let remote = self.client.configuration.revocation_endpoint.is_some();
                match store.try_operate(cx, (), move |store, worker, ()| retire(store, worker, &authorization, remote)) {
                    Ok(task) => self.custody = C::Retiring(task),
                    Err(failure) => {
                        let (cause, retained) = failure.into_parts();
                        if let Some((store, ())) = retained { self.custody = C::ReadyToRetire(store); }
                        return Err(OAuthRefreshLogoutError::Submission(cause));
                    }
                }
            }
            C::ReadyToRevoke { store, grant } => {
                // Election BEFORE the network future can suspend. Neither a
                // timeout nor dropping this advance can restore the token.
                self.custody = C::Stopped(Some(store));
                self.report.remote = OAuthPersistentRevocation::Uncertain;
                let outcome = self.client.revoke_refresh_grant(cx, *grant).await;
                self.report.remote = match outcome {
                    Ok(outcome) => OAuthPersistentRevocation::Outcome(outcome),
                    Err(error) => OAuthPersistentRevocation::PreflightRefused(error),
                };
                let C::Stopped(Some(store)) = std::mem::replace(&mut self.custody, C::Stopped(None)) else {
                    return Err(OAuthRefreshLogoutError::Stopped);
                };
                self.custody = C::Complete(store);
            }
            complete @ C::Complete(_) => self.custody = complete,
            other => {
                self.custody = other;
                return Err(OAuthRefreshLogoutError::Stopped);
            }
        }
        Ok(self.stage())
    }
}

fn retire<A: CredentialCommitAnchor, P: OAuthGrantProtector>(
    store: &mut super::OAuthRefreshStore<A, P>, cx: &Cx,
    authorization: &PartitionAuthorization, attempt_remote: bool,
) -> Result<OAuthRefreshRetirement, OAuthRefreshStoreError> {
    let remote = if attempt_remote {
        match store.take_refresh(cx, authorization) {
            Ok(Some(grant)) => return Ok(OAuthRefreshRetirement {
                revision: store.revision().ok_or(OAuthRefreshStoreError::InvalidGrant)?,
                grant: Some(grant), remote: OAuthPersistentRevocation::NotAttempted,
            }),
            Ok(None) => OAuthPersistentRevocation::NoStoredGrant,
            // These failures cannot authorize issuer contact. Local logout can
            // still discard an unreadable envelope, through fresh authorized
            // anchor admission. NEVER do this for uncertain storage failures.
            Err(OAuthRefreshStoreError::Protection(_) | OAuthRefreshStoreError::InvalidGrant
                | OAuthRefreshStoreError::TooLarge) => OAuthPersistentRevocation::GrantUnavailable,
            Err(error) => return Err(error),
        }
    } else { OAuthPersistentRevocation::EndpointUnavailable };
    let revision = store.invalidate(cx, authorization)?;
    Ok(OAuthRefreshRetirement { revision, grant: None, remote })
}

#[cfg(test)]
mod grant_tests;

#[cfg(test)]
mod tests;
