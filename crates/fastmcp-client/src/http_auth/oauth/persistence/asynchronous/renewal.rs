//! One owned persistent renewal: consume -> issuer exchange -> persist -> deliver.
//!
//! This joins the native OAuth driver to the existing bounded storage lane. A
//! stored access token is never reconstructed. The old refresh grant is durably
//! consumed before the single issuer exchange, and the replacement is durably
//! stored before completion. No failure automatically repeats an exchange.

/// Install a completed persistent renewal into an existing shared access owner.
pub mod installation;

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
    OAuthGrantProtector, OAuthRefreshGrant, OAuthRefreshStoreError,
    OAuthRefreshSubmissionFailure, OAuthRefreshTake, OAuthRefreshWrite,
    PartitionAuthorization, SlotRevision,
};
use crate::http_auth::oauth::{OAuthError, operation_deadline, within};
use crate::http_auth::managed::{ManagedOAuthSession, OAuthSessionError, OAuthSessionPolicy};

/// Non-secret progress. ReadyToPersist never means the replacement is durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthRefreshRenewalStage {
    ReadyToTake,
    Taking,
    ReadyToExchange,
    ReadyToPersist,
    Persisting,
    Complete,
    Stopped,
}

/// Exact ownership after stopping observation. No variant clones a grant or
/// reconstructs an operation. Pending tasks may be awaited under a new observer
/// to learn the SAME transaction's disposition, even after this run expires.
///
/// A stopped exchange has no grant to retry. A stopped storage operation may
/// retain credentials; inspect their refresh ownership and the storage error,
/// never infer non-dispatch from their presence. Explicit close/drop of returned
/// stores and pending tasks retains the storage lane's ordinary cleanup rules.
pub enum OAuthRefreshRenewalCustody<A, P> {
    ReadyToTake(AsyncOAuthRefreshStore<A, P>),
    Taking(CredentialSlotTask<OAuthRefreshTake<A, P>>),
    ReadyToExchange { store: AsyncOAuthRefreshStore<A, P>, grant: OAuthRefreshGrant },
    ReadyToPersist { store: AsyncOAuthRefreshStore<A, P>, credentials: OAuthCredentials },
    Persisting(CredentialSlotTask<OAuthRefreshWrite<A, P>>),
    Complete { store: AsyncOAuthRefreshStore<A, P>, credentials: OAuthCredentials, revision: SlotRevision },
    Stopped { store: Option<AsyncOAuthRefreshStore<A, P>>, credentials: Option<OAuthCredentials> },
}

#[derive(Debug)]
pub enum OAuthRefreshRenewalError {
    Context(OAuthError),
    Submission(AsyncOAuthRefreshError),
    Completion(CredentialIoError),
    Storage(OAuthRefreshStoreError),
    Session(OAuthSessionError),
    NoStoredGrant,
    NotComplete,
    Stopped,
}
impl fmt::Display for OAuthRefreshRenewalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Context(error) => error.fmt(f),
            Self::Submission(error) => error.fmt(f),
            Self::Completion(error) => error.fmt(f),
            Self::Storage(error) => error.fmt(f),
            Self::Session(error) => error.fmt(f),
            Self::NoStoredGrant => f.write_str("no stored OAuth refresh grant; explicit login required"),
            Self::NotComplete => f.write_str("persistent OAuth renewal is not complete"),
            Self::Stopped => f.write_str("persistent OAuth renewal stopped; no exchange retry is authorized"),
        }
    }
}
impl std::error::Error for OAuthRefreshRenewalError {}

/// A caller-driven transaction owner, not a background task or protocol session.
/// The original caller, cancellation domain and absolute deadline remain fixed
/// across pauses and observers. An observer may impose a shorter deadline.
///
/// Dropping an advance/run FUTURE during storage leaves its completion mailbox
/// here; observation can resume without another transaction. Dropping it during
/// the issuer exchange permanently stops the run: the issuer may have rotated
/// the old token. Admission refusal before a storage job starts retains the
/// original input and can be explicitly attempted again, without re-exchanging.
/// Other failures stop the run and require inspecting `into_custody`.
///
/// Synchronous providers must still bound/cooperate with their supplied worker
/// Cx. Cancellation cannot preempt a running syscall/provider call. An unpolled
/// owner does not run timers; dropping its pending task requests cancellation.
/// The host remains responsible for qualified persistent protection and anchor
/// services. File reopen is not a claim of process-crash or rollback protection.
pub struct OAuthRefreshRenewal<A, P> {
    origin: Cx,
    cancellation: McpRequestCancellation,
    deadline: Time,
    client: OAuthClient,
    authorization: PartitionAuthorization,
    custody: OAuthRefreshRenewalCustody<A, P>,
}

impl<A, P> AsyncOAuthRefreshStore<A, P>
where A: CredentialCommitAnchor + 'static, P: OAuthGrantProtector + 'static,
{
    /// Prepares persistent renewal without file, provider or network effects.
    /// Reject a different issuer/client/resource/trust configuration BEFORE
    /// consuming its stored lineage. Failure returns the original store owner.
    /// Timeout covers the entire run, including pauses, and is at most 5 minutes.
    pub fn begin_renewal(
        self, cx: &Cx, client: &OAuthClient, authorization: PartitionAuthorization,
        cancellation: &McpRequestCancellation, timeout: Duration,
    ) -> Result<OAuthRefreshRenewal<A, P>, OAuthRefreshSubmissionFailure<A, P, ()>> {
        let admitted = (|| {
            if timeout.is_zero() || timeout > Duration::from_secs(300) {
                return Err(AsyncOAuthRefreshError::Io(CredentialIoError::InvalidLimits));
            }
            if self.store.configuration != client.configuration {
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
        Ok(OAuthRefreshRenewal {
            origin: cx.clone(), cancellation: cancellation.clone(), deadline,
            client: client.clone(), authorization,
            custody: OAuthRefreshRenewalCustody::ReadyToTake(self),
        })
    }
}

impl<A, P> OAuthRefreshRenewal<A, P> {
    pub fn stage(&self) -> OAuthRefreshRenewalStage {
        use OAuthRefreshRenewalCustody as C;
        use OAuthRefreshRenewalStage as S;
        match &self.custody {
            C::ReadyToTake(_) => S::ReadyToTake,
            C::Taking(_) => S::Taking,
            C::ReadyToExchange { .. } => S::ReadyToExchange,
            C::ReadyToPersist { .. } => S::ReadyToPersist,
            C::Persisting(_) => S::Persisting,
            C::Complete { .. } => S::Complete,
            C::Stopped { .. } => S::Stopped,
        }
    }

    /// Transfers, never duplicates, current custody for completion or cleanup.
    /// Only Complete establishes successful persistence of the replacement.
    /// Returned access credentials retain their ORIGINAL issuer-admitted expiry
    /// and no in-memory refresh token. They can authorize native HTTP requests;
    /// renewing them later requires another explicit persistent renewal.
    pub fn into_custody(self) -> OAuthRefreshRenewalCustody<A, P> { self.custody }

    /// Hands a completed renewal to the ordinary managed client exactly once.
    /// The returned store retains the persistent refresh lineage; the session
    /// owns access only and will not silently switch to in-memory renewal.
    /// Session generation starts at one and is NOT the persisted file revision.
    /// A premature/cancelled call preserves custody. If native session admission
    /// fails after extraction, the store remains in Stopped for explicit cleanup.
    pub fn take_managed_session(
        &mut self, observer: &Cx, policy: OAuthSessionPolicy,
    ) -> Result<(ManagedOAuthSession, AsyncOAuthRefreshStore<A, P>, SlotRevision), OAuthRefreshRenewalError> {
        if self.cancellation.is_cancel_requested() || self.origin.checkpoint().is_err() || observer.checkpoint().is_err() {
            return Err(OAuthRefreshRenewalError::Context(OAuthError::Cancelled));
        }
        if self.origin.now() >= self.deadline || observer.budget().deadline.is_some_and(|deadline| observer.now() >= deadline) {
            return Err(OAuthRefreshRenewalError::Context(OAuthError::TimedOut));
        }
        if self.stage() != OAuthRefreshRenewalStage::Complete { return Err(OAuthRefreshRenewalError::NotComplete); }
        let OAuthRefreshRenewalCustody::Complete { store, credentials, revision } = std::mem::replace(
            &mut self.custody, OAuthRefreshRenewalCustody::Stopped { store: None, credentials: None },
        ) else { return Err(OAuthRefreshRenewalError::NotComplete); };
        match ManagedOAuthSession::from_credentials(observer, self.client.clone(), policy, credentials) {
            Ok(session) => Ok((session, store, revision)),
            Err(error) => {
                self.custody = OAuthRefreshRenewalCustody::Stopped { store: Some(store), credentials: None };
                Err(OAuthRefreshRenewalError::Session(error))
            }
        }
    }

    /// Cancels this run and requests cancellation of its current storage worker.
    /// It neither revokes issuer tokens nor invalidates stored custody. Keep the
    /// task via into_custody to observe a potentially committed transaction.
    pub fn cancel(&self) {
        self.cancellation.cancel();
        self.cancel_worker();
    }

    fn cancel_worker(&self) {
        match &self.custody {
            OAuthRefreshRenewalCustody::Taking(task) => { let _ = task.request_cancel(); }
            OAuthRefreshRenewalCustody::Persisting(task) => { let _ = task.request_cancel(); }
            _ => {},
        }
    }
}

impl<A, P> OAuthRefreshRenewal<A, P>
where A: CredentialCommitAnchor + 'static, P: OAuthGrantProtector + 'static,
{
    /// Drives until persistence completes, or returns the first error. It never
    /// retries a refused submission, token exchange or storage transaction.
    /// After admission refusal only, a later explicit call may retry admission.
    pub async fn run(&mut self, observer: &Cx) -> Result<(), OAuthRefreshRenewalError> {
        loop {
            if self.advance(observer).await? == OAuthRefreshRenewalStage::Complete { return Ok(()); }
        }
    }

    /// Advances one boundary, retaining a pending storage task across cancelled
    /// or abandoned waits. No result is released merely because a timer fired.
    pub async fn advance(&mut self, observer: &Cx) -> Result<OAuthRefreshRenewalStage, OAuthRefreshRenewalError> {
        let origin = self.origin.clone();
        let cancellation = self.cancellation.clone();
        let deadline = self.deadline;
        // A fresh observer can have a different runtime clock origin. Only
        // the original clock defines the operation end; translate its remaining
        // duration for the observer, while still guarding the original deadline.
        let observer_deadline = observer.now().saturating_add_nanos(
            deadline.as_nanos().saturating_sub(origin.now().as_nanos()),
        );
        let result = {
            let work = async {
                let mut step = std::pin::pin!(self.advance_inner(&origin));
                let mut cancelled = std::pin::pin!(cancellation.cancelled());
                poll_fn(|task| {
                    if cancelled.as_mut().poll(task).is_ready() {
                        return Poll::Ready(Err(OAuthRefreshRenewalError::Context(OAuthError::Cancelled)));
                    }
                    let result = step.as_mut().poll(task);
                    if cancellation.is_cancel_requested() {
                        Poll::Ready(Err(OAuthRefreshRenewalError::Context(OAuthError::Cancelled)))
                    } else { result }
                }).await
            };
            // Both contexts register cancellation wakes; changing an observer
            // never replaces the original operation's lifetime or authority.
            within(observer, observer_deadline, async {
                Ok(within(&origin, deadline, async { Ok(work.await) }).await)
            }).await
                .map_err(OAuthRefreshRenewalError::Context)
                .and_then(|result| result.map_err(OAuthRefreshRenewalError::Context))
                .and_then(|result| result)
        };
        if cancellation.is_cancel_requested() || origin.is_cancel_requested() || origin.now() >= deadline {
            self.cancel_worker();
        }
        result
    }

    async fn advance_inner(&mut self, cx: &Cx) -> Result<OAuthRefreshRenewalStage, OAuthRefreshRenewalError> {
        use OAuthRefreshRenewalCustody as C;
        match &mut self.custody {
            C::Taking(task) => {
                let completion = match task.wait(cx).await {
                    Ok(completion) => completion,
                    Err(error) => {
                        if terminal_completion(error) {
                            self.custody = C::Stopped { store: None, credentials: None };
                        }
                        return Err(OAuthRefreshRenewalError::Completion(error));
                    }
                };
                let (store, outcome) = completion.into_parts();
                match outcome {
                    Ok(Some(grant)) => self.custody = C::ReadyToExchange { store, grant },
                    Ok(None) => {
                        self.custody = C::Stopped { store: Some(store), credentials: None };
                        return Err(OAuthRefreshRenewalError::NoStoredGrant);
                    }
                    Err(error) => {
                        self.custody = C::Stopped { store: Some(store), credentials: None };
                        return Err(OAuthRefreshRenewalError::Storage(error));
                    }
                }
                return Ok(self.stage());
            }
            C::Persisting(task) => {
                let completion = match task.wait(cx).await {
                    Ok(completion) => completion,
                    Err(error) => {
                        if terminal_completion(error) {
                            self.custody = C::Stopped { store: None, credentials: None };
                        }
                        return Err(OAuthRefreshRenewalError::Completion(error));
                    }
                };
                let (store, (credentials, outcome)) = completion.into_parts();
                match outcome {
                    Ok(revision) => self.custody = C::Complete { store, credentials, revision },
                    Err(error) => {
                        self.custody = C::Stopped { store: Some(store), credentials: Some(credentials) };
                        return Err(OAuthRefreshRenewalError::Storage(error));
                    }
                }
                return Ok(self.stage());
            }
            _ => {},
        }
        let previous = std::mem::replace(&mut self.custody, C::Stopped { store: None, credentials: None });
        match previous {
            C::ReadyToTake(store) => match store.try_take_refresh(cx, self.authorization) {
                Ok(task) => self.custody = C::Taking(task),
                Err(failure) => {
                    let (cause, retained) = failure.into_parts();
                    if let Some((store, ())) = retained { self.custody = C::ReadyToTake(store); }
                    return Err(OAuthRefreshRenewalError::Submission(cause));
                }
            },
            C::ReadyToExchange { store, grant } => {
                // Commit this election before the first possible network poll.
                // Dropping or failing the exchange cannot restore its grant.
                self.custody = C::Stopped { store: Some(store), credentials: None };
                let credentials = self.client.refresh_grant(cx, grant).await.map_err(OAuthRefreshRenewalError::Context)?;
                let C::Stopped { store: Some(store), .. } = std::mem::replace(
                    &mut self.custody, C::Stopped { store: None, credentials: None },
                ) else { return Err(OAuthRefreshRenewalError::Stopped); };
                self.custody = C::ReadyToPersist { store, credentials };
            }
            C::ReadyToPersist { store, credentials } => {
                let expected = store.revision();
                match store.try_store_refresh(cx, self.authorization, expected, credentials) {
                    Ok(task) => self.custody = C::Persisting(task),
                    Err(failure) => {
                        let (cause, retained) = failure.into_parts();
                        if let Some((store, credentials)) = retained {
                            self.custody = C::ReadyToPersist { store, credentials };
                        }
                        return Err(OAuthRefreshRenewalError::Submission(cause));
                    }
                }
            }
            other => {
                self.custody = other;
                if self.stage() != OAuthRefreshRenewalStage::Complete { return Err(OAuthRefreshRenewalError::Stopped); }
            }
        }
        Ok(self.stage())
    }
}

fn terminal_completion(error: CredentialIoError) -> bool {
    matches!(error, CredentialIoError::WorkerStopped | CredentialIoError::WorkerPanicked | CredentialIoError::AlreadyReceived)
}

#[cfg(test)]
mod tests;
