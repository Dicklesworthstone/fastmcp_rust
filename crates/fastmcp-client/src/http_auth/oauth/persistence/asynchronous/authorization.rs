//! Initial OAuth login with protected refresh custody before access delivery.
//!
//! The stored partition and exact replacement revision are checked before the
//! browser or hosted redirect driver runs. The existing native code/PKCE flow
//! then produces one grant, whose refresh token is committed through the
//! caller's credential-I/O lane before a managed session can be taken. Access
//! tokens, authorization codes, state and PKCE verifiers are never persisted.

use std::fmt;
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};

use super::{
    AsyncOAuthRefreshError, AsyncOAuthRefreshStore, CredentialCommitAnchor, CredentialIoError,
    CredentialSlotTask, OAuthClient, OAuthCredentials, OAuthGrantProtector, OAuthRefreshCompletion,
    OAuthRefreshStoreError, OAuthRefreshSubmissionFailure, OAuthRefreshWrite,
    PartitionAuthorization, SlotRevision,
};
use crate::http_auth::caller::with_caller;
use crate::http_auth::managed::{ManagedOAuthSession, OAuthSessionError, OAuthSessionPolicy};
use crate::http_auth::oauth::{
    OAuthError, ensure_live, interrupted, operation_deadline, require_native_effects, within,
};

pub type OAuthAuthorizationCheck<A, P> =
    OAuthRefreshCompletion<A, P, Result<(), OAuthRefreshStoreError>>;

/// Non-secret progress. Only Complete proves a successful refresh-store commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthAuthorizationStage {
    ReadyToCheck,
    Checking,
    ReadyToAuthorize,
    ReadyToPersist,
    Persisting,
    Complete,
    Stopped,
}

/// Exclusive recovery/cleanup custody, not an alternative login-success result.
///
/// A pending task can be observed under another live caller to learn the SAME
/// transaction's disposition, including after this operation's deadline. Never
/// reconstruct a grant or repeat a code exchange from an interrupted wait.
/// ReadyToPersist and failed storage may retain uncommitted credentials; only
/// Complete establishes persistence. The managed-session method refuses every
/// other state. An uncertain commit removes in-memory refresh ownership.
pub enum OAuthAuthorizationCustody<A, P> {
    ReadyToCheck(AsyncOAuthRefreshStore<A, P>),
    Checking(CredentialSlotTask<OAuthAuthorizationCheck<A, P>>),
    ReadyToAuthorize(AsyncOAuthRefreshStore<A, P>),
    ReadyToPersist {
        store: AsyncOAuthRefreshStore<A, P>,
        credentials: OAuthCredentials,
    },
    Persisting(CredentialSlotTask<OAuthRefreshWrite<A, P>>),
    Complete {
        store: AsyncOAuthRefreshStore<A, P>,
        credentials: OAuthCredentials,
        revision: SlotRevision,
    },
    Stopped {
        store: Option<AsyncOAuthRefreshStore<A, P>>,
        credentials: Option<OAuthCredentials>,
    },
}

#[derive(Debug)]
pub enum OAuthAuthorizationError {
    Context(OAuthError),
    Authorization(OAuthError),
    Submission(AsyncOAuthRefreshError),
    Completion(CredentialIoError),
    Storage(OAuthRefreshStoreError),
    Session(OAuthSessionError),
    NotComplete,
    Stopped,
}

impl fmt::Display for OAuthAuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Context(error) | Self::Authorization(error) => error.fmt(f),
            Self::Submission(error) => error.fmt(f),
            Self::Completion(error) => error.fmt(f),
            Self::Storage(error) => error.fmt(f),
            Self::Session(error) => error.fmt(f),
            Self::NotComplete => f.write_str("persistent OAuth authorization is not complete"),
            Self::Stopped => {
                f.write_str("persistent OAuth authorization stopped; inspect its retained custody")
            }
        }
    }
}
impl std::error::Error for OAuthAuthorizationError {}

/// Caller-owned initial login, with one deadline across preflight, browser wait,
/// code redemption, storage and delivery. It creates no runtime or worker lane.
///
/// Dropping a run future during browser/code work stops that flow permanently
/// and retains its store. Dropping a storage wait leaves the one-use completion
/// mailbox here. A new observer can resume that wait without repeating the
/// browser or token exchange. Only pre-submission storage refusal permits an
/// explicit retry of the same unexecuted storage command.
/// An unpolled owner runs no deadline timer. Synchronous providers must bound
/// and cooperate with worker cancellation; stopping observation cannot preempt
/// their running calls or undo a committed write.
///
/// The host must select a partition for the authenticated user independently;
/// matching issuer/client/resource configuration does not prove that identity.
/// The issuer must grant a refresh token. Qualified protection and independent
/// anchor services remain deployment requirements, and no enterprise OIDC
/// pending-flow or confidential-client custody is supplied by this workflow.
#[must_use = "drive authorization to persistence or inspect its exclusive custody"]
pub struct OAuthAuthorization<A, P> {
    origin: Cx,
    cancellation: McpRequestCancellation,
    deadline: Time,
    client: OAuthClient,
    authorization: PartitionAuthorization,
    expected_revision: Option<SlotRevision>,
    custody: OAuthAuthorizationCustody<A, P>,
}

impl<A, P> AsyncOAuthRefreshStore<A, P>
where
    A: CredentialCommitAnchor + 'static,
    P: OAuthGrantProtector + 'static,
{
    /// Prepares login without invoking the browser, filesystem or a provider.
    /// The exact prior revision authorizes replacement, including None for a
    /// never-written store. A fresh partition/anchor/file read also precedes
    /// browser launch. Timeout covers the whole operation and is at most 5 minutes.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_authorization(
        self,
        cx: &Cx,
        client: &OAuthClient,
        authorization: PartitionAuthorization,
        expected_revision: Option<SlotRevision>,
        cancellation: &McpRequestCancellation,
        timeout: Duration,
    ) -> Result<OAuthAuthorization<A, P>, OAuthRefreshSubmissionFailure<A, P, ()>> {
        let admitted = (|| {
            if timeout.is_zero() || timeout > Duration::from_secs(300) {
                return Err(AsyncOAuthRefreshError::Io(CredentialIoError::InvalidLimits));
            }
            if self.store.configuration != client.configuration {
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
            Err(cause) => {
                return Err(OAuthRefreshSubmissionFailure {
                    cause,
                    retained: Some(Box::new((self, ()))),
                });
            }
        };
        Ok(OAuthAuthorization {
            origin: cx.clone(),
            cancellation: cancellation.clone(),
            deadline,
            client: client.clone(),
            authorization,
            expected_revision,
            custody: OAuthAuthorizationCustody::ReadyToCheck(self),
        })
    }
}

impl<A, P> OAuthAuthorization<A, P> {
    pub fn stage(&self) -> OAuthAuthorizationStage {
        use OAuthAuthorizationCustody as C;
        use OAuthAuthorizationStage as S;
        match &self.custody {
            C::ReadyToCheck(_) => S::ReadyToCheck,
            C::Checking(_) => S::Checking,
            C::ReadyToAuthorize(_) => S::ReadyToAuthorize,
            C::ReadyToPersist { .. } => S::ReadyToPersist,
            C::Persisting(_) => S::Persisting,
            C::Complete { .. } => S::Complete,
            C::Stopped { .. } => S::Stopped,
        }
    }

    pub fn into_custody(self) -> OAuthAuthorizationCustody<A, P> {
        self.custody
    }

    /// Delivers managed access only after a known protected-store commit. The
    /// session owns access only; the returned store owns the refresh lineage.
    /// Use its explicit renewal/install/logout APIs for subsequent lifecycle.
    /// A premature or interrupted call preserves custody. Session-admission
    /// failure leaves the store in Stopped for explicit cleanup or recovery.
    pub fn take_managed_session(
        &mut self,
        observer: &Cx,
        policy: OAuthSessionPolicy,
    ) -> Result<
        (
            ManagedOAuthSession,
            AsyncOAuthRefreshStore<A, P>,
            SlotRevision,
        ),
        OAuthAuthorizationError,
    > {
        with_caller(observer, || {
            with_caller(&self.origin, || {
                let origin = interrupted(&self.origin);
                let observed = interrupted(observer);
                if self.cancellation.is_cancel_requested()
                    || origin == Some(OAuthError::Cancelled)
                    || observed == Some(OAuthError::Cancelled)
                {
                    return Err(OAuthAuthorizationError::Context(OAuthError::Cancelled));
                }
                if !Cx::current().is_some_and(|active| active.capabilities().time) {
                    return Err(OAuthAuthorizationError::Context(
                        OAuthError::RuntimeTimerUnavailable,
                    ));
                }
                if origin.is_some()
                    || observed.is_some()
                    || self.origin.now() >= self.deadline
                    || observer
                        .budget()
                        .deadline
                        .is_some_and(|end| observer.now() >= end)
                {
                    return Err(OAuthAuthorizationError::Context(OAuthError::TimedOut));
                }
                Ok(())
            })
        })?;
        if self.stage() != OAuthAuthorizationStage::Complete {
            return Err(OAuthAuthorizationError::NotComplete);
        }
        let OAuthAuthorizationCustody::Complete {
            store,
            credentials,
            revision,
        } = std::mem::replace(&mut self.custody, stopped())
        else {
            return Err(OAuthAuthorizationError::NotComplete);
        };
        match ManagedOAuthSession::from_credentials(
            observer,
            self.client.clone(),
            policy,
            credentials,
        ) {
            Ok(session) => Ok((session, store, revision)),
            Err(error) => {
                self.custody = OAuthAuthorizationCustody::Stopped {
                    store: Some(store),
                    credentials: None,
                };
                Err(OAuthAuthorizationError::Session(error))
            }
        }
    }

    /// Stops this login and requests cancellation of its pending storage job.
    /// Cancellation cannot undo a committed write or preempt a provider; retain
    /// its mailbox to observe that disposition. This is not issuer revocation.
    pub fn cancel(&self) {
        self.cancellation.cancel();
        self.cancel_worker();
    }

    fn cancel_worker(&self) {
        match &self.custody {
            OAuthAuthorizationCustody::Checking(task) => {
                let _ = task.request_cancel();
            }
            OAuthAuthorizationCustody::Persisting(task) => {
                let _ = task.request_cancel();
            }
            _ => {}
        }
    }
}

impl<A, P> OAuthAuthorization<A, P>
where
    A: CredentialCommitAnchor + 'static,
    P: OAuthGrantProtector + 'static,
{
    /// Preflights custody, drives the native loopback/PKCE browser flow, then
    /// persists its refresh grant. The browser driver may await the callback
    /// response because the existing native driver is jointly polled.
    ///
    /// If code redemption already completed, this resumes storage and never
    /// invokes the supplied driver again. A failed/dropped authorization flow
    /// stays Stopped; a new login requires a new owner and fresh state/PKCE.
    pub async fn run_with_browser_driver<D, F>(
        &mut self,
        observer: &Cx,
        driver: D,
    ) -> Result<(), OAuthAuthorizationError>
    where
        D: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<(), OAuthError>>,
    {
        let client = self.client.clone();
        let origin = self.origin.clone();
        let timeout = client.configuration.authorization_timeout;
        Box::pin(self.run_authorization(observer, async move {
            client
                .authorize_with_browser_driver(&origin, timeout, driver)
                .await
        }))
        .await
    }

    /// The same transaction using a separately registered, host-owned HTTPS
    /// callback instead of a loopback listener. The driver must follow
    /// `OAuthClient::authorize_with_redirect_driver`'s route and cleanup contract.
    /// No web framework or persistent pending OAuth security values are added.
    pub async fn run_with_redirect_driver<D, F>(
        &mut self,
        observer: &Cx,
        redirect_uri: CanonicalHttpUrl,
        driver: D,
    ) -> Result<(), OAuthAuthorizationError>
    where
        D: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<String, OAuthError>>,
    {
        let client = self.client.clone();
        let origin = self.origin.clone();
        Box::pin(self.run_authorization(observer, async move {
            client
                .authorize_with_redirect_driver(&origin, redirect_uri, driver)
                .await
        }))
        .await
    }

    async fn run_authorization(
        &mut self,
        observer: &Cx,
        authorization: impl Future<Output = Result<OAuthCredentials, OAuthError>>,
    ) -> Result<(), OAuthAuthorizationError> {
        while matches!(
            self.stage(),
            OAuthAuthorizationStage::ReadyToCheck | OAuthAuthorizationStage::Checking
        ) {
            self.advance(observer).await?;
        }
        if self.stage() == OAuthAuthorizationStage::ReadyToAuthorize {
            let origin = self.origin.clone();
            let cancellation = self.cancellation.clone();
            let deadline = self.deadline;
            observe(&origin, &cancellation, deadline, observer, async {
                let OAuthAuthorizationCustody::ReadyToAuthorize(store) =
                    std::mem::replace(&mut self.custody, stopped())
                else {
                    return Err(OAuthAuthorizationError::Stopped);
                };
                // Elect once before polling any browser or network work. The
                // retained store survives a dropped authorization future, but
                // its state/code cannot be replayed by another call to run.
                self.custody = OAuthAuthorizationCustody::Stopped {
                    store: Some(store),
                    credentials: None,
                };
                let credentials = authorization
                    .await
                    .map_err(OAuthAuthorizationError::Authorization)?;
                let OAuthAuthorizationCustody::Stopped {
                    store: Some(store), ..
                } = std::mem::replace(&mut self.custody, stopped())
                else {
                    return Err(OAuthAuthorizationError::Stopped);
                };
                if !credentials.has_refresh_token() {
                    self.custody = OAuthAuthorizationCustody::Stopped {
                        store: Some(store),
                        credentials: Some(credentials),
                    };
                    return Err(OAuthAuthorizationError::Storage(
                        OAuthRefreshStoreError::RefreshUnavailable,
                    ));
                }
                // No suspension between successful redemption and retaining
                // exclusive grant custody, even if an outer guard then stops.
                self.custody = OAuthAuthorizationCustody::ReadyToPersist { store, credentials };
                Ok(())
            })
            .await?;
        }
        self.finish(observer).await
    }

    /// Finishes an already-redeemed grant's storage, without accepting a browser
    /// driver or repeating the token exchange. A dropped wait can be resumed.
    /// The same fixed operation lifetime applies to every observer and pause.
    pub async fn finish(&mut self, observer: &Cx) -> Result<(), OAuthAuthorizationError> {
        loop {
            match self.stage() {
                OAuthAuthorizationStage::ReadyToPersist
                | OAuthAuthorizationStage::Persisting
                | OAuthAuthorizationStage::Complete => {
                    if self.advance(observer).await? == OAuthAuthorizationStage::Complete {
                        return Ok(());
                    }
                }
                OAuthAuthorizationStage::Stopped => return Err(OAuthAuthorizationError::Stopped),
                _ => return Err(OAuthAuthorizationError::NotComplete),
            }
        }
    }

    /// Advances one storage boundary. ReadyToAuthorize waits for an explicit
    /// browser/redirect run; this method alone never launches or redeems a code.
    pub async fn advance(
        &mut self,
        observer: &Cx,
    ) -> Result<OAuthAuthorizationStage, OAuthAuthorizationError> {
        let origin = self.origin.clone();
        let cancellation = self.cancellation.clone();
        let deadline = self.deadline;
        let result = observe(
            &origin,
            &cancellation,
            deadline,
            observer,
            Box::pin(self.advance_inner(&origin)),
        )
        .await;
        if cancellation.is_cancel_requested()
            || origin.is_cancel_requested()
            || origin.now() >= deadline
        {
            self.cancel_worker();
        }
        result
    }

    async fn advance_inner(
        &mut self,
        cx: &Cx,
    ) -> Result<OAuthAuthorizationStage, OAuthAuthorizationError> {
        use OAuthAuthorizationCustody as C;
        match &mut self.custody {
            C::Checking(task) => {
                let completion = match task.wait(cx).await {
                    Ok(completion) => completion,
                    Err(error) => {
                        if terminal_completion(error) {
                            self.custody = stopped();
                        }
                        return Err(OAuthAuthorizationError::Completion(error));
                    }
                };
                let (store, outcome) = completion.into_parts();
                match outcome {
                    Ok(()) => self.custody = C::ReadyToAuthorize(store),
                    Err(error) => {
                        self.custody = C::Stopped {
                            store: Some(store),
                            credentials: None,
                        };
                        return Err(OAuthAuthorizationError::Storage(error));
                    }
                }
                return Ok(self.stage());
            }
            C::Persisting(task) => {
                let completion = match task.wait(cx).await {
                    Ok(completion) => completion,
                    Err(error) => {
                        if terminal_completion(error) {
                            self.custody = stopped();
                        }
                        return Err(OAuthAuthorizationError::Completion(error));
                    }
                };
                let (store, (credentials, outcome)) = completion.into_parts();
                match outcome {
                    Ok(revision) => {
                        self.custody = C::Complete {
                            store,
                            credentials,
                            revision,
                        };
                    }
                    Err(error) => {
                        self.custody = C::Stopped {
                            store: Some(store),
                            credentials: Some(credentials),
                        };
                        return Err(OAuthAuthorizationError::Storage(error));
                    }
                }
                return Ok(self.stage());
            }
            _ => {}
        }
        // The storage lane accepts an explicit Cx and spawns a worker from it.
        // Carry the observer/host intersection into that worker rather than
        // restoring the original wider handle. Obtain it before moving custody.
        let active = Cx::current().ok_or(OAuthAuthorizationError::Context(
            OAuthError::RuntimeCapabilityUnavailable,
        ))?;
        match std::mem::replace(&mut self.custody, stopped()) {
            C::ReadyToCheck(store) => {
                let expected = self.expected_revision;
                let authorization = self.authorization;
                match store.try_operate(&active, (), move |store, worker, ()| {
                    if store.revision() != expected {
                        return Err(OAuthRefreshStoreError::RevisionMismatch);
                    }
                    // Revalidate partition, independent anchor and actual file
                    // before any browser effect. No plaintext is opened here.
                    drop(store.slot.load(worker, &authorization)?);
                    Ok(())
                }) {
                    Ok(task) => self.custody = C::Checking(task),
                    Err(failure) => {
                        let (cause, retained) = failure.into_parts();
                        if let Some((store, ())) = retained {
                            self.custody = C::ReadyToCheck(store);
                        }
                        return Err(OAuthAuthorizationError::Submission(cause));
                    }
                }
            }
            C::ReadyToPersist { store, credentials } => {
                match store.try_store_refresh(
                    &active,
                    self.authorization,
                    self.expected_revision,
                    credentials,
                ) {
                    Ok(task) => self.custody = C::Persisting(task),
                    Err(failure) => {
                        let (cause, retained) = failure.into_parts();
                        if let Some((store, credentials)) = retained {
                            self.custody = C::ReadyToPersist { store, credentials };
                        }
                        return Err(OAuthAuthorizationError::Submission(cause));
                    }
                }
            }
            other => {
                self.custody = other;
                if self.stage() == OAuthAuthorizationStage::Stopped {
                    return Err(OAuthAuthorizationError::Stopped);
                }
            }
        }
        Ok(self.stage())
    }
}

fn stopped<A, P>() -> OAuthAuthorizationCustody<A, P> {
    OAuthAuthorizationCustody::Stopped {
        store: None,
        credentials: None,
    }
}

fn terminal_completion(error: CredentialIoError) -> bool {
    matches!(
        error,
        CredentialIoError::WorkerStopped
            | CredentialIoError::WorkerPanicked
            | CredentialIoError::AlreadyReceived
            | CredentialIoError::ProcessChanged
    )
}

async fn observe<T>(
    origin: &Cx,
    cancellation: &McpRequestCancellation,
    deadline: Time,
    observer: &Cx,
    work: impl Future<Output = Result<T, OAuthAuthorizationError>>,
) -> Result<T, OAuthAuthorizationError> {
    let observer_deadline = with_caller(observer, || {
        with_caller(origin, || {
            if cancellation.is_cancel_requested() {
                return Err(OAuthError::Cancelled);
            }
            require_native_effects(origin)?;
            require_native_effects(observer)?;
            ensure_live(origin, deadline)?;
            Ok(observer
                .now()
                .saturating_add_nanos(deadline.as_nanos().saturating_sub(origin.now().as_nanos())))
        })
    })
    .map_err(OAuthAuthorizationError::Context)?;
    let work = async {
        let mut work = std::pin::pin!(work);
        let mut cancelled = std::pin::pin!(cancellation.cancelled());
        poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(OAuthAuthorizationError::Context(OAuthError::Cancelled)));
            }
            let result = work.as_mut().poll(task);
            if cancellation.is_cancel_requested() {
                Poll::Ready(Err(OAuthAuthorizationError::Context(OAuthError::Cancelled)))
            } else {
                result
            }
        })
        .await
    };
    // Each Cx registers cancellation and its own timer. Both caller capability
    // ceilings remain in effect; an observer with another clock cannot extend
    // the original deadline or replace the original cancellation domain.
    within(observer, observer_deadline, async {
        Ok(within(origin, deadline, async { Ok(work.await) }).await)
    })
    .await
    .map_err(OAuthAuthorizationError::Context)
    .and_then(|result| result.map_err(OAuthAuthorizationError::Context))?
}
