//! Persistence-gated recovery of a staged set of saved Tasks.
//!
//! Read one freshly authenticated outcome, handle its application result, then
//! explicitly persist or retain its checkpoint before reading another. Network
//! reconciliation and local storage keep their existing independent ownership
//! domains; neither a failed read nor an interrupted write is replayed.

use std::fmt;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;

use super::StagedTaskRestart;
use super::super::{
    AsyncTaskResumeStore, TaskResumeBinding, TaskResumeCompletion, TaskResumeProtector,
};
use super::super::persistence::{
    TaskResumePersistence, TaskResumePersistenceError, TaskResumePersistenceStatus,
};
use crate::http_auth::managed::tasks::ManagedTasksClient;
use crate::http_auth::managed::tasks::watch::checkpoint::resume::TaskResumeError;
use crate::http_auth::managed::tasks::watch::checkpoint::resume::client::lifecycle::TaskResumeChange;
use crate::http_auth::managed::tasks::watch::checkpoint::resume::client::restart::{
    ManagedTaskRestart, TaskResumeRestartError, TaskResumeRestartItem,
};

#[derive(Debug)]
pub enum PersistedTaskRestartError {
    Resume(TaskResumeError),
    Restart(TaskResumeRestartError),
    Persistence(TaskResumePersistenceError),
    AcknowledgementRequired,
    NoPending,
    /// Explicit inspection/reconciliation is required; no write is resubmitted.
    PersistenceFailed,
}

impl fmt::Display for PersistedTaskRestartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resume(error) => error.fmt(f),
            Self::Restart(error) => error.fmt(f),
            Self::Persistence(error) => error.fmt(f),
            Self::AcknowledgementRequired => {
                f.write_str("dispose of the pending Task restart outcome before another read")
            }
            Self::NoPending => f.write_str("no Task restart outcome is pending"),
            Self::PersistenceFailed => {
                f.write_str("Task restart persistence failed; recover its owner without replay")
            }
        }
    }
}
impl std::error::Error for PersistedTaskRestartError {}

/// A failed staging/preparation still returns the exact storage owner. Preparing
/// performs no network or storage mutation. A consumed plan can be explicitly
/// reloaded from this unchanged store; a failed remote read is never retried here.
pub struct TaskRestartPreparationFailure<P> {
    cause: PersistedTaskRestartError,
    store: Box<AsyncTaskResumeStore<P>>,
}

impl<P> TaskRestartPreparationFailure<P> {
    pub fn cause(&self) -> &PersistedTaskRestartError {
        &self.cause
    }

    pub fn into_parts(self) -> (PersistedTaskRestartError, AsyncTaskResumeStore<P>) {
        (self.cause, *self.store)
    }
}
impl<P> fmt::Debug for TaskRestartPreparationFailure<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskRestartPreparationFailure")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}
impl<P> fmt::Display for TaskRestartPreparationFailure<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(f)
    }
}
impl<P> std::error::Error for TaskRestartPreparationFailure<P> {}

/// Disposition of the pending outcome's LOCAL checkpoint operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartCheckpointState {
    NotAttempted,
    /// An interrupted wait is not rollback; the original mailbox is retained.
    Pending,
    /// The operation failed. The result, command and storage owner remain held.
    Failed,
}

impl<P: TaskResumeProtector + 'static> TaskResumeCompletion<P, StagedTaskRestart> {
    /// Bind the completed storage selection to one currently selected login.
    /// Admission uses the existing resource/owner/cancellation/ID checks. No
    /// network is contacted and no checkpoint changes during preparation.
    ///
    /// The binding comes from try_load_restart's host-supplied current facts,
    /// never from the saved controls. Associating those facts with this login
    /// remains the host's responsibility. The original restart timeout begins
    /// here and is not reset between reads or after checkpoint acknowledgement.
    pub fn prepare_persisted_restart(
        self,
        cx: &Cx,
        client: &ManagedTasksClient,
        cancellation: &McpRequestCancellation,
        id_prefix: String,
    ) -> Result<PersistedManagedTaskRestart<P>, TaskRestartPreparationFailure<P>> {
        let (store, staged) = self.into_parts();
        let staged = match staged {
            Ok(staged) => staged,
            Err(error) => {
                return Err(TaskRestartPreparationFailure {
                    cause: PersistedTaskRestartError::Persistence(
                        TaskResumePersistenceError::Store(error),
                    ),
                    store: Box::new(store),
                });
            }
        };
        let (current, plan) = staged.into_parts();
        let restart = match client.prepare_task_restart_with_cancellation(
            cx,
            cancellation,
            current.clone(),
            plan,
            id_prefix,
        ) {
            Ok(restart) => restart,
            Err(error) => {
                return Err(TaskRestartPreparationFailure {
                    cause: PersistedTaskRestartError::Restart(error),
                    store: Box::new(store),
                });
            }
        };
        Ok(PersistedManagedTaskRestart {
            restart,
            commit: RestartCommit::new(store, current),
        })
    }
}

/// One sequential recovery with at most one delivered, unacknowledged result.
///
/// next_reconciled performs fresh discovery/get through ManagedTaskRestart and
/// retains its outcome in this owner. It cannot advance while that item awaits
/// disposition. Call acknowledge only AFTER handling or durably recording a
/// terminal application result: it conditionally removes terminal/unavailable
/// hints and persists active controls using the existing TaskResumeChange.
/// take_without_persisting explicitly leaves the original checkpoint untouched.
///
/// An abandoned acknowledgement keeps its storage job. A later acknowledge
/// waits for that SAME outcome, never submits the command again. A storage
/// failure retains the item and command and blocks automatic progression; use
/// into_parts for explicit reconciliation. A failed/abandoned network read
/// likewise keeps the underlying restart's pending and unvisited records.
///
/// Remote reads keep the original login, request cancellation and absolute
/// restart deadline. Acknowledgement is a separate, explicit LOCAL storage
/// disposition under the supplied caller's I/O budget and checkpoint retention,
/// not renewed authorization or a remote operation. It can observe an already
/// committed write after a read deadline expires. It never resets that deadline
/// or starts a watch, replays tools/call, submits inputs or cancels remote work.
/// The host must keep current owner/profile facts valid for local disposition.
#[must_use = "drive or recover the retained Task outcomes and storage owner"]
pub struct PersistedManagedTaskRestart<P> {
    restart: ManagedTaskRestart,
    commit: RestartCommit<P>,
}

impl<P> fmt::Debug for PersistedManagedTaskRestart<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistedManagedTaskRestart")
            .field("remaining_reads", &self.restart.remaining())
            .field("pending_outcome", &self.commit.pending.is_some())
            .field("checkpoint_state", &self.commit.state)
            .finish_non_exhaustive()
    }
}

/// Explicit recovery custody, including a possibly still-running write. The
/// storage wrapper's finish_pending observes that write; take_store transfers
/// settled custody for exact-version reconciliation. Neither operation retries
/// a remote read or discards a terminal application result on the caller's behalf.
pub struct PersistedTaskRestartParts<P> {
    pub restart: ManagedTaskRestart,
    pub current: TaskResumeBinding,
    pub storage: TaskResumePersistence<P>,
    pub pending: Option<TaskResumeRestartItem>,
    pub pending_change: Option<TaskResumeChange>,
    pub checkpoint_state: RestartCheckpointState,
}

impl<P: TaskResumeProtector + 'static> PersistedManagedTaskRestart<P> {
    pub fn pending(&self) -> Option<&TaskResumeRestartItem> {
        self.commit.pending.as_ref()
    }

    pub fn pending_change(&self) -> Option<&TaskResumeChange> {
        self.commit.change.as_ref()
    }

    pub fn checkpoint_state(&self) -> RestartCheckpointState {
        self.commit.state
    }

    /// Read-only inspection includes a failed network read's retained outcome.
    pub fn restart_state(&self) -> &ManagedTaskRestart {
        &self.restart
    }

    pub async fn next_reconciled(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<&TaskResumeRestartItem>, PersistedTaskRestartError> {
        if self.commit.pending.is_some() {
            return Err(PersistedTaskRestartError::AcknowledgementRequired);
        }
        let item = self
            .restart
            .next_reconciled(cx)
            .await
            .map_err(PersistedTaskRestartError::Restart)?;
        // No suspension between receiving a result and placing it in custody.
        self.commit.pending = item;
        Ok(self.commit.pending.as_ref())
    }

    /// Explicitly acknowledge result handling and apply its conditional local
    /// change. Success returns the retained item AFTER durable acknowledgement.
    /// An interrupted call may be continued with a fresh caller, observing the
    /// same job. A completed error must be handled through into_parts, not retry.
    pub async fn acknowledge(
        &mut self,
        cx: &Cx,
    ) -> Result<TaskResumeRestartItem, PersistedTaskRestartError> {
        self.commit.acknowledge(cx).await
    }

    /// Deliberately preserve the saved hint and take this result without a
    /// storage effect. For example, keep an unavailable Task for later recovery.
    /// Fresh active controls returned this way are NOT acknowledged as durable.
    /// Refused once a write was attempted, even if its wait was abandoned.
    pub fn take_without_persisting(
        &mut self,
    ) -> Result<TaskResumeRestartItem, PersistedTaskRestartError> {
        self.commit.take_without_persisting()
    }

    pub fn into_parts(self) -> PersistedTaskRestartParts<P> {
        let RestartCommit { current, storage, pending, change, state } = self.commit;
        PersistedTaskRestartParts {
            restart: self.restart,
            current,
            storage,
            pending,
            pending_change: change,
            checkpoint_state: state,
        }
    }
}

struct RestartCommit<P> {
    current: TaskResumeBinding,
    storage: TaskResumePersistence<P>,
    pending: Option<TaskResumeRestartItem>,
    change: Option<TaskResumeChange>,
    state: RestartCheckpointState,
}

impl<P: TaskResumeProtector + 'static> RestartCommit<P> {
    fn new(store: AsyncTaskResumeStore<P>, current: TaskResumeBinding) -> Self {
        Self {
            storage: TaskResumePersistence::new(store, current.clone()),
            current,
            pending: None,
            change: None,
            state: RestartCheckpointState::NotAttempted,
        }
    }

    async fn acknowledge(
        &mut self,
        cx: &Cx,
    ) -> Result<TaskResumeRestartItem, PersistedTaskRestartError> {
        let pending = self.pending.as_ref().ok_or(PersistedTaskRestartError::NoPending)?;
        let outcome = match self.state {
            RestartCheckpointState::NotAttempted => {
                let change = pending
                    .storage_change(cx, &self.current)
                    .map_err(PersistedTaskRestartError::Resume)?;
                self.change = Some(change.clone());
                self.state = RestartCheckpointState::Pending;
                self.storage.persist_change(cx, change).await
            }
            RestartCheckpointState::Pending => self.storage.finish_pending(cx).await,
            RestartCheckpointState::Failed => {
                return Err(PersistedTaskRestartError::PersistenceFailed);
            }
        };
        if let Err(error) = outcome {
            self.state = if matches!(
                self.storage.status(),
                Ok(TaskResumePersistenceStatus::Pending)
            ) {
                RestartCheckpointState::Pending
            } else {
                RestartCheckpointState::Failed
            };
            return Err(PersistedTaskRestartError::Persistence(error));
        }
        // A successful storage outcome cannot be rewritten as cancellation.
        // Result handling preceded this explicit acknowledgement; no remote
        // authority is inferred from transferring the original item now.
        self.change = None;
        self.state = RestartCheckpointState::NotAttempted;
        self.pending.take().ok_or(PersistedTaskRestartError::NoPending)
    }

    fn take_without_persisting(&mut self) -> Result<TaskResumeRestartItem, PersistedTaskRestartError> {
        if self.state != RestartCheckpointState::NotAttempted {
            return Err(PersistedTaskRestartError::AcknowledgementRequired);
        }
        self.pending.take().ok_or(PersistedTaskRestartError::NoPending)
    }
}

#[cfg(test)]
mod tests;
