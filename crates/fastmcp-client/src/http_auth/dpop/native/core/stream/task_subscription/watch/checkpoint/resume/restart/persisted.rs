//! Protected-store acknowledgement for staged native DPoP Task restart.
//!
//! Reuses the common exact-version persistence owner and completion mailbox.
//! Network authority never extends to a storage retry, nor does a local write
//! renew the original remote lifetime.

use std::fmt;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::FinalRequestMeta;

use super::{
    DpopTaskRestart, DpopTaskRestartError, DpopTaskRestartItem, TaskResumeBinding,
    TaskResumeChange, TaskResumeError,
};
use crate::http_auth::dpop::native::{DpopCredential, DpopHttpClient};
use crate::http_auth::dpop::native::core::stream::DpopStreamLimits;
use crate::http_auth::managed::tasks::watch::checkpoint::resume::store::TaskResumeProtector;
use crate::http_auth::managed::tasks::watch::checkpoint::resume::store::asynchronous::{
    AsyncTaskResumeStore, TaskResumeCompletion,
};
use crate::http_auth::managed::tasks::watch::checkpoint::resume::store::asynchronous::persistence::{
    TaskResumePersistence, TaskResumePersistenceError,
};
use crate::http_auth::managed::tasks::watch::checkpoint::resume::store::asynchronous::restart::StagedTaskRestart;
use crate::http_auth::managed::tasks::watch::checkpoint::resume::store::asynchronous::restart::workflow::{
    RestartCheckpointItem, RestartCommit,
};

pub use crate::http_auth::managed::tasks::watch::checkpoint::resume::store::asynchronous::restart::workflow::{
    PersistedTaskRestartError, RestartCheckpointState,
};

/// Remote read failures and local checkpoint dispositions retain distinct
/// typed causes. Neither is an instruction to repeat the failed operation.
#[derive(Debug)]
pub enum PersistedDpopTaskRestartError {
    Restart(DpopTaskRestartError),
    Checkpoint(PersistedTaskRestartError),
}

impl fmt::Display for PersistedDpopTaskRestartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Restart(error) => error.fmt(f),
            Self::Checkpoint(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for PersistedDpopTaskRestartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Restart(error) => Some(error),
            Self::Checkpoint(error) => Some(error),
        }
    }
}

/// Failed staging or admission returns the exact protected storage owner.
/// Preparation does not contact the server or change a checkpoint. The host
/// may explicitly reload a consumed plan from the unchanged store.
pub struct DpopTaskRestartPreparationFailure<P> {
    cause: PersistedDpopTaskRestartError,
    store: Box<AsyncTaskResumeStore<P>>,
}

impl<P> DpopTaskRestartPreparationFailure<P> {
    pub fn cause(&self) -> &PersistedDpopTaskRestartError {
        &self.cause
    }

    pub fn into_parts(self) -> (PersistedDpopTaskRestartError, AsyncTaskResumeStore<P>) {
        (self.cause, *self.store)
    }
}

impl<P> fmt::Debug for DpopTaskRestartPreparationFailure<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopTaskRestartPreparationFailure")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}
impl<P> fmt::Display for DpopTaskRestartPreparationFailure<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(f)
    }
}
impl<P> std::error::Error for DpopTaskRestartPreparationFailure<P> {}

impl RestartCheckpointItem for DpopTaskRestartItem {
    fn storage_change(
        &self,
        cx: &Cx,
        current: &TaskResumeBinding,
    ) -> Result<TaskResumeChange, TaskResumeError> {
        DpopTaskRestartItem::storage_change(self, cx, current)
    }
}

impl<P: TaskResumeProtector + 'static> TaskResumeCompletion<P, StagedTaskRestart> {
    /// Bind a fully loaded protected selection to an explicitly chosen DPoP
    /// login. Current owner/profile facts come from try_load_restart's host
    /// binding, never saved controls. The host associates them with this login.
    ///
    /// Admission consumes the complete bounded plan before network I/O and
    /// starts one absolute remote lifetime. Every later checkpoint pause uses
    /// that same lifetime; acknowledgement does not renew it.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_persisted_dpop_restart<'client>(
        self,
        cx: &Cx,
        client: &'client mut DpopHttpClient,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        id_prefix: String,
        limits: DpopStreamLimits,
    ) -> Result<PersistedDpopTaskRestart<'client, P>, DpopTaskRestartPreparationFailure<P>> {
        let (store, staged) = self.into_parts();
        let staged = match staged {
            Ok(staged) => staged,
            Err(error) => {
                return Err(DpopTaskRestartPreparationFailure {
                    cause: PersistedDpopTaskRestartError::Checkpoint(
                        PersistedTaskRestartError::Persistence(TaskResumePersistenceError::Store(
                            error,
                        )),
                    ),
                    store: Box::new(store),
                });
            }
        };
        let (current, plan) = staged.into_parts();
        let restart = match client.prepare_task_restart(
            cx,
            cancellation,
            credential,
            metadata,
            current.clone(),
            plan,
            id_prefix,
            limits,
        ) {
            Ok(restart) => restart,
            Err(error) => {
                return Err(DpopTaskRestartPreparationFailure {
                    cause: PersistedDpopTaskRestartError::Restart(error),
                    store: Box::new(store),
                });
            }
        };
        Ok(PersistedDpopTaskRestart {
            restart,
            commit: RestartCommit::new(store, current),
        })
    }
}

/// One staged restart with one application outcome awaiting local disposition.
///
/// Handle or durably save a terminal result BEFORE acknowledge. The common
/// checkpoint owner then compares the exact previous record, replaces active
/// controls or removes a terminal/unavailable hint, and returns the same item.
/// No result payload is serialized into resume storage. A crash before ACK can
/// redeliver a terminal result; this is not exactly-once delivery.
///
/// Acknowledgement uses the caller's separate LOCAL I/O budget. Dropping its
/// wait retains the original storage job and mailbox. A later acknowledge
/// observes that SAME job, never resubmits it, and can finish after remote
/// authority expires. A completed storage error retains item/change/store for
/// explicit recovery through into_parts and blocks automatic progression.
///
/// A failed or abandoned remote read retains its underlying restart custody.
/// No read/write is automatically replayed, and no watch, creating call, input
/// answer, remote cancellation or server-side durable execution is implied.
#[must_use = "drive or recover the retained Task outcome and protected store"]
pub struct PersistedDpopTaskRestart<'client, P> {
    restart: DpopTaskRestart<'client>,
    commit: RestartCommit<P, DpopTaskRestartItem>,
}

impl<P> fmt::Debug for PersistedDpopTaskRestart<'_, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistedDpopTaskRestart")
            .field("remaining_reads", &self.restart.remaining())
            .field("pending_outcome", &self.commit.pending.is_some())
            .field("checkpoint_state", &self.commit.state)
            .finish_non_exhaustive()
    }
}

/// Explicit recovery custody, including a possibly still-running local write.
/// The storage owner's finish_pending observes that write; take_store transfers
/// settled storage for exact-version reconciliation without a new remote read.
pub struct PersistedDpopTaskRestartParts<'client, P> {
    pub restart: DpopTaskRestart<'client>,
    pub current: TaskResumeBinding,
    pub storage: TaskResumePersistence<P>,
    pub pending: Option<DpopTaskRestartItem>,
    pub pending_change: Option<TaskResumeChange>,
    pub checkpoint_state: RestartCheckpointState,
}

impl<'client, P: TaskResumeProtector + 'static> PersistedDpopTaskRestart<'client, P> {
    pub fn pending(&self) -> Option<&DpopTaskRestartItem> {
        self.commit.pending.as_ref()
    }
    pub fn pending_change(&self) -> Option<&TaskResumeChange> {
        self.commit.change.as_ref()
    }
    pub fn checkpoint_state(&self) -> RestartCheckpointState {
        self.commit.state
    }
    pub fn restart_state(&self) -> &DpopTaskRestart<'client> {
        &self.restart
    }

    pub async fn next_reconciled(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<&DpopTaskRestartItem>, PersistedDpopTaskRestartError> {
        if self.commit.pending.is_some() {
            return Err(PersistedDpopTaskRestartError::Checkpoint(
                PersistedTaskRestartError::AcknowledgementRequired,
            ));
        }
        let item = self
            .restart
            .next_reconciled(cx)
            .await
            .map_err(PersistedDpopTaskRestartError::Restart)?;
        // No suspension can separate delivery from retained result custody.
        self.commit.pending = item;
        Ok(self.commit.pending.as_ref())
    }

    /// Explicit acknowledgement AFTER result handling. An interrupted wait may
    /// be continued under a fresh local caller, observing the original mailbox.
    pub async fn acknowledge(
        &mut self,
        cx: &Cx,
    ) -> Result<DpopTaskRestartItem, PersistedDpopTaskRestartError> {
        self.commit
            .acknowledge(cx)
            .await
            .map_err(PersistedDpopTaskRestartError::Checkpoint)
    }

    /// Deliberately take the item while leaving its saved hint untouched. Fresh
    /// active controls are not acknowledged as durable. Refused after any write
    /// attempt, including one whose wait was abandoned.
    pub fn take_without_persisting(
        &mut self,
    ) -> Result<DpopTaskRestartItem, PersistedDpopTaskRestartError> {
        self.commit
            .take_without_persisting()
            .map_err(PersistedDpopTaskRestartError::Checkpoint)
    }

    pub fn into_parts(self) -> PersistedDpopTaskRestartParts<'client, P> {
        let RestartCommit {
            current,
            storage,
            pending,
            change,
            state,
        } = self.commit;
        PersistedDpopTaskRestartParts {
            restart: self.restart,
            current,
            storage,
            pending,
            pending_change: change,
            checkpoint_state: state,
        }
    }
}
