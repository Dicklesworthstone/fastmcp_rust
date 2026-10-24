//! Ready-to-use persistence callbacks for Task creation and resumed watches.
//!
//! Clones share one exclusive store and one completion mailbox. Abandoning a
//! callback drops only its wait; the transaction and exact outcome stay owned.
//! A new callback refuses pending custody instead of replaying a write or
//! accidentally acknowledging a different snapshot.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use asupersync::Cx;
use asupersync::sync::{Mutex, OwnedMutexGuard};

use super::{
    AsyncTaskResumeStore, CredentialIoError, CredentialSlotTask, TaskResumeBinding,
    TaskResumeCompletion, TaskResumeProtector, TaskResumeStoreError,
};
use super::super::super::client::creation::TaskResumeInsert;
use super::super::super::client::lifecycle::TaskResumeChange;

/// Non-secret custody state, not evidence about the remote Task's lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskResumePersistenceStatus {
    Ready,
    Pending,
    Closing,
    Closed,
    Unavailable,
}

#[derive(Debug)]
pub enum TaskResumePersistenceError {
    /// Another live callback or recovery observer currently owns the mutex.
    Busy,
    /// A previous write must be observed explicitly, never resubmitted.
    OperationPending,
    /// No write remains to observe; a previous acknowledgement is not repeated.
    NoPending,
    /// Close has started; only explicit close observation may continue.
    Closing,
    Closed,
    /// Scheduling/worker failure lost the in-memory owner. Reopen and reconcile.
    Unavailable,
    Io(CredentialIoError),
    Store(TaskResumeStoreError),
}

impl fmt::Display for TaskResumePersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => f.write_str("Task checkpoint persistence is already observed"),
            Self::OperationPending => {
                f.write_str("observe the pending Task checkpoint write before another command")
            }
            Self::NoPending => f.write_str("no Task checkpoint write is pending"),
            Self::Closing => f.write_str("Task checkpoint persistence is closing"),
            Self::Closed => f.write_str("Task checkpoint persistence is closed"),
            Self::Unavailable => {
                f.write_str("Task checkpoint owner unavailable; reopen and reconcile")
            }
            Self::Io(error) => error.fmt(f),
            Self::Store(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for TaskResumePersistenceError {}

pub type TaskResumePersistenceFuture =
    Pin<Box<dyn Future<Output = Result<(), TaskResumePersistenceError>> + Send + 'static>>;

enum Phase<P> {
    Ready(AsyncTaskResumeStore<P>),
    Pending(CredentialSlotTask<TaskResumeCompletion<P, ()>>),
    Closing(CredentialSlotTask<()>),
    Closed,
    Unavailable,
}

struct State<P> {
    current: TaskResumeBinding,
    phase: Phase<P>,
}

// Both variants contain only admitted, bounded checkpoint controls. This is
// not a public arbitrary closure or application-payload storage interface.
enum Command {
    Insert(TaskResumeInsert),
    Change(TaskResumeChange),
}

/// Shared persistence for the existing creating-call and persisted-watch APIs.
///
/// `insert_callback` plugs into initial Task checkpoint submission;
/// `change_callback` plugs into `resume_task_watch_persisted`. Both invoke the
/// SAME synchronous conditional commands in the existing caller-owned I/O lane.
/// No protector or filesystem operation executes in these callback futures.
///
/// Keep a clone outside the watch. If its callback is cancelled or dropped,
/// use `finish_pending` with a live caller to retrieve the original disposition.
/// A new callback will NOT resubmit or consume that old outcome as its own ACK.
/// Even after successful storage, an outer watch may reject publication due to
/// cancellation or login expiry. Storage success is not remote authorization.
///
/// This wrapper has no wait queue: concurrent use fails Busy. A pending write
/// blocks new writes and close until explicitly observed. Transaction errors
/// retain the same store, including its uncertain-commit quarantine. After
/// settling, `take_store` transfers that owner for exact-version reconciliation
/// or inspection and closes this wrapper for ALL clones. No automatic retry,
/// plaintext protector, detached task or new runtime is supplied.
pub struct TaskResumePersistence<P> {
    state: Arc<Mutex<State<P>>>,
}

impl<P> Clone for TaskResumePersistence<P> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}
impl<P> fmt::Debug for TaskResumePersistence<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TaskResumePersistence(<shared checkpoint custody>)")
    }
}

impl<P: TaskResumeProtector + 'static> TaskResumePersistence<P> {
    /// No I/O or implicit authorization. Every command rechecks `current`
    /// against the protected store before inspecting or changing a record.
    pub fn new(store: AsyncTaskResumeStore<P>, current: TaskResumeBinding) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                current,
                phase: Phase::Ready(store),
            })),
        }
    }

    pub fn status(&self) -> Result<TaskResumePersistenceStatus, TaskResumePersistenceError> {
        let state = self.lock()?;
        Ok(match &state.phase {
            Phase::Ready(_) => TaskResumePersistenceStatus::Ready,
            Phase::Pending(_) => TaskResumePersistenceStatus::Pending,
            Phase::Closing(_) => TaskResumePersistenceStatus::Closing,
            Phase::Closed => TaskResumePersistenceStatus::Closed,
            Phase::Unavailable => TaskResumePersistenceStatus::Unavailable,
        })
    }

    pub fn insert_callback(
        &self,
        cx: Cx,
    ) -> impl FnMut(TaskResumeInsert) -> TaskResumePersistenceFuture + Send + 'static {
        let owner = self.clone();
        move |insert| -> TaskResumePersistenceFuture {
            let owner = owner.clone();
            let cx = cx.clone();
            Box::pin(async move { owner.persist_insert(&cx, insert).await })
        }
    }

    pub fn change_callback(
        &self,
        cx: Cx,
    ) -> impl FnMut(TaskResumeChange) -> TaskResumePersistenceFuture + Send + 'static {
        let owner = self.clone();
        move |change| -> TaskResumePersistenceFuture {
            let owner = owner.clone();
            let cx = cx.clone();
            Box::pin(async move { owner.persist_change(&cx, change).await })
        }
    }

    pub async fn persist_insert(
        &self,
        cx: &Cx,
        insert: TaskResumeInsert,
    ) -> Result<(), TaskResumePersistenceError> {
        self.persist(cx, Command::Insert(insert)).await
    }

    pub async fn persist_change(
        &self,
        cx: &Cx,
        change: TaskResumeChange,
    ) -> Result<(), TaskResumePersistenceError> {
        self.persist(cx, Command::Change(change)).await
    }

    async fn persist(&self, cx: &Cx, command: Command) -> Result<(), TaskResumePersistenceError> {
        let mut state = self.lock()?;
        let store = take_ready(&mut state)?;
        let current = state.current.clone();
        let submission = store.try_operate(
            cx,
            current,
            command,
            |store, worker, current, command| match command {
                Command::Insert(insert) => insert.apply(worker, current, store),
                Command::Change(change) => change.apply(worker, current, store),
            },
        );
        match submission {
            Ok(task) => state.phase = Phase::Pending(task),
            Err(failure) => {
                let (cause, retained) = failure.into_parts();
                // This exact command did not run when custody was returned.
                // The enclosing watch still owns its pending control change.
                if let Some((store, _, _)) = retained {
                    state.phase = Phase::Ready(store);
                }
                return Err(TaskResumePersistenceError::Io(cause));
            }
        }
        // The mailbox is IN shared state before the first await. Dropping
        // this future releases only the mutex, never that transaction owner.
        finish(&mut state, cx).await
    }

    /// Observe ONLY the existing transaction. This never schedules another
    /// write, even after a previous wait was cancelled or a callback abandoned.
    /// Once consumed, the outcome cannot be acknowledged a second time.
    pub async fn finish_pending(&self, cx: &Cx) -> Result<(), TaskResumePersistenceError> {
        let mut state = self.lock()?;
        finish(&mut state, cx).await
    }

    /// Transfer a settled owner for explicit inspection/reconciliation. Every
    /// callback clone becomes Closed. Pending or closing custody is unchanged.
    pub fn take_store(&self) -> Result<AsyncTaskResumeStore<P>, TaskResumePersistenceError> {
        let mut state = self.lock()?;
        let store = take_ready(&mut state)?;
        state.phase = Phase::Closed;
        Ok(store)
    }

    /// Close without abandoning a write. Interrupted close observation retains
    /// its cleanup mailbox; a later close call waits for that SAME cleanup.
    pub async fn close(&self, cx: &Cx) -> Result<(), TaskResumePersistenceError> {
        let mut state = self.lock()?;
        if matches!(&state.phase, Phase::Ready(_)) {
            let store = take_ready(&mut state)?;
            state.phase = match store.close(cx) {
                Ok(task) => Phase::Closing(task),
                Err(error) => return Err(TaskResumePersistenceError::Io(error)),
            };
        }
        let result = match &mut state.phase {
            Phase::Closing(task) => task.wait(cx).await,
            Phase::Pending(_) => return Err(TaskResumePersistenceError::OperationPending),
            Phase::Closed => return Ok(()),
            Phase::Ready(_) | Phase::Unavailable => {
                return Err(TaskResumePersistenceError::Unavailable);
            }
        };
        match result {
            Ok(()) => {
                state.phase = Phase::Closed;
                Ok(())
            }
            Err(error) => {
                if !retains_wait(error) {
                    state.phase = Phase::Unavailable;
                }
                Err(TaskResumePersistenceError::Io(error))
            }
        }
    }

    fn lock(&self) -> Result<OwnedMutexGuard<State<P>>, TaskResumePersistenceError> {
        self.state
            .try_lock_owned()
            .map_err(|_| TaskResumePersistenceError::Busy)
    }
}

fn take_ready<P>(state: &mut State<P>) -> Result<AsyncTaskResumeStore<P>, TaskResumePersistenceError> {
    match std::mem::replace(&mut state.phase, Phase::Unavailable) {
        Phase::Ready(store) => Ok(store),
        other => {
            let error = match &other {
                Phase::Pending(_) => TaskResumePersistenceError::OperationPending,
                Phase::Closing(_) => TaskResumePersistenceError::Closing,
                Phase::Closed => TaskResumePersistenceError::Closed,
                Phase::Ready(_) | Phase::Unavailable => TaskResumePersistenceError::Unavailable,
            };
            state.phase = other;
            Err(error)
        }
    }
}

fn retains_wait(error: CredentialIoError) -> bool {
    matches!(
        error,
        CredentialIoError::WaitCancelled
            | CredentialIoError::WaitTimedOut
            | CredentialIoError::CapabilityUnavailable
            | CredentialIoError::ProcessChanged
    )
}

async fn finish<P>(state: &mut State<P>, cx: &Cx) -> Result<(), TaskResumePersistenceError> {
    let result = match &mut state.phase {
        Phase::Pending(task) => task.wait(cx).await,
        Phase::Ready(_) => return Err(TaskResumePersistenceError::NoPending),
        Phase::Closing(_) => return Err(TaskResumePersistenceError::Closing),
        Phase::Closed => return Err(TaskResumePersistenceError::Closed),
        Phase::Unavailable => return Err(TaskResumePersistenceError::Unavailable),
    };
    match result {
        Ok(completion) => {
            let (owner, outcome) = completion.into_parts();
            state.phase = Phase::Ready(owner);
            outcome.map_err(TaskResumePersistenceError::Store)
        }
        Err(error) => {
            if !retains_wait(error) {
                state.phase = Phase::Unavailable;
            }
            Err(TaskResumePersistenceError::Io(error))
        }
    }
}
