//! Caller-owned asynchronous access to the coordinated credential slot.
//!
//! File and anchor operations run in the supplied runtime's blocking pool.
//! Submission transfers the entire slot, including its file lock, to one job;
//! there is no second usable owner while a transaction is outstanding. A
//! cancelled wait retains its completion mailbox and can be resumed. Cancelling
//! the job is explicit and never means that a transaction did not commit.
//!
//! This is still storage for caller-protected blobs. Encryption, an independent
//! durable anchor, provider authentication, and restore-epoch custody remain
//! the existing coordinator's deployment requirements. No runtime, thread pool,
//! plaintext persistence, detached cleanup worker, or provider fallback is added.

use std::fmt;
use std::fs::File;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::runtime::TaskHandle;
use fastmcp_core::partition::{CredentialStoreKey, PartitionAuthorization};
use fastmcp_core::runtime::{ProcessBoundToken, ProcessGenerationGuard};

use super::{CoordinatedCredentialSlot, CoordinatedSlotError, CredentialCommitAnchor};
use super::super::{CredentialSlotError, SlotCommit, SlotRecoveryOutcome, SlotRevision};
use super::super::super::{AtomicFileError, SecureAtomicFile};

/// Scheduling/wait failures, distinct from the transaction's own disposition.
/// In particular WaitCancelled/WaitTimedOut say nothing about commit status.
/// No error retains a path, credential, or provider panic payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialIoError {
    ProcessChanged,
    CapabilityUnavailable,
    BlockingPoolUnavailable,
    SubmissionCancelled,
    SubmissionTimedOut,
    RuntimeUnavailable,
    WaitCancelled,
    WaitTimedOut,
    WorkerStopped,
    WorkerPanicked,
    AlreadyReceived,
}

impl fmt::Display for CredentialIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ProcessChanged => "credential I/O process generation changed",
            Self::CapabilityUnavailable => "credential I/O requires caller-owned spawn, I/O and time capabilities",
            Self::BlockingPoolUnavailable => "credential I/O requires an installed caller-owned blocking pool",
            Self::SubmissionCancelled => "credential I/O submission cancelled",
            Self::SubmissionTimedOut => "credential I/O submission deadline exceeded",
            Self::RuntimeUnavailable => "credential I/O could not enter the caller's runtime",
            Self::WaitCancelled => "credential I/O wait cancelled; transaction disposition is not implied",
            Self::WaitTimedOut => "credential I/O wait timed out; transaction disposition is not implied",
            Self::WorkerStopped => "credential I/O worker stopped without a completion; reopen and reconcile",
            Self::WorkerPanicked => "credential I/O worker panicked; reopen and reconcile",
            Self::AlreadyReceived => "credential I/O completion already received",
        })
    }
}
impl std::error::Error for CredentialIoError {}

/// One owned operation, with at most one completion delivery.
///
/// Keep this value after cancelling or dropping a `wait` future: another live
/// observer can await the SAME operation without submitting it again. The
/// completion uses a separate non-cancellable mailbox because the runtime's
/// blocking-task result is cancellation-dominant and can suppress a committed
/// transaction's returned value. No credential result travels in TaskHandle.
///
/// Dropping this owner requests worker cancellation and discards any eventual
/// handoff. A syscall/provider call already running cannot be forcibly stopped;
/// the caller's runtime region retains that worker until it settles. Drop does
/// not claim synchronous cleanup. Reopening must acquire the real file lock
/// and reconcile the independent anchor; Busy is not permission to steal it.
#[must_use = "retain the operation to observe its transaction disposition"]
pub struct CredentialSlotTask<T> {
    process: Arc<ProcessBoundToken>,
    worker: Option<TaskHandle<()>>,
    receiver: oneshot::Receiver<Result<T, CredentialIoError>>,
    received: bool,
}

impl<T> CredentialSlotTask<T> {
    /// Waits without resubmitting. A completion, including a terminal worker
    /// failure, is delivered once. Caller cancellation or deadline ends only
    /// this wait and consumes nothing. A later wait may use a fresh live Cx.
    /// The caller's timer is required when it sets a deadline.
    pub async fn wait(&mut self, cx: &Cx) -> Result<T, CredentialIoError> {
        self.process.verify().map_err(|_| CredentialIoError::ProcessChanged)?;
        if self.received { return Err(CredentialIoError::AlreadyReceived); }
        cx.checkpoint().map_err(|_| CredentialIoError::WaitCancelled)?;
        let received = if let Some(deadline) = cx.budget().deadline {
            if !cx.capabilities().time || cx.timer_driver().is_none() {
                return Err(CredentialIoError::CapabilityUnavailable);
            }
            if cx.now() >= deadline { return Err(CredentialIoError::WaitTimedOut); }
            asupersync::time::timeout_at(deadline, self.receiver.recv(cx)).await
                .map_err(|_| CredentialIoError::WaitTimedOut)?
        } else {
            self.receiver.recv(cx).await
        };
        match received {
            Ok(result) => {
                // The worker has moved both owner and disposition into this
                // mailbox. A cancelled join cannot rewrite that election.
                self.received = true;
                self.worker = None;
                result
            }
            Err(oneshot::RecvError::Cancelled) => Err(CredentialIoError::WaitCancelled),
            Err(oneshot::RecvError::Closed) => {
                self.received = true;
                if let Some(worker) = self.worker.take() { worker.abort(); }
                Err(CredentialIoError::WorkerStopped)
            }
            Err(oneshot::RecvError::PolledAfterCompletion) => {
                self.received = true;
                if let Some(worker) = self.worker.take() { worker.abort(); }
                Err(CredentialIoError::AlreadyReceived)
            }
        }
    }

    /// Requests cancellation of this worker only. Keep waiting to discover its
    /// actual storage outcome. Cancellation cannot reverse rename or anchor CAS.
    pub fn request_cancel(&self) -> Result<(), CredentialIoError> {
        self.process.verify().map_err(|_| CredentialIoError::ProcessChanged)?;
        if let Some(worker) = &self.worker { worker.abort(); }
        Ok(())
    }
}

impl<T> Drop for CredentialSlotTask<T> {
    fn drop(&mut self) {
        if self.process.verify().is_ok() {
            if let Some(worker) = &self.worker { worker.abort(); }
        }
    }
}
impl<T> fmt::Debug for CredentialSlotTask<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialSlotTask").field("received", &self.received).finish_non_exhaustive()
    }
}

/// An operation's slot owner and exact coordinated-storage outcome.
/// Failure does not erase the owner or change its requires_recovery flag.
/// There is no Clone, Debug, or serialization of the possibly sensitive result.
pub struct CredentialSlotCompletion<A, T> {
    owner: AsyncCoordinatedCredentialSlot<A>,
    outcome: Result<T, CoordinatedSlotError>,
}
impl<A, T> CredentialSlotCompletion<A, T> {
    pub fn into_parts(self) -> (AsyncCoordinatedCredentialSlot<A>, Result<T, CoordinatedSlotError>) {
        (self.owner, self.outcome)
    }
}

/// Result of opening/recovering through the caller-owned blocking lane.
pub type CredentialSlotOpen<A> = Result<
    (AsyncCoordinatedCredentialSlot<A>, Option<SlotRecoveryOutcome>),
    CoordinatedSlotError,
>;

/// Exclusive asynchronous custody of one durable credential slot.
///
/// Every submitted operation consumes this owner and returns it ONLY in the
/// operation completion. No mutex or Clone can permit a second command during
/// an uncertain first command. Inspect storage errors before further use; a
/// quarantined coordinator still requires explicit close/reopen recovery.
/// Providers must bound their synchronous calls and keep destructors nonblocking.
/// All filesystem/provider work after successful submission is off the poller.
/// A synchronous submission failure consumes this owner without starting the
/// transaction; reopen with the independently anchored revision to continue.
pub struct AsyncCoordinatedCredentialSlot<A> {
    process: Arc<ProcessBoundToken>,
    slot: CoordinatedCredentialSlot<A>,
}

impl<A: CredentialCommitAnchor + 'static> AsyncCoordinatedCredentialSlot<A> {
    /// Opens and, when necessary, recovers both file and anchor in the worker.
    /// The directory handle is supplied by the host; no ambient path is opened.
    /// The returned task, not this method, owns the opening/recovery outcome.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        cx: &Cx,
        guard: &ProcessGenerationGuard,
        directory: File,
        leaf: String,
        maximum_bytes: usize,
        key: CredentialStoreKey,
        authorization: PartitionAuthorization,
        namespace: String,
        anchor: A,
    ) -> Result<CredentialSlotTask<CredentialSlotOpen<A>>, CredentialIoError> {
        guard.verify_current().map_err(|_| CredentialIoError::ProcessChanged)?;
        let process = Arc::new(guard.token());
        let owner_process = Arc::clone(&process);
        submit(cx, process, move |worker_cx| {
            let file = SecureAtomicFile::open(worker_cx, directory, &leaf, maximum_bytes)
                .map_err(|error| CoordinatedSlotError::Slot(CredentialSlotError::Storage(error)))?;
            let (slot, recovery) = CoordinatedCredentialSlot::open(
                worker_cx, file, &key, &authorization, &namespace, anchor,
            )?;
            Ok((Self { process: owner_process, slot }, recovery))
        })
    }

    pub fn revision(&self) -> Option<SlotRevision> { self.slot.revision() }
    pub fn requires_recovery(&self) -> bool { self.slot.requires_recovery() }
    pub fn maximum_payload_bytes(&self) -> usize { self.slot.maximum_payload_bytes() }

    /// Authenticated ciphertext lookup, preserving absent versus tombstoned state
    /// through the returned owner's revision. It does not decrypt a credential.
    pub fn load(self, cx: &Cx, authorization: PartitionAuthorization)
        -> Result<CredentialSlotTask<CredentialSlotCompletion<A, Option<Vec<u8>>>>, CredentialIoError>
    {
        self.operate(cx, move |slot, cx| slot.load(cx, &authorization))
    }

    /// Commits protected bytes through the existing intent/file/anchor sequence.
    /// Success is never synthesized from a runtime join or an observed filename.
    pub fn replace(self, cx: &Cx, authorization: PartitionAuthorization,
        expected: Option<SlotRevision>, protected_payload: Vec<u8>)
        -> Result<CredentialSlotTask<CredentialSlotCompletion<A, SlotRevision>>, CredentialIoError>
    {
        if protected_payload.len() > self.maximum_payload_bytes() {
            check_submission(cx, &self.process)?;
            return Ok(ready(Arc::clone(&self.process), CredentialSlotCompletion {
                owner: self,
                outcome: Err(CoordinatedSlotError::Slot(CredentialSlotError::Storage(AtomicFileError::TooLarge))),
            }));
        }
        self.operate(cx, move |slot, cx| slot.replace(cx, &authorization, expected, &protected_payload))
    }

    /// Releases the old protected payload only after the coordinated tombstone
    /// commit. Retaining the pending task, rather than retrying take, is how a
    /// caller survives interruption of its wait without duplicating the handoff.
    pub fn take(self, cx: &Cx, authorization: PartitionAuthorization, expected: SlotRevision)
        -> Result<CredentialSlotTask<CredentialSlotCompletion<A, SlotCommit>>, CredentialIoError>
    {
        self.operate(cx, move |slot, cx| slot.take(cx, &authorization, expected))
    }

    /// Persistent logout/invalidation; no old credential payload is returned.
    pub fn invalidate(self, cx: &Cx, authorization: PartitionAuthorization)
        -> Result<CredentialSlotTask<CredentialSlotCompletion<A, SlotRevision>>, CredentialIoError>
    {
        self.operate(cx, move |slot, cx| slot.invalidate(cx, &authorization))
    }

    /// Drops the file lock and provider on the owned blocking lane. This is
    /// local closure only: it neither invalidates storage nor revokes a token.
    pub fn close(self, cx: &Cx) -> Result<CredentialSlotTask<()>, CredentialIoError> {
        submit(cx, Arc::clone(&self.process), move |_| drop(self))
    }

    fn operate<T, F>(mut self, cx: &Cx, operation: F)
        -> Result<CredentialSlotTask<CredentialSlotCompletion<A, T>>, CredentialIoError>
    where
        T: Send + 'static,
        F: FnOnce(&mut CoordinatedCredentialSlot<A>, &Cx) -> Result<T, CoordinatedSlotError> + Send + 'static,
    {
        submit(cx, Arc::clone(&self.process), move |worker_cx| {
            let outcome = operation(&mut self.slot, worker_cx);
            CredentialSlotCompletion { owner: self, outcome }
        })
    }
}
impl<A> fmt::Debug for AsyncCoordinatedCredentialSlot<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncCoordinatedCredentialSlot").finish_non_exhaustive()
    }
}

fn check_submission(cx: &Cx, process: &ProcessBoundToken) -> Result<(), CredentialIoError> {
    process.verify().map_err(|_| CredentialIoError::ProcessChanged)?;
    cx.checkpoint().map_err(|_| CredentialIoError::SubmissionCancelled)?;
    let capabilities = cx.capabilities();
    if !capabilities.spawn || !capabilities.io || !capabilities.time {
        return Err(CredentialIoError::CapabilityUnavailable);
    }
    // Cx::spawn_blocking otherwise has an inline fallback. Never let that
    // fallback perform disk/provider work on an asynchronous polling thread.
    if cx.blocking_pool_handle().is_none() {
        return Err(CredentialIoError::BlockingPoolUnavailable);
    }
    if cx.budget().deadline.is_some_and(|deadline| cx.now() >= deadline) {
        return Err(CredentialIoError::SubmissionTimedOut);
    }
    Ok(())
}

fn ready<T>(process: Arc<ProcessBoundToken>, value: T) -> CredentialSlotTask<T> {
    let (sender, receiver) = oneshot::channel();
    let _ = sender.send_blocking(Ok(value));
    CredentialSlotTask { process, worker: None, receiver, received: false }
}

fn submit<T, F>(cx: &Cx, process: Arc<ProcessBoundToken>, work: F)
    -> Result<CredentialSlotTask<T>, CredentialIoError>
where T: Send + 'static, F: FnOnce(&Cx) -> T + Send + 'static,
{
    check_submission(cx, &process)?;
    let worker_process = Arc::clone(&process);
    let (sender, receiver) = oneshot::channel();
    let worker = cx.spawn_blocking(move |worker_cx| {
        let result = if worker_process.verify().is_err() {
            Err(CredentialIoError::ProcessChanged)
        } else {
            // Provider panic hooks are host-owned. No panic text is retained in
            // our diagnostics, nor is a possibly-mutated owner returned on panic.
            catch_unwind(AssertUnwindSafe(|| work(&worker_cx)))
                .map_err(|_| CredentialIoError::WorkerPanicked)
        };
        // Publishing a disposition is not another credential effect. This send
        // deliberately does not consult the now-possibly-cancelled worker Cx.
        let _ = sender.send_blocking(result);
    }).map_err(|_| CredentialIoError::RuntimeUnavailable)?;
    Ok(CredentialSlotTask { process, worker: Some(worker), receiver, received: false })
}

#[cfg(test)]
mod tests;
